using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Web.WebView2.Core;

namespace Recognition.Browser
{
    // Tor tabs. Each Tor tab runs in its own engine profile that is created with a Tor proxy, so Tor tabs and normal tabs live in the
    // same window but share nothing: no cookies, no cache, no proxy. Tor tabs are private (nothing is written to history or bookmarks)
    // and fail closed: when Tor is not running they do not open, and they never fall back to a direct connection.
    // Recognition does not bundle Tor. It uses Tor that is already running (Tor Browser on 9150, or the Tor service on 9050).
    // The whole feature can be switched off in Settings; when it is off there is no menu item and the VPN page does not mention it.
    public partial class MainWindow
    {
        private bool _torEnabled = true;                 // persisted in browser_settings.json as tor_enabled
        private CoreWebView2Environment? _torEnv;
        private string? _torDir;
        private int _torPort;
        private string _torWebRtc = "unknown";

        private void ApplyTorVisibility()
        {
            try { TorMenuItem.Visibility = _torEnabled ? Visibility.Visible : Visibility.Collapsed; } catch { }
        }

        private async Task<int> FindTorPortAsync()
        {
            var a = ProbeAsync("127.0.0.1", TorRules.BrowserPort); var b = ProbeAsync("127.0.0.1", TorRules.ServicePort);
            bool bu = await a >= 0, su = await b >= 0;
            return TorRules.ChoosePort(bu, su);
        }

        private async void MenuTor_Click(object sender, RoutedEventArgs e)
        {
            if (!_torEnabled) return;
            var port = await FindTorPortAsync();
            if (port == 0) { OpenInternalInActiveTab("tor"); return; }   // explains how to start Tor; never opens a direct tab
            await OpenTorTabAsync(port);
        }

        private async Task<BrowserTab?> OpenTorTabAsync(int port)
        {
            if (!_torEnabled || port == 0) return null;
            try
            {
                if (_torEnv == null)
                {
                    _torDir = Path.Combine(Path.GetTempPath(), "rb-tor-" + Guid.NewGuid().ToString("N"));
                    Directory.CreateDirectory(_torDir);
                    var o = new CoreWebView2EnvironmentOptions { AdditionalBrowserArguments = TorRules.EngineArgs(port) };
                    _torEnv = await CoreWebView2Environment.CreateAsync(null, _torDir, o);
                    _torPort = port;
                }
            }
            catch (Exception ex) { Status("Tor tab failed to start: " + ex.Message); return null; }
            var tab = await NewTabCoreAsync("Tor", true, _torEnv, true);
            if (tab == null) return null;
            Tabs.SelectedItem = tab.Item; ShowActiveWebView();
            LoadInternal(tab, "start");
            AddressBar.Text = ""; AddressBar.Focus();
            _actions?.Append("tor.tab_open", "port:" + _torPort);
            Status("Tor tab - traffic goes through Tor on this computer (port " + _torPort + "), nothing is saved");
            return tab;
        }

        private void CleanupTorOnExit()
        {
            foreach (var t in _tabs.Where(x => x.Tor).ToList()) { try { t.Web.Dispose(); } catch { } }
            if (_torDir != null) { try { if (Directory.Exists(_torDir)) Directory.Delete(_torDir, true); } catch { } }
        }

        private void PostToTorPage(object payload)
        {
            var t = Active; if (t == null || t.Internal != "tor") return;
            try { t.Web.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(payload)); } catch { }
        }

        private async Task SendTorStateAsync(string? check = null)
        {
            var port = _torEnabled ? await FindTorPortAsync() : 0;
            PostToTorPage(new { type = "state", enabled = _torEnabled, running = port != 0, port, tabs = _tabs.Count(t => t.Tor), check = check ?? "" });
        }

        private async void HandleTorMessage(string msg)
        {
            try
            {
                if (msg == "tor-state") { await SendTorStateAsync(); return; }
                if (msg == "tor-enable:off")
                {
                    foreach (var t in _tabs.Where(x => x.Tor).ToList()) CloseTab(t);
                    _torEnabled = false; SaveSettings(); ApplyTorVisibility(); _actions?.Append("tor.disabled", "");
                    Status("Tor features are off"); RefreshInternalIf("settings", "tor", "vpn"); return;
                }
                if (msg == "tor-enable:on")
                {
                    _torEnabled = true; SaveSettings(); ApplyTorVisibility(); _actions?.Append("tor.enabled", "");
                    Status("Tor features are on"); RefreshInternalIf("settings", "tor", "vpn"); return;
                }
                if (!_torEnabled) return;
                if (msg == "tor-open")
                {
                    var port = await FindTorPortAsync();
                    if (port == 0) { await SendTorStateAsync(); return; }
                    await OpenTorTabAsync(port); return;
                }
                if (msg == "tor-site")
                {
                    var port = await FindTorPortAsync(); if (port == 0) { await SendTorStateAsync(); return; }
                    var t = await OpenTorTabAsync(port); if (t != null) NavigateTab(t, "https://check.torproject.org/");
                    return;
                }
                if (msg == "tor-check") { await RunTorCheckAsync(); return; }
            }
            catch (Exception ex) { PostToTorPage(new { type = "check", text = "error: " + ex.Message }); }
        }

        private void RefreshInternalIf(params string[] names)
        {
            var a = Active; if (a != null && names.Contains(a.Internal)) LoadInternal(a, a.Internal);
        }

        private async Task RunTorCheckAsync()
        {
            PostToTorPage(new { type = "check", text = "Checking..." });
            var port = await FindTorPortAsync();
            bool apiOk = false, isTor = false; string ip = "";
            if (port != 0)
            {
                try
                {
                    // asks the Tor Project which network the request came from, through the same Tor port the Tor tabs use
                    using var h = new SocketsHttpHandler { Proxy = new WebProxy(TorRules.ProxyUrl(port)), UseProxy = true, ConnectTimeout = TimeSpan.FromSeconds(15) };
                    using var c = new HttpClient(h) { Timeout = TimeSpan.FromSeconds(25) };
                    var body = await c.GetStringAsync("https://check.torproject.org/api/ip");
                    apiOk = TorRules.ParseTorApi(body, out isTor, out ip);
                }
                catch { apiOk = false; }
            }
            var tt = _tabs.FirstOrDefault(t => t.Tor && t.Ready);
            _torWebRtc = "unknown";
            if (tt != null)
            {
                try
                {
                    var r = await tt.Web.CoreWebView2.ExecuteScriptAsync(TorRules.WebRtcProbeScript);
                    _torWebRtc = r.Trim('"') == "ok" ? "ok" : "exposed";
                }
                catch { _torWebRtc = "unknown"; }
            }
            _actions?.Append("tor.check", (isTor ? "tor" : "not_tor") + ":" + _torWebRtc);
            PostToTorPage(new
            {
                type = "check", verdict = TorRules.Verdict(port != 0, apiOk, isTor, _torWebRtc),
                running = port != 0, port, isTor, exitIp = ip, webrtc = _torWebRtc, torTabs = _tabs.Count(t => t.Tor)
            });
        }

        private string TorStartHtml()
        {
            return @"<!doctype html><html><head><meta charset='utf-8'><meta name='rec-internal' content='1'><title>Tor tab</title><style>
html,body{height:100%;margin:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:radial-gradient(1200px 600px at 50% -10%,#2b2147,#15121f 60%);color:#e8e8e8;display:flex;flex-direction:column;align-items:center;justify-content:center}
h1{font-weight:600;margin:0 0 4px;font-size:26px}.sub{color:#b4a6dd;margin-bottom:26px;font-size:12.5px;max-width:520px;text-align:center}
form{display:flex;width:min(640px,82vw);border-radius:10px;box-shadow:0 8px 30px rgba(0,0,0,.4)}
input{flex:1;padding:15px 18px;border:1px solid #3d3456;border-right:none;border-radius:10px 0 0 10px;background:#12101a;color:#e8e8e8;font-size:15px;outline:none}
button{padding:0 26px;border:1px solid #7a4bd6;border-radius:0 10px 10px 0;background:#7a4bd6;color:#fff;font-size:15px;cursor:pointer}
.pills{margin-top:22px;display:flex;gap:10px;flex-wrap:wrap;justify-content:center}.pill{border:1px solid #45395f;background:#221c33;color:#bdb2dd;border-radius:999px;padding:6px 12px;font-size:11.5px}
a{color:#b9a4ff;text-decoration:none;font-size:12.5px;margin-top:22px}
</style></head><body><h1>Tor tab</h1>
<div class='sub'>This tab reaches the web through the Tor network. It has its own profile, nothing is saved, and WebRTC is blocked.</div>
<form id='f'><input id='q' autofocus autocomplete='off' spellcheck='false' placeholder='Search DuckDuckGo or type an address (.onion works)'><button type='submit'>Go</button></form>
<div class='pills'><span class='pill'>Own profile</span><span class='pill'>No history</span><span class='pill'>WebRTC off</span><span class='pill'>Erased on close</span></div>
<a href='recognition:tor'>Run a leak check</a>
<script>document.getElementById('f').addEventListener('submit',function(e){e.preventDefault();var v=(document.getElementById('q').value||'').trim();if(!v)return;
if(/^[a-z][a-z0-9+.\-]*:\/\//i.test(v)){location.href=v;}else if(v.indexOf('.')>-1&&v.indexOf(' ')===-1){location.href=(/\.onion(\/|$)/i.test(v)?'http://':'https://')+v;}else{location.href='https://duckduckgo.com/?q='+encodeURIComponent(v);}});</script></body></html>";
        }

        private string TorHtml()
        {
            var sb = new StringBuilder(PageHead);
            sb.Append("<title>Tor</title><h1>Tor</h1>");
            if (!_torEnabled)
            {
                sb.Append("<div class='muted'>Tor features are off. Nothing about Tor appears in menus or on the VPN page.</div><div style='margin:10px 0'><a class='btn' onclick=\"send('tor-enable:on')\">Turn Tor features on</a></div>");
                sb.Append(SendScript()).Append(PageFoot); return sb.ToString();
            }
            sb.Append(@"<div class='muted'>A Tor tab opens a separate private profile that reaches the web (and .onion sites) through the Tor network, next to your normal tabs. Recognition does not include Tor: install Tor Browser and leave it open, or run the Tor service, and Recognition uses it.</div>
<div id='st' class='row' style='display:block'></div>
<div style='margin:8px 0;display:flex;gap:8px;flex-wrap:wrap'><a class='btn' onclick=""send('tor-open')"">Open a Tor tab</a><a class='btn ghost' onclick=""send('tor-check')"">Run leak check</a><a class='btn ghost' onclick=""send('tor-site')"">Open the Tor Project check in a Tor tab</a></div>
<div id='res' class='row' style='display:none'></div>
<div class='muted' style='margin-top:14px'><b>What Tor tabs do:</b> a separate profile (no shared cookies or cache), a Tor-only proxy with names looked up through Tor, WebRTC and camera/microphone blocked, QUIC off, nothing saved to history, and no fallback to a direct connection when Tor stops. <b>What they do not do:</b> make you look like every other Tor user. Tor Browser is built for that and Recognition is not, so for strong anonymity use Tor Browser. Do not log in to accounts that know who you are.</div>
<div style='margin:14px 0'><a class='btn ghost' onclick=""send('tor-enable:off')"">Turn Tor features off</a></div>
<script>
function $(i){return document.getElementById(i)}
function line(t,c){var d=document.createElement('div');d.textContent=t;if(c)d.className=c;return d}
window.chrome.webview.addEventListener('message',function(ev){var m=ev.data;if(!m)return;
 if(m.type==='state'){var s=$('st');s.textContent='';s.appendChild(line(m.running?('Tor is running on this computer (port '+m.port+').'):'Tor is not running. Start Tor Browser (leave it open) or the Tor service, then come back.','t'));s.appendChild(line(m.tabs+' Tor tab(s) open','u'))}
 if(m.type==='check'){var r=$('res');r.style.display='block';r.textContent='';r.appendChild(line(m.verdict||m.text,'t'));
  if(m.verdict){r.appendChild(line('Tor port: '+(m.running?'reachable ('+m.port+')':'not reachable'),'u'));r.appendChild(line('Exit network: '+(m.isTor?'Tor ('+(m.exitIp||'address hidden')+')':'not Tor'),'u'));r.appendChild(line('WebRTC in Tor tabs: '+(m.webrtc==='ok'?'blocked':(m.webrtc==='exposed'?'EXPOSED':'not tested (open a Tor tab first)')),'u'))}}
});
send('tor-state');
</script>");
            sb.Append(SendScript()).Append(PageFoot);
            return sb.ToString();
        }

        private string TorSettingsRow() =>
            "<div class='row'><div><div class='t'>Tor tabs</div><div class='u'>" + (_torEnabled
                ? "On. Menu &rarr; Private Tor tab opens a separate private tab through Tor, if Tor is running on this computer."
                : "Off. Tor does not appear anywhere in the browser.") + "</div></div><div class='ts'>" +
            (_torEnabled ? "<a class='btn ghost' href='recognition:tor'>Tor page</a> <a class='btn ghost' onclick=\"send('tor-enable:off')\">Turn off</a>"
                         : "<a class='btn' onclick=\"send('tor-enable:on')\">Turn on</a>") + "</div></div>";
    }
}
