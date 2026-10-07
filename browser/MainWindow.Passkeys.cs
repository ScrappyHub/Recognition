using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace Recognition.Browser
{
    // recognition:passkeys — passkey (WebAuthn) support, diagnostics and per-site policy.
    //
    // What Recognition does NOT do: it does not create, store, sync or see passkeys. Creating and signing happens in the Windows
    // WebAuthn stack (Windows Hello, security keys, or a passkey provider you installed in Windows) through the WebView2 engine.
    // What it adds: (1) a guard script that counts passkey calls (kind only, never credential data) and can switch passkeys off
    // for a site, (2) a self-test that creates a throw-away credential for "localhost" and verifies the signature itself,
    // (3) a shortcut to Windows' own passkey settings.
    //
    // The self-test needs a secure context whose host is a valid WebAuthn RP ID, so the browser serves one page from
    // http://localhost:<random port>/pk/<random token>/ . The listener is bound to localhost only, answers only that token path,
    // rejects any Host header other than localhost:<port> (DNS rebinding), serves two static scripts, never receives any credential
    // data, and shuts itself down after 10 minutes or when the app closes.
    public partial class MainWindow
    {
        private readonly string _pkTel = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
        private string _passkeyLevel = "on";                                  // on | off (persisted in browser_settings.json)
        private readonly Dictionary<string, long> _pkTotals = new();           // session counts: pk_create / pk_get
        private HttpListener? _pkListener;
        private string _pkToken = "";
        private int _pkPort;
        private DispatcherTimer? _pkStop;
        private string? _pkGuardBody, _pkTestJs;

        private void MenuPasskeys_Click(object sender, RoutedEventArgs e) => OpenInternalInActiveTab("passkeys");

        // ---- guard script ----------------------------------------------------------------------------------------------

        private string? ReadResource(string name)
        {
            try
            {
                using var s = typeof(MainWindow).Assembly.GetManifestResourceStream(name);
                if (s == null) return null;
                using var r = new StreamReader(s, Encoding.UTF8);
                return r.ReadToEnd();
            }
            catch { return null; }
        }

        private string? PasskeyGuardScript()
        {
            _pkGuardBody ??= ReadResource("passkey_guard.js");
            if (_pkGuardBody == null) return null;
            var sites = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var kv in _sitePolicyState)
                if (kv.Key.StartsWith("passkeys|", StringComparison.Ordinal) && kv.Value is "on" or "off") sites[kv.Key.Substring("passkeys|".Length)] = kv.Value;
            var suffixes = PublicSuffixList.BuiltIn.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Where(x => x.Count(c => c == '.') == 1 && !x.Contains('*')).ToArray();
            var cfg = JsonSerializer.Serialize(new { tel = _pkTel, level = _passkeyLevel, sites, suffixes });
            return "(function(g,__cfg){" + _pkGuardBody + "\n})(window," + cfg + ");";
        }

        private async Task RegisterPasskeyGuardAsync(BrowserTab tab)
        {
            try
            {
                var core = tab.Web.CoreWebView2; if (core == null) return;
                if (tab.PasskeyScriptId != null) { core.RemoveScriptToExecuteOnDocumentCreated(tab.PasskeyScriptId); tab.PasskeyScriptId = null; }
                var js = PasskeyGuardScript();
                if (js != null) tab.PasskeyScriptId = await core.AddScriptToExecuteOnDocumentCreatedAsync(js);
            }
            catch { }
        }

        // Called from the shield poll timer for the active tab. Values originate in a web page: parsed defensively.
        private async Task PollPasskeysAsync(BrowserTab t)
        {
            try
            {
                if (t.PasskeyScriptId == null) return;
                var raw = await t.Web.CoreWebView2.ExecuteScriptAsync("(function(){try{var f=window['__rc_" + _pkTel + "'];return typeof f==='function'?String(f()):''}catch(e){return ''}})()");
                if (string.IsNullOrEmpty(raw) || raw == "null") return;
                var s = JsonSerializer.Deserialize<string>(raw) ?? "";
                if (s.Length == 0 || s.Length > 100) return;
                var origin = PasswordRules.OriginOf(t.Web.Source?.ToString()) ?? "";
                foreach (var part in s.Split(','))
                {
                    var kv = part.Split('=');
                    if (kv.Length != 2 || (kv[0] != "pk_create" && kv[0] != "pk_get") || !int.TryParse(kv[1], out var n) || n <= 0 || n > 10000) continue;
                    _pkTotals[kv[0]] = (_pkTotals.TryGetValue(kv[0], out var o) ? o : 0) + n;
                    if (!t.Private) _actions?.Append("passkey." + kv[0].Substring(3), origin + ":" + n);   // kind + site + count; never credential data
                }
            }
            catch { }
        }

        // ---- self-test server ----------------------------------------------------------------------------------------------

        private string StartPasskeyServer()
        {
            StopPasskeyServer();
            _pkTestJs ??= ReadResource("passkey_test.js") ?? "";
            var tl = new TcpListener(IPAddress.Loopback, 0); tl.Start(); _pkPort = ((IPEndPoint)tl.LocalEndpoint).Port; tl.Stop();
            _pkToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
            var listener = new HttpListener();
            listener.Prefixes.Add("http://localhost:" + _pkPort + "/pk/" + _pkToken + "/");
            listener.Start();
            _pkListener = listener;
            _ = Task.Run(() => PasskeyServeLoop(listener, _pkPort, _pkToken, _pkTestJs));
            _pkStop?.Stop();
            _pkStop = new DispatcherTimer { Interval = TimeSpan.FromMinutes(10) };
            _pkStop.Tick += (_, __) => StopPasskeyServer();
            _pkStop.Start();
            return "http://localhost:" + _pkPort + "/pk/" + _pkToken + "/";
        }

        private void StopPasskeyServer()
        {
            _pkStop?.Stop(); _pkStop = null;
            var l = _pkListener; _pkListener = null;
            if (l != null) { try { l.Close(); } catch { } }
        }

        private const string PkRunnerJs = "RecognitionPasskeyTest.run().then(function(r){var o=document.getElementById('out');o.textContent='';var good=0;r.forEach(function(x){var d=document.createElement('div');d.className=x.ok?'ok':'bad';d.textContent=(x.ok?'PASS  ':'FAIL  ')+x.name+(x.detail?'  -  '+x.detail:'');o.appendChild(d);if(x.ok)good++});var s=document.createElement('div');s.className='sum';s.textContent=good+' of '+r.length+' checks passed.';o.appendChild(s)}).catch(function(e){document.getElementById('out').textContent='Test error: '+e});";

        private const string PkPageHtml = "<!doctype html><html><head><meta charset='utf-8'><title>Recognition passkey test</title><style>" +
            "body{font-family:Segoe UI,Arial,sans-serif;background:#191c22;color:#e8e8e8;max-width:760px;margin:40px auto;padding:0 20px}" +
            ".ok{color:#6fcf97;margin:4px 0}.bad{color:#ff8a80;margin:4px 0}.sum{margin-top:12px;font-weight:600}.u{color:#9aa0a6;font-size:13px}" +
            "button{background:#3b6bff;color:#fff;border:0;border-radius:6px;padding:9px 16px;font-size:14px;cursor:pointer}</style></head><body>" +
            "<h1>Passkey test</h1><p class='u'>This page creates one throw-away passkey for <b>localhost</b> with Windows Hello or a security key, signs in with it, and checks the signature itself. Nothing is sent anywhere. " +
            "The test credential may remain in Windows (Settings, Accounts, Passkeys); you can delete it there.</p>" +
            "<p><button id='go'>Start test</button></p><div id='out'>Click Start. Windows will ask you to confirm twice (create, then sign in).</div>" +
            "<script src='test.js'></script><script>document.getElementById('go').onclick=function(){this.disabled=true;var s=document.createElement('script');s.src='run.js';document.body.appendChild(s)}</script></body></html>";

        private async Task PasskeyServeLoop(HttpListener l, int port, string token, string testJs)
        {
            var prefix = "/pk/" + token + "/";
            int served = 0;
            while (l.IsListening && served < 40)
            {
                HttpListenerContext ctx;
                try { ctx = await l.GetContextAsync(); } catch { break; }
                served++;
                try
                {
                    var rq = ctx.Request; var rs = ctx.Response;
                    string body; string mime = "text/plain; charset=utf-8"; int code = 200;
                    var hostOk = string.Equals(rq.UserHostName, "localhost:" + port, StringComparison.OrdinalIgnoreCase);
                    var path = rq.Url?.AbsolutePath ?? "";
                    if (!hostOk || rq.HttpMethod != "GET" || !path.StartsWith(prefix, StringComparison.Ordinal)) { code = 404; body = "not found"; }
                    else
                    {
                        var leaf = path.Substring(prefix.Length);
                        if (leaf.Length == 0) { body = PkPageHtml; mime = "text/html; charset=utf-8"; }
                        else if (leaf == "test.js") { body = testJs; mime = "text/javascript; charset=utf-8"; }
                        else if (leaf == "run.js") { body = PkRunnerJs; mime = "text/javascript; charset=utf-8"; }
                        else { code = 404; body = "not found"; }
                    }
                    var bytes = Encoding.UTF8.GetBytes(body);
                    rs.StatusCode = code; rs.ContentType = mime; rs.ContentLength64 = bytes.Length;
                    rs.Headers["Cache-Control"] = "no-store"; rs.Headers["X-Content-Type-Options"] = "nosniff"; rs.Headers["Referrer-Policy"] = "no-referrer";
                    rs.Headers["Content-Security-Policy"] = "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
                    await rs.OutputStream.WriteAsync(bytes, 0, bytes.Length);
                    rs.Close();
                }
                catch { try { ctx.Response.Abort(); } catch { } }
            }
        }

        // ---- page messages ---------------------------------------------------------------------------------------------------

        private void PostToPasskeyPage(object payload)
        {
            var t = Active; if (t == null || t.Internal != "passkeys") return;
            try { t.Web.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(payload)); } catch { }
        }

        private void SendPasskeySnapshot()
        {
            string wv = ""; try { wv = Microsoft.Web.WebView2.Core.CoreWebView2Environment.GetAvailableBrowserVersionString(); } catch { }
            var sites = _sitePolicyState.Where(kv => kv.Key.StartsWith("passkeys|", StringComparison.Ordinal))
                .Select(kv => new { host = kv.Key.Substring("passkeys|".Length), value = kv.Value }).OrderBy(x => x.host).ToList();
            PostToPasskeyPage(new
            {
                type = "snapshot", level = _passkeyLevel, sites,
                windows = Environment.OSVersion.VersionString, webview = wv,
                created = _pkTotals.TryGetValue("pk_create", out var c) ? c : 0, used = _pkTotals.TryGetValue("pk_get", out var g) ? g : 0,
                serverOn = _pkListener != null
            });
        }

        private async void HandlePasskeyMessage(string msg)
        {
            try
            {
                if (msg == "pk-state") { SendPasskeySnapshot(); return; }
                if (msg.StartsWith("pk-level:"))
                {
                    var lv = msg.Substring("pk-level:".Length); if (lv is not ("on" or "off")) return;
                    _passkeyLevel = lv; SaveSettings(); _actions?.Append("passkeys.level", lv);
                    foreach (var t in _tabs.ToList()) if (t.Ready) await RegisterPasskeyGuardAsync(t);
                    Status("passkeys " + (lv == "on" ? "allowed" : "blocked") + " by default (applies to pages you load next)"); SendPasskeySnapshot(); return;
                }
                if (msg.StartsWith("pk-site:"))
                {
                    var p = msg.Substring("pk-site:".Length).Split(':');
                    var host = p.Length == 2 ? p[0].Trim().ToLowerInvariant() : "";
                    if (host.Length == 0 || host.Length > 253 || !host.All(c => char.IsAsciiLetterOrDigit(c) || c == '.' || c == '-') || p[1] is not ("on" or "off" or "inherit")) { Status("site setting rejected"); return; }
                    SitePolicySet(host, "passkeys", p[1]); _actions?.Append("passkeys.site", host + ":" + p[1]);
                    foreach (var t in _tabs.ToList()) if (t.Ready) await RegisterPasskeyGuardAsync(t);
                    SendPasskeySnapshot(); return;
                }
                if (msg == "pk-test")
                {
                    string url;
                    try { url = StartPasskeyServer(); }
                    catch (Exception ex) { PostToPasskeyPage(new { type = "action", ok = false, text = "could not start the local test page: " + ex.Message }); return; }
                    var tab = await NewTabCoreAsync("Passkey test");
                    if (tab == null) return;
                    Tabs.SelectedItem = tab.Item; ShowActiveWebView(); NavigateTab(tab, url);
                    _actions?.Append("passkeys.test");
                    return;
                }
                if (msg == "pk-open-windows")
                {
                    try { Process.Start(new ProcessStartInfo("ms-settings:savedpasskeys") { UseShellExecute = true }); }   // fixed Windows Settings page, opens only on click
                    catch (Exception ex) { PostToPasskeyPage(new { type = "action", ok = false, text = "could not open Windows settings: " + ex.Message }); }
                    return;
                }
            }
            catch (Exception ex) { PostToPasskeyPage(new { type = "action", ok = false, text = "error: " + ex.Message }); }
        }

        private string PasskeysHtml()
        {
            var sb = new StringBuilder(PageHead);
            sb.Append(@"<title>Passkeys</title><h1>Passkeys</h1>
<div class='muted'>Passkeys let you sign in with Windows Hello (face, fingerprint, PIN) or a security key instead of a password. <b>Recognition does not store or see your passkeys.</b> Windows creates and keeps them (or a passkey app you have installed in Windows), and they work with Recognition through the Windows WebAuthn system. Recognition adds a test, per-site control, and a record that a passkey was used (the site and the kind of action, never any credential data). The Passwords page is separate and cannot hold passkeys.</div>
<div id='msg' class='u' style='min-height:18px;margin:8px 0'></div>
<div id='info' class='row' style='display:block'></div>

<h1 style='font-size:16px'>Test passkeys on this computer</h1>
<div class='muted'>Opens a local test page (served only to this computer) that creates a throw-away passkey for <b>localhost</b>, signs in with it and verifies the signature. Windows will ask you to confirm twice. It shows exactly which step fails if something is wrong. The test passkey can be deleted in Windows settings afterwards.</div>
<div style='margin:8px 0'><a class='btn' onclick=""send('pk-test')"">Run passkey test</a> <a class='btn ghost' onclick=""send('pk-open-windows')"">Open Windows passkey settings</a></div>

<h1 style='font-size:16px'>Control</h1>
<div class='muted'>Switching passkeys off for a site makes the site think passkeys are unavailable and rejects its passkey requests the same way cancelling does, so it falls back to a password. Password credentials are not affected.</div>
<div style='margin:8px 0;display:flex;gap:8px;align-items:center;flex-wrap:wrap'><span class='u'>Default:</span><a class='btn' id='lv_on' onclick=""send('pk-level:on')"">Allowed</a><a class='btn' id='lv_off' onclick=""send('pk-level:off')"">Blocked</a></div>
<div style='margin:8px 0;display:flex;gap:6px;flex-wrap:wrap;align-items:center'><span class='u'>Per site:</span>
 <input id='h' placeholder='example.com' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:6px'>
 <a class='btn ghost' onclick=""site('on')"">Allow</a><a class='btn ghost' onclick=""site('off')"">Block</a><a class='btn ghost' onclick=""site('inherit')"">Use default</a></div>
<div id='sites'></div>
<script>
function $(i){return document.getElementById(i)}
function el(t,txt,cls){var e=document.createElement(t);if(txt!=null)e.textContent=txt;if(cls)e.className=cls;return e}
function site(v){var h=$('h').value.trim();if(h)send('pk-site:'+h+':'+v)}
function render(m){
  var i=$('info');i.textContent='';
  i.appendChild(el('div','Passkey requests this session: '+m.created+' created, '+m.used+' sign-ins','t'));
  i.appendChild(el('div','Windows: '+m.windows+'   ·   Web engine: '+(m.webview||'unknown'),'u'));
  i.appendChild(el('div','Passkeys by default: '+(m.level==='on'?'allowed':'BLOCKED'),'u'));
  $('lv_on').className='btn'+(m.level==='on'?'':' ghost');$('lv_off').className='btn'+(m.level==='off'?'':' ghost');
  var s=$('sites');s.textContent='';(m.sites||[]).forEach(function(x){var r=el('div',null,'row');r.appendChild(el('div',x.host+'  ·  '+(x.value==='off'?'blocked':'allowed'),'t'));var b=el('div',null,'ts');var a=el('a','Remove','btn ghost');a.onclick=function(){send('pk-site:'+x.host+':inherit')};b.appendChild(a);r.appendChild(b);s.appendChild(r)})}
window.chrome.webview.addEventListener('message',function(ev){var m=ev.data;if(!m)return;if(m.type==='snapshot')render(m);else if(m.type==='action')$('msg').textContent=m.text});
send('pk-state');
</script>");
            sb.Append(SendScript()).Append(PageFoot);
            return sb.ToString();
        }
    }
}
