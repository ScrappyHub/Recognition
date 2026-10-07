using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace Recognition.Browser
{
    // Network panel (recognition:network): what you are connected to, live traffic, ping, an on-demand
    // speed test, saved networks with trusted/guest/blocked labels, and a connection history.
    // Everything that touches the OS or network happens ONLY when the page is open or a button is clicked:
    //  - live rates and the connection observer read local adapter counters / `netsh` (no external traffic)
    //  - ping and the speed test run only on an explicit click and say which host they contact
    //  - connect / disconnect / forget are explicit, confirmed where destructive, and receipted
    // The parsing, statistics and validation logic lives in NetworkInfo.cs and is executed by browser.tests.
    public partial class MainWindow
    {
        private GovernedActions _netHistory = null!;       // runtime\network_history.v1.enc (DPAPI, hash-chained)
        private DispatcherTimer? _netObserveTimer;
        private DispatcherTimer? _netRateTimer;
        private string _netCurrent = "";                   // id of the network we are currently recording ("" = none)
        private RateCalc _rate = new();
        private static readonly HttpClient SpeedHttp = new() { Timeout = TimeSpan.FromSeconds(45) };

        // ---- OS helpers (always called off the UI thread) -------------------------
        private static (int code, string output) RunNetsh(params string[] args)
        {
            try
            {
                var psi = new ProcessStartInfo("netsh.exe") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
                foreach (var a in args) psi.ArgumentList.Add(a);   // argument list: no shell, no injection
                using var p = Process.Start(psi);
                if (p == null) return (-1, "could not start netsh");
                var o = p.StandardOutput.ReadToEndAsync(); var e = p.StandardError.ReadToEndAsync();
                if (!p.WaitForExit(8000)) { try { p.Kill(); } catch { } return (-1, "timeout"); }
                return (p.ExitCode, o.Result + e.Result);
            }
            catch (Exception ex) { return (-1, ex.Message); }
        }

        private static NetworkInterface? PrimaryAdapter()
        {
            try
            {
                return NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n =>
                    n.OperationalStatus == OperationalStatus.Up &&
                    n.NetworkInterfaceType != NetworkInterfaceType.Loopback && n.NetworkInterfaceType != NetworkInterfaceType.Tunnel &&
                    n.GetIPProperties().GatewayAddresses.Any(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                                                                   !g.Address.Equals(System.Net.IPAddress.Any)));
            }
            catch { return null; }
        }

        private static (string id, string kind) DetectCurrentNetwork()
        {
            var wi = NetParsers.ParseWlanInterface(RunNetsh("wlan", "show", "interfaces").output);
            if (wi.TryGetValue("State", out var st) && st.Equals("connected", StringComparison.OrdinalIgnoreCase) &&
                wi.TryGetValue("SSID", out var ssid) && ssid.Length > 0) return (ssid, "wifi");
            var p = PrimaryAdapter();
            return p != null ? ("Wired: " + p.Name, "wired") : ("", "none");
        }

        // ---- connection observer (history of what you were connected to, while the browser runs) ----
        private void StartNetworkObserver()
        {
            _ = ObserveNetworkAsync();
            _netObserveTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
            _netObserveTimer.Tick += async (_, __) => await ObserveNetworkAsync();
            _netObserveTimer.Start();
        }

        private async Task ObserveNetworkAsync()
        {
            try
            {
                var (id, kind) = await Task.Run(DetectCurrentNetwork);
                if (id == _netCurrent) return;
                if (_netCurrent != "") _netHistory.Append(NetHistory.DisconnectPrefix + _netCurrent);
                if (id != "")
                {
                    _netHistory.Append(NetHistory.ConnectPrefix + id, kind);
                    if (SitePolicyGet(NetParsers.SsidKey(id), "netlabel", "none") == "blocked")
                    {
                        _actions?.Append("net.blocked_network_connected", id);
                        Status("connected to a network you marked BLOCKED: " + id);
                    }
                }
                _netCurrent = id;
            }
            catch { }
        }

        private void RecordNetworkEnd()
        {
            if (_netCurrent == "" || _netHistory == null) return;
            try { _netHistory.Append(NetHistory.DisconnectPrefix + _netCurrent); } catch { }
            _netCurrent = "";
        }

        // ---- snapshot ------------------------------------------------------------
        private static DateTime ParseTs(string ts) =>
            DateTime.TryParse(ts, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var d) ? d.ToUniversalTime() : DateTime.UtcNow;

        private (string download, string upload) LoadSpeedConfig()
        {
            string down = "https://speed.cloudflare.com/__down?bytes=12000000", up = "https://speed.cloudflare.com/__up";
            try
            {
                var p = Path.Combine(_repoRoot, "config", "speedtest.v1.json");
                if (File.Exists(p))
                {
                    using var d = JsonDocument.Parse(File.ReadAllText(p));
                    if (d.RootElement.TryGetProperty("download_url", out var du) && du.GetString() is string dus && dus.StartsWith("https://")) down = dus;
                    if (d.RootElement.TryGetProperty("upload_url", out var uu) && uu.GetString() is string uus && uus.StartsWith("https://")) up = uus;
                }
            }
            catch { }
            return (down, up);
        }

        private async Task SendNetSnapshotAsync()
        {
            try
            {
                var raw = await Task.Run(() =>
                {
                    var adapters = NetworkInterface.GetAllNetworkInterfaces()
                        .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback && n.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                        .Select(n =>
                        {
                            var ip = n.GetIPProperties();
                            return new
                            {
                                name = n.Name, type = n.NetworkInterfaceType.ToString(), status = n.OperationalStatus.ToString(),
                                speedMbps = n.Speed > 0 ? n.Speed / 1_000_000 : 0,
                                ipv4 = string.Join(", ", ip.UnicastAddresses.Where(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).Select(a => a.Address.ToString())),
                                gateway = string.Join(", ", ip.GatewayAddresses.Where(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).Select(g => g.Address.ToString())),
                                dns = string.Join(", ", ip.DnsAddresses.Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).Select(a => a.ToString())),
                                mac = n.GetPhysicalAddress().ToString()
                            };
                        }).ToList();
                    var wifi = NetParsers.ParseWlanInterface(RunNetsh("wlan", "show", "interfaces").output);
                    var profiles = NetParsers.ParseWlanProfiles(RunNetsh("wlan", "show", "profiles").output);
                    return (adapters, wifi, profiles);
                });

                var saved = raw.profiles.Select(p => new { name = p, label = SitePolicyGet(NetParsers.SsidKey(p), "netlabel", "none"), current = p == _netCurrent }).ToList();
                var history = NetHistory.Summarize(_netHistory.Items.Select(i => (ParseTs(i.Ts), i.Action)), DateTime.UtcNow)
                    .Select(r => new { ssid = r.Ssid, connections = r.Connections, seconds = r.TotalSeconds, last = r.LastSeenUtc.ToString("o"), label = SitePolicyGet(NetParsers.SsidKey(r.Ssid), "netlabel", "none") }).ToList();
                var (down, up) = LoadSpeedConfig();
                PostToNetPage(new
                {
                    type = "snapshot", adapters = raw.adapters, wifi = raw.wifi, saved, history, current = _netCurrent,
                    speed = new { download = down, upload = up, host = new Uri(down).Host },
                    gateway = PrimaryAdapter()?.GetIPProperties().GatewayAddresses.FirstOrDefault(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.Address.ToString() ?? ""
                });
            }
            catch (Exception ex) { PostToNetPage(new { type = "action", ok = false, text = "could not read network state: " + ex.Message }); }
        }

        private void PostToNetPage(object payload)
        {
            var t = Active; if (t == null || t.Internal != "network") return;
            try { t.Web.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(payload)); } catch { }
        }

        // ---- live traffic (local adapter counters only) -----------------------------
        private void StartNetRateTimer()
        {
            if (_netRateTimer != null) return;
            _rate = new RateCalc();
            _netRateTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _netRateTimer.Tick += (_, __) =>
            {
                var t = Active;
                if (t == null || t.Internal != "network") { _netRateTimer?.Stop(); _netRateTimer = null; return; }   // stops itself when you leave the page
                try
                {
                    var p = PrimaryAdapter();
                    if (p == null) { PostToNetPage(new { type = "rate", rx = 0.0, tx = 0.0, adapter = "" }); return; }
                    var s = p.GetIPv4Statistics();
                    var (rx, tx) = _rate.Sample(s.BytesReceived, s.BytesSent, DateTime.UtcNow);
                    PostToNetPage(new { type = "rate", rx, tx, adapter = p.Name });
                }
                catch { }
            };
            _netRateTimer.Start();
        }

        // ---- ping (explicit click) ---------------------------------------------------
        private async Task RunPingAsync(string target, string label)
        {
            var rtts = new List<long?>();
            try
            {
                using var ping = new Ping();
                for (int i = 0; i < 8; i++)
                {
                    try { var r = await ping.SendPingAsync(target, 2000); rtts.Add(r.Status == IPStatus.Success ? r.RoundtripTime : (long?)null); }
                    catch { rtts.Add(null); }
                    await Task.Delay(250);
                }
            }
            catch { }
            var s = PingStats.Summarize(rtts);
            _actions?.Append("net.ping", target);
            PostToNetPage(new { type = "ping", target = label, sent = s.Sent, received = s.Received, loss = s.LossPct, min = s.Min, avg = s.Avg, max = s.Max, jitter = s.Jitter });
        }

        // ---- speed test (explicit click; contacts the configured host DIRECTLY, not via the VPN/proxy) ----
        private async Task RunSpeedTestAsync()
        {
            var (down, up) = LoadSpeedConfig();
            double dl = 0, ul = 0, latency = 0; string err = "";
            PostToNetPage(new { type = "speedstart", host = new Uri(down).Host });
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, down);
                var sw = Stopwatch.StartNew();
                using var resp = await SpeedHttp.SendAsync(req, HttpCompletionOption.ResponseHeadersRead);
                latency = sw.Elapsed.TotalMilliseconds;
                resp.EnsureSuccessStatusCode();
                using var stream = await resp.Content.ReadAsStreamAsync();
                var buf = new byte[65536]; long total = 0; var sw2 = Stopwatch.StartNew(); int n;
                while ((n = await stream.ReadAsync(buf, 0, buf.Length)) > 0) { total += n; if (sw2.Elapsed.TotalSeconds > 10) break; }
                dl = total * 8.0 / Math.Max(0.001, sw2.Elapsed.TotalSeconds) / 1e6;
            }
            catch (Exception ex) { err += "download: " + ex.Message + " "; }
            try
            {
                var payload = new byte[4 * 1024 * 1024]; Random.Shared.NextBytes(payload);
                var sw3 = Stopwatch.StartNew();
                using var r = await SpeedHttp.PostAsync(up, new ByteArrayContent(payload));
                sw3.Stop(); r.EnsureSuccessStatusCode();
                ul = payload.Length * 8.0 / Math.Max(0.001, sw3.Elapsed.TotalSeconds) / 1e6;
            }
            catch (Exception ex) { err += "upload: " + ex.Message; }
            _actions?.Append("net.speedtest", down);
            PostToNetPage(new { type = "speed", download = Math.Round(dl, 2), upload = Math.Round(ul, 2), latency = Math.Round(latency, 0), error = err.Trim() });
        }

        // ---- explicit network actions ---------------------------------------------------
        private async Task NetActionAsync(string action, string name)
        {
            try
            {
                if (action != "disconnect" && !NetParsers.IsSafeNetworkName(name)) { PostToNetPage(new { type = "action", ok = false, text = "invalid network name" }); return; }
                (int code, string output) res;
                switch (action)
                {
                    case "connect":
                        if (SitePolicyGet(NetParsers.SsidKey(name), "netlabel", "none") == "blocked")
                        { PostToNetPage(new { type = "action", ok = false, text = "'" + name + "' is labelled BLOCKED. Change its label first if you really want to connect." }); return; }
                        res = await Task.Run(() => RunNetsh("wlan", "connect", "name=" + name)); break;
                    case "disconnect":
                        res = await Task.Run(() => RunNetsh("wlan", "disconnect")); break;
                    case "forget":
                        if (MessageBox.Show(this, "Forget the saved network '" + name + "'?\n\nWindows will remove its saved profile (including the password). You will need to enter the password again to reconnect.",
                                "Recognition — Forget network", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
                        { PostToNetPage(new { type = "action", ok = false, text = "cancelled" }); return; }
                        res = await Task.Run(() => RunNetsh("wlan", "delete", "profile", "name=" + name)); break;
                    default: return;
                }
                _actions?.Append("net." + action, name);
                PostToNetPage(new { type = "action", ok = res.code == 0, text = (res.code == 0 ? "done: " : "failed (may need administrator rights): ") + res.output.Trim() });
            }
            catch (Exception ex) { PostToNetPage(new { type = "action", ok = false, text = ex.Message }); }
            await SendNetSnapshotAsync();
        }

        private void HandleNetMessage(string msg)
        {
            string Dec(string s) { try { return Uri.UnescapeDataString(s); } catch { return ""; } }
            if (msg == "net-snapshot") { _ = SendNetSnapshotAsync(); StartNetRateTimer(); }
            else if (msg == "net-ping:gateway")
            {
                var gw = PrimaryAdapter()?.GetIPProperties().GatewayAddresses.FirstOrDefault(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.Address.ToString();
                if (string.IsNullOrEmpty(gw)) PostToNetPage(new { type = "action", ok = false, text = "no default gateway found" });
                else _ = RunPingAsync(gw, "gateway " + gw);
            }
            else if (msg.StartsWith("net-ping-host:"))
            {
                var h = Dec(msg.Substring("net-ping-host:".Length)).Trim();
                if (!NetParsers.IsSafeHost(h)) PostToNetPage(new { type = "action", ok = false, text = "not a valid host name or IP address" });
                else _ = RunPingAsync(h, h);
            }
            else if (msg == "net-speed") _ = RunSpeedTestAsync();
            else if (msg == "net-disconnect") _ = NetActionAsync("disconnect", "");
            else if (msg.StartsWith("net-connect:")) _ = NetActionAsync("connect", Dec(msg.Substring("net-connect:".Length)));
            else if (msg.StartsWith("net-forget:")) _ = NetActionAsync("forget", Dec(msg.Substring("net-forget:".Length)));
            else if (msg.StartsWith("net-label:"))
            {
                var parts = msg.Substring("net-label:".Length).Split(':');
                var name = parts.Length == 2 ? Dec(parts[0]) : "";
                var label = parts.Length == 2 ? parts[1] : "";
                if (NetParsers.IsSafeNetworkName(name) && (label is "none" or "trusted" or "guest" or "blocked"))
                {
                    SitePolicySet(NetParsers.SsidKey(name), "netlabel", label);
                    _actions?.Append("net.label." + label, name);
                    Status("network '" + name + "' marked " + label);
                    _ = SendNetSnapshotAsync();
                }
            }
        }

        private void MenuNetwork_Click(object sender, RoutedEventArgs e) => OpenInternalInActiveTab("network");

        // ---- the page ---------------------------------------------------------------------
        private string NetworkHtml()
        {
            var sb = new System.Text.StringBuilder(PageHead);
            sb.Append(@"<title>Network</title><h1>Network</h1>
<div class='muted'>What this computer is connected to. Reading adapters, live traffic and saved networks is local only. Ping and the speed test run only when you click them and say which host they contact.</div>
<div id='msg' class='u' style='min-height:18px;margin-bottom:8px'></div>

<h1 style='font-size:16px'>Connection</h1><div id='conn'><div class='empty'>Reading network state&hellip;</div></div>

<h1 style='font-size:16px'>Live traffic</h1>
<div class='row'><div><div class='t'>Receiving</div><div class='u' id='rxa'>&nbsp;</div></div><div class='ts'><span class='big' id='rx'>&ndash;</span></div></div>
<div class='row'><div><div class='t'>Sending</div><div class='u'>local adapter counters, updated every second</div></div><div class='ts'><span class='big' id='tx'>&ndash;</span></div></div>

<h1 style='font-size:16px'>Latency</h1>
<div style='margin:0 0 8px;display:flex;gap:10px;flex-wrap:wrap;align-items:center'>
  <a class='btn' onclick=""send('net-ping:gateway')"">Ping gateway</a>
  <input id='host' placeholder='host or IP (e.g. example.com)' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:8px 10px;width:230px'>
  <a class='btn ghost' onclick=""send('net-ping-host:'+encodeURIComponent(document.getElementById('host').value))"">Ping host</a>
</div><div id='ping' class='u' style='margin-bottom:18px'></div>

<h1 style='font-size:16px'>Speed test</h1>
<div class='u' id='speedinfo' style='margin-bottom:8px'></div>
<div style='margin:0 0 8px'><a class='btn' onclick=""send('net-speed')"">Run speed test</a></div>
<div id='speed' class='u' style='margin-bottom:18px'></div>

<h1 style='font-size:16px'>Saved networks</h1>
<div class='muted'>Label a network <b>trusted</b>, <b>guest</b> or <b>blocked</b> (Recognition warns if you connect to a blocked one, and refuses to connect to it from here). <b>Forget</b> removes the saved profile from Windows.</div>
<div id='saved'></div>
<div style='margin:10px 0 18px'><a class='btn ghost' onclick=""send('net-disconnect')"">Disconnect Wi-Fi</a></div>

<h1 style='font-size:16px'>Connection history</h1>
<div class='muted'>Networks this browser has seen you connected to while it was running (stored encrypted, hash-chained). It cannot see times when Recognition was closed.</div>
<div id='hist'></div>
<script>
function $(i){return document.getElementById(i)}
function el(t,txt,cls){var e=document.createElement(t);if(txt!=null)e.textContent=txt;if(cls)e.className=cls;return e}
function kv(k,v){var r=el('div',null,'kv');r.appendChild(el('div',k,'k'));r.appendChild(el('div',v,'v'));return r}
function rate(bps){var b=bps*8;if(b>=1e6)return (b/1e6).toFixed(2)+' Mbps';if(b>=1e3)return (b/1e3).toFixed(1)+' kbps';return b.toFixed(0)+' bps'}
function dur(s){s=Math.round(s);var h=Math.floor(s/3600),m=Math.floor(s%3600/60);return h>0?h+' h '+m+' min':(m>0?m+' min '+(s%60)+' s':s+' s')}
var enc=encodeURIComponent;
function btn(t,cmd,ghost){var a=el('a',t,'btn'+(ghost?' ghost':''));a.style.marginLeft='6px';a.onclick=function(){send(cmd)};return a}
function labelSel(name,cur){var s=el('select');s.style.cssText='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:5px 6px';
  ['none','trusted','guest','blocked'].forEach(function(v){var o=el('option',v==='none'?'no label':v);o.value=v;if(v===cur)o.selected=true;s.appendChild(o)});
  s.onchange=function(){send('net-label:'+enc(name)+':'+s.value)};return s}
function render(m){
  var c=$('conn');c.textContent='';var w=m.wifi||{};
  if(w.State){c.appendChild(kv('Wi-Fi',w.State+(w.SSID?' to '+w.SSID:'')));
    if(w.Signal)c.appendChild(kv('Signal',w.Signal));
    if(w['Receive rate (Mbps)'])c.appendChild(kv('Link speed (rx / tx)',w['Receive rate (Mbps)']+' / '+(w['Transmit rate (Mbps)']||'?')+' Mbps'));
    if(w['Radio type'])c.appendChild(kv('Radio / channel',w['Radio type']+(w.Channel?' · channel '+w.Channel:'')));
    if(w.Authentication)c.appendChild(kv('Security',w.Authentication+(w.Cipher?' / '+w.Cipher:'')));}
  (m.adapters||[]).forEach(function(a){var t=a.name+' ('+a.type+', '+a.status+(a.speedMbps?', '+a.speedMbps+' Mbps':'')+')';
    var d=[];if(a.ipv4)d.push('IPv4 '+a.ipv4);if(a.gateway)d.push('gateway '+a.gateway);if(a.dns)d.push('DNS '+a.dns);if(a.mac)d.push('MAC '+a.mac);
    c.appendChild(kv(t,d.join('  ·  ')||'no address'))});
  if(!c.childNodes.length)c.appendChild(el('div','No network adapters found.','empty'));
  $('speedinfo').textContent='Contacts '+m.speed.host+' directly (not through the VPN/proxy), which shows your IP address to that server. Change the endpoints in config/speedtest.v1.json.';
  var s=$('saved');s.textContent='';
  if(!(m.saved||[]).length)s.appendChild(el('div','No saved Wi-Fi networks (or no wireless adapter).','empty'));
  (m.saved||[]).forEach(function(n){var r=el('div',null,'row');var l=el('div');l.appendChild(el('div',n.name+(n.current?'  (connected now)':''),'t'));r.appendChild(l);
    var right=el('div',null,'ts');right.appendChild(labelSel(n.name,n.label));right.appendChild(btn('Connect','net-connect:'+enc(n.name),true));right.appendChild(btn('Forget','net-forget:'+enc(n.name),true));r.appendChild(right);s.appendChild(r)});
  var h=$('hist');h.textContent='';
  if(!(m.history||[]).length)h.appendChild(el('div','Nothing recorded yet.','empty'));
  (m.history||[]).forEach(function(x){var r=el('div',null,'row');var l=el('div');l.appendChild(el('div',x.ssid+(x.label&&x.label!=='none'?'  ['+x.label+']':''),'t'));
    l.appendChild(el('div',x.connections+' connection'+(x.connections===1?'':'s')+' · '+dur(x.seconds)+' total · last seen '+new Date(x.last).toLocaleString(),'u'));r.appendChild(l);h.appendChild(r)});
}
window.chrome.webview.addEventListener('message',function(e){var m=e.data;if(!m)return;
  if(m.type==='snapshot')render(m);
  else if(m.type==='rate'){$('rx').textContent=rate(m.rx);$('tx').textContent=rate(m.tx);$('rxa').textContent=m.adapter?('adapter: '+m.adapter):'no active adapter'}
  else if(m.type==='ping'){$('ping').textContent=m.target+': '+m.received+'/'+m.sent+' replies, '+m.loss+'% loss'+(m.received?(' · min '+m.min+' / avg '+m.avg+' / max '+m.max+' ms · jitter '+m.jitter+' ms'):'')}
  else if(m.type==='speedstart'){$('speed').textContent='Testing against '+m.host+'…'}
  else if(m.type==='speed'){$('speed').textContent='Download '+m.download+' Mbps · Upload '+m.upload+' Mbps · latency '+m.latency+' ms'+(m.error?' · '+m.error:'')}
  else if(m.type==='action'){$('msg').textContent=m.text}});
send('net-snapshot');
</script>");
            sb.Append(SendScript()).Append(PageFoot);
            return sb.ToString();
        }
    }
}
