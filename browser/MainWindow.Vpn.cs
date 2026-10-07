using System;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;

namespace Recognition.Browser
{
    // The VPN / proxy page. Recognition ships no VPN servers: an "exit" here is a proxy you bring (from a VPN provider, your own server,
    // or similar). The web engine takes its proxy when it starts, so a change applies after a restart, and the page says so. Every action
    // reports its result on the page. The checks on what you type are in ProxyRules.cs (executed by tests).
    public partial class MainWindow
    {
        private void PostToVpnPage(object payload)
        {
            var t = Active; if (t == null || t.Internal != "vpn") return;
            try { t.Web.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(payload)); } catch { }
        }

        private async Task SendVpnSnapshotAsync(string? note = null, bool ok = true)
        {
            var exits = _netEndpoints.Select(e => new
            {
                name = e.Name, label = string.IsNullOrEmpty(e.Region) ? e.Name : e.Region, address = ProxyRules.Describe(e.Proxy),
                user = e.User, local = ProxyRules.IsLocal(e.Proxy), active = _netMode == "proxy" && _netProxy == e.Proxy
            }).ToList();
            PostToVpnPage(new
            {
                type = "snapshot", mode = _netMode, proxy = ProxyRules.Describe(_netProxy), region = _netExitRegion ?? "",
                down = _netProxyDown, activeNow = NetActive(), exits,
                note = note ?? "", ok
            });
        }

        private NetEndpoint? FindExit(string name) => _netEndpoints.FirstOrDefault(e => e.Name == name);

        private async void HandleVpnMessage(string msg)
        {
            string Dec(string s) { try { return Uri.UnescapeDataString(s); } catch { return ""; } }
            try
            {
                if (msg == "exit-state") { await SendVpnSnapshotAsync(); return; }
                if (msg == "exit-off") { SetVpnOff(); await SendVpnSnapshotAsync("Direct connection chosen. It applies after you restart Recognition."); return; }
                if (msg == "exit-restart") { RestartToApply(); return; }
                if (msg.StartsWith("exit-test:", StringComparison.Ordinal))
                {
                    var ep = FindExit(Dec(msg.Substring("exit-test:".Length)));
                    if (ep == null) { await SendVpnSnapshotAsync("That exit no longer exists.", false); return; }
                    var (h, pt) = ParseHostPort(ep.Proxy);
                    var ms = h == null ? -1 : await ProbeAsync(h, pt);
                    await SendVpnSnapshotAsync(ms >= 0 ? (ep.Name + ": reachable (" + Math.Round(ms) + " ms). This only checks that something is listening, not that it is a working VPN.")
                                                       : (ep.Name + ": could not be reached at " + ProxyRules.Describe(ep.Proxy) + "."), ms >= 0);
                    return;
                }
                if (msg.StartsWith("exit-use:", StringComparison.Ordinal))
                {
                    var ep = FindExit(Dec(msg.Substring("exit-use:".Length)));
                    if (ep == null) { await SendVpnSnapshotAsync("That exit no longer exists.", false); return; }
                    var (h, pt) = ParseHostPort(ep.Proxy);
                    var ms = h == null ? -1 : await ProbeAsync(h, pt);
                    if (ms < 0) { await SendVpnSnapshotAsync(ep.Name + " could not be reached at " + ProxyRules.Describe(ep.Proxy) + ", so it was not chosen. Start it (or fix the address) and try again.", false); return; }
                    _netMode = "proxy"; _netProxy = ep.Proxy; _netExitRegion = string.IsNullOrEmpty(ep.Region) ? ep.Name : ep.Region; _netProxyDown = false;
                    SaveNetworkConfig(); UpdateVpn(); _actions?.Append("vpn.pick", ep.Proxy);
                    await SendVpnSnapshotAsync(ep.Name + " is chosen. Restart Recognition to start using it.");
                    return;
                }
                if (msg.StartsWith("exit-remove:", StringComparison.Ordinal))
                {
                    var ep = FindExit(Dec(msg.Substring("exit-remove:".Length)));
                    if (ep == null || !ep.User) { await SendVpnSnapshotAsync("Only exits you added can be removed.", false); return; }
                    _netEndpoints.Remove(ep);
                    if (_netMode == "proxy" && _netProxy == ep.Proxy) { _netMode = "off"; _netProxy = ""; _netExitRegion = ""; UpdateVpn(); }
                    SaveNetworkConfig(); _actions?.Append("vpn.exit_removed", ep.Proxy);
                    await SendVpnSnapshotAsync(ep.Name + " was removed.");
                    return;
                }
                if (msg.StartsWith("exit-add:", StringComparison.Ordinal))
                {
                    string name, type, host, port;
                    try
                    {
                        using var d = JsonDocument.Parse(Dec(msg.Substring("exit-add:".Length)));
                        var r = d.RootElement;
                        string G(string k) => r.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? (v.GetString() ?? "") : "";
                        name = G("name"); type = G("type"); host = G("host"); port = G("port");
                    }
                    catch { await SendVpnSnapshotAsync("That form could not be read.", false); return; }
                    if (_netEndpoints.Count(x => x.User) >= ProxyRules.MaxExits) { await SendVpnSnapshotAsync("There are already " + ProxyRules.MaxExits + " exits. Remove one first.", false); return; }
                    if (!ProxyRules.TryBuild(type, host, port, out var proxy, out var err)) { await SendVpnSnapshotAsync(err, false); return; }
                    var label = ProxyRules.CleanName(name); if (label.Length == 0) label = host.Trim().ToLowerInvariant();
                    label = ProxyRules.UniqueName(label, n => _netEndpoints.Any(x => x.Name == n));
                    if (_netEndpoints.Any(x => x.Proxy == proxy)) { await SendVpnSnapshotAsync("That address is already in the list.", false); return; }
                    _netEndpoints.Add(new NetEndpoint { Name = label, Region = label, Proxy = proxy, User = true });
                    SaveNetworkConfig(); _actions?.Append("vpn.exit_added", proxy);
                    var (h, pt) = ParseHostPort(proxy);
                    var ms = h == null ? -1 : await ProbeAsync(h, pt);
                    await SendVpnSnapshotAsync(ms >= 0 ? (label + " was added and is reachable (" + Math.Round(ms) + " ms). Press Use to choose it.")
                                                       : (label + " was added, but nothing answered at " + ProxyRules.Describe(proxy) + " just now. Check the address, port and that the service is running."), ms >= 0);
                    return;
                }
            }
            catch (Exception ex) { PostToVpnPage(new { type = "action", ok = false, text = "error: " + ex.Message }); }
        }

        private string VpnHtml()
        {
            var sb = new StringBuilder(PageHead);
            sb.Append(@"<title>VPN / proxy</title><h1>VPN / proxy</h1>
<div class='muted'>Recognition does <b>not</b> provide VPN servers, so this page has no built-in locations. It sends your browsing through an <b>exit</b> that you bring: a proxy from your VPN provider or your own server. You have two ways to get one:
<br>1. <b>A proxy from a VPN provider</b>, or from your own server (SOCKS5 or HTTP). Add its address below.
<br>2. <b>A VPN app for the whole computer</b> (WireGuard, OpenVPN, your provider's app). Recognition follows it automatically, so there is nothing to set here.
<br>The web engine takes its proxy when it starts, so a change needs a restart. A SOCKS5 exit also looks up website names through the exit. Only the traffic of this browser goes through an exit.</div>
<div id='msg' class='u' style='min-height:20px;margin:10px 0;font-size:13px'></div>
<div id='info' class='row' style='display:block'></div>
<div style='margin:8px 0 4px;display:flex;gap:8px;flex-wrap:wrap'><a class='btn' onclick=""send('exit-restart')"">Restart to apply</a><a class='btn ghost' onclick=""send('exit-off')"">Use a direct connection</a></div>
<h1 style='font-size:16px'>Exits</h1><div id='exits'></div>
<h1 style='font-size:16px'>Add an exit</h1>
<div style='display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:8px 0'>
 <input id='n' placeholder='Name (optional)' style='width:150px;background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:7px'>
 <select id='t' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:7px'><option value='socks5'>SOCKS5</option><option value='http'>HTTP</option></select>
 <input id='h' placeholder='host or IP, e.g. proxy.example.com' style='width:250px;background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:7px'>
 <input id='p' placeholder='port' style='width:80px;background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:7px'>
 <a class='btn' onclick=""add()"">Add and test</a></div>
<div class='muted'>Proxy user names and passwords are not supported here yet, so use an exit that allows your IP address or needs no login (most self-hosted proxies do).</div>
<script>
function $(i){return document.getElementById(i)}
function el(t,txt,cls){var e=document.createElement(t);if(txt!=null)e.textContent=txt;if(cls)e.className=cls;return e}
var enc=encodeURIComponent;
function add(){send('exit-add:'+enc(JSON.stringify({name:$('n').value,type:$('t').value,host:$('h').value,port:$('p').value})))}
function btn(t,cmd,ghost){var a=el('a',t,'btn'+(ghost?' ghost':''));a.style.marginLeft='6px';a.onclick=function(){send(cmd)};return a}
function render(m){
  var i=$('info');i.textContent='';
  var s=m.mode==='proxy'&&m.proxy?(m.down?'Chosen exit: '+m.region+' ('+m.proxy+'), but it could not be reached when Recognition started, so this session is DIRECT.':(m.activeNow?'In use now: '+m.region+' ('+m.proxy+')':'Chosen exit: '+m.region+' ('+m.proxy+'). Restart to start using it.')):'No exit chosen: Recognition connects directly.';
  i.appendChild(el('div',s,'t'));
  var x=$('exits');x.textContent='';
  (m.exits||[]).forEach(function(e){var r=el('div',null,'row');var l=el('div');
    l.appendChild(el('div',e.label+(e.active?'   (chosen)':''),'t'));l.appendChild(el('div',e.address+(e.local?'  ·  on this computer':''),'u'));r.appendChild(l);
    var b=el('div',null,'ts');b.appendChild(btn('Test','exit-test:'+enc(e.name),true));b.appendChild(btn('Use','exit-use:'+enc(e.name),false));if(e.user)b.appendChild(btn('Remove','exit-remove:'+enc(e.name),true));r.appendChild(b);x.appendChild(r)});
  if(!(m.exits||[]).length)x.appendChild(el('div','No exits yet. Add one below.','empty'));
  var g=$('msg');g.textContent=m.note||'';g.style.color=m.note?(m.ok?'#7fd6a0':'#e0a0a0'):''}
window.chrome.webview.addEventListener('message',function(ev){var m=ev.data;if(!m)return;if(m.type==='snapshot')render(m);else if(m.type==='action'){$('msg').textContent=m.text;$('msg').style.color='#e0a0a0'}});
send('exit-state');
</script>");
            sb.Append(SendScript()).Append(PageFoot);
            return sb.ToString();
        }
    }
}
