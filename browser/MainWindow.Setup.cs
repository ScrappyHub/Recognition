using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;

namespace Recognition.Browser
{
    // Setup snapshot page (recognition:setup): copy how this Recognition is set up to another device with a
    // temporary code. No account, no server. The snapshot is an encrypted text blob (or file); the code is shown
    // once and never stored. Crypto, validation and expiry logic live in SetupSnapshot.cs (executed by browser.tests).
    // Nothing is applied until you have previewed what it contains and clicked Apply.
    public partial class MainWindow
    {
        private sealed class PendingSetup { public SetupPlan Plan = new(); public string Id = ""; public DateTime Expires; }
        private PendingSetup? _setupPending;
        private static readonly string[] SetupCategories = { "appearance", "preferences", "bookmarks", "site_permissions", "network_labels", "cert_trust" };

        private void MenuSetup_Click(object sender, RoutedEventArgs e) => OpenInternalInActiveTab("setup");

        private void PostToSetupPage(object payload)
        {
            var t = Active; if (t == null || t.Internal != "setup") return;
            try { t.Web.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(payload)); } catch { }
        }

        private Dictionary<string, object> BuildSetupCategories(ISet<string> chosen)
        {
            var cats = new Dictionary<string, object>();
            if (chosen.Contains("appearance")) cats["appearance"] = JsonSerializer.Deserialize<JsonElement>(_appearance.ToJson());
            if (chosen.Contains("preferences")) cats["preferences"] = new { home_url = _homeUrl, blocking_enabled = _blockingEnabled };
            if (chosen.Contains("bookmarks")) cats["bookmarks"] = _bookmarks.Select(b => new { url = b.Url, title = b.Title }).ToList();
            foreach (var cat in new[] { "site_permissions", "network_labels", "cert_trust" })
            {
                if (!chosen.Contains(cat)) continue;
                var list = new List<object>();
                foreach (var kv in _sitePolicyState)
                {
                    var i = kv.Key.IndexOf('|'); if (i <= 0) continue;
                    var key = kv.Key.Substring(0, i); var origin = kv.Key.Substring(i + 1);
                    if (SetupValidate.SiteCategory(key) == cat && SetupValidate.IsValidSiteEntry(key, origin, kv.Value))
                        list.Add(new { key, origin, value = kv.Value });
                }
                cats[cat] = list;
            }
            return cats;
        }

        private async Task SetupCreateAsync(string json)
        {
            try
            {
                using var d = JsonDocument.Parse(json);
                var chosen = new HashSet<string>(d.RootElement.GetProperty("categories").EnumerateArray().Select(x => x.GetString() ?? "").Where(x => SetupCategories.Contains(x)));
                int minutes = d.RootElement.GetProperty("minutes").GetInt32();
                if (chosen.Count == 0) { PostToSetupPage(new { type = "action", ok = false, text = "choose at least one category" }); return; }
                if (minutes != 15 && minutes != 60 && minutes != 1440 && minutes != 10080) { PostToSetupPage(new { type = "action", ok = false, text = "invalid expiry" }); return; }
                var now = DateTime.UtcNow;
                var id = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();
                var payload = SetupPayload.Build(id, now, now.AddMinutes(minutes), BuildSetupCategories(chosen));
                var code = SetupCode.Generate();
                var blob = await Task.Run(() => SetupBlob.Seal(payload, code));
                _actions?.Append("setup.create", id + ":" + string.Join(",", chosen.OrderBy(x => x)));   // receipt is hash-only; code is never logged
                PostToSetupPage(new { type = "created", code, blob, expires = now.AddMinutes(minutes).ToString("o"), categories = chosen.OrderBy(x => x).ToList() });
            }
            catch (Exception ex) { PostToSetupPage(new { type = "action", ok = false, text = "could not create snapshot: " + ex.Message }); }
        }

        private async Task SetupPreviewAsync(string json)
        {
            try
            {
                using var d = JsonDocument.Parse(json);
                var blob = d.RootElement.GetProperty("blob").GetString() ?? "";
                var code = d.RootElement.GetProperty("code").GetString() ?? "";
                var res = await Task.Run(() => SetupBlob.Open(blob, code, DateTime.UtcNow));
                if (!res.Ok) { _setupPending = null; PostToSetupPage(new { type = "preview", ok = false, text = res.Reason }); return; }
                var plan = SetupPlan.Parse(res.PayloadJson);
                _setupPending = new PendingSetup { Plan = plan, Id = res.SnapshotId, Expires = res.ExpiresUtc };
                PostToSetupPage(new
                {
                    type = "preview", ok = true, created = res.CreatedUtc.ToString("o"), expires = res.ExpiresUtc.ToString("o"),
                    appearance = plan.Appearance != null, home = plan.HomeUrl, blocking = plan.BlockingEnabled,
                    bookmarks = plan.Bookmarks.Count, bookmarksRejected = plan.BookmarksRejected,
                    site_permissions = plan.SiteEntries.Count(x => x.Category == "site_permissions"),
                    network_labels = plan.SiteEntries.Count(x => x.Category == "network_labels"),
                    cert_trust = plan.SiteEntries.Count(x => x.Category == "cert_trust"),
                    rejected = plan.SiteRejected, unknown = plan.UnknownCategories
                });
            }
            catch (Exception ex) { PostToSetupPage(new { type = "preview", ok = false, text = "could not read snapshot: " + ex.Message }); }
        }

        private void SetupApply(string json)
        {
            var p = _setupPending;
            if (p == null) { PostToSetupPage(new { type = "action", ok = false, text = "nothing to apply: preview a snapshot first" }); return; }
            try
            {
                if (DateTime.UtcNow > p.Expires) { _setupPending = null; PostToSetupPage(new { type = "action", ok = false, text = "snapshot expired" }); return; }
                using var d = JsonDocument.Parse(json);
                var chosen = new HashSet<string>(d.RootElement.GetProperty("categories").EnumerateArray().Select(x => x.GetString() ?? ""));
                var done = new List<string>();
                var plan = p.Plan;
                if (chosen.Contains("appearance") && plan.Appearance != null)
                {
                    var a = plan.Appearance;
                    _appearance.Set("theme", a.Theme); _appearance.Set("darkstyle", a.DarkStyle); _appearance.Set("bg", a.PageBg);
                    _appearance.Set("text", a.PageText); _appearance.Set("link", a.LinkColor); _appearance.Set("font", a.Font);
                    _appearance.Set("overridefonts", a.OverrideSiteFonts ? "on" : "off");
                    done.Add("appearance");
                }
                if (chosen.Contains("preferences"))
                {
                    if (plan.HomeUrl != null) _homeUrl = plan.HomeUrl;
                    if (plan.BlockingEnabled.HasValue) _blockingEnabled = plan.BlockingEnabled.Value;
                    done.Add("preferences");
                }
                SaveSettings(); ApplyAppearanceAll(); UpdateShield();
                int added = 0;
                if (chosen.Contains("bookmarks"))
                {
                    foreach (var (url, title) in plan.Bookmarks)
                        if (!IsBookmarked(url)) { _bookmarks.Add(new Bookmark { Url = url, Title = title, Ts = Iso(DateTime.UtcNow) }); added++; }
                    SaveBookmarks(); done.Add("bookmarks(+" + added + ")");
                }
                foreach (var cat in new[] { "site_permissions", "network_labels", "cert_trust" })
                {
                    if (!chosen.Contains(cat)) continue;
                    var es = plan.SiteEntries.Where(x => x.Category == cat).ToList();
                    foreach (var (key, origin, value, _) in es) SitePolicySet(origin, key, value);
                    done.Add(cat + "(" + es.Count + ")");
                }
                _actions?.Append("setup.apply", p.Id + ":" + string.Join(",", done));
                _setupPending = null;   // plan is dropped after applying; preview again to re-apply
                Status("setup applied: " + string.Join(", ", done));
                PostToSetupPage(new { type = "applied", text = "Applied: " + string.Join(", ", done) + ". Open Settings to review." });
            }
            catch (Exception ex) { PostToSetupPage(new { type = "action", ok = false, text = "apply failed: " + ex.Message }); }
        }

        private void HandleSetupMessage(string msg)
        {
            string Dec(string s) { try { return Uri.UnescapeDataString(s); } catch { return ""; } }
            if (msg.StartsWith("setup-create:")) _ = SetupCreateAsync(Dec(msg.Substring("setup-create:".Length)));
            else if (msg.StartsWith("setup-preview:")) _ = SetupPreviewAsync(Dec(msg.Substring("setup-preview:".Length)));
            else if (msg.StartsWith("setup-apply:")) SetupApply(Dec(msg.Substring("setup-apply:".Length)));
            else if (msg == "setup-openfile")
            {
                var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Open a Recognition setup snapshot", Filter = "Recognition setup (*.rsetup;*.txt)|*.rsetup;*.txt|All files|*.*" };
                if (dlg.ShowDialog(this) == true)
                {
                    try
                    {
                        var fi = new FileInfo(dlg.FileName);
                        if (fi.Length > 12 * 1024 * 1024) { PostToSetupPage(new { type = "action", ok = false, text = "file too large to be a setup snapshot" }); return; }
                        PostToSetupPage(new { type = "loaded", blob = File.ReadAllText(dlg.FileName).Trim() });
                    }
                    catch (Exception ex) { PostToSetupPage(new { type = "action", ok = false, text = ex.Message }); }
                }
            }
            else if (msg.StartsWith("setup-savefile:"))
            {
                var blob = Dec(msg.Substring("setup-savefile:".Length));
                if (!blob.StartsWith(SetupBlob.Prefix, StringComparison.Ordinal)) return;
                var dlg = new Microsoft.Win32.SaveFileDialog { Title = "Save setup snapshot", FileName = "recognition-setup.rsetup", Filter = "Recognition setup (*.rsetup)|*.rsetup" };
                if (dlg.ShowDialog(this) == true)
                {
                    try { File.WriteAllText(dlg.FileName, blob, new UTF8Encoding(false)); PostToSetupPage(new { type = "action", ok = true, text = "saved. Send the code separately." }); }
                    catch (Exception ex) { PostToSetupPage(new { type = "action", ok = false, text = ex.Message }); }
                }
            }
        }

        private string SetupHtml()
        {
            var sb = new StringBuilder(PageHead);
            sb.Append(@"<title>Setup snapshot</title><h1>Setup snapshot</h1>
<div class='muted'>Copy how Recognition is set up to another device. No account and no server: you get an encrypted snapshot and a temporary code. Send them by <b>different routes</b>. A snapshot is only made when you click Create; nothing is kept ready, and the code is shown once and never stored. It can be applied on any device, any number of times, until it expires. Passwords are never included.</div>
<div id='msg' class='u' style='min-height:18px;margin:8px 0'></div>

<h1 style='font-size:16px'>Create a snapshot on this device</h1>
<div id='cats'></div>
<div style='margin:8px 0'>Valid for
 <select id='mins' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:5px 6px'>
  <option value='15'>15 minutes</option><option value='60' selected>1 hour</option><option value='1440'>24 hours</option><option value='10080'>7 days</option></select>
 &nbsp;<a class='btn' onclick='create()'>Create snapshot</a></div>
<div id='made' style='display:none'>
 <div class='row'><div><div class='t'>One-time code</div><div class='u'>Write this down or read it out. It is not stored anywhere.</div></div><div class='ts'><span class='big' id='code' style='letter-spacing:2px'></span></div></div>
 <div class='u' style='margin:6px 0'>Snapshot (encrypted text, safe to paste or send):</div>
 <textarea id='blobout' readonly style='width:100%;height:80px;background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:8px'></textarea>
 <div style='margin:6px 0 18px'><a class='btn ghost' onclick='copyBlob()'>Copy</a> <a class='btn ghost' onclick='saveBlob()'>Save as file&hellip;</a> <span class='u' id='exp'></span></div>
</div>

<h1 style='font-size:16px'>Apply a snapshot from another device</h1>
<div class='muted'>Paste the snapshot (or open the file) and enter the code. You will see what it contains before anything changes.</div>
<textarea id='blobin' placeholder='RSETUP1:...' style='width:100%;height:70px;background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:8px;margin-top:8px'></textarea>
<div style='margin:6px 0;display:flex;gap:10px;flex-wrap:wrap;align-items:center'>
 <a class='btn ghost' onclick=""send('setup-openfile')"">Open file&hellip;</a>
 <input id='codein' placeholder='XXXXX-XXXXX-XXXXX-XXXXX' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:8px 10px;width:250px;letter-spacing:1px'>
 <a class='btn' onclick='preview()'>Preview</a></div>
<div id='prev'></div>
<script>
function $(i){return document.getElementById(i)}
function el(t,txt,cls){var e=document.createElement(t);if(txt!=null)e.textContent=txt;if(cls)e.className=cls;return e}
var enc=encodeURIComponent;
var CATS=[['appearance','Appearance (theme, colours, fonts)',true],['preferences','Preferences (home page, tracker blocking)',true],['bookmarks','Bookmarks',true],
 ['site_permissions','Per-site permissions and tracker exemptions',true],['network_labels','Network labels (trusted / guest / blocked)',true],['cert_trust','Pinned certificate exceptions (sensitive)',false]];
function drawCats(){var c=$('cats');CATS.forEach(function(x){var l=el('label');l.style.display='block';l.style.margin='4px 0';var i=el('input');i.type='checkbox';i.id='c_'+x[0];i.checked=x[2];l.appendChild(i);l.appendChild(document.createTextNode(' '+x[1]));c.appendChild(l)})}
drawCats();
function create(){var cs=CATS.filter(function(x){return $('c_'+x[0]).checked}).map(function(x){return x[0]});
  send('setup-create:'+enc(JSON.stringify({categories:cs,minutes:parseInt($('mins').value,10)})))}
function copyBlob(){var t=$('blobout');t.select();try{document.execCommand('copy');$('msg').textContent='copied'}catch(e){}}
function saveBlob(){send('setup-savefile:'+enc($('blobout').value))}
function preview(){send('setup-preview:'+enc(JSON.stringify({blob:$('blobin').value,code:$('codein').value})))}
function applySel(){var cs=CATS.filter(function(x){var b=$('a_'+x[0]);return b&&b.checked}).map(function(x){return x[0]});
  send('setup-apply:'+enc(JSON.stringify({categories:cs})))}
function showPrev(m){var p=$('prev');p.textContent='';
  if(!m.ok){p.appendChild(el('div',m.text,'empty'));return}
  p.appendChild(el('div','Created '+new Date(m.created).toLocaleString()+' · expires '+new Date(m.expires).toLocaleString(),'u'));
  var rows=[['appearance',m.appearance?'included':'',m.appearance],['preferences',(m.home||m.blocking!==null)?('home: '+(m.home||'unchanged')+(m.blocking===null?'':' · blocking '+(m.blocking?'on':'off'))):'',!!(m.home||m.blocking!==null)],
   ['bookmarks',m.bookmarks+' to merge'+(m.bookmarksRejected?' ('+m.bookmarksRejected+' invalid skipped)':''),m.bookmarks>0],
   ['site_permissions',m.site_permissions+' entries',m.site_permissions>0],['network_labels',m.network_labels+' entries',m.network_labels>0],['cert_trust',m.cert_trust+' entries (grants trust to those certificates)',m.cert_trust>0]];
  rows.forEach(function(r){var cat=CATS.filter(function(x){return x[0]===r[0]})[0];if(!r[2])return;
    var l=el('label');l.style.display='block';l.style.margin='4px 0';var i=el('input');i.type='checkbox';i.id='a_'+r[0];i.checked=(r[0]!=='cert_trust');l.appendChild(i);l.appendChild(document.createTextNode(' '+cat[1]+' — '+r[1]));p.appendChild(l)});
  if(m.rejected)p.appendChild(el('div',m.rejected+' invalid entr'+(m.rejected===1?'y':'ies')+' dropped','u'));
  if(m.unknown&&m.unknown.length)p.appendChild(el('div','Ignored unknown categories: '+m.unknown.join(', '),'u'));
  var b=el('a','Apply selected','btn');b.style.marginTop='8px';b.onclick=applySel;p.appendChild(b)}
window.chrome.webview.addEventListener('message',function(e){var m=e.data;if(!m)return;
  if(m.type==='created'){$('made').style.display='block';$('code').textContent=m.code;$('blobout').value=m.blob;$('exp').textContent=' expires '+new Date(m.expires).toLocaleString();$('msg').textContent='Snapshot created.'}
  else if(m.type==='loaded'){$('blobin').value=m.blob}
  else if(m.type==='preview')showPrev(m);
  else if(m.type==='applied'){$('prev').textContent='';$('msg').textContent=m.text}
  else if(m.type==='action'){$('msg').textContent=m.text}});
</script>");
            sb.Append(SendScript()).Append(PageFoot);
            return sb.ToString();
        }
    }
}
