using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Threading;

namespace Recognition.Browser
{
    // Passwords page (recognition:passwords). Core rules (storage, validation, exact-origin matching, generator,
    // audit, fill script) live in PasswordVault.cs and are executed by browser.tests; this file is the WPF glue.
    //  - Nothing is ever auto-filled or auto-saved. Fill / Copy / Reveal are explicit clicks.
    //  - The list sent to the page never contains passwords. Reveal sends one for a few seconds.
    //  - Receipts (hash-chained) record that an action happened and for which site, never the secret.
    public partial class MainWindow
    {
        private PasswordVault _vault = null!;
        private DispatcherTimer? _clipTimer;

        private void EnsureVault()
        {
            if (_vault != null) return;
            _vault = new PasswordVault(Path.Combine(_repoRoot, "runtime", "vault_passwords.v1.enc"));
            var skipped = _vault.Load();
            if (skipped > 0) Status("password vault: " + skipped + " damaged record(s) were skipped");
        }

        private void MenuPasswords_Click(object sender, RoutedEventArgs e) => OpenInternalInActiveTab("passwords");

        private void PostToPwPage(object payload)
        {
            var t = Active; if (t == null || t.Internal != "passwords") return;
            try { t.Web.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(payload)); } catch { }
        }

        private string? CurrentSiteSuggestion()
        {
            foreach (var t in Enumerable.Reverse(_tabs))
                if (!t.IsInternal && t.Web?.CoreWebView2 != null) { var o = PasswordRules.OriginOf(t.Web.Source?.ToString()); if (o != null) return o; }
            return null;
        }

        private void SendPwSnapshot()
        {
            EnsureVault();
            var audit = _vault.Audit();
            PostToPwPage(new
            {
                type = "snapshot", current = CurrentSiteSuggestion(),
                entries = _vault.Entries.OrderBy(e => e.Origin).ThenBy(e => e.Username).Select(e => new
                {
                    id = e.Id, origin = e.Origin, username = e.Username, strength = PasswordRules.Strength(e.Password), updated = e.UpdatedUtc,
                    reused = audit.Any(a => a.Id == e.Id && a.Kind == "reused"), hasNote = e.Note.Length > 0
                }).ToList()
            });
        }

        private void CopySecret(string value, string what)
        {
            try
            {
                var dob = new DataObject();
                dob.SetText(value);
                // Best effort: ask Windows not to keep this in clipboard history / cloud clipboard.
                dob.SetData("ExcludeClipboardContentFromMonitorProcessing", new MemoryStream(new byte[] { 1, 0, 0, 0 }));
                Clipboard.SetDataObject(dob, true);
                _clipTimer?.Stop();
                _clipTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
                _clipTimer.Tick += (_, __) =>
                {
                    _clipTimer?.Stop();
                    try { if (Clipboard.ContainsText() && Clipboard.GetText() == value) Clipboard.Clear(); } catch { }
                };
                _clipTimer.Start();
                PostToPwPage(new { type = "action", ok = true, text = what + " copied. It is cleared from the clipboard in 30 seconds." });
            }
            catch (Exception ex) { PostToPwPage(new { type = "action", ok = false, text = "could not use the clipboard: " + ex.Message }); }
        }

        private async void PwFill(VaultEntry e)
        {
            var target = _tabs.FirstOrDefault(t => !t.IsInternal && t.Web?.CoreWebView2 != null && PasswordRules.MayFill(e.Origin, t.Web.Source?.ToString()));
            if (target == null)
            {
                PostToPwPage(new { type = "action", ok = false, text = "no open tab is on exactly https://" + e.Origin + ". Open the site in a tab first, then click Fill. (Subdomains and look-alike sites are never filled.)" });
                return;
            }
            Tabs.SelectedItem = target.Item; ShowActiveWebView();
            try
            {
                // re-check at the moment of injection: the page may have navigated since the match above
                if (!PasswordRules.MayFill(e.Origin, target.Web.Source?.ToString())) { Status("fill cancelled: the page changed"); return; }
                var res = await target.Web.CoreWebView2.ExecuteScriptAsync(FillScript.Build(e.Username, e.Password));
                _actions?.Append("vault.fill", e.Origin + ":" + e.Id);
                Status(res.Contains("no-password-field") ? "no password field found on the page" : "filled for " + e.Origin + " (not submitted)");
            }
            catch (Exception ex) { Status("fill failed: " + ex.Message); }
        }

        private void HandlePwMessage(string msg)
        {
            EnsureVault();
            string Dec(string s) { try { return Uri.UnescapeDataString(s); } catch { return ""; } }
            if (msg == "pw-list") { SendPwSnapshot(); return; }
            if (msg.StartsWith("pw-gen:"))
            {
                try
                {
                    using var d = JsonDocument.Parse(Dec(msg.Substring("pw-gen:".Length))); var r = d.RootElement;
                    bool B(string k) => r.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.True;
                    var pw = PasswordGenerator.Generate(r.GetProperty("length").GetInt32(), B("lower"), B("upper"), B("digits"), B("symbols"), B("ambig"));
                    PostToPwPage(new { type = "generated", pw });
                }
                catch (ArgumentException ex) { PostToPwPage(new { type = "action", ok = false, text = ex.Message }); }
                catch { PostToPwPage(new { type = "action", ok = false, text = "invalid generator settings" }); }
            }
            else if (msg.StartsWith("pw-add:"))
            {
                try
                {
                    using var d = JsonDocument.Parse(Dec(msg.Substring("pw-add:".Length))); var r = d.RootElement;
                    string S(string k) => r.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
                    var err = _vault.Add(S("origin"), S("username"), S("password"), S("note"), DateTime.UtcNow, out var added);
                    if (err != null) { PostToPwPage(new { type = "action", ok = false, text = err }); return; }
                    _actions?.Append("vault.add", added!.Origin + ":" + added.Id);
                    PostToPwPage(new { type = "added" }); SendPwSnapshot();
                }
                catch { PostToPwPage(new { type = "action", ok = false, text = "invalid entry" }); }
            }
            else if (msg.StartsWith("pw-reveal:"))
            {
                var e = _vault.Get(msg.Substring("pw-reveal:".Length));
                if (e == null) return;
                _actions?.Append("vault.reveal", e.Origin + ":" + e.Id);
                PostToPwPage(new { type = "reveal", id = e.Id, pw = e.Password });
            }
            else if (msg.StartsWith("pw-copy:"))
            {
                var parts = msg.Substring("pw-copy:".Length).Split(':');
                var e = parts.Length == 2 ? _vault.Get(parts[0]) : null;
                if (e == null) return;
                if (parts[1] == "pass") { _actions?.Append("vault.copy_password", e.Origin + ":" + e.Id); CopySecret(e.Password, "password"); }
                else if (parts[1] == "user") CopySecret(e.Username, "username");
            }
            else if (msg.StartsWith("pw-fill:"))
            {
                var e = _vault.Get(msg.Substring("pw-fill:".Length));
                if (e != null) PwFill(e);
            }
            else if (msg.StartsWith("pw-del:"))
            {
                var e = _vault.Get(msg.Substring("pw-del:".Length));
                if (e == null) return;
                if (MessageBox.Show(this, "Delete the saved login for " + e.Username + " at " + e.Origin + "?\n\nThis cannot be undone.", "Recognition — Passwords", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
                _vault.Remove(e.Id);
                _actions?.Append("vault.delete", e.Origin + ":" + e.Id);
                SendPwSnapshot();
            }
        }

        private string PasswordsHtml()
        {
            var sb = new StringBuilder(PageHead);
            sb.Append(@"<title>Passwords</title><h1>Passwords</h1>
<div class='muted'>Logins are stored encrypted for your Windows account (DPAPI). <b>Nothing is filled or saved automatically</b>: you click Fill, Copy or Reveal. Fill only works on a tab that is on <b>exactly</b> the saved site over https (no subdomains, no look-alikes) and never submits the form. Copied passwords are cleared from the clipboard after 30 seconds. Passwords are never included in setup snapshots or receipts. Limit: any program running as you could still ask Windows to decrypt this file.</div>
<div id='msg' class='u' style='min-height:18px;margin:8px 0'></div>

<h1 style='font-size:16px'>Add a login</h1>
<div style='display:grid;grid-template-columns:110px 1fr;gap:8px;max-width:640px;align-items:center'>
 <div>Site</div><input id='o' placeholder='example.com' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:8px'>
 <div>Username</div><input id='u' autocomplete='off' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:8px'>
 <div>Password</div><div style='display:flex;gap:6px'><input id='p' type='password' autocomplete='new-password' style='flex:1;background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:8px'><a class='btn ghost' onclick='togglePw()'>Show</a></div>
 <div>Note</div><input id='n' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:8px'>
</div>
<div style='margin:8px 0;display:flex;gap:10px;flex-wrap:wrap;align-items:center'>
 <span class='u'>Generator:</span>
 <input id='len' type='number' min='8' max='128' value='20' style='width:64px;background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:6px'>
 <label><input type='checkbox' id='g_lower' checked> a-z</label><label><input type='checkbox' id='g_upper' checked> A-Z</label><label><input type='checkbox' id='g_digits' checked> 0-9</label><label><input type='checkbox' id='g_symbols' checked> symbols</label><label><input type='checkbox' id='g_ambig' checked> avoid look-alikes</label>
 <a class='btn ghost' onclick='gen()'>Generate</a> <a class='btn' onclick='add()'>Save login</a></div>

<h1 style='font-size:16px'>Saved logins</h1>
<div id='list'></div>
<script>
function $(i){return document.getElementById(i)}
function el(t,txt,cls){var e=document.createElement(t);if(txt!=null)e.textContent=txt;if(cls)e.className=cls;return e}
var enc=encodeURIComponent;
function togglePw(){var p=$('p');p.type=p.type==='password'?'text':'password'}
function gen(){send('pw-gen:'+enc(JSON.stringify({length:parseInt($('len').value,10)||0,lower:$('g_lower').checked,upper:$('g_upper').checked,digits:$('g_digits').checked,symbols:$('g_symbols').checked,ambig:$('g_ambig').checked})))}
function add(){send('pw-add:'+enc(JSON.stringify({origin:$('o').value,username:$('u').value,password:$('p').value,note:$('n').value})))}
function btn(t,cmd,ghost){var a=el('a',t,'btn'+(ghost?' ghost':''));a.style.marginLeft='6px';a.onclick=function(){send(cmd)};return a}
function render(m){
  if(m.current&&!$('o').value)$('o').value=m.current;
  var l=$('list');l.textContent='';
  if(!m.entries.length){l.appendChild(el('div','No saved logins yet.','empty'));return}
  m.entries.forEach(function(e){var r=el('div',null,'row');r.id='r_'+e.id;var d=el('div');
    d.appendChild(el('div',e.origin,'t'));
    d.appendChild(el('div',(e.username||'(no username)')+'  ·  strength: '+e.strength+(e.reused?'  ·  REUSED on another site':'')+(e.hasNote?'  ·  has note':''),'u'));
    var pv=el('div',null,'u');pv.id='pv_'+e.id;d.appendChild(pv);r.appendChild(d);
    var b=el('div',null,'ts');
    b.appendChild(btn('Fill','pw-fill:'+e.id));b.appendChild(btn('Copy password','pw-copy:'+e.id+':pass',true));b.appendChild(btn('Copy username','pw-copy:'+e.id+':user',true));
    b.appendChild(btn('Reveal','pw-reveal:'+e.id,true));b.appendChild(btn('Delete','pw-del:'+e.id,true));r.appendChild(b);l.appendChild(r)})}
window.chrome.webview.addEventListener('message',function(ev){var m=ev.data;if(!m)return;
  if(m.type==='snapshot')render(m);
  else if(m.type==='generated'){$('p').value=m.pw;$('p').type='text'}
  else if(m.type==='added'){$('u').value='';$('p').value='';$('p').type='password';$('n').value='';$('msg').textContent='Saved.'}
  else if(m.type==='reveal'){var s=$('pv_'+m.id);if(s){s.textContent='Password: '+m.pw+'   (hides in 10 s)';setTimeout(function(){s.textContent=''},10000)}}
  else if(m.type==='action'){$('msg').textContent=m.text}});
send('pw-list');
</script>");
            sb.Append(SendScript()).Append(PageFoot);
            return sb.ToString();
        }
    }
}
