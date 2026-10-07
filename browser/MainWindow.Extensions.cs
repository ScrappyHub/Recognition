using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Web.WebView2.Core;

namespace Recognition.Browser
{
    // recognition:extensions — install, review, test, enable/disable and remove Chromium extensions.
    //
    // Trust model (the same one the PowerShell governance tool uses; see ExtensionGovernance.cs, which is executed by the tests):
    //   * Identity   = SHA-256 of the extension's files. Any changed byte is a different extension.
    //   * Decision   = deterministic policy (config\extension_policy.v1.json): allow / review / deny.
    //   * Ledger     = hash-chained record of every install, approval and removal (proofs\receipts\...extension_governance.v1.ndjson).
    //   * Load gate  = at startup and on enable, the identity is recomputed from the files on disk and the extension loads ONLY if the
    //                  latest ledger record for those exact bytes says "allow". Extensions the browser did not approve are removed
    //                  from the engine profile at startup.
    //   * Deny       = cannot be installed from here. Review = installable only after an explicit "I reviewed these permissions" click.
    //
    // Honest limits: WebView2 supports a subset of the Chromium extension system (content scripts and background workers generally work;
    // toolbar buttons, popups and some APIs may not). Use Test before relying on one. The policy scores API and host permissions; content
    // script match patterns and optional permissions are shown to you but not scored. A reviewed extension still runs with the access
    // it declared. Chrome Web Store downloads are not built in: use a file, a folder, or an https link to the developer's .crx/.zip.
    public partial class MainWindow
    {
        private sealed class ExtItem
        {
            public string Gid { get; set; } = "";
            public string Name { get; set; } = "";
            public string Version { get; set; } = "";
            public string Dir { get; set; } = "";            // relative to the repo root
            public bool Enabled { get; set; } = true;
            public string InstalledUtc { get; set; } = "";
            public string Source { get; set; } = "";
            public string ChromiumId { get; set; } = "";
        }
        private sealed class ExtState { public bool Enabled { get; set; } public List<ExtItem> Items { get; set; } = new(); }
        private sealed class ExtPending
        {
            public string Staging = "", Root = "", Source = "";
            public ExtIdentity Identity = null!; public ExtManifest Manifest = null!; public ExtDecision Decision = null!;
        }

        private ExtState _extState = new();
        private readonly Dictionary<string, string> _extStatus = new();
        private ExtPending? _extPending;
        private bool _extEnabledAtStart, _extConfigEnabled;
        private CoreWebView2Environment? _extTestEnv;
        private string? _extTestDir;
        private const long MaxExtDownloadBytes = 100L * 1024 * 1024;

        private void MenuExtensions_Click(object sender, RoutedEventArgs e) => OpenInternalInActiveTab("extensions");

        private string ExtStatePath => Path.Combine(_repoRoot, "runtime", "extensions.v1.json");
        private string ExtLedgerPath => Path.Combine(_repoRoot, "proofs", "receipts", "recognition.extension_governance.v1.ndjson");
        private string ExtPolicyPath => Path.Combine(_repoRoot, "config", "extension_policy.v1.json");
        private string ExtDirAbs(ExtItem i) => Path.GetFullPath(Path.Combine(_repoRoot, i.Dir));

        private void LoadExtState()
        {
            _extState = new ExtState();
            try
            {
                if (File.Exists(ExtStatePath))
                {
                    var s = JsonSerializer.Deserialize<ExtState>(File.ReadAllText(ExtStatePath));
                    if (s != null)
                    {
                        s.Items = s.Items.Where(i => i != null && i.Gid.Length == 64 && i.Gid.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
                                                     && i.Dir == Path.Combine("runtime", "extensions", i.Gid)).ToList();   // a state file can only point inside runtime\extensions\<id>
                        _extState = s;
                    }
                }
            }
            catch { }
        }

        private void SaveExtState()
        {
            try { Directory.CreateDirectory(Path.GetDirectoryName(ExtStatePath)!); File.WriteAllText(ExtStatePath, JsonSerializer.Serialize(_extState), new UTF8Encoding(false)); } catch { }
        }

        private CoreWebView2Profile? AnyMainProfile()
            => _tabs.FirstOrDefault(t => !t.Private && t.Ready && t.Web?.CoreWebView2 != null)?.Web.CoreWebView2.Profile;

        // ---- startup loader (replaces the old PowerShell-based gate) ----------------------------------------------------------------

        private (bool Ok, string Gid, string Note) GateDirectory(string dir)
        {
            try
            {
                var id = ExtGovernance.ComputeIdentity(dir);
                var (ok, note) = ExtGovernance.Gate(ExtLedgerPath, id.Id);
                return (ok, id.Id, note);
            }
            catch (Exception ex) { return (false, "", ex.Message); }
        }

        private async Task LoadExtensionsAsync(BrowserTab tab)
        {
            if (_extLoaded || !_extEnabled || tab.Web.CoreWebView2 == null) return;
            _extLoaded = true;
            int ok = 0, refused = 0;
            try
            {
                var profile = tab.Web.CoreWebView2.Profile;
                var desired = new List<(string Label, string Dir, ExtItem? Item)>();
                foreach (var rel in _extPaths)
                {
                    var source = Path.IsPathRooted(rel) ? rel : Path.Combine(_repoRoot, rel);
                    try { var dir = PrepareExtensionSource(source); if (dir != null) desired.Add((rel, dir, null)); }
                    catch (Exception ex) { Status("extension package error (" + rel + "): " + ex.Message); }
                }
                foreach (var it in _extState.Items.Where(i => i.Enabled)) desired.Add((it.Name, ExtDirAbs(it), it));
                foreach (var it in _extState.Items.Where(i => !i.Enabled)) _extStatus[it.Gid] = "disabled";

                var approved = new List<(string Label, string Dir, ExtItem? Item, string Gid)>();
                foreach (var d in desired)
                {
                    var dd = d;
                    var (good, gid, note) = await Task.Run(() => GateDirectory(dd.Dir));
                    if (!good)
                    {
                        refused++; if (d.Item != null) _extStatus[d.Item.Gid] = "refused: " + note;
                        _actions?.Append("extension.refused", d.Item != null ? d.Item.Gid : d.Label);
                        Status("extension refused by governance: " + d.Label + " — " + note);
                        continue;
                    }
                    approved.Add((d.Label, d.Dir, d.Item, gid));
                }

                // anything in the engine profile that is not an approved extension we already track is removed
                var keep = new HashSet<string>(approved.Where(a => a.Item != null && a.Item.ChromiumId.Length > 0).Select(a => a.Item!.ChromiumId), StringComparer.Ordinal);
                var present = new HashSet<string>(StringComparer.Ordinal);
                foreach (var e in await profile.GetBrowserExtensionsAsync())
                {
                    if (keep.Contains(e.Id)) { present.Add(e.Id); continue; }
                    try { await e.RemoveAsync(); _actions?.Append("extension.removed_unapproved", e.Id); } catch { }
                }
                foreach (var a in approved)
                {
                    if (a.Item != null && a.Item.ChromiumId.Length > 0 && present.Contains(a.Item.ChromiumId)) { _extStatus[a.Item.Gid] = "loaded"; ok++; continue; }
                    try
                    {
                        var ext = await profile.AddBrowserExtensionAsync(a.Dir);
                        if (a.Item != null) { a.Item.ChromiumId = ext.Id; _extStatus[a.Item.Gid] = "loaded"; }
                        ok++; _actions?.Append("extension.loaded", a.Gid);
                    }
                    catch (Exception ex) { if (a.Item != null) _extStatus[a.Item.Gid] = "error: " + ex.Message; Status("extension load error (" + a.Label + "): " + ex.Message); }
                }
                SaveExtState();
            }
            catch (Exception ex) { Status("extension loading failed: " + ex.Message); }
            if (ok > 0) Status($"loaded {ok} governed extension(s)" + (refused > 0 ? $", refused {refused}" : ""));
            else if (refused > 0) Status($"all {refused} configured extension(s) refused by governance");
        }

        // ---- staging, review ---------------------------------------------------------------------------------------------------------

        private string NewStagingDir()
        {
            var dir = Path.Combine(_repoRoot, "runtime", "extensions_staging", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir); return dir;
        }

        private void DiscardPending()
        {
            var p = _extPending; _extPending = null;
            if (p != null) { try { Directory.Delete(p.Staging, true); } catch { } }
        }

        private ExtPending Review(string staging, string root, string source)
        {
            var id = ExtGovernance.ComputeIdentity(root);
            var man = ExtGovernance.ReadManifest(root);
            var pol = ExtGovernance.ParsePolicy(File.ReadAllText(ExtPolicyPath));
            var dec = ExtGovernance.Decide(man, id.Id, pol);
            return new ExtPending { Staging = staging, Root = root, Source = source, Identity = id, Manifest = man, Decision = dec };
        }

        private ExtPending StageBytes(byte[] package, string source)
        {
            var staging = NewStagingDir();
            try { var root = ExtPackage.Unpack(package, Path.Combine(staging, "x")); return Review(staging, root, source); }
            catch { try { Directory.Delete(staging, true); } catch { } throw; }
        }

        private ExtPending StageFolder(string folder, string source)
        {
            long total = 0; int count = 0;
            foreach (var f in Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories))
            {
                if (++count > ExtGovernance.MaxFiles) throw new ExtGovException("too many files in the folder");
                total += new FileInfo(f).Length; if (total > ExtGovernance.MaxTotalBytes) throw new ExtGovException("folder is larger than " + ExtGovernance.MaxTotalBytes / 1024 / 1024 + " MB");
            }
            var staging = NewStagingDir();
            try { var dst = Path.Combine(staging, "x"); ExtPackage.CopyDirectory(folder, dst); return Review(staging, ExtPackage.ResolveRoot(dst), source); }
            catch { try { Directory.Delete(staging, true); } catch { } throw; }
        }

        private async Task<byte[]> DownloadExtensionAsync(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps) throw new ExtGovException("only https addresses are accepted");
            using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 4 }) { Timeout = TimeSpan.FromSeconds(60) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("Recognition-extension-installer/1.1");
            using var resp = await http.GetAsync(u, HttpCompletionOption.ResponseHeadersRead);
            if (!resp.IsSuccessStatusCode) throw new ExtGovException("server answered " + (int)resp.StatusCode);
            if (resp.RequestMessage?.RequestUri?.Scheme != Uri.UriSchemeHttps) throw new ExtGovException("redirected away from https; refused");
            if (resp.Content.Headers.ContentLength is long cl && cl > MaxExtDownloadBytes) throw new ExtGovException("download is larger than " + MaxExtDownloadBytes / 1024 / 1024 + " MB");
            using var ms = new MemoryStream();
            using (var net = await resp.Content.ReadAsStreamAsync())
            {
                var buf = new byte[81920]; int n;
                while ((n = await net.ReadAsync(buf, 0, buf.Length)) > 0) { ms.Write(buf, 0, n); if (ms.Length > MaxExtDownloadBytes) throw new ExtGovException("download is larger than " + MaxExtDownloadBytes / 1024 / 1024 + " MB"); }
            }
            return ms.ToArray();
        }

        private static string CleanLabel(string? s) => new string((s ?? "").Where(c => !char.IsControl(c)).Take(120).ToArray());

        private void PostToExtPage(object payload)
        {
            var t = Active; if (t == null || t.Internal != "extensions") return;
            try { t.Web.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(payload)); } catch { }
        }
        private void ExtReport(string text, bool ok = true) { Status(text); PostToExtPage(new { type = "action", ok, text }); }

        private object? PendingView()
        {
            var p = _extPending; if (p == null) return null;
            return new
            {
                name = CleanLabel(p.Manifest.Name), version = CleanLabel(p.Manifest.Version), description = CleanLabel(p.Manifest.Description), mv = p.Manifest.ManifestVersion,
                id = p.Identity.Id, files = p.Identity.Files.Count, bytes = p.Identity.TotalBytes, source = CleanLabel(p.Source),
                permissions = p.Manifest.Permissions.Select(CleanLabel).ToList(), hosts = p.Manifest.HostPermissions.Select(CleanLabel).ToList(),
                optional = p.Manifest.OptionalPermissions.Select(CleanLabel).ToList(), contentScripts = p.Manifest.ContentScriptMatches.Select(CleanLabel).ToList(),
                decision = p.Decision.Decision, reasons = p.Decision.Reasons.Select(CleanLabel).ToList(),
                already = _extState.Items.Any(i => i.Gid == p.Identity.Id)
            };
        }

        private void SendExtSnapshot()
        {
            (int Count, string Head, string? Error) ledger;
            try { var v = ExtGovernance.VerifyLedger(ExtLedgerPath); ledger = (v.Count, v.Head, null); } catch (Exception ex) { ledger = (0, "", ex.Message); }
            PostToExtPage(new
            {
                type = "snapshot",
                support = _extEnabled, supportConfig = _extConfigEnabled, supportSaved = _extState.Enabled, restartNeeded = (_extConfigEnabled || _extState.Enabled) != _extEnabledAtStart,
                items = _extState.Items.OrderBy(i => i.Name).Select(i => new
                {
                    gid = i.Gid, name = CleanLabel(i.Name), version = CleanLabel(i.Version), enabled = i.Enabled, installed = i.InstalledUtc, source = CleanLabel(i.Source),
                    status = _extStatus.TryGetValue(i.Gid, out var s) ? s : (i.Enabled ? (_extEnabled ? "not loaded yet" : "extension support is off") : "disabled"),
                    chromiumId = i.ChromiumId
                }).ToList(),
                pending = PendingView(),
                ledger = new { count = ledger.Count, head = ledger.Head, error = ledger.Error }
            });
        }

        // ---- messages from the page ---------------------------------------------------------------------------------------------------

        private async void HandleExtMessage(string msg)
        {
            string Dec(string s) { try { return Uri.UnescapeDataString(s); } catch { return ""; } }
            try
            {
                if (msg == "ext-state") { SendExtSnapshot(); return; }
                if (msg.StartsWith("ext-support:"))
                {
                    var on = msg.EndsWith(":on"); _extState.Enabled = on; SaveExtState(); _actions?.Append("extensions.support", on ? "on" : "off");
                    ExtReport("extension support " + (on ? "ON" : "OFF") + " — restart Recognition to apply."); SendExtSnapshot(); return;
                }
                if (msg == "ext-restart") { RestartToApply(); return; }
                if (msg == "ext-open-policy") { OpenFolder(Path.Combine(_repoRoot, "config")); return; }
                if (msg == "ext-pick-file")
                {
                    var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Choose an extension package", Filter = "Extension package (*.crx;*.zip)|*.crx;*.zip|All files|*.*" };
                    if (dlg.ShowDialog(this) != true) return;
                    var fi = new FileInfo(dlg.FileName);
                    if (fi.Length > ExtPackage.MaxPackageBytes) { ExtReport("that file is larger than " + ExtPackage.MaxPackageBytes / 1024 / 1024 + " MB", false); return; }
                    DiscardPending();
                    _extPending = await Task.Run(() => StageBytes(File.ReadAllBytes(dlg.FileName), fi.Name));
                    SendExtSnapshot(); return;
                }
                if (msg == "ext-pick-folder")
                {
                    var dlg = new Microsoft.Win32.OpenFolderDialog { Title = "Choose an unpacked extension folder (it contains manifest.json)" };
                    if (dlg.ShowDialog(this) != true) return;
                    DiscardPending();
                    _extPending = await Task.Run(() => StageFolder(dlg.FolderName, Path.GetFileName(dlg.FolderName.TrimEnd('\\', '/')) + " (folder)"));
                    SendExtSnapshot(); return;
                }
                if (msg.StartsWith("ext-url:"))
                {
                    var url = Dec(msg.Substring("ext-url:".Length)).Trim();
                    ExtReport("downloading…");
                    var bytes = await DownloadExtensionAsync(url);
                    DiscardPending();
                    var host = new Uri(url).Host;
                    _extPending = await Task.Run(() => StageBytes(bytes, host));
                    ExtReport("downloaded " + (bytes.Length / 1024) + " KB (sha256 " + Convert.ToHexString(SHA256.HashData(bytes)).Substring(0, 12).ToLowerInvariant() + "…). Review it below before installing.");
                    SendExtSnapshot(); return;
                }
                if (msg == "ext-cancel") { DiscardPending(); SendExtSnapshot(); return; }
                if (msg.StartsWith("ext-install:")) { ExtInstall(msg.EndsWith(":approve")); return; }
                if (msg == "ext-verify-chain")
                {
                    try { var v = ExtGovernance.VerifyLedger(ExtLedgerPath); ExtReport("ledger verified: " + v.Count + " records, head " + (v.Head.Length >= 12 ? v.Head.Substring(0, 12) : v.Head) + "…"); }
                    catch (Exception ex) { ExtReport("LEDGER PROBLEM: " + ex.Message + ". Extensions will not load until this is resolved.", false); }
                    return;
                }
                if (msg == "ext-test-pending")
                {
                    var p = _extPending; if (p == null) { ExtReport("nothing to test", false); return; }
                    if (p.Decision.Decision == "deny") { ExtReport("refused: policy denies this extension, so it cannot be tested either.", false); return; }
                    await ExtTestAsync(p.Root, p.Identity.Id); return;
                }
                if (msg.StartsWith("ext-test:"))
                {
                    var it = _extState.Items.FirstOrDefault(i => i.Gid == msg.Substring("ext-test:".Length));
                    if (it == null) return;
                    var (good, _, note) = GateDirectory(ExtDirAbs(it));
                    if (!good) { ExtReport("refused by governance: " + note, false); return; }
                    await ExtTestAsync(ExtDirAbs(it), it.Gid); return;
                }
                if (msg.StartsWith("ext-toggle:")) { await ExtToggleAsync(msg.Substring("ext-toggle:".Length)); return; }
                if (msg.StartsWith("ext-remove:")) { await ExtRemoveAsync(msg.Substring("ext-remove:".Length)); return; }
            }
            catch (ExtGovException ex) { ExtReport("not accepted: " + ex.Message, false); }
            catch (Exception ex) { ExtReport("error: " + ex.Message, false); }
        }

        private void ExtInstall(bool approved)
        {
            var p = _extPending;
            if (p == null) { ExtReport("nothing to install", false); return; }
            var decision = p.Decision.Decision;
            if (decision == "deny") { ExtReport("refused: policy denies this extension (" + string.Join("; ", p.Decision.Reasons) + "). To change the policy, edit config\\extension_policy.v1.json yourself.", false); return; }
            if (decision == "review" && !approved) { ExtReport("this extension needs your explicit approval of the permissions listed", false); return; }
            var gid = p.Identity.Id;
            var rel = Path.Combine("runtime", "extensions", gid); var dst = Path.Combine(_repoRoot, rel);
            try
            {
                if (!Directory.Exists(dst)) ExtPackage.CopyDirectory(p.Root, dst);
                var fin = ExtGovernance.ComputeIdentity(dst);
                if (fin.Id != gid) { try { Directory.Delete(dst, true); } catch { } ExtReport("the installed copy did not match the reviewed files; nothing was installed", false); return; }
                var reasons = p.Decision.Reasons.ToList();
                string recDecision = decision;
                if (decision == "review") { recDecision = "allow"; reasons.Add("user_approved_review"); } else reasons.Add("user_installed");
                ExtGovernance.Record(ExtLedgerPath, gid, p.Manifest, fin.Files, recDecision, reasons, DateTime.UtcNow);
                _extState.Items.RemoveAll(i => i.Gid == gid);
                _extState.Items.Add(new ExtItem { Gid = gid, Name = CleanLabel(p.Manifest.Name), Version = CleanLabel(p.Manifest.Version), Dir = rel, Enabled = true, InstalledUtc = DateTime.UtcNow.ToString("o"), Source = CleanLabel(p.Source) });
                SaveExtState();
                _actions?.Append("extension.install", gid + ":" + (decision == "review" ? "approved" : "allowed"));
                DiscardPending();
                ExtReport("installed " + CleanLabel(p.Manifest.Name) + (_extEnabled ? "." : ". Extension support is off: turn it on and restart to load it."));
                if (_extEnabled) _ = LoadOneAsync(_extState.Items.First(i => i.Gid == gid));
            }
            catch (Exception ex) { ExtReport("install failed: " + ex.Message, false); }
            SendExtSnapshot();
        }

        private async Task LoadOneAsync(ExtItem it)
        {
            try
            {
                var profile = AnyMainProfile(); if (profile == null) { _extStatus[it.Gid] = "will load at next start"; return; }
                var (good, _, note) = await Task.Run(() => GateDirectory(ExtDirAbs(it)));
                if (!good) { _extStatus[it.Gid] = "refused: " + note; _actions?.Append("extension.refused", it.Gid); return; }
                var ext = await profile.AddBrowserExtensionAsync(ExtDirAbs(it));
                it.ChromiumId = ext.Id; _extStatus[it.Gid] = "loaded"; SaveExtState();
                _actions?.Append("extension.loaded", it.Gid);
            }
            catch (Exception ex) { _extStatus[it.Gid] = "error: " + ex.Message; }
            SendExtSnapshot();
        }

        private async Task RemoveFromProfileAsync(ExtItem it)
        {
            var profile = AnyMainProfile(); if (profile == null || it.ChromiumId.Length == 0) return;
            try { foreach (var e in await profile.GetBrowserExtensionsAsync()) if (e.Id == it.ChromiumId) await e.RemoveAsync(); } catch { }
            it.ChromiumId = "";
        }

        private async Task ExtToggleAsync(string gid)
        {
            var it = _extState.Items.FirstOrDefault(i => i.Gid == gid); if (it == null) return;
            it.Enabled = !it.Enabled; SaveExtState(); _actions?.Append("extension." + (it.Enabled ? "enable" : "disable"), gid);
            if (!it.Enabled) { await RemoveFromProfileAsync(it); _extStatus[gid] = "disabled"; SaveExtState(); }
            else if (_extEnabled && _extLoaded) await LoadOneAsync(it);
            else _extStatus[gid] = _extEnabled ? "will load at next start" : "extension support is off";
            SendExtSnapshot();
        }

        private async Task ExtRemoveAsync(string gid)
        {
            var it = _extState.Items.FirstOrDefault(i => i.Gid == gid); if (it == null) return;
            if (MessageBox.Show(this, "Remove \"" + it.Name + "\"?\n\nIts files are deleted and the removal is recorded in the governance ledger. Its stored data in the browser engine is removed with it.", "Recognition — Extensions", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
            await RemoveFromProfileAsync(it);
            var dir = ExtDirAbs(it);
            try
            {
                if (Directory.Exists(dir))
                {
                    var man = ExtGovernance.ReadManifest(dir); var id = ExtGovernance.ComputeIdentity(dir);
                    ExtGovernance.Record(ExtLedgerPath, id.Id, man, id.Files, "deny", new[] { "user_removed" }, DateTime.UtcNow);
                }
            }
            catch { /* a damaged copy is still removed below; the earlier ledger records stay as they are */ }
            try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch (Exception ex) { ExtReport("removed from the list, but some files could not be deleted: " + ex.Message, false); }
            _extState.Items.Remove(it); _extStatus.Remove(gid); SaveExtState();
            _actions?.Append("extension.remove", gid);
            ExtReport("removed " + it.Name);
            SendExtSnapshot();
        }

        // ---- test in an isolated, throw-away profile -------------------------------------------------------------------------------------

        private async Task<CoreWebView2Environment> EnsureExtTestEnvAsync()
        {
            if (_extTestEnv != null) return _extTestEnv;
            _extTestDir = Path.Combine(Path.GetTempPath(), "rb-exttest-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_extTestDir);
            var o = await PrivateEnvOptsAsync();
            o.AreBrowserExtensionsEnabled = true;
            _extTestEnv = await CoreWebView2Environment.CreateAsync(null, _extTestDir, o);
            return _extTestEnv;
        }

        // Loads the extension into a separate temporary profile (no history, cookies or passwords of yours; deleted when Recognition closes)
        // in a private tab, opens the extension's own options/popup page when it has one, and reports what the engine said.
        private async Task ExtTestAsync(string dir, string gid)
        {
            try
            {
                var env = await EnsureExtTestEnvAsync();
                var tab = await NewTabCoreAsync("Extension test", true, env);
                if (tab == null) { ExtReport("could not open the test tab", false); return; }
                Tabs.SelectedItem = tab.Item; ShowActiveWebView();
                var core = tab.Web.CoreWebView2;
                foreach (var old in await core.Profile.GetBrowserExtensionsAsync()) { try { await old.RemoveAsync(); } catch { } }
                var ext = await core.Profile.AddBrowserExtensionAsync(dir);
                string? page = null;
                try
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(dir, "manifest.json")).TrimStart('﻿'), new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
                    var r = doc.RootElement;
                    string? Pick(JsonElement e, string a, string b) => e.TryGetProperty(a, out var x) && x.ValueKind == JsonValueKind.Object && x.TryGetProperty(b, out var y) && y.ValueKind == JsonValueKind.String ? y.GetString() : null;
                    page = Pick(r, "options_ui", "page") ?? (r.TryGetProperty("options_page", out var op) && op.ValueKind == JsonValueKind.String ? op.GetString() : null)
                           ?? Pick(r, "action", "default_popup") ?? Pick(r, "browser_action", "default_popup");
                }
                catch { }
                bool safePage = page != null && !page.Contains("..") && !page.Contains(':') && !page.Contains('\\');
                if (page != null && safePage) { tab.Internal = ""; core.Navigate("chrome-extension://" + ext.Id + "/" + page.TrimStart('/')); }
                else LoadInternal(tab, "start");
                _actions?.Append("extension.test", gid);
                ExtReport("loaded in a temporary test profile (engine id " + ext.Id + ", enabled: " + ext.IsEnabled + ")." + (page != null && safePage ? " Opened its page." : " It has no page of its own: browse to a site where it should act in the test tab.") + " Nothing from this test is kept.");
            }
            catch (Exception ex) { ExtReport("the engine could not load this extension: " + ex.Message, false); }
        }

        private void CleanupExtensionsOnExit()
        {
            DiscardPending();
            if (_extTestDir != null) { try { if (Directory.Exists(_extTestDir)) Directory.Delete(_extTestDir, true); } catch { } }
            try { var s = Path.Combine(_repoRoot, "runtime", "extensions_staging"); if (Directory.Exists(s)) Directory.Delete(s, true); } catch { }
        }

        // ---- page ---------------------------------------------------------------------------------------------------------------------------

        private string ExtensionsHtml()
        {
            var sb = new StringBuilder(PageHead);
            sb.Append(@"<title>Extensions</title><h1>Extensions</h1>
<div class='muted'>Every extension is <b>identified by a hash of its files</b>, judged by a written policy, recorded in a tamper-evident ledger, and re-checked every time the browser starts: if even one byte changed since you approved it, it does not load. Extensions the browser did not approve are removed from the engine at startup. Extensions that ask for broad access (all sites, debugging, proxy control, native messaging) are <b>refused</b>; ones that ask for sensitive access (tabs, cookies, history, downloads, request blocking...) need your explicit approval.</div>
<div class='muted' style='margin-top:6px'><b>Limits:</b> Recognition uses the Chromium engine through Windows WebView2, which supports only part of the extension system. Content scripts and background workers generally work; toolbar buttons, popups and some APIs may not. Use <b>Test</b> before relying on an extension. Approving an extension means it runs with the access it declared. Chrome Web Store downloads are not built in: use a file, a folder, or an https link to the developer's own .crx or .zip.</div>
<div id='msg' class='u' style='min-height:18px;margin:8px 0'></div>
<div id='support' class='row' style='display:block'></div>

<h1 style='font-size:16px'>Add an extension</h1>
<div style='display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:6px 0'>
 <a class='btn' onclick=""send('ext-pick-file')"">Choose a .crx or .zip&hellip;</a>
 <a class='btn ghost' onclick=""send('ext-pick-folder')"">Choose an unpacked folder&hellip;</a>
 <input id='url' placeholder='https://example.com/extension.crx' style='flex:1;min-width:260px;background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:8px'>
 <a class='btn ghost' onclick='fromUrl()'>Download and review</a></div>
<div id='pending'></div>

<h1 style='font-size:16px'>Installed</h1>
<div id='list'></div>

<h1 style='font-size:16px'>Governance ledger</h1>
<div id='ledger' class='u'></div>
<div style='margin:6px 0'><a class='btn ghost' onclick=""send('ext-verify-chain')"">Verify ledger</a> <a class='btn ghost' onclick=""send('ext-open-policy')"">Open the policy folder</a></div>
<script>
function $(i){return document.getElementById(i)}
function el(t,txt,cls){var e=document.createElement(t);if(txt!=null)e.textContent=txt;if(cls)e.className=cls;return e}
var enc=encodeURIComponent;
function fromUrl(){var u=$('url').value.trim();if(u)send('ext-url:'+enc(u))}
function btn(t,cmd,ghost){var a=el('a',t,'btn'+(ghost?' ghost':''));a.style.marginLeft='6px';a.onclick=function(){send(cmd)};return a}
function kb(n){return n>1048576?(n/1048576).toFixed(1)+' MB':Math.max(1,Math.round(n/1024))+' KB'}
function listBlock(parent,title,items){if(!items||!items.length)return;parent.appendChild(el('div',title,'t'));var d=el('div',items.join('   '),'u');d.style.wordBreak='break-all';parent.appendChild(d)}
function render(m){
  var s=$('support');s.textContent='';
  s.appendChild(el('div','Extension support: '+(m.support?'ON':'OFF')+(m.restartNeeded?'   (restart needed to apply your change)':''),'t'));
  var b=el('div',null,'ts');
  b.appendChild(btn(m.supportSaved||m.supportConfig?'Turn off':'Turn on','ext-support:'+(m.supportSaved||m.supportConfig?'off':'on')));
  if(m.restartNeeded)b.appendChild(btn('Restart Recognition','ext-restart'));
  s.appendChild(b);
  var P=$('pending');P.textContent='';var p=m.pending;
  if(p){var r=el('div',null,'row');r.style.display='block';
    r.appendChild(el('div',p.name+'  '+p.version+'   (manifest v'+p.mv+')','t'));
    if(p.description)r.appendChild(el('div',p.description,'u'));
    r.appendChild(el('div','Source: '+p.source+'  ·  '+p.files+' files, '+kb(p.bytes)+'  ·  identity '+p.id.slice(0,16)+'…','u'));
    var dec=el('div','Policy decision: '+p.decision.toUpperCase()+(p.reasons.length?'  —  '+p.reasons.join('; '):''),'t');dec.style.color=p.decision==='deny'?'#e57373':(p.decision==='review'?'#e0b050':'#6fcf97');r.appendChild(dec);
    listBlock(r,'Permissions',p.permissions);listBlock(r,'Site access (host permissions)',p.hosts);listBlock(r,'Content scripts will run on (not scored by the policy)',p.contentScripts);listBlock(r,'Optional permissions it may ask for later (not scored)',p.optional);
    var a=el('div',null,'ts');
    if(p.decision==='deny'){a.appendChild(el('span','Refused by policy: it cannot be installed here.','u'));}
    else{ if(p.decision==='review')a.appendChild(btn('I reviewed these permissions: install','ext-install:approve'));else a.appendChild(btn('Install','ext-install:plain'));
          a.appendChild(btn('Test first (temporary profile)','ext-test-pending',true)); }
    a.appendChild(btn('Discard','ext-cancel',true));r.appendChild(a);P.appendChild(r);}
  var L=$('list');L.textContent='';
  if(!m.items.length)L.appendChild(el('div','No extensions installed.','empty'));
  m.items.forEach(function(x){var r=el('div',null,'row');var d=el('div');
    d.appendChild(el('div',x.name+'  '+x.version,'t'));d.appendChild(el('div',x.status+'  ·  from '+x.source+'  ·  '+x.gid.slice(0,16)+'…','u'));r.appendChild(d);
    var c=el('div',null,'ts');c.appendChild(btn(x.enabled?'Disable':'Enable','ext-toggle:'+x.gid,true));c.appendChild(btn('Test','ext-test:'+x.gid,true));c.appendChild(btn('Remove','ext-remove:'+x.gid,true));r.appendChild(c);L.appendChild(r)});
  $('ledger').textContent=m.ledger.error?('PROBLEM: '+m.ledger.error+'. Extensions will not load until this is resolved.'):(m.ledger.count+' records, head '+(m.ledger.head||'').slice(0,16)+'…')}
window.chrome.webview.addEventListener('message',function(ev){var m=ev.data;if(!m)return;
  if(m.type==='snapshot')render(m);else if(m.type==='action'){$('msg').textContent=m.text;$('msg').style.color=m.ok?'':'#e57373'}});
send('ext-state');
</script>");
            sb.Append(SendScript()).Append(PageFoot);
            return sb.ToString();
        }
    }
}
