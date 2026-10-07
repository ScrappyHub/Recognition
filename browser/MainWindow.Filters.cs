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
using System.Windows.Threading;
using Microsoft.Web.WebView2.Core;

namespace Recognition.Browser
{
    // recognition:shield — ad / tracker filtering (FilterEngine.cs) and the fingerprint shield (shield\fingerprint_shield.js).
    // The matching rules and the farbling maths are executed by tests (browser.tests: C# engine tests, shield.test.js under node);
    // this file is the glue: wiring into WebView2, the list downloader, per-site policy and the page.
    //
    // Network use: the ONLY thing here that talks to the internet by itself is the list updater, and only when the user clicks
    // Update. It accepts https only, caps the size, refuses anything that does not parse as a filter list, and records the SHA-256
    // of what it stored in the hash-chained receipt log. Lists are data: they can block requests and hide page elements, nothing else.
    public partial class MainWindow
    {
        private FilterEngine _filters = new();
        private string _shieldLevel = "standard";                        // off | standard | strict (persisted in browser_settings.json)
        private readonly string _shieldKey = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        private readonly string _shieldTel = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
        private readonly Dictionary<string, long> _fpTotals = new();    // session totals by kind
        private DispatcherTimer? _fpTimer;
        private string? _shieldBody;

        private sealed class ListState
        {
            public bool Enabled { get; set; }
            public string Name { get; set; } = "";
            public string Url { get; set; } = "";
            public string License { get; set; } = "";
            public string Updated { get; set; } = "";
            public string Sha256 { get; set; } = "";
            public long Bytes { get; set; }
            public int Rules { get; set; }
        }
        private readonly Dictionary<string, ListState> _listState = new(StringComparer.Ordinal);
        private string _customRules = "";
        private bool _filtersBuilding, _filtersDirty;

        private const long MaxListBytes = 24L * 1024 * 1024;
        private const int MaxCustomRulesChars = 256 * 1024;

        // Well-known public lists. URLs are only fetched when the user presses Update; nothing is downloaded by default.
        private static readonly (string Id, string Name, string Url, string License)[] FilterCatalog =
        {
            ("easylist",       "EasyList (ads)",              "https://easylist.to/easylist/easylist.txt",                    "CC BY-SA 3.0 or GPL v3"),
            ("easyprivacy",    "EasyPrivacy (trackers)",      "https://easylist.to/easylist/easyprivacy.txt",                 "CC BY-SA 3.0 or GPL v3"),
            ("ublock-filters", "uBlock Origin filters",       "https://ublockorigin.github.io/uAssets/filters/filters.txt",   "GPL v3"),
            ("ublock-privacy", "uBlock Origin privacy",       "https://ublockorigin.github.io/uAssets/filters/privacy.txt",   "GPL v3"),
        };

        private void MenuShield_Click(object sender, RoutedEventArgs e) => OpenInternalInActiveTab("shield");

        private string FilterDir => Path.Combine(_repoRoot, "runtime", "filters");
        private static bool ValidListId(string id) => id.Length is > 0 and <= 40 && id.All(c => char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_');

        // ---- startup -------------------------------------------------------------------------------------------------

        private void InitFilters()
        {
            LoadFilterState();
            _filters = BuildEngine(_blockHosts.ToArray(), Array.Empty<(string, string)>(), "");   // built-in hosts first: ready immediately
            RebuildFiltersAsync();
        }

        private void RebuildFiltersAsync()
        {
            if (_filtersBuilding) { _filtersDirty = true; return; }   // a build is running: run once more when it ends
            _filtersBuilding = true; _filtersDirty = false;
            var hosts = _blockHosts.ToArray();
            var lists = _listState.Where(kv => kv.Value.Enabled && ValidListId(kv.Key)).Select(kv => (kv.Key, Path.Combine(FilterDir, kv.Key + ".txt"))).ToArray();
            var custom = _customRules;
            Task.Run(() =>
            {
                FilterEngine? fe = null;
                try { fe = BuildEngine(hosts, lists, custom); } catch { }
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    _filtersBuilding = false;
                    if (_filtersDirty) { if (fe != null) _filters = fe; RebuildFiltersAsync(); return; }
                    if (fe != null) { _filters = fe; UpdateShield(); var a = Active; if (a != null && a.Internal == "shield") SendShieldSnapshot(); }
                }));
            });
        }

        private static FilterEngine BuildEngine(string[] hosts, (string Id, string Path)[] lists, string custom)
        {
            var fe = new FilterEngine();
            foreach (var h in hosts) fe.AddHostBlock(h, "builtin");
            foreach (var (id, path) in lists)
            {
                try { var fi = new FileInfo(path); if (fi.Exists && fi.Length <= MaxListBytes) fe.AddList(File.ReadAllText(path, Encoding.UTF8), id); } catch { }
            }
            if (!string.IsNullOrWhiteSpace(custom)) fe.AddList(custom, "custom");
            return fe;
        }

        private void LoadFilterState()
        {
            _listState.Clear();
            foreach (var c in FilterCatalog) _listState[c.Id] = new ListState { Name = c.Name, Url = c.Url, License = c.License };
            try
            {
                var p = Path.Combine(FilterDir, "state.v1.json");
                if (File.Exists(p))
                {
                    var saved = JsonSerializer.Deserialize<Dictionary<string, ListState>>(File.ReadAllText(p));
                    if (saved != null)
                        foreach (var kv in saved)
                        {
                            if (!ValidListId(kv.Key) || kv.Value == null) continue;
                            if (_listState.TryGetValue(kv.Key, out var cat))
                            {   // catalogue entries keep their built-in URL/name/licence; only the user's state is restored
                                cat.Enabled = kv.Value.Enabled; cat.Updated = kv.Value.Updated ?? ""; cat.Sha256 = kv.Value.Sha256 ?? ""; cat.Bytes = kv.Value.Bytes; cat.Rules = kv.Value.Rules;
                            }
                            else if (kv.Key.StartsWith("custom-", StringComparison.Ordinal) && Uri.TryCreate(kv.Value.Url, UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps)
                                _listState[kv.Key] = kv.Value;
                        }
                }
                var cp = Path.Combine(FilterDir, "custom.txt");
                if (File.Exists(cp)) { var t = File.ReadAllText(cp, Encoding.UTF8); _customRules = t.Length > MaxCustomRulesChars ? t.Substring(0, MaxCustomRulesChars) : t; }
            }
            catch { }
        }

        private void SaveFilterState()
        {
            try
            {
                Directory.CreateDirectory(FilterDir);
                File.WriteAllText(Path.Combine(FilterDir, "state.v1.json"), JsonSerializer.Serialize(_listState), new UTF8Encoding(false));
            }
            catch { }
        }

        // ---- request / page integration ------------------------------------------------------------------------------

        private static string PageUrlFor(BrowserTab tab)
        {
            if (tab.TopNavUrl.Length > 0) return tab.TopNavUrl;
            return tab.CurrentUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? tab.CurrentUrl : "";
        }

        private static bool SameDocumentUrl(string a, string b)
        {
            if (a.Length == 0 || b.Length == 0) return false;
            int i = a.IndexOf('#'); if (i >= 0) a = a.Substring(0, i);
            int j = b.IndexOf('#'); if (j >= 0) b = b.Substring(0, j);
            return string.Equals(a, b, StringComparison.Ordinal);
        }

        // WebView2 reports iframes as "Document" too. A Document request for the URL the tab is navigating to is the page itself
        // (never blocked by ordinary rules, so you can always open a site you typed); any other Document request is an iframe.
        private static ResType FilterTypeFor(BrowserTab tab, CoreWebView2WebResourceRequestedEventArgs e) => e.ResourceContext switch
        {
            CoreWebView2WebResourceContext.Document => SameDocumentUrl(e.Request.Uri, tab.TopNavUrl) ? ResType.Document : ResType.Subdocument,
            CoreWebView2WebResourceContext.Stylesheet => ResType.Stylesheet,
            CoreWebView2WebResourceContext.Image => ResType.Image,
            CoreWebView2WebResourceContext.Media => ResType.Media,
            CoreWebView2WebResourceContext.Font => ResType.Font,
            CoreWebView2WebResourceContext.Script => ResType.Script,
            CoreWebView2WebResourceContext.XmlHttpRequest => ResType.Xhr,
            CoreWebView2WebResourceContext.Fetch => ResType.Xhr,
            CoreWebView2WebResourceContext.EventSource => ResType.Xhr,
            CoreWebView2WebResourceContext.Websocket => ResType.WebSocket,
            CoreWebView2WebResourceContext.Ping => ResType.Ping,
            CoreWebView2WebResourceContext.CspViolationReport => ResType.Ping,
            CoreWebView2WebResourceContext.TextTrack => ResType.Media,
            _ => ResType.Other
        };

        // Element hiding. Constructable stylesheets are not subject to the page's CSP style-src, a <style> element is the fallback.
        private async void InjectCosmetic(BrowserTab tab)
        {
            try
            {
                if (!_blockingEnabled || tab.IsInternal || tab.Web?.CoreWebView2 == null) return;
                var url = PageUrlFor(tab); var host = TryHost(url);
                if (string.IsNullOrEmpty(host) || SitePolicyGet(host, "tracker_blocking", "inherit") == "off") return;
                var css = _filters.CosmeticCssFor(host);
                if (css.Length == 0) return;
                var lit = JsonSerializer.Serialize(css);
                await tab.Web.CoreWebView2.ExecuteScriptAsync(
                    "(function(){var c=" + lit + ";try{var s=new CSSStyleSheet();s.replaceSync(c);document.adoptedStyleSheets=document.adoptedStyleSheets.concat([s]);}" +
                    "catch(e){try{var t=document.createElement('style');t.textContent=c;(document.head||document.documentElement).appendChild(t);}catch(e2){}}})()");
            }
            catch { }
        }

        // ---- fingerprint shield --------------------------------------------------------------------------------------

        private string? LoadShieldBody()
        {
            if (_shieldBody != null) return _shieldBody;
            try
            {
                using var s = typeof(MainWindow).Assembly.GetManifestResourceStream("fingerprint_shield.js");
                if (s == null) return null;
                using var r = new StreamReader(s, Encoding.UTF8);
                return _shieldBody = r.ReadToEnd();
            }
            catch { return null; }
        }

        private string? ShieldScript()
        {
            var sites = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var kv in _sitePolicyState)
            {
                if (!kv.Key.StartsWith("fp_shield|", StringComparison.Ordinal)) continue;
                var host = kv.Key.Substring("fp_shield|".Length);
                if (kv.Value is "off" or "standard" or "strict") sites[host] = kv.Value;
            }
            if (_shieldLevel == "off" && sites.Count == 0) return null;
            var body = LoadShieldBody(); if (body == null) return null;
            var suffixes = PublicSuffixList.BuiltIn.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Where(x => x.Count(c => c == '.') == 1 && !x.Contains('*')).ToArray();
            var cfg = JsonSerializer.Serialize(new { key = _shieldKey, tel = _shieldTel, level = _shieldLevel, sites, suffixes });
            return "(function(g,__cfg){" + body + "\n})(window," + cfg + ");";
        }

        private async Task RegisterShieldAsync(BrowserTab tab)
        {
            try
            {
                var core = tab.Web.CoreWebView2; if (core == null) return;
                if (tab.ShieldScriptId != null) { core.RemoveScriptToExecuteOnDocumentCreated(tab.ShieldScriptId); tab.ShieldScriptId = null; }
                var js = ShieldScript();
                if (js != null) tab.ShieldScriptId = await core.AddScriptToExecuteOnDocumentCreatedAsync(js);
                if (_fpTimer == null)
                {
                    _fpTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
                    _fpTimer.Tick += (_, __) => PollShield();
                    _fpTimer.Start();
                }
            }
            catch { }
        }

        private async void RefreshShieldAll()
        {
            foreach (var t in _tabs.ToList()) if (t.Ready) await RegisterShieldAsync(t);
        }

        private static readonly HashSet<string> FpKinds = new(StringComparer.Ordinal) { "canvas", "webgl", "audio", "navigator", "screen", "other" };

        // Reads (and resets) the counters kept inside the page's shield closure. Values come from a web page, so they are parsed
        // defensively: known kinds only, bounded integers, bounded length.
        private async void PollShield()
        {
            try
            {
                var t = Active;
                if (t == null || t.IsInternal || !t.Ready || t.Web?.CoreWebView2 == null) return;
                await PollPasskeysAsync(t);
                if (t.ShieldScriptId == null) return;
                var raw = await t.Web.CoreWebView2.ExecuteScriptAsync("(function(){try{var f=window['__rc_" + _shieldTel + "'];return typeof f==='function'?String(f()):''}catch(e){return ''}})()");
                if (string.IsNullOrEmpty(raw) || raw == "null") return;
                var s = JsonSerializer.Deserialize<string>(raw) ?? "";
                if (s.Length == 0 || s.Length > 200) return;
                foreach (var part in s.Split(','))
                {
                    var kv = part.Split('=');
                    if (kv.Length != 2 || !FpKinds.Contains(kv[0]) || !int.TryParse(kv[1], out var n) || n < 0 || n > 10_000_000) continue;
                    t.Fp[kv[0]] = (t.Fp.TryGetValue(kv[0], out var o) ? o : 0) + n;
                    _fpTotals[kv[0]] = (_fpTotals.TryGetValue(kv[0], out var ot) ? ot : 0) + n;
                }
                var a = Active; if (a != null && a.Internal == "shield") SendShieldSnapshot();
            }
            catch { }
        }

        // ---- list updater --------------------------------------------------------------------------------------------

        private async Task<(bool Ok, string Message)> DownloadFilterListAsync(string id)
        {
            if (!_listState.TryGetValue(id, out var st)) return (false, "unknown list");
            if (!Uri.TryCreate(st.Url, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps) return (false, "only https lists are accepted");
            try
            {
                using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 3 }) { Timeout = TimeSpan.FromSeconds(45) };
                http.DefaultRequestHeaders.UserAgent.ParseAdd("Recognition-filter-updater/1.1");
                using var resp = await http.GetAsync(u, HttpCompletionOption.ResponseHeadersRead);
                if (!resp.IsSuccessStatusCode) return (false, "server answered " + (int)resp.StatusCode);
                if (resp.RequestMessage?.RequestUri?.Scheme != Uri.UriSchemeHttps) return (false, "redirected away from https; refused");
                if (resp.Content.Headers.ContentLength is long cl && cl > MaxListBytes) return (false, "list is larger than the " + (MaxListBytes >> 20) + " MB limit");
                using var ms = new MemoryStream();
                using (var net = await resp.Content.ReadAsStreamAsync())
                {
                    var buf = new byte[81920]; int n;
                    while ((n = await net.ReadAsync(buf, 0, buf.Length)) > 0)
                    {
                        ms.Write(buf, 0, n);
                        if (ms.Length > MaxListBytes) return (false, "list is larger than the " + (MaxListBytes >> 20) + " MB limit");
                    }
                }
                var bytes = ms.ToArray();
                var text = Encoding.UTF8.GetString(bytes);
                var probe = new FilterEngine(); probe.AddList(text, id);
                int rules = probe.NetworkRules + probe.CosmeticRules;
                if (rules < 10) return (false, "that file does not look like a filter list (" + rules + " usable rules); not saved");
                Directory.CreateDirectory(FilterDir);
                var final = Path.Combine(FilterDir, id + ".txt"); var tmp = final + ".tmp";
                File.WriteAllBytes(tmp, bytes); File.Move(tmp, final, true);
                st.Sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
                st.Bytes = bytes.Length; st.Rules = rules; st.Updated = DateTime.UtcNow.ToString("o"); st.Enabled = true;
                SaveFilterState();
                _actions?.Append("filters.update", id + ":" + st.Sha256 + ":" + bytes.Length);
                return (true, st.Name + ": " + rules.ToString("N0") + " rules, " + (bytes.Length / 1024) + " KB, sha256 " + st.Sha256.Substring(0, 12) + "…");
            }
            catch (TaskCanceledException) { return (false, "timed out"); }
            catch (Exception ex) { return (false, ex.Message); }
        }

        // ---- page messages ---------------------------------------------------------------------------------------------

        private void PostToShieldPage(object payload)
        {
            var t = Active; if (t == null || t.Internal != "shield") return;
            try { t.Web.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(payload)); } catch { }
        }

        private void SendShieldSnapshot()
        {
            var sites = _sitePolicyState.Where(kv => kv.Key.StartsWith("fp_shield|", StringComparison.Ordinal))
                .Select(kv => new { host = kv.Key.Substring("fp_shield|".Length), level = kv.Value }).OrderBy(x => x.host).ToList();
            var exempt = _sitePolicyState.Where(kv => kv.Key.StartsWith("tracker_blocking|", StringComparison.Ordinal) && kv.Value == "off")
                .Select(kv => kv.Key.Substring("tracker_blocking|".Length)).OrderBy(x => x).ToList();
            PostToShieldPage(new
            {
                type = "snapshot",
                building = _filtersBuilding,
                blockingEnabled = _blockingEnabled,
                level = _shieldLevel,
                sites, exempt,
                stats = new { network = _filters.NetworkRules, cosmetic = _filters.CosmeticRules, unsupported = _filters.Unsupported, rejected = _filters.Rejected, blockedSession = _blockedSession, popups = _popupsBlocked, external = _externalBlocked },
                tracking = _trackingLevel,
                popupSites = _sitePolicyState.Where(kv => kv.Key.StartsWith("popups|", StringComparison.Ordinal) && kv.Value == "allow").Select(kv => kv.Key.Substring("popups|".Length)).OrderBy(x => x).ToList(),
                fpSession = _fpTotals,
                fpPage = Active?.Fp,
                lists = _listState.OrderBy(kv => kv.Key.StartsWith("custom-") ? 1 : 0).ThenBy(kv => kv.Key)
                    .Select(kv => new { id = kv.Key, name = kv.Value.Name, url = kv.Value.Url, license = kv.Value.License, enabled = kv.Value.Enabled, updated = kv.Value.Updated, sha = kv.Value.Sha256, bytes = kv.Value.Bytes, rules = kv.Value.Rules, custom = kv.Key.StartsWith("custom-") }).ToList(),
                customRules = _customRules
            });
        }

        private async void HandleShieldMessage(string msg)
        {
            string Dec(string s) { try { return Uri.UnescapeDataString(s); } catch { return ""; } }
            try
            {
                if (msg == "flt-state") { SendShieldSnapshot(); return; }
                if (msg.StartsWith("shield-level:"))
                {
                    var lv = msg.Substring("shield-level:".Length);
                    if (lv is not ("off" or "standard" or "strict")) return;
                    _shieldLevel = lv; SaveSettings(); RefreshShieldAll();
                    _actions?.Append("shield.level", lv); Status("fingerprint shield: " + lv + " (applies to pages you load next)");
                    SendShieldSnapshot(); return;
                }
                if (msg.StartsWith("shield-site:"))
                {
                    var p = msg.Substring("shield-site:".Length).Split(':');
                    var host = p.Length == 2 ? p[0].Trim().ToLowerInvariant() : "";
                    if (host.Length == 0 || host.Length > 253 || !host.All(c => char.IsAsciiLetterOrDigit(c) || c == '.' || c == '-') || p[1] is not ("off" or "standard" or "strict" or "inherit")) { Status("site setting rejected"); return; }
                    SitePolicySet(host, "fp_shield", p[1]); RefreshShieldAll();
                    Status("fingerprint shield for " + host + ": " + p[1]); SendShieldSnapshot(); return;
                }
                if (msg.StartsWith("shield-tracking:"))
                {
                    var lv = msg.Substring("shield-tracking:".Length);
                    if (lv is not ("off" or "basic" or "balanced" or "strict")) return;
                    _trackingLevel = lv; SaveSettings(); ApplyTrackingPreventionAll(); _actions?.Append("shield.tracking", lv);
                    Status("engine tracking prevention: " + lv); SendShieldSnapshot(); return;
                }
                if (msg.StartsWith("flt-popup:"))
                {
                    var p = msg.Substring("flt-popup:".Length).Split(':');
                    var host = p.Length == 2 ? p[0].Trim().ToLowerInvariant() : "";
                    if (host.Length == 0 || host.Length > 253 || !host.All(c => char.IsAsciiLetterOrDigit(c) || c == '.' || c == '-') || p[1] is not ("allow" or "inherit")) { Status("site setting rejected"); return; }
                    SitePolicySet(host, "popups", p[1]); Status("pop-ups opened without a click on " + host + ": " + (p[1] == "allow" ? "allowed" : "blocked")); SendShieldSnapshot(); return;
                }
                if (msg.StartsWith("flt-site:"))
                {
                    var p = msg.Substring("flt-site:".Length).Split(':');
                    var host = p.Length == 2 ? p[0].Trim().ToLowerInvariant() : "";
                    if (host.Length == 0 || host.Length > 253 || !host.All(c => char.IsAsciiLetterOrDigit(c) || c == '.' || c == '-') || p[1] is not ("off" or "inherit")) { Status("site setting rejected"); return; }
                    SitePolicySet(host, "tracker_blocking", p[1]);
                    Status("ad/tracker blocking for " + host + ": " + (p[1] == "off" ? "exempted" : "inherits global setting")); SendShieldSnapshot(); return;
                }
                if (msg.StartsWith("flt-toggle:"))
                {
                    var id = msg.Substring("flt-toggle:".Length);
                    if (_listState.TryGetValue(id, out var st) && (st.Rules > 0 || st.Enabled)) { st.Enabled = !st.Enabled; SaveFilterState(); _actions?.Append("filters.toggle", id + ":" + (st.Enabled ? "on" : "off")); RebuildFiltersAsync(); }
                    SendShieldSnapshot(); return;
                }
                if (msg == "flt-update-all") { foreach (var id in _listState.Keys.Where(k => _listState[k].Enabled || _listState[k].Rules > 0).ToList()) await UpdateOneList(id); return; }
                if (msg.StartsWith("flt-update:")) { await UpdateOneList(msg.Substring("flt-update:".Length)); return; }
                if (msg.StartsWith("flt-add:"))
                {
                    var url = Dec(msg.Substring("flt-add:".Length)).Trim();
                    if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps || url.Length > 500) { PostToShieldPage(new { type = "action", ok = false, text = "enter a full https:// address" }); return; }
                    var id = "custom-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(url))).Substring(0, 10).ToLowerInvariant();
                    if (_listState.Count >= 40) { PostToShieldPage(new { type = "action", ok = false, text = "too many lists (limit 40)" }); return; }
                    _listState[id] = new ListState { Name = u.Host + u.AbsolutePath, Url = url, License = "unknown: check the list's own terms" };
                    await UpdateOneList(id);
                    if (_listState.TryGetValue(id, out var added) && added.Rules == 0) { _listState.Remove(id); SaveFilterState(); SendShieldSnapshot(); }
                    return;
                }
                if (msg.StartsWith("flt-remove:"))
                {
                    var id = msg.Substring("flt-remove:".Length);
                    if (_listState.TryGetValue(id, out var st))
                    {
                        try { var f = Path.Combine(FilterDir, id + ".txt"); if (File.Exists(f)) File.Delete(f); } catch { }
                        if (id.StartsWith("custom-", StringComparison.Ordinal)) _listState.Remove(id); else { st.Enabled = false; st.Rules = 0; st.Sha256 = ""; st.Bytes = 0; st.Updated = ""; }
                        SaveFilterState(); _actions?.Append("filters.remove", id); RebuildFiltersAsync();
                    }
                    SendShieldSnapshot(); return;
                }
                if (msg.StartsWith("flt-custom:"))
                {
                    var text = Dec(msg.Substring("flt-custom:".Length));
                    if (text.Length > MaxCustomRulesChars) { PostToShieldPage(new { type = "action", ok = false, text = "custom rules are limited to " + MaxCustomRulesChars / 1024 + " KB" }); return; }
                    var probe = new FilterEngine(); probe.AddList(text, "custom");
                    _customRules = text; Directory.CreateDirectory(FilterDir);
                    File.WriteAllText(Path.Combine(FilterDir, "custom.txt"), text, new UTF8Encoding(false));
                    _actions?.Append("filters.custom", probe.NetworkRules + "+" + probe.CosmeticRules);
                    RebuildFiltersAsync();
                    PostToShieldPage(new { type = "action", ok = true, text = "saved: " + probe.NetworkRules + " network and " + probe.CosmeticRules + " cosmetic rules" + (probe.Rejected + probe.Unsupported > 0 ? ", " + (probe.Rejected + probe.Unsupported) + " line(s) ignored (unsupported or unsafe)" : "") });
                    return;
                }
                if (msg.StartsWith("flt-test:"))
                {
                    using var d = JsonDocument.Parse(Dec(msg.Substring("flt-test:".Length))); var r = d.RootElement;
                    string S(string k) => r.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
                    var ty = Enum.TryParse<ResType>(S("type"), true, out var rt) && rt != ResType.None && rt != ResType.All && rt != ResType.AllButDocument ? rt : ResType.Script;
                    var url = S("url"); var page = S("page");
                    if (url.Length > 4096 || page.Length > 4096) return;
                    var m = _filters.Match(url, page.Length == 0 ? null : page, ty);
                    PostToShieldPage(new { type = "test", blocked = m.Blocked, rule = m.Rule, list = m.ListId });
                    return;
                }
            }
            catch (Exception ex) { PostToShieldPage(new { type = "action", ok = false, text = "error: " + ex.Message }); }
        }

        private async Task UpdateOneList(string id)
        {
            if (!ValidListId(id) || !_listState.ContainsKey(id)) return;
            PostToShieldPage(new { type = "action", ok = true, text = "downloading " + _listState[id].Name + " …" });
            var (ok, message) = await DownloadFilterListAsync(id);
            PostToShieldPage(new { type = "action", ok, text = ok ? "updated. " + message : "not updated: " + message });
            if (ok) RebuildFiltersAsync();
            SendShieldSnapshot();
        }

        // ---- page ------------------------------------------------------------------------------------------------------

        private string ShieldHtml()
        {
            var sb = new StringBuilder(PageHead);
            sb.Append(@"<title>Shield</title><h1>Shield</h1>
<div class='muted'>Two protections: <b>ad and tracker filtering</b> (network requests are blocked, page elements are hidden) and a <b>fingerprint shield</b> (makes the values trackers use to recognise your device unstable or less distinctive). Both run on your computer; nothing here sends data anywhere. The only network use is the list updater, and only when you press Update.</div>
<div id='msg' class='u' style='min-height:18px;margin:8px 0'></div>
<div id='stats' class='row' style='display:block'></div>

<h1 style='font-size:16px'>Fingerprint shield</h1>
<div class='muted'>Canvas, WebGL and audio readbacks get tiny noise that is <b>the same on one site during a session but different on every other site and every session</b>, so a tracker on two sites cannot link them. Hardware details are reduced (CPU cores, device memory, graphics vendor and renderer, User-Agent Client Hints). <b>Strict</b> also rounds the screen size, hides the battery API and the voice list. It does not hide fonts or timing, a determined script can notice that noise is present, and it does not cover web workers. It reduces tracking; it is not anonymity. Sites that make or edit images in the browser may need the shield off for that site.</div>
<div style='margin:8px 0;display:flex;gap:8px;align-items:center;flex-wrap:wrap'><span class='u'>Default level:</span>
 <a class='btn' id='lv_off' onclick=""send('shield-level:off')"">Off</a><a class='btn' id='lv_standard' onclick=""send('shield-level:standard')"">Standard</a><a class='btn' id='lv_strict' onclick=""send('shield-level:strict')"">Strict</a>
 <span class='u'>Changes apply to pages you load next.</span></div>
<div class='u' id='fpnow'></div>
<div style='margin:8px 0;display:flex;gap:6px;flex-wrap:wrap;align-items:center'><span class='u'>Per site:</span>
 <input id='sh' placeholder='example.com' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:6px'>
 <a class='btn ghost' onclick=""site('off')"">Off</a><a class='btn ghost' onclick=""site('standard')"">Standard</a><a class='btn ghost' onclick=""site('strict')"">Strict</a><a class='btn ghost' onclick=""site('inherit')"">Use default</a></div>
<div id='sites'></div>

<h1 style='font-size:16px'>Engine tracking prevention</h1>
<div class='muted'>The Chromium engine has its own tracker prevention that restricts storage and cookies for known third-party trackers. <b>Balanced</b> is the engine default; <b>Strict</b> blocks more and can break some sites. This is separate from the filter lists below and from the fingerprint shield above.</div>
<div style='margin:8px 0;display:flex;gap:8px;align-items:center;flex-wrap:wrap'><a class='btn' id='tp_off' onclick=""send('shield-tracking:off')"">Off</a><a class='btn' id='tp_basic' onclick=""send('shield-tracking:basic')"">Basic</a><a class='btn' id='tp_balanced' onclick=""send('shield-tracking:balanced')"">Balanced</a><a class='btn' id='tp_strict' onclick=""send('shield-tracking:strict')"">Strict</a></div>

<h1 style='font-size:16px'>Pop-ups and other programs</h1>
<div class='muted'>A page can open a new tab only when you click or press a key; scripted pop-ups are blocked, and pop-ups may only go to http(s) addresses. A link opened from a private tab stays private. Links that start another program (such as ms-msdt: or search-ms:) are blocked; only mailto: and tel: links you click are passed to Windows. Allow scripted pop-ups for one site:</div>
<div id='popstats' class='u'></div>
<div style='margin:8px 0;display:flex;gap:6px;flex-wrap:wrap;align-items:center'>
 <input id='ph' placeholder='example.com' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:6px'>
 <a class='btn ghost' onclick=""popsite('allow')"">Allow</a><a class='btn ghost' onclick=""popsite('inherit')"">Block (default)</a></div>
<div id='popsites'></div>

<h1 style='font-size:16px'>Ad and tracker filter lists</h1>
<div class='muted'>The built-in tracker host list is always on (while blocking is on). You can add well-known public lists. They are downloaded only when you click Update, only over https, size-limited, and refused if they do not parse as a filter list. The SHA-256 of what was stored goes into the receipt log. Lists are separate projects with their own licences; Recognition does not bundle them. Downloads go directly from this PC, not through the browser's proxy or VPN setting. Supported: network rules (domain, path, wildcard, anchors, type and third-party options, exceptions) and element hiding. Not supported: scriptlets and procedural cosmetic filters; those lines are counted and skipped.</div>
<div id='lists'></div>
<div style='margin:8px 0;display:flex;gap:6px;flex-wrap:wrap'>
 <input id='lu' placeholder='https://example.com/list.txt' style='flex:1;min-width:260px;background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:8px'>
 <a class='btn' onclick='addList()'>Add list</a><a class='btn ghost' onclick=""send('flt-update-all')"">Update all</a></div>

<h1 style='font-size:16px'>Your own rules</h1>
<div class='muted'>One rule per line, same syntax as EasyList. Example: <code>||ads.example.com^</code> or <code>example.com##.cookie-banner</code>. Lines starting with ! are comments.</div>
<textarea id='custom' rows='6' style='width:100%;box-sizing:border-box;background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:8px;font-family:Consolas,monospace'></textarea>
<div style='margin:6px 0'><a class='btn' onclick='saveCustom()'>Save rules</a></div>

<h1 style='font-size:16px'>Test a request</h1>
<div class='muted'>Check what the current rules would do with a request without loading anything.</div>
<div style='display:grid;grid-template-columns:90px 1fr;gap:6px;max-width:700px;align-items:center'>
 <div>Request URL</div><input id='tu' placeholder='https://ads.example.net/banner.js' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:6px'>
 <div>On page</div><input id='tp' placeholder='https://news.example.org/story' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:6px'>
 <div>Type</div><select id='tt' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:6px'><option>Script</option><option>Image</option><option>Stylesheet</option><option>Xhr</option><option>Subdocument</option><option>Font</option><option>Media</option><option>WebSocket</option><option>Ping</option><option>Other</option></select></div>
<div style='margin:6px 0'><a class='btn' onclick='testReq()'>Test</a> <span id='tres' class='u'></span></div>

<h1 style='font-size:16px'>Sites exempt from ad and tracker blocking</h1>
<div id='exempt'></div>
<script>
function $(i){return document.getElementById(i)}
function el(t,txt,cls){var e=document.createElement(t);if(txt!=null)e.textContent=txt;if(cls)e.className=cls;return e}
var enc=encodeURIComponent;
function site(l){var h=$('sh').value.trim();if(h)send('shield-site:'+h+':'+l)}
function popsite(v){var h=$('ph').value.trim();if(h)send('flt-popup:'+h+':'+v)}
function addList(){send('flt-add:'+enc($('lu').value.trim()))}
function saveCustom(){send('flt-custom:'+enc($('custom').value))}
function testReq(){send('flt-test:'+enc(JSON.stringify({url:$('tu').value.trim(),page:$('tp').value.trim(),type:$('tt').value})))}
function btn(t,cmd,ghost){var a=el('a',t,'btn'+(ghost?' ghost':''));a.style.marginLeft='6px';a.onclick=function(){send(cmd)};return a}
function fmt(n){return Number(n).toLocaleString()}
function render(m){
  var s=m.stats;$('stats').textContent='';
  var l1=el('div','Blocking is '+(m.blockingEnabled?'ON':'OFF')+(m.building?'  (loading lists…)':''),'t');$('stats').appendChild(l1);
  $('stats').appendChild(el('div',fmt(s.network)+' network rules · '+fmt(s.cosmetic)+' element-hiding rules · '+fmt(s.unsupported)+' unsupported lines skipped · '+fmt(s.rejected)+' unsafe or invalid lines rejected · '+fmt(s.blockedSession)+' requests blocked this session','u'));
  var fp=m.fpSession||{},parts=[];for(var k in fp)parts.push(k+' '+fp[k]);
  $('stats').appendChild(el('div','Fingerprint attempts intercepted this session: '+(parts.length?parts.join(' · '):'none yet'),'u'));
  ['off','standard','strict'].forEach(function(x){$('lv_'+x).className='btn'+(m.level===x?'':' ghost')});
  var pg=m.fpPage||{},pp=[];for(var k2 in pg)pp.push(k2+' '+pg[k2]);
  $('fpnow').textContent='This tab: '+(pp.length?pp.join(' · '):'no fingerprinting calls seen');
  ['off','basic','balanced','strict'].forEach(function(x){$('tp_'+x).className='btn'+(m.tracking===x?'':' ghost')});
  $('popstats').textContent='Blocked this session: '+s.popups+' pop-up(s), '+s.external+' attempt(s) to start another program.';
  var pp=$('popsites');pp.textContent='';(m.popupSites||[]).forEach(function(h){var r=el('div',null,'row');r.appendChild(el('div',h+'  ·  scripted pop-ups allowed','t'));var b=el('div',null,'ts');b.appendChild(btn('Block again','flt-popup:'+h+':inherit',true));r.appendChild(b);pp.appendChild(r)});
  var ss=$('sites');ss.textContent='';(m.sites||[]).forEach(function(x){var r=el('div',null,'row');r.appendChild(el('div',x.host+'  ·  '+x.level,'t'));var b=el('div',null,'ts');b.appendChild(btn('Remove','shield-site:'+x.host+':inherit',true));r.appendChild(b);ss.appendChild(r)});
  var L=$('lists');L.textContent='';
  m.lists.forEach(function(x){var r=el('div',null,'row');var d=el('div');
    d.appendChild(el('div',x.name+(x.enabled?'':'  (off)'),'t'));
    d.appendChild(el('div',(x.rules?fmt(x.rules)+' rules · '+Math.round(x.bytes/1024)+' KB · updated '+x.updated.slice(0,10)+' · sha256 '+x.sha.slice(0,12)+'…':'not downloaded')+'  ·  licence: '+x.license,'u'));
    d.appendChild(el('div',x.url,'u'));r.appendChild(d);
    var b=el('div',null,'ts');b.appendChild(btn(x.rules?'Update':'Download','flt-update:'+x.id));
    if(x.rules)b.appendChild(btn(x.enabled?'Turn off':'Turn on','flt-toggle:'+x.id,true));
    if(x.rules||x.custom)b.appendChild(btn('Remove','flt-remove:'+x.id,true));
    r.appendChild(b);L.appendChild(r)});
  if(document.activeElement!==$('custom'))$('custom').value=m.customRules||'';
  var ex=$('exempt');ex.textContent='';if(!(m.exempt||[]).length)ex.appendChild(el('div','None. Add one from the page menu when a site breaks.','empty'));
  (m.exempt||[]).forEach(function(h){var r=el('div',null,'row');r.appendChild(el('div',h,'t'));var b=el('div',null,'ts');b.appendChild(btn('Re-enable blocking','flt-site:'+h+':inherit',true));r.appendChild(b);ex.appendChild(r)})}
window.chrome.webview.addEventListener('message',function(ev){var m=ev.data;if(!m)return;
  if(m.type==='snapshot')render(m);
  else if(m.type==='action')$('msg').textContent=m.text;
  else if(m.type==='test')$('tres').textContent=m.blocked?('BLOCKED by '+m.rule+'  ('+m.list+')'):(m.rule?('allowed by exception '+m.rule+'  ('+m.list+')'):'allowed (no rule matches)')});
send('flt-state');
</script>");
            sb.Append(SendScript()).Append(PageFoot);
            return sb.ToString();
        }
    }
}
