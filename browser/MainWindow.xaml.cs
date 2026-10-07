using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;

namespace Recognition.Browser
{
    // WBS 5.x / §5 / §10 / §20 / §24 / §29 — governed WebView2 shell.
    //
    // Feel: Chrome/Firefox-style multi-tab chrome (favicons, tab pills, omnibox).
    // Optimization: Opera/Edge-style "sleeping tabs" — hidden tabs are suspended
    //   (TrySuspendAsync) to release memory/CPU, resumed on activation.
    // Privacy: Brave-style tracker/ad blocking at the network layer
    //   (WebResourceRequested against a governed host blocklist) with a per-site
    //   shield counter, on top of HTTPS-first, no autofill, no telemetry, fail-closed
    //   locked startup, hash-chained history, and session export to a governed packet.
    public partial class MainWindow : Window
    {
        private readonly string _repoRoot;
        private readonly string _sessionId = "rb-" + Guid.NewGuid().ToString("N").Substring(0, 12);
        private readonly DateTime _startedUtc = DateTime.UtcNow;

        private CoreWebView2Environment? _env;
        private bool _preflightOk;
        private readonly List<BrowserTab> _tabs = new();

        private GovernedHistory _history = null!;
        private GovernedActions _actions = null!;
        private GovernedActions _cookies = null!;   // dedicated governed ledger for cookie state changes (§23)
        private readonly Dictionary<string, string> _cookieLastSeen = new();   // domain|name -> value_sha256, dedupes the ledger to real changes
        private GovernedActions _sitePolicy = null!;   // per-origin policy ledger (§53.1/§54.1) — permissions + tracker-blocking overrides + certificate trust
        private readonly Dictionary<string, string> _sitePolicyState = new(StringComparer.OrdinalIgnoreCase);   // "key|origin" -> value, replayed from the ledger (latest wins)
        private readonly Dictionary<string, (string Fp, string Err)> _certErrors = new(StringComparer.OrdinalIgnoreCase);   // host -> last-seen cert error (session-only, lets Settings offer "trust this certificate")
        private readonly List<Bookmark> _bookmarks = new();
        private readonly List<DownloadRec> _downloads = new();
        private bool _suppressSuggest;

        // Tracker/ad blocking (Brave-style)
        private readonly HashSet<string> _blockHosts = new(StringComparer.OrdinalIgnoreCase);
        private bool _blockingEnabled = true;
        private bool _stripTracking = true, _sendGpc = true;   // privacy conveniences, persisted in browser_settings.json
        private int _paramsStripped;
        private DateTime _lastTabShortcutUtc = DateTime.MinValue;
        private int _blockedSession;

        // Private/incognito: a separate ephemeral profile in a temp folder, deleted on exit.
        // Incognito ALWAYS routes through the VPN when an endpoint is available (safe default).
        private CoreWebView2Environment? _privateEnv;
        private string? _privateDir;
        private string _privateVpnRegion = "";   // region label the private env is tunneled through ("" = none)
        private bool _privateVpnOn;

        // Governed network / VPN (config/network.v1.json)
        private string _netMode = "off";       // off | proxy | wireguard | system
        private string _netProxy = "";
        private string _netExitRegion = "";
        private string _netExitCheckUrl = "";
        private bool _netAutoOptimize;
        private bool _netProxyDown;   // configured exit is unreachable this session (run direct, warn)
        private sealed class NetEndpoint { public string Name = ""; public string Region = ""; public string Proxy = ""; }
        private readonly List<NetEndpoint> _netEndpoints = new();

        // Home page (config: browser_settings.json home_url)
        private string _homeUrl = "recognition:start";

        // Governed Chromium extensions (config/extensions.v1.json — explicit allowlist)
        private bool _extEnabled;
        private bool _extLoaded;
        private readonly List<string> _extPaths = new();

        private const string StartMarker = "recognition:start";

        private const string ShortcutScript = @"
document.addEventListener('keydown',function(e){
  if(!e.isTrusted)return;
  var k=(e.key||'').toLowerCase(); var m=null;
  if(e.ctrlKey&&e.shiftKey&&k==='n')m='newprivate';
  else if(e.ctrlKey&&k==='t')m='newtab';
  else if(e.ctrlKey&&k==='w')m='closetab';
  else if(e.ctrlKey&&k==='l')m='focusaddr';
  else if((e.ctrlKey&&k==='r')||k==='f5')m='reload';
  else if(e.ctrlKey&&k==='f')m='find';
  else if(e.ctrlKey&&k==='d')m='bookmark';
  else if(e.ctrlKey&&(k==='='||k==='+'))m='zoomin';
  else if(e.ctrlKey&&k==='-')m='zoomout';
  else if(e.ctrlKey&&k==='0')m='zoomreset';
  else if(e.ctrlKey&&k==='tab')m=e.shiftKey?'prevtab':'nexttab';
  else if(e.altKey&&k==='arrowleft')m='back';
  else if(e.altKey&&k==='arrowright')m='forward';
  if(m){e.preventDefault();window.chrome.webview.postMessage('sc:'+m);}
},true);";

        private sealed class BrowserTab
        {
            public TabItem Item = null!;
            public WebView2 Web = null!;
            public TextBlock Header = null!;
            public Image Fav = null!;
            public readonly List<(string Url, string Title, DateTime Ts)> Visits = new();
            public string CurrentUrl = StartMarker;
            public string CurrentTitle = "New tab";
            public bool Ready;
            public bool Private;
            public int Blocked;
            public string Internal = "start";
            public bool IsInternal => Internal.Length > 0;
            public string? StyleScriptId;   // document-created script that applies the user's appearance CSS
            public string? PasskeyScriptId; // document-created script of the passkey guard
            public string? ShieldScriptId;  // document-created script of the fingerprint shield
            public string TopNavUrl = "";   // top-level document currently being loaded (http/https only)
            public readonly Dictionary<string, int> Fp = new();   // fingerprint-shield interventions on the current page
        }

        private readonly AppearanceSettings _appearance = new();

        public MainWindow()
        {
            InitializeComponent();
            _repoRoot = FindRepoRoot(AppContext.BaseDirectory);
            Loaded += OnLoaded;
            Closing += OnClosing;
        }

        private void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
        {
            RecordNetworkEnd();
            StopPasskeyServer();
            CleanupExtensionsOnExit();
            CleanupViewerAll();
            foreach (var t in _tabs) { if (t.Private) { try { t.Web.Dispose(); } catch { } } }
            if (_privateDir != null) { try { if (Directory.Exists(_privateDir)) Directory.Delete(_privateDir, true); } catch { } }
        }

        private static string FindRepoRoot(string start)
        {
            var d = new DirectoryInfo(start);
            while (d != null)
            {
                var s = Path.Combine(d.FullName, "scripts", "recognition_export_session_packet_v1.ps1");
                if (File.Exists(s)) return d.FullName;
                d = d.Parent;
            }
            return Directory.GetCurrentDirectory();
        }

        private BrowserTab? Active =>
            (Tabs.SelectedItem is TabItem ti && ti.Tag is BrowserTab bt) ? bt : null;

        // ---- startup ------------------------------------------------------------

        private async void OnLoaded(object sender, RoutedEventArgs e)
        {
            try
            {
                Status("preparing governed profile…");
                var userData = Path.Combine(_repoRoot, "runtime", "browser_profile");
                Directory.CreateDirectory(userData);

                _history = new GovernedHistory(Path.Combine(_repoRoot, "runtime", "history.v1.enc"), Path.Combine(_repoRoot, "runtime", "history.v1.ndjson"));
                _history.Load();
                _actions = new GovernedActions(Path.Combine(_repoRoot, "runtime", "actions.v1.enc"));
                _actions.Load();
                _actions.Append("session.start");
                _cookies = new GovernedActions(Path.Combine(_repoRoot, "runtime", "cookies.v1.enc"));
                _cookies.Load();
                _netHistory = new GovernedActions(Path.Combine(_repoRoot, "runtime", "network_history.v1.enc"));
                _netHistory.Load();
                _sitePolicy = new GovernedActions(Path.Combine(_repoRoot, "runtime", "site_policy.v1.enc"));
                _sitePolicy.Load();
                RebuildSitePolicyState();
                LoadBookmarks();
                LoadDownloads();
                LoadSettings();
                LoadBlocklist();
                InitFilters();
                LoadNetworkConfig();
                LoadExtensionsConfig();

                // Reachability check: if the configured exit is a dead/placeholder host, the engine
                // would fail-closed and load nothing. Probe first; if it is unreachable, flag it so
                // NetOpts() runs direct this session and the toolbar shows the warning.
                if (_netMode == "proxy" && !string.IsNullOrWhiteSpace(_netProxy))
                {
                    Status("checking VPN exit reachability…");
                    var (h, pt) = ParseHostPort(_netProxy);
                    _netProxyDown = h == null || await ProbeAsync(h, pt) < 0;
                    if (_netProxyDown) Status("VPN exit unreachable — running direct this session (see the 🌐 indicator)");
                }

                Status("initializing web engine…");
                _env = await CoreWebView2Environment.CreateAsync(null, userData, NetOpts());

                Status("verifying locked startup (identity · policy · trust · evidence)…");
                _preflightOk = await Task.Run(Preflight);

                if (!_preflightOk)
                {
                    var locked = await NewTabCoreAsync("Locked");
                    if (locked != null) locked.Web.CoreWebView2.NavigateToString(LockedHtml());
                    AddressBar.IsEnabled = GoBtn.IsEnabled = ExportBtn.IsEnabled = false;
                    BackBtn.IsEnabled = FwdBtn.IsEnabled = ReloadBtn.IsEnabled = NewTabBtn.IsEnabled = StarBtn.IsEnabled = false;
                    GovText.Text = "LOCKED";
                    GovText.Foreground = new SolidColorBrush(Color.FromRgb(0xE0, 0x6C, 0x6C));
                    Status("LOCKED: startup verification failed — see page");
                    return;
                }

                await OpenNewTabAsync();
                CheckRuntimeVersion();
                UpdateShield();
                UpdateVpn();
                StartNetworkObserver();
                if (_extEnabled && Active != null) await LoadExtensionsAsync(Active);
                Status("locked startup OK — governed profile: " + userData);
            }
            catch (Exception ex) { ShowFatal("Startup error", ex.ToString()); }
        }

        // ---- tab lifecycle ------------------------------------------------------

        private async void NewTab_Click(object sender, RoutedEventArgs e) => await OpenNewTabAsync();
        private async void NewTabCmd_Executed(object sender, ExecutedRoutedEventArgs e) => await OpenNewTabAsync();   // the "+" in the tab strip

        private async Task OpenNewTabAsync()
        {
            var tab = await NewTabCoreAsync("New tab");
            if (tab == null) return;
            Tabs.SelectedItem = tab.Item;
            ShowActiveWebView();
            LoadInternal(tab, "start");
            AddressBar.Text = "";
            AddressBar.Focus();
        }

        private async Task OpenNewPrivateTabAsync()
        {
            var tab = await NewTabCoreAsync("Private", true);
            if (tab == null) return;
            Tabs.SelectedItem = tab.Item;
            ShowActiveWebView();
            LoadInternal(tab, "start");   // renders the private start page for private tabs
            AddressBar.Text = "";
            AddressBar.Focus();
            Status(_privateVpnOn
                ? ("private tab — VPN on" + (string.IsNullOrEmpty(_privateVpnRegion) ? "" : " (" + _privateVpnRegion + ")") + ", nothing persisted")
                : (_netEndpoints.Count == 0 || (string.IsNullOrWhiteSpace(_netProxy) && _netEndpoints.Count == 0)
                    ? "private tab — nothing persisted (add a VPN endpoint in Settings to tunnel incognito)"
                    : "private tab — nothing persisted; VPN could not engage (exit unreachable — bring your exit online, e.g. run Tor for tor-local)"));
        }

        private async Task<CoreWebView2Environment> EnsurePrivateEnvAsync()
        {
            if (_privateEnv != null) return _privateEnv;
            _privateDir = Path.Combine(Path.GetTempPath(), "rb-private-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_privateDir);
            _privateEnv = await CoreWebView2Environment.CreateAsync(null, _privateDir, await PrivateEnvOptsAsync());
            return _privateEnv;
        }

        // Incognito forces the VPN on: use the active proxy, else the first configured
        // endpoint. The private env's proxy is fixed at creation, so we probe the chosen
        // exit first — a reachable exit engages the tunnel; an unreachable one would make
        // the private window fail-closed (load nothing), so we fall back to direct and mark
        // the tab so the user knows the tunnel could not engage rather than silently breaking.
        private async Task<CoreWebView2EnvironmentOptions> PrivateEnvOptsAsync()
        {
            var o = new CoreWebView2EnvironmentOptions();
            string proxy = _netProxy, region = _netExitRegion;
            if (string.IsNullOrWhiteSpace(proxy) && _netEndpoints.Count > 0)
            {
                proxy = _netEndpoints[0].Proxy;
                region = string.IsNullOrEmpty(_netEndpoints[0].Region) ? _netEndpoints[0].Name : _netEndpoints[0].Region;
            }
            if (!string.IsNullOrWhiteSpace(proxy))
            {
                var (h, pt) = ParseHostPort(proxy);
                bool reachable = h != null && await ProbeAsync(h, pt) >= 0;
                if (reachable)
                {
                    o.AdditionalBrowserArguments = "--proxy-server=\"" + proxy + "\"";
                    _privateVpnOn = true; _privateVpnRegion = region ?? "";
                    return o;
                }
            }
            _privateVpnOn = false; _privateVpnRegion = "";
            return o;
        }

        private async void MenuNewPrivate_Click(object sender, RoutedEventArgs e) => await OpenNewPrivateTabAsync();

        private async Task<BrowserTab?> NewTabCoreAsync(string title, bool priv = false, CoreWebView2Environment? envOverride = null)
        {
            var tab = new BrowserTab { Private = priv };
            var web = new WebView2 { Visibility = Visibility.Collapsed };
            tab.Web = web;
            WebHost.Children.Add(web);

            var panel = new StackPanel { Orientation = Orientation.Horizontal };
            var fav = new Image { Width = 16, Height = 16, Margin = new Thickness(0, 0, 6, 0), VerticalAlignment = VerticalAlignment.Center };
            tab.Fav = fav;
            var hdr = new TextBlock
            {
                Text = title, MaxWidth = 180, TextTrimming = TextTrimming.CharacterEllipsis,
                VerticalAlignment = VerticalAlignment.Center
            };
            var close = new Button
            {
                Content = "✕", Margin = new Thickness(10, 0, 0, 0), Padding = new Thickness(3, 0, 3, 0),
                BorderThickness = new Thickness(0), Background = Brushes.Transparent,
                Foreground = new SolidColorBrush(Color.FromRgb(0x9A, 0x9F, 0xA9)),
                ToolTip = "Close tab (Ctrl+W)", Cursor = Cursors.Hand, FontSize = 11
            };
            close.Click += (_, __) => CloseTab(tab);
            panel.Children.Add(fav);
            panel.Children.Add(hdr);
            panel.Children.Add(close);
            tab.Header = hdr;

            tab.Item = new TabItem { Header = panel, Tag = tab };
            _tabs.Add(tab);
            Tabs.Items.Add(tab.Item);

            Tabs.SelectedItem = tab.Item;
            ShowActiveWebView();
            WebHost.UpdateLayout();

            CoreWebView2Environment? envToUse = envOverride ?? _env;
            if (priv && envOverride == null)
            {
                try { envToUse = await EnsurePrivateEnvAsync(); }
                catch (Exception ex)
                {
                    _tabs.Remove(tab); Tabs.Items.Remove(tab.Item); WebHost.Children.Remove(web);
                    ShowFatal("Private mode failed", "Could not create the ephemeral private profile.\n\n" + ex);
                    return null;
                }
            }
            try { await web.EnsureCoreWebView2Async(envToUse); }
            catch (Exception ex)
            {
                _tabs.Remove(tab); Tabs.Items.Remove(tab.Item); WebHost.Children.Remove(web);
                ShowFatal("Web engine failed to initialize",
                    "The WebView2 runtime could not start.\n\nMost common cause: another Recognition window is still open " +
                    "and holding the profile (runtime\\browser_profile). Close all Recognition windows and relaunch.\n\n" + ex);
                return null;
            }

            var s = web.CoreWebView2.Settings;
            s.IsPasswordAutosaveEnabled = false;
            s.IsGeneralAutofillEnabled = false;
            s.IsStatusBarEnabled = false;
            s.AreDevToolsEnabled = true;

            // Brave-style network blocking
            web.CoreWebView2.AddWebResourceRequestedFilter("*", CoreWebView2WebResourceContext.All);
            web.CoreWebView2.WebResourceRequested += (o, ev) => OnResourceRequested(tab, ev);
            web.CoreWebView2.PermissionRequested  += (o, ev) => OnPermissionRequested(tab, ev);
            web.CoreWebView2.ServerCertificateErrorDetected += (o, ev) => OnServerCertificateError(tab, ev);
            web.CoreWebView2.ClientCertificateRequested     += (o, ev) => OnClientCertificateRequested(tab, ev);

            web.CoreWebView2.NavigationStarting   += (o, ev) => OnNavStarting(tab, ev);
            web.CoreWebView2.SourceChanged        += (o, ev) => OnSourceChanged(tab);
            web.CoreWebView2.NavigationCompleted  += (o, ev) => OnNavCompleted(tab, ev);
            web.CoreWebView2.DocumentTitleChanged += (o, ev) => { if (!tab.IsInternal) SetHeader(tab, web.CoreWebView2.DocumentTitle); };
            web.CoreWebView2.WebMessageReceived   += (o, ev) => OnWebMessage(tab, ev);
            web.CoreWebView2.DownloadStarting     += (o, ev) => OnDownloadStarting(ev);
            web.CoreWebView2.NewWindowRequested   += OnNewWindowRequested;
            web.CoreWebView2.FaviconChanged       += (o, ev) => OnFaviconChanged(tab);
            web.CoreWebView2.ContentLoading       += (o, ev) => InjectCosmetic(tab);
            HookExternalUri(web.CoreWebView2, tab);
            ApplyTrackingPrevention(web.CoreWebView2);
            try { await web.CoreWebView2.AddScriptToExecuteOnDocumentCreatedAsync(ShortcutScript); } catch { }
            await RegisterShieldAsync(tab);
            await RegisterPasskeyGuardAsync(tab);
            await ApplyAppearanceAsync(tab);

            tab.Ready = true;
            return tab;
        }

        // ---- appearance (themes, dark-mode style, page colours, fonts) -----------
        // All values are validated by AppearanceSettings (hex colours / allowlisted fonts only), so a
        // crafted web message can never inject arbitrary CSS or script into a page.
        private async Task ApplyAppearanceAsync(BrowserTab tab)
        {
            try
            {
                var core = tab.Web.CoreWebView2; if (core == null) return;
                core.Profile.PreferredColorScheme = _appearance.PreferredScheme() switch
                {
                    2 => CoreWebView2PreferredColorScheme.Dark,
                    1 => CoreWebView2PreferredColorScheme.Light,
                    _ => CoreWebView2PreferredColorScheme.Auto
                };
                if (tab.StyleScriptId != null) { core.RemoveScriptToExecuteOnDocumentCreated(tab.StyleScriptId); tab.StyleScriptId = null; }
                var js = _appearance.InjectScript();
                if (!string.IsNullOrEmpty(_appearance.PageCss())) tab.StyleScriptId = await core.AddScriptToExecuteOnDocumentCreatedAsync(js);
                if (!tab.IsInternal) await core.ExecuteScriptAsync(js);   // restyle (or clear) the page that is already open
            }
            catch { }
        }

        private async void ApplyAppearanceAll()
        {
            foreach (var t in _tabs.ToList()) if (t.Ready) await ApplyAppearanceAsync(t);
        }

        private void CloseTab(BrowserTab tab)
        {
            int idx = _tabs.IndexOf(tab);
            CleanupViewer(tab);
            _tabs.Remove(tab);
            Tabs.Items.Remove(tab.Item);
            WebHost.Children.Remove(tab.Web);
            try { tab.Web.Dispose(); } catch { }

            if (_tabs.Count == 0) { if (_preflightOk) _ = OpenNewTabAsync(); return; }
            if (Tabs.SelectedItem == null) Tabs.SelectedItem = _tabs[Math.Min(idx, _tabs.Count - 1)].Item;
            ShowActiveWebView();
        }

        private void Tabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (!ReferenceEquals(e.OriginalSource, Tabs)) return;
            ShowActiveWebView();
            var a = Active; if (a == null) return;
            SetAddress(a); UpdateStar(a); UpdateShield(); UpdateVpn();
            Status(a.IsInternal ? ("recognition:" + a.Internal)
                                : $"{a.CurrentTitle}  ({a.Visits.Count} visit(s) this tab)");
        }

        // Opera/Edge-style sleeping tabs: only the active WebView2 is resumed; the
        // rest are suspended to free memory/CPU.
        private void ShowActiveWebView()
        {
            var a = Active;
            foreach (var t in _tabs)
            {
                bool on = ReferenceEquals(t, a);
                t.Web.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
                if (!t.Ready) continue;
                try
                {
                    if (on) t.Web.CoreWebView2.Resume();
                    else _ = SuspendTab(t);
                }
                catch { }
            }
        }
        private static async Task SuspendTab(BrowserTab t)
        {
            try { await t.Web.CoreWebView2.TrySuspendAsync(); } catch { }
        }

        private void SetHeader(BrowserTab tab, string title)
        {
            if (!tab.IsInternal && !string.IsNullOrWhiteSpace(title)) tab.CurrentTitle = title;
            var label = tab.IsInternal && tab.Internal != "viewer" ? InternalTitle(tab.Internal) : tab.CurrentTitle;
            tab.Header.Text = (tab.Private ? "🕶 " : "") + label;
        }

        private static string InternalTitle(string name) => name switch
        {
            "start" => "New tab",
            "history" => "History",
            "downloads" => "Downloads",
            "bookmarks" => "Bookmarks",
            "settings" => "Settings",
            "network" => "Network",
            "setup" => "Setup snapshot",
            "passwords" => "Passwords",
            "tools" => "Tools",
            "shield" => "Shield",
            "passkeys" => "Passkeys",
            "extensions" => "Extensions",
            _ => "Recognition"
        };

        private void SetAddress(BrowserTab tab)
        {
            _suppressSuggest = true;
            AddressBar.Text = tab.IsInternal ? (tab.Internal == "start" ? "" : "recognition:" + tab.Internal) : tab.CurrentUrl;
            _suppressSuggest = false;
        }

        // ---- favicons -----------------------------------------------------------

        private async void OnFaviconChanged(BrowserTab tab)
        {
            try
            {
                if (tab.IsInternal) { tab.Fav.Source = null; return; }
                using var stream = await tab.Web.CoreWebView2.GetFaviconAsync(CoreWebView2FaviconImageFormat.Png);
                if (stream == null) { tab.Fav.Source = null; return; }
                var ms = new MemoryStream();
                await stream.CopyToAsync(ms);
                if (ms.Length == 0) { tab.Fav.Source = null; return; }
                ms.Position = 0;
                var bmp = new BitmapImage();
                bmp.BeginInit(); bmp.CacheOption = BitmapCacheOption.OnLoad; bmp.StreamSource = ms; bmp.EndInit(); bmp.Freeze();
                tab.Fav.Source = bmp;
            }
            catch { }
        }

        // ---- tracker / ad blocking (Brave-style) --------------------------------

        private void OnResourceRequested(BrowserTab tab, CoreWebView2WebResourceRequestedEventArgs e)
        {
            // Global Privacy Control + Do Not Track on every http(s) request (cheap, standards-based opt-out signal).
            if (_sendGpc) { try { var hs = e.Request.Headers; hs.SetHeader("Sec-GPC", "1"); hs.SetHeader("DNT", "1"); } catch { } }
            if (!_blockingEnabled || _env == null) return;
            try
            {
                // Per-origin exemption (§53.1/§54.1): the SITE being visited (not the
                // resource host) may be exempted from blocking by an explicit, receipted
                // site-policy decision — lets one broken site opt out without disabling
                // the global shield for every other site.
                var pageUrl = PageUrlFor(tab);
                var pageHost = TryHost(pageUrl);
                if (!string.IsNullOrEmpty(pageHost) && SitePolicyGet(pageHost, "tracker_blocking", "inherit") == "off") return;

                var rtype = FilterTypeFor(tab, e);
                var verdict = _filters.Match(e.Request.Uri, pageUrl, rtype);
                if (!verdict.Blocked) return;
                e.Response = tab.Web.CoreWebView2.Environment.CreateWebResourceResponse(null, 403, "Blocked by Recognition", "");   // the tab's own environment (private and test tabs use different ones)
                tab.Blocked++; _blockedSession++;
                if (ReferenceEquals(tab, Active)) UpdateShield();
            }
            catch { }
        }

        // ---- per-origin permission governance (§53.1/§54.1) ---------------------
        // WebView2 fires PermissionRequested for camera/mic/geolocation/notifications/
        // clipboard/etc. Recognition has NO built-in interactive prompt (that would be
        // unmanaged, untested UI on a hot event path) — instead every permission is
        // DENIED BY DEFAULT unless an operator has explicitly allowed that exact
        // (origin, kind) pair via Settings → Site Permissions. This mirrors the same
        // explicit-allowlist pattern already used for VPN exits and extensions: nothing
        // is granted on first sight, and every decision (grant or refusal) is receipted.
        private void OnPermissionRequested(BrowserTab tab, CoreWebView2PermissionRequestedEventArgs e)
        {
            try
            {
                var kind = e.PermissionKind.ToString();
                var origin = TryHost(e.Uri);
                var decision = SitePolicyGet(origin, "perm." + kind, "deny");
                if (decision == "allow")
                {
                    e.State = CoreWebView2PermissionState.Allow;
                    _actions?.Append("permission.auto_allow:" + kind, origin);
                }
                else
                {
                    e.State = CoreWebView2PermissionState.Deny;
                    _actions?.Append("permission.auto_deny:" + kind, origin);
                    Status(kind + " request denied for " + origin + " — manage in Settings → Site Permissions");
                }
            }
            catch { try { e.State = CoreWebView2PermissionState.Deny; } catch { } }
        }

        // ---- Certificate Manager v1 (§54, Certificate Manager) ------------------
        // A TLS certificate error (expired, self-signed, hostname mismatch, revoked,
        // untrusted root, ...) is REFUSED BY DEFAULT — fail-closed, same as every other
        // governed decision in this browser. Trust is pinned to the EXACT certificate
        // presented (a fingerprint of subject+issuer+validity, not just the host), so
        // approving one bad certificate for a host does not silently trust a DIFFERENT
        // certificate later substituted for that same host. Every decision — allow or
        // refuse — is receipted via the action ledger; explicit trust is recorded in the
        // same per-origin site-policy ledger used for permissions/tracker exemptions
        // (key "cert.<fingerprint>", reusing GovernedActions wholesale, zero new crypto).
        private void OnServerCertificateError(BrowserTab tab, CoreWebView2ServerCertificateErrorDetectedEventArgs e)
        {
            try
            {
                var host = TryHost(e.RequestUri);
                var fp = CertFingerprint(e.ServerCertificate);
                _certErrors[host] = (fp, e.ErrorStatus.ToString());
                var decision = SitePolicyGet(host, "cert." + fp, "deny");
                if (decision == "allow")
                {
                    // This SDK's enum has no plain "Allow"; AlwaysAllow also makes the engine
                    // remember the exception for the session, so a revoke or a swapped
                    // certificate takes full effect on next launch (documented limit).
                    e.Action = CoreWebView2ServerCertificateErrorAction.AlwaysAllow;
                    _actions?.Append("cert.auto_allow:" + e.ErrorStatus, host);
                }
                else
                {
                    e.Action = CoreWebView2ServerCertificateErrorAction.Cancel;
                    _actions?.Append("cert.auto_deny:" + e.ErrorStatus, host);
                    Status("TLS certificate error for " + host + " (" + e.ErrorStatus + ") — refused; trust it explicitly in Settings → TLS Certificate Errors if expected");
                }
            }
            catch { try { e.Action = CoreWebView2ServerCertificateErrorAction.Cancel; } catch { } }
        }

        // Fingerprint = "der:" + SHA-256 of the certificate's raw DER bytes (via the documented
        // CoreWebView2Certificate.ToX509Certificate2().RawData). This is full-certificate pinning:
        // any byte difference — including a different public key behind identical subject/issuer/
        // validity — yields a different fingerprint and is refused again. If the DER bytes cannot
        // be obtained for any reason it falls back to a SUBJECT|ISSUER|VALIDITY metadata
        // fingerprint ("meta:" prefix, so the two never collide), which is weaker but still
        // fail-closed against renewed/swapped certificates.
        private static string CertFingerprint(CoreWebView2Certificate? cert)
        {
            // NOTE: separators are '-' (not ':' or '|') because the fingerprint travels inside
            // "cert-trust:host:fp:value" web messages and "site_policy.set|key|origin|value" records.
            if (cert == null) return "meta-" + Convert.ToHexString(SHA256.HashData(Array.Empty<byte>())).ToLowerInvariant();
            try
            {
                using var x = cert.ToX509Certificate2();
                if (x != null && x.RawData != null && x.RawData.Length > 0)
                    return "der-" + Convert.ToHexString(SHA256.HashData(x.RawData)).ToLowerInvariant();
            }
            catch { }
            var s = (cert.Subject ?? "") + "|" + (cert.Issuer ?? "") + "|" + cert.ValidFrom.ToString("o") + "|" + cert.ValidTo.ToString("o");
            return "meta-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
        }

        // Mutual-TLS client certificate requests are ALWAYS refused — Recognition never
        // auto-presents a client certificate to any site. Unlike server-cert trust, this
        // has no explicit-allow escape hatch in v1: picking a client cert is a stronger,
        // identity-revealing action than viewing a page, and the safe default is simply
        // never to do it automatically. Every request is receipted either way.
        private void OnClientCertificateRequested(BrowserTab tab, CoreWebView2ClientCertificateRequestedEventArgs e)
        {
            try
            {
                e.Cancel = true;
                _actions?.Append("client_cert.auto_refuse", e.Host + ":" + e.Port);
                Status("client certificate request from " + e.Host + " refused — Recognition never auto-presents client certificates");
            }
            catch { try { e.Cancel = true; } catch { } }
        }

        // ---- per-origin site policy store (§53.1/§54.1) --------------------------
        // Reuses the ALREADY-PROVEN GovernedActions hash-chained, DPAPI-encrypted
        // ledger wholesale (zero new crypto). Each decision is one append-only record
        // whose ACTION field carries "site_policy.set|<key>|<origin>|<value>" (cleartext
        // — these are governance decisions, not secrets, same as "vpn.pick"/"extension.loaded").
        // Current state is a pure replay: latest record per (key,origin) wins.
        private const string SitePolicyPrefix = "site_policy.set|";

        private void RebuildSitePolicyState()
        {
            _sitePolicyState.Clear();
            if (_sitePolicy == null) return;
            foreach (var it in _sitePolicy.Items)
            {
                if (!it.Action.StartsWith(SitePolicyPrefix, StringComparison.Ordinal)) continue;
                var parts = it.Action.Split('|');
                if (parts.Length != 4) continue;
                _sitePolicyState[parts[1] + "|" + parts[2].ToLowerInvariant()] = parts[3];
            }
        }

        private void SitePolicySet(string origin, string key, string value)
        {
            if (string.IsNullOrWhiteSpace(origin) || string.IsNullOrWhiteSpace(key)) return;
            origin = origin.ToLowerInvariant();
            _sitePolicy.Append(SitePolicyPrefix + key + "|" + origin + "|" + value);
            _sitePolicyState[key + "|" + origin] = value;
        }

        private string SitePolicyGet(string origin, string key, string def)
        {
            if (string.IsNullOrWhiteSpace(origin)) return def;
            origin = origin.ToLowerInvariant();
            return _sitePolicyState.TryGetValue(key + "|" + origin, out var v) ? v : def;
        }

        private bool IsBlockedHost(string host)
        {
            host = (host ?? "").ToLowerInvariant();
            if (host.Length == 0) return false;
            if (_blockHosts.Contains(host)) return true;
            int dot = host.IndexOf('.');
            while (dot >= 0)
            {
                var parent = host.Substring(dot + 1);
                if (_blockHosts.Contains(parent)) return true;
                dot = host.IndexOf('.', dot + 1);
            }
            return false;
        }

        private void LoadBlocklist()
        {
            _blockHosts.Clear();
            foreach (var h in DefaultBlocklist) _blockHosts.Add(h);
            // Optional governed override/extension: config\blocklist.v1.txt (one host per line, # comments)
            var path = Path.Combine(_repoRoot, "config", "blocklist.v1.txt");
            try
            {
                if (File.Exists(path))
                    foreach (var raw in File.ReadAllLines(path))
                    {
                        var line = raw.Trim();
                        if (line.Length == 0 || line.StartsWith("#")) continue;
                        _blockHosts.Add(line.ToLowerInvariant());
                    }
            }
            catch { }
        }

        private static readonly string[] DefaultBlocklist = new[]
        {
            // analytics / tag managers
            "google-analytics.com","googletagmanager.com","google-analytics.l.google.com",
            "analytics.google.com","stats.g.doubleclick.net","ssl.google-analytics.com",
            // ad networks
            "doubleclick.net","googlesyndication.com","googleadservices.com","adservice.google.com",
            "pagead2.googlesyndication.com","adnxs.com","adsrvr.org","rubiconproject.com",
            "pubmatic.com","openx.net","criteo.com","criteo.net","taboola.com","outbrain.com",
            "moatads.com","doubleverify.com","adform.net","smartadserver.com","teads.tv",
            "amazon-adsystem.com","bidswitch.net","casalemedia.com","33across.com","sharethrough.com",
            // social trackers
            "connect.facebook.net","facebook.com/tr","pixel.facebook.com","ads.linkedin.com",
            "analytics.twitter.com","ads-twitter.com","t.co","bat.bing.com",
            // product analytics / session replay
            "hotjar.com","mixpanel.com","segment.com","segment.io","amplitude.com",
            "fullstory.com","mouseflow.com","clarity.ms","quantserve.com","scorecardresearch.com",
            "chartbeat.com","newrelic.com","nr-data.net","branch.io","appsflyer.com",
            "crazyegg.com","optimizely.com","yandex.ru/metrika","mc.yandex.ru"
        };

        private void UpdateShield()
        {
            var a = Active;
            int n = a?.Blocked ?? 0;
            ShieldBtn.Content = _blockingEnabled ? ("🛡 " + n) : "🛡✕";
            ShieldBtn.Foreground = new SolidColorBrush(_blockingEnabled ? Color.FromRgb(0x6F, 0xCF, 0x97) : Color.FromRgb(0x8B, 0x90, 0x9A));
            ShieldBtn.ToolTip = _blockingEnabled
                ? $"{n} trackers/ads blocked on this page ({_blockedSession} this session) — click for settings"
                : "Tracker/ad blocking is OFF — click for settings";
        }
        private void Shield_Click(object sender, RoutedEventArgs e) => OpenInternalInActiveTab("settings");

        // ---- VPN toolbar indicator ---------------------------------------------
        private void UpdateVpn()
        {
            // Three states: ON (green, tunnel live), WARNING (amber, configured exit unreachable →
            // running direct), OFF (grey, direct by choice).
            bool warn = _netMode == "proxy" && !string.IsNullOrWhiteSpace(_netProxy) && _netProxyDown;
            bool on = NetActive();
            var region = string.IsNullOrEmpty(_netExitRegion) ? "on" : _netExitRegion;
            if (warn)
            {
                VpnBtn.Content = "\U0001F310 !";
                VpnBtn.Foreground = new SolidColorBrush(Color.FromRgb(0xE0, 0xB4, 0x4C)); // amber
                VpnBtn.ToolTip = "VPN exit unreachable (" + (_netExitRegion ?? "") + ") — running DIRECT this session. "
                               + "Fix the exit host in Network settings, or pick another exit, then Apply (restart).";
            }
            else
            {
                VpnBtn.Content = on ? ("\U0001F310 " + region) : "\U0001F310";
                VpnBtn.Foreground = new SolidColorBrush(on ? Color.FromRgb(0x6F, 0xCF, 0x97) : Color.FromRgb(0x8B, 0x90, 0x9A));
                VpnBtn.ToolTip = on
                    ? ("VPN ON — " + _netMode + (string.IsNullOrEmpty(_netExitRegion) ? "" : " · " + _netExitRegion) + "  (click for settings)")
                    : "VPN OFF — click to configure";
            }
        }
        private void Vpn_Click(object sender, RoutedEventArgs e)
        {
            var cm = new ContextMenu();
            var off = new MenuItem { Header = "Off (direct connection)", IsChecked = !NetActive() };
            off.Click += (_, __) => SetVpnOff();
            cm.Items.Add(off);
            if (_netEndpoints.Count > 0)
            {
                cm.Items.Add(new Separator());
                foreach (var ep in _netEndpoints)
                {
                    var label = string.IsNullOrEmpty(ep.Region) ? ep.Name : ep.Region;
                    var mi = new MenuItem { Header = label, IsChecked = (_netMode == "proxy" && _netProxy == ep.Proxy) };
                    var epc = ep;
                    mi.Click += (_, __) => { _ = SetVpnEndpoint(epc); };
                    cm.Items.Add(mi);
                }
                cm.Items.Add(new Separator());
                var opt = new MenuItem { Header = "Auto-optimize (best placement)" };
                opt.Click += (_, __) => { var a = Active; if (a != null) _ = OptimizeVpnAsync(a); };
                cm.Items.Add(opt);
            }
            cm.Items.Add(new Separator());
            var netPanel = new MenuItem { Header = "Network panel (connection, ping, speed, saved networks)…" };
            netPanel.Click += (_, __) => OpenInternalInActiveTab("network");
            cm.Items.Add(netPanel);
            var apply = new MenuItem { Header = "Apply changes now (restart)" };
            apply.Click += (_, __) => RestartToApply();
            cm.Items.Add(apply);
            var settings = new MenuItem { Header = "Network settings…" };
            settings.Click += (_, __) => OpenInternalInActiveTab("settings");
            cm.Items.Add(settings);
            cm.PlacementTarget = VpnBtn;
            cm.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
            cm.IsOpen = true;
        }

        private void SetVpnOff()
        {
            _netMode = "off"; _netProxy = ""; _netExitRegion = ""; SaveNetworkConfig(); UpdateVpn();
            _actions?.Append("vpn.off");
            var a = Active; if (a != null && a.Internal == "settings") LoadInternal(a, "settings");
            Status("VPN off — direct connection (applies to new sessions on next launch)");
        }
        private async Task SetVpnEndpoint(NetEndpoint ep)
        {
            var label = string.IsNullOrEmpty(ep.Region) ? ep.Name : ep.Region;
            var (h, pt) = ParseHostPort(ep.Proxy);
            if (h == null) { Status("VPN exit '" + label + "' has an invalid proxy address — not applied"); return; }
            Status("checking " + label + " reachability…");
            var ms = await ProbeAsync(h, pt);
            if (ms < 0)
            {
                Status("VPN exit '" + label + "' is unreachable (" + ep.Proxy + ") — not applied. "
                     + "Bring its exit online (your proxy/WireGuard, or Tor for tor-local) or fix the host in Network settings.");
                return;
            }
            _netMode = "proxy"; _netProxy = ep.Proxy; _netExitRegion = label; _netProxyDown = false;
            SaveNetworkConfig(); UpdateVpn();
            _actions?.Append("vpn.pick", ep.Proxy);
            var a = Active; if (a != null && a.Internal == "settings") LoadInternal(a, "settings");
            Status("VPN exit set to " + label + " (" + Math.Round(ms) + " ms) — click Apply (restart) to route traffic through it now");
        }

        // Live-apply a routing change: WebView2 fixes the engine proxy at startup, so we
        // relaunch cleanly — a helper waits for THIS process to exit (releasing the
        // profile), then starts a fresh instance which reads the new config.
        private void RestartToApply()
        {
            try
            {
                var exe = Environment.ProcessPath;
                if (string.IsNullOrEmpty(exe)) { Status("cannot locate the executable to restart"); return; }
                // cmd.exe is always present (the previous version needed PowerShell 7 on the machine). It waits for this
                // process to release the profile, then starts a fresh instance that reads the new configuration.
                var args = "/c ping -n 4 127.0.0.1 >nul & start \"\" \"" + exe + "\"";
                Process.Start(new ProcessStartInfo("cmd.exe", args) { UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden });
                Application.Current.Shutdown();
            }
            catch (Exception ex) { Status("restart failed: " + ex.Message); }
        }

        // ---- settings persistence ----------------------------------------------

        private string SettingsPath() => Path.Combine(_repoRoot, "runtime", "browser_settings.json");
        private void LoadSettings()
        {
            try
            {
                var p = SettingsPath();
                if (!File.Exists(p)) return;
                using var doc = JsonDocument.Parse(File.ReadAllText(p));
                var r = doc.RootElement;
                if (r.TryGetProperty("blocking_enabled", out var b)) _blockingEnabled = b.GetBoolean();
                if (r.TryGetProperty("strip_tracking", out var st) && (st.ValueKind == JsonValueKind.True || st.ValueKind == JsonValueKind.False)) _stripTracking = st.GetBoolean();
                if (r.TryGetProperty("send_gpc", out var gp) && (gp.ValueKind == JsonValueKind.True || gp.ValueKind == JsonValueKind.False)) _sendGpc = gp.GetBoolean();
                if (r.TryGetProperty("shield_level", out var sl) && sl.ValueKind == JsonValueKind.String && sl.GetString() is "off" or "standard" or "strict") _shieldLevel = sl.GetString()!;
                if (r.TryGetProperty("passkeys_level", out var pl) && pl.ValueKind == JsonValueKind.String && pl.GetString() is "on" or "off") _passkeyLevel = pl.GetString()!;
                if (r.TryGetProperty("tracking_level", out var tl) && tl.ValueKind == JsonValueKind.String && tl.GetString() is "off" or "basic" or "balanced" or "strict") _trackingLevel = tl.GetString()!;
                if (r.TryGetProperty("home_url", out var hu)) { var s = hu.GetString(); if (!string.IsNullOrWhiteSpace(s)) _homeUrl = s; }
                if (r.TryGetProperty("appearance", out var ap) && ap.ValueKind == JsonValueKind.Object) _appearance.FromJson(ap);
            }
            catch { }
        }
        private void SaveSettings()
        {
            try
            {
                var p = SettingsPath();
                Directory.CreateDirectory(Path.GetDirectoryName(p)!);
                File.WriteAllText(p, "{" + J("blocking_enabled") + ":" + (_blockingEnabled ? "true" : "false") + "," +
                                          J("strip_tracking") + ":" + (_stripTracking ? "true" : "false") + "," + J("send_gpc") + ":" + (_sendGpc ? "true" : "false") + "," + J("shield_level") + ":" + J(_shieldLevel) + "," + J("passkeys_level") + ":" + J(_passkeyLevel) + "," + J("tracking_level") + ":" + J(_trackingLevel) + "," +
                                          J("home_url") + ":" + J(_homeUrl) + "," + J("appearance") + ":" + _appearance.ToJson() + "}\n", new UTF8Encoding(false));
            }
            catch { }
        }

        // ---- governed network / VPN (config/network.v1.json) --------------------
        private void LoadNetworkConfig()
        {
            try
            {
                var p = Path.Combine(_repoRoot, "config", "network.v1.json");
                if (!File.Exists(p)) return;
                using var doc = JsonDocument.Parse(File.ReadAllText(p));
                var r = doc.RootElement;
                _netMode        = Get(r, "mode"); if (string.IsNullOrEmpty(_netMode)) _netMode = "off";
                _netProxy       = Get(r, "proxy");
                _netExitRegion  = Get(r, "exit_region");
                _netExitCheckUrl = Get(r, "exit_check_url");
                _netAutoOptimize = r.TryGetProperty("auto_optimize", out var ao) && ao.ValueKind == JsonValueKind.True;
                _netEndpoints.Clear();
                if (r.TryGetProperty("endpoints", out var eps) && eps.ValueKind == JsonValueKind.Array)
                    foreach (var ep in eps.EnumerateArray())
                        _netEndpoints.Add(new NetEndpoint { Name = Get(ep, "name"), Region = Get(ep, "region"), Proxy = Get(ep, "proxy") });
            }
            catch { }
        }

        private void SaveNetworkConfig()
        {
            try
            {
                var sb = new StringBuilder("{" + J("schema") + ":" + J("recognition.network.v1") + "," +
                    J("mode") + ":" + J(_netMode) + "," + J("proxy") + ":" + J(_netProxy) + "," +
                    J("exit_region") + ":" + J(_netExitRegion) + "," + J("exit_check_url") + ":" + J(_netExitCheckUrl) + "," +
                    J("auto_optimize") + ":" + (_netAutoOptimize ? "true" : "false") + "," + J("endpoints") + ":[");
                for (int i = 0; i < _netEndpoints.Count; i++)
                {
                    var ep = _netEndpoints[i]; if (i > 0) sb.Append(",");
                    sb.Append("{" + J("name") + ":" + J(ep.Name) + "," + J("region") + ":" + J(ep.Region) + "," + J("proxy") + ":" + J(ep.Proxy) + "}");
                }
                sb.Append("]}");
                var p = Path.Combine(_repoRoot, "config", "network.v1.json");
                Directory.CreateDirectory(Path.GetDirectoryName(p)!);
                File.WriteAllText(p, sb.ToString() + "\n", new UTF8Encoding(false));
            }
            catch { }
        }

        // Browser engine options — routes the browser through the configured proxy (proxy mode)
        // and enables governed Chromium extensions when configured.
        private CoreWebView2EnvironmentOptions NetOpts()
        {
            var o = new CoreWebView2EnvironmentOptions();
            o.AreBrowserExtensionsEnabled = _extEnabled;
            // Only route through the proxy if it is reachable this session. A dead/placeholder
            // exit would make the engine fail-closed (no page loads at all), so we fall back to
            // a direct connection and surface a warning in the toolbar instead of breaking.
            if (_netMode == "proxy" && !string.IsNullOrWhiteSpace(_netProxy) && !_netProxyDown)
                o.AdditionalBrowserArguments = "--proxy-server=\"" + _netProxy + "\"";
            return o;
        }
        // VPN is genuinely carrying traffic only when configured proxy mode AND the exit is reachable.
        private bool NetActive() => _netMode != "off" && _netMode == "proxy" && !string.IsNullOrWhiteSpace(_netProxy) && !_netProxyDown;

        // ---- governed Chromium extensions (config/extensions.v1.json allowlist) --
        private void LoadExtensionsConfig()
        {
            _extEnabled = false; _extConfigEnabled = false; _extLoaded = false; _extPaths.Clear();
            try
            {
                var p = Path.Combine(_repoRoot, "config", "extensions.v1.json");
                if (File.Exists(p))
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(p));
                    var r = doc.RootElement;
                    _extConfigEnabled = r.TryGetProperty("enabled", out var en) && en.ValueKind == JsonValueKind.True;
                    if (r.TryGetProperty("load", out var l) && l.ValueKind == JsonValueKind.Array)
                        foreach (var it in l.EnumerateArray()) { var s = it.GetString(); if (!string.IsNullOrWhiteSpace(s)) _extPaths.Add(s); }
                }
            }
            catch { }
            LoadExtState();
            _extEnabled = _extConfigEnabled || _extState.Enabled;   // the Extensions page switch (runtime) or the operator's config
            _extEnabledAtStart = _extEnabled;
        }

        // Universal extension adapter: config/extensions.v1.json entries may name an unpacked folder, a .zip or a .crx, and the
        // Extensions page installs into runtime\extensions\<id>. Both go through the same load gate in MainWindow.Extensions.cs
        // (identity recomputed from the bytes on disk, latest governance-ledger record must say "allow"). Nothing is auto-trusted.

        // Normalizes an extension source into an unpacked folder. A raw directory is
        // used as-is; a .zip or .crx is extracted once into a content-addressed cache
        // under runtime\extensions_cache\<sha256-of-source-file>\ (re-extraction is
        // skipped if that cache folder already exists — deterministic and idempotent).
        // Returns null for a missing/unsupported source (never throws for that case).
        private string? PrepareExtensionSource(string source)
        {
            if (Directory.Exists(source)) return source;
            if (!File.Exists(source)) return null;

            var ext = Path.GetExtension(source).ToLowerInvariant();
            if (ext != ".zip" && ext != ".crx") return null;

            var fi = new FileInfo(source);
            if (fi.Length > ExtPackage.MaxPackageBytes) throw new InvalidDataException("package is larger than " + ExtPackage.MaxPackageBytes / 1024 / 1024 + " MB");
            var bytes = File.ReadAllBytes(source);
            var sourceHash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            var cacheDir = Path.Combine(_repoRoot, "runtime", "extensions_cache", sourceHash);
            if (Directory.Exists(cacheDir) && Directory.EnumerateFileSystemEntries(cacheDir).Any()) return ExtPackage.ResolveRoot(cacheDir);
            try { return ExtPackage.Unpack(bytes, cacheDir); }   // safe unpack: path checks, size limits, CRX2/CRX3 and wrapped-folder handling
            catch { try { Directory.Delete(cacheDir, true); } catch { } throw; }
        }

        // ---- governed updater UI (§54) -------------------------------------------
        // All security logic lives in the already-selftested recognition_update_v1.ps1 (signature vs
        // the pinned trust root, per-file hashes, no unlisted/unsafe paths, strictly-newer version,
        // backup + auto-rollback). The browser only picks a package folder, shells out, and shows the
        // verdict. APPLY always runs the full verification first (inside the script) and additionally
        // requires an explicit user confirmation here; nothing is ever downloaded or applied silently.
        private string InstalledVersion()
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(_repoRoot, "config", "version.v1.json")));
                return doc.RootElement.TryGetProperty("version", out var v) ? (v.GetString() ?? "unknown") : "unknown";
            }
            catch { return "unknown"; }
        }

        private (bool ok, string text) RunUpdater(string action, string pkgDir)
        {
            try
            {
                var script = Path.Combine(_repoRoot, "scripts", "recognition_update_v1.ps1");
                if (!File.Exists(script)) return (false, "updater script not found");
                var psi = new ProcessStartInfo("pwsh.exe",
                    $"-NoProfile -ExecutionPolicy Bypass -File \"{script}\" -RepoRoot \"{_repoRoot}\" -Action {action} -PackageDir \"{pkgDir}\"")
                { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
                var p = Process.Start(psi);
                if (p == null) return (false, "could not start pwsh");
                var outp = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                p.WaitForExit();
                var token = action == "apply" ? "RECOGNITION_UPDATE_V1_APPLY_OK" : "RECOGNITION_UPDATE_V1_VERIFY_OK";
                if (outp.Contains(token))
                    return (true, (outp.Split('\n').FirstOrDefault(l => l.StartsWith("Update ") || l.StartsWith("Applied update")) ?? "ok").Trim());
                var why = outp.Split('\n').FirstOrDefault(l => l.StartsWith("REFUSED"))?.Trim();
                return (false, string.IsNullOrEmpty(why) ? "refused (see script output)" : why);
            }
            catch (Exception ex) { return (false, "updater error: " + ex.Message); }
        }

        private async void UpdateFlow(BrowserTab tab, bool apply)
        {
            try
            {
                var dlg = new Microsoft.Win32.OpenFolderDialog { Title = apply ? "Choose the update package folder to APPLY" : "Choose the update package folder to verify" };
                if (dlg.ShowDialog(this) != true || string.IsNullOrWhiteSpace(dlg.FolderName)) return;
                var dir = dlg.FolderName;
                Status("verifying update package…");
                var v = await Task.Run(() => RunUpdater("verify", dir));
                if (!v.ok)
                {
                    _actions?.Append("update.refused", dir);
                    Status("update refused: " + v.text);
                    MessageBox.Show(this, "This update package was REFUSED and nothing was changed.\n\n" + v.text, "Recognition — Update", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                if (!apply)
                {
                    _actions?.Append("update.verified", dir);
                    Status("update package verified: " + v.text);
                    MessageBox.Show(this, "Package is authentic, intact, and newer than the installed version.\n\n" + v.text + "\n\nNothing was changed. Use \"Apply update\" to install it.", "Recognition — Update", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }
                var ok = MessageBox.Show(this, "Verified: " + v.text + "\n\nApply this update now? Replaced files are backed up and the install is rolled back automatically if anything fails. Restart Recognition afterwards.",
                    "Recognition — Apply update", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (ok != MessageBoxResult.Yes) { Status("update not applied (cancelled)"); return; }
                Status("applying update…");
                var a = await Task.Run(() => RunUpdater("apply", dir));
                _actions?.Append(a.ok ? "update.applied" : "update.refused", dir);
                Status(a.ok ? "update applied — restart Recognition to use it" : "update NOT applied: " + a.text);
                MessageBox.Show(this, a.ok ? a.text + "\n\nRestart Recognition to use the new version." : "Update was NOT applied (any partial change was rolled back).\n\n" + a.text,
                    "Recognition — Update", MessageBoxButton.OK, a.ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
            }
            catch (Exception ex) { Status("update error: " + ex.Message); }
            finally { if (tab.Internal == "settings") LoadInternal(tab, "settings"); }
        }

        // ---- keyboard shortcuts -------------------------------------------------

        private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            bool ctrl = (Keyboard.Modifiers & ModifierKeys.Control) != 0;
            bool alt  = (Keyboard.Modifiers & ModifierKeys.Alt) != 0;
            string? m = null;
            if (ctrl && (Keyboard.Modifiers & ModifierKeys.Shift) != 0 && e.Key == Key.N) m = "newprivate";
            else if (ctrl && e.Key == Key.T) m = "newtab";
            else if (ctrl && e.Key == Key.W) m = "closetab";
            else if (ctrl && e.Key == Key.L) m = "focusaddr";
            else if ((ctrl && e.Key == Key.R) || e.Key == Key.F5) m = "reload";
            else if (ctrl && e.Key == Key.F) m = "find";
            else if (ctrl && e.Key == Key.D) m = "bookmark";
            else if (ctrl && (e.Key == Key.OemPlus || e.Key == Key.Add)) m = "zoomin";
            else if (ctrl && (e.Key == Key.OemMinus || e.Key == Key.Subtract)) m = "zoomout";
            else if (ctrl && (e.Key == Key.D0 || e.Key == Key.NumPad0)) m = "zoomreset";
            else if (ctrl && e.Key == Key.Tab) m = (Keyboard.Modifiers & ModifierKeys.Shift) != 0 ? "prevtab" : "nexttab";
            else if (alt && e.Key == Key.Left) m = "back";
            else if (alt && e.Key == Key.Right) m = "forward";
            else if (alt && e.Key == Key.Home) m = "home";
            if (m != null) { e.Handled = true; HandleShortcut(m); }
        }

        private async void HandleShortcut(string m)
        {
            var a = Active;
            switch (m)
            {
                case "newtab": await OpenNewTabAsync(); break;
                case "newprivate": await OpenNewPrivateTabAsync(); break;
                case "closetab": if (a != null) CloseTab(a); break;
                case "focusaddr": AddressBar.Focus(); AddressBar.SelectAll(); break;
                case "reload": Reload_Click(this, new RoutedEventArgs()); break;
                case "find": OpenFind(); break;
                case "bookmark": ToggleBookmark(); break;
                case "zoomin": Zoom(+0.1); break;
                case "zoomout": Zoom(-0.1); break;
                case "zoomreset": Zoom(0); break;
                case "nexttab": CycleTab(+1); break;
                case "prevtab": CycleTab(-1); break;
                case "back": Back_Click(this, new RoutedEventArgs()); break;
                case "forward": Forward_Click(this, new RoutedEventArgs()); break;
                case "home": Home_Click(this, new RoutedEventArgs()); break;
            }
        }

        // ---- home ---------------------------------------------------------------
        private void Home_Click(object sender, RoutedEventArgs e) { var a = Active; if (a != null) NavigateTab(a, _homeUrl); }
        private void MenuHome_Click(object sender, RoutedEventArgs e) => Home_Click(sender, e);
        private void MenuSetHome_Click(object sender, RoutedEventArgs e)
        {
            var a = Active;
            if (a != null && !a.IsInternal && !string.IsNullOrEmpty(a.CurrentUrl)) { _homeUrl = a.CurrentUrl; Status("home set to " + _homeUrl); }
            else { _homeUrl = "recognition:start"; Status("home set to the start page"); }
            SaveSettings();
        }

        private void CycleTab(int dir)
        {
            if (_tabs.Count < 2) return;
            var a = Active; int i = a == null ? 0 : _tabs.IndexOf(a);
            i = (i + dir + _tabs.Count) % _tabs.Count;
            Tabs.SelectedItem = _tabs[i].Item; ShowActiveWebView();
        }

        private void Zoom(double delta)
        {
            var a = Active; if (a == null || !a.Ready) return;
            try
            {
                a.Web.ZoomFactor = delta == 0 ? 1.0 : Math.Clamp(a.Web.ZoomFactor + delta, 0.3, 3.0);
                Status($"zoom {Math.Round(a.Web.ZoomFactor * 100)}%");
            }
            catch { }
        }

        // ---- find in page -------------------------------------------------------

        private void OpenFind() { FindBar.Visibility = Visibility.Visible; FindBox.Focus(); FindBox.SelectAll(); }
        private void MenuFind_Click(object sender, RoutedEventArgs e) => OpenFind();
        private void FindClose_Click(object sender, RoutedEventArgs e) { FindBar.Visibility = Visibility.Collapsed; ClearFind(); }
        private void FindNext_Click(object sender, RoutedEventArgs e) => DoFind(false);
        private void FindPrev_Click(object sender, RoutedEventArgs e) => DoFind(true);
        private void FindBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) { DoFind((Keyboard.Modifiers & ModifierKeys.Shift) != 0); e.Handled = true; }
            else if (e.Key == Key.Escape) { FindClose_Click(sender, e); e.Handled = true; }
        }
        private async void DoFind(bool backwards)
        {
            var a = Active; if (a == null || !a.Ready || a.IsInternal) return;
            var term = FindBox.Text ?? "";
            if (term.Length == 0) { ClearFind(); return; }
            var js = "window.find(" + JsStr(term) + ",false," + (backwards ? "true" : "false") + ",true,false,true,false)";
            try { await a.Web.CoreWebView2.ExecuteScriptAsync(js); } catch { }
        }
        private async void ClearFind()
        {
            var a = Active; if (a == null || !a.Ready) return;
            try { await a.Web.CoreWebView2.ExecuteScriptAsync("window.getSelection && window.getSelection().removeAllRanges()"); } catch { }
        }
        private static string JsStr(string s) => "\"" + (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

        // ---- bookmarks ----------------------------------------------------------

        private sealed class Bookmark { public string Url = ""; public string Title = ""; public string Ts = ""; }

        private void LoadBookmarks()
        {
            _bookmarks.Clear();
            var legacy = Path.Combine(_repoRoot, "runtime", "bookmarks.v1.ndjson");
            var text = ReadSecure(BookmarksPath());
            bool migrated = false;
            if (text.Length == 0 && File.Exists(legacy)) { text = File.ReadAllText(legacy); migrated = true; }
            foreach (var line in text.Split('\n'))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try { using var d = JsonDocument.Parse(line); var r = d.RootElement;
                      _bookmarks.Add(new Bookmark { Url = Get(r, "url"), Title = Get(r, "title"), Ts = Get(r, "ts_utc") }); }
                catch { }
            }
            if (migrated) { SaveBookmarks(); try { File.Delete(legacy); } catch { } }   // encrypt-in-place, drop plaintext
        }
        private string BookmarksPath() => Path.Combine(_repoRoot, "runtime", "bookmarks.v1.enc");
        private void SaveBookmarks()
        {
            var sb = new StringBuilder();
            foreach (var b in _bookmarks)
                sb.Append("{" + J("schema") + ":" + J("recognition.bookmark.v1") + "," + J("ts_utc") + ":" + J(b.Ts) + "," +
                          J("url") + ":" + J(b.Url) + "," + J("title") + ":" + J(b.Title) + "}\n");
            WriteSecure(BookmarksPath(), sb.ToString());
        }
        private bool IsBookmarked(string url) => _bookmarks.Any(b => b.Url == url);
        private void Star_Click(object sender, RoutedEventArgs e) => ToggleBookmark();
        private void ToggleBookmark()
        {
            var a = Active; if (a == null || a.IsInternal || string.IsNullOrEmpty(a.CurrentUrl)) return;
            if (IsBookmarked(a.CurrentUrl)) { _bookmarks.RemoveAll(b => b.Url == a.CurrentUrl); _actions?.Append("bookmark.remove", a.CurrentUrl); Status("bookmark removed"); }
            else { _bookmarks.Add(new Bookmark { Url = a.CurrentUrl, Title = a.CurrentTitle, Ts = Iso(DateTime.UtcNow) }); _actions?.Append("bookmark.add", a.CurrentUrl); Status("bookmarked"); }
            SaveBookmarks(); UpdateStar(a);
            if (a.Internal == "bookmarks") LoadInternal(a, "bookmarks");
        }
        private void UpdateStar(BrowserTab tab)
        {
            bool on = !tab.IsInternal && IsBookmarked(tab.CurrentUrl);
            StarBtn.Content = on ? "★" : "☆";
            StarBtn.Foreground = new SolidColorBrush(on ? Color.FromRgb(0xF2, 0xC1, 0x4E) : Color.FromRgb(0xC7, 0xCC, 0xD4));
            StarBtn.IsEnabled = !tab.IsInternal && !tab.Private;
        }

        // ---- locked startup preflight (worker thread) ---------------------------

        private string _preflightOut = "";

        private bool Preflight()
        {
            try
            {
                var script = Path.Combine(_repoRoot, "scripts", "recognition_locked_startup_browser_v1.ps1");
                if (!File.Exists(script)) { _preflightOut = "locked startup script not found: " + script; return false; }
                var bin = BinaryPathForVerify();
                var psi = new ProcessStartInfo("pwsh.exe",
                    $"-NoProfile -ExecutionPolicy Bypass -File \"{script}\" -RepoRoot \"{_repoRoot}\" -BinaryPath \"{bin}\" -EnforceSoftwareId")
                { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
                var p = Process.Start(psi);
                if (p == null) { _preflightOut = "could not start pwsh for preflight"; return false; }
                _preflightOut = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                p.WaitForExit();
                return _preflightOut.Contains("RECOGNITION_LOCKED_STARTUP_OK");
            }
            catch (Exception ex) { _preflightOut = "preflight error: " + ex.Message; return false; }
        }

        // The binary whose bytes define the SoftwareID: the managed assembly for a normal
        // build, the single-file exe for a self-contained publish.
        private static string BinaryPathForVerify()
        {
#pragma warning disable IL3000   // Location is empty in a single-file publish; that case falls through to Environment.ProcessPath below
            try { var loc = System.Reflection.Assembly.GetEntryAssembly()?.Location; if (!string.IsNullOrEmpty(loc) && File.Exists(loc)) return loc; } catch { }
#pragma warning restore IL3000
            try { var pp = Environment.ProcessPath; if (!string.IsNullOrEmpty(pp)) return pp; } catch { }
            return "";
        }

        private (string state, string id) SoftwareIdState()
        {
            try
            {
                var bin = BinaryPathForVerify();
                if (string.IsNullOrEmpty(bin) || !File.Exists(bin)) return ("unknown", "");
                string id;
                using (var sha = SHA256.Create()) id = Convert.ToHexString(sha.ComputeHash(File.ReadAllBytes(bin))).ToLowerInvariant();
                var rec = Path.Combine(_repoRoot, "proofs", "software", "software_id.json");
                if (!File.Exists(rec)) return ("unattested build", id);
                using var doc = JsonDocument.Parse(File.ReadAllText(rec));
                var recorded = doc.RootElement.TryGetProperty("software_id", out var v) ? (v.GetString() ?? "") : "";
                return (string.Equals(recorded, id, StringComparison.OrdinalIgnoreCase) ? "verified authentic" : "MISMATCH — binary modified", id);
            }
            catch { return ("unknown", ""); }
        }

        private string LockedHtml() =>
            "<html><body style='font-family:Segoe UI,Arial;background:#1e1f22;color:#e8e8e8;padding:48px'>"
          + "<h1>&#128274; Recognition — Locked</h1>"
          + "<p>Startup verification failed. Per the runtime laws (&sect;5, &sect;20), the browser will not open until identity, policy, the trust root, and the evidence chain verify.</p>"
          + "<pre style='background:#111;padding:16px;border-radius:8px;white-space:pre-wrap'>"
          + System.Net.WebUtility.HtmlEncode(_preflightOut) + "</pre></body></html>";

        private void ShowFatal(string title, string detail)
        {
            Status(title);
            var html = "<html><body style='font-family:Segoe UI,Arial;background:#1e1f22;color:#e8e8e8;padding:48px'>"
                     + "<h1>&#9888; " + System.Net.WebUtility.HtmlEncode(title) + "</h1>"
                     + "<pre style='background:#111;padding:16px;border-radius:8px;white-space:pre-wrap'>"
                     + System.Net.WebUtility.HtmlEncode(detail) + "</pre></body></html>";
            try { var a = Active; if (a?.Web.CoreWebView2 != null) { a.Web.CoreWebView2.NavigateToString(html); return; } } catch { }
            MessageBox.Show(this, detail, title, MessageBoxButton.OK, MessageBoxImage.Error);
        }

        // ---- internal pages -----------------------------------------------------

        private void LoadInternal(BrowserTab tab, string name)
        {
            tab.Internal = name;
            tab.CurrentUrl = "recognition:" + name;
            tab.Fav.Source = null;
            SetHeader(tab, "");
            if (ReferenceEquals(tab, Active)) { SetAddress(tab); UpdateStar(tab); }
            string html = name switch
            {
                "history"   => HistoryHtml(),
                "downloads" => DownloadsHtml(),
                "bookmarks" => BookmarksHtml(),
                "settings"  => SettingsHtml(),
                "network"   => NetworkHtml(),
                "setup"     => SetupHtml(),
                "passwords" => PasswordsHtml(),
                "tools"     => ToolsHtml(),
                "shield"    => ShieldHtml(),
                "passkeys"  => PasskeysHtml(),
                "extensions" => ExtensionsHtml(),
                "viewer"    => ViewerReloadHtml(tab),
                _         => (tab.Private ? PrivateStartPageHtml() : StartPageHtml())
            };
            try { tab.Web.CoreWebView2.NavigateToString(html); } catch (Exception ex) { Status("page error: " + ex.Message); }
        }

        private void OpenInternalInActiveTab(string name)
        {
            var a = Active; if (a == null) { _ = OpenNewTabAsync(); return; }
            LoadInternal(a, name);
        }

        private void Menu_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button b && b.ContextMenu is ContextMenu cm)
            {
                cm.PlacementTarget = b;
                cm.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
                cm.MinWidth = 240;
                cm.HorizontalOffset = b.ActualWidth - 240;
                cm.VerticalOffset = 4;
                cm.IsOpen = true;
            }
        }
        private async void MenuNewTab_Click(object sender, RoutedEventArgs e) => await OpenNewTabAsync();
        private void MenuHistory_Click(object sender, RoutedEventArgs e) => OpenInternalInActiveTab("history");
        private void MenuDownloads_Click(object sender, RoutedEventArgs e) => OpenInternalInActiveTab("downloads");
        private void MenuBookmarks_Click(object sender, RoutedEventArgs e) => OpenInternalInActiveTab("bookmarks");
        private void MenuSettings_Click(object sender, RoutedEventArgs e) => OpenInternalInActiveTab("settings");
        private void MenuZoomIn_Click(object sender, RoutedEventArgs e) => Zoom(+0.1);
        private void MenuZoomOut_Click(object sender, RoutedEventArgs e) => Zoom(-0.1);
        private void MenuZoomReset_Click(object sender, RoutedEventArgs e) => Zoom(0);

        // ---- page HTML ----------------------------------------------------------

        // The base stylesheet is dark; the user's appearance preferences (light theme, font) are
        // layered on top. The rec-internal meta tells the appearance script not to restyle our own pages.
        private string PageHead => PageHeadBase + _appearance.InternalPageCss() + "</style></head><body><div class='wrap'>";
        private const string PageHeadBase =
            "<!doctype html><html><head><meta charset='utf-8'><meta name='rec-internal' content='1'>" +
            // Internal pages keep inline script (they are built from strings), but may not make network requests, load frames/plugins,
            // change the base URL or submit forms, so a script injected into one cannot send data anywhere except by loading an image.
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: http: https:; font-src data:; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'\">" +
            "<style>" +
            "html,body{margin:0;height:100%}" +
            "body{font-family:'Segoe UI',Arial,sans-serif;background:#191c22;color:#e8e8e8}" +
            ".wrap{max-width:900px;margin:0 auto;padding:38px 28px}" +
            "h1{font-size:22px;font-weight:600;margin:0 0 4px}" +
            ".muted{color:#7f8794;font-size:12.5px;margin-bottom:22px}" +
            ".row{display:flex;justify-content:space-between;gap:16px;padding:11px 14px;border:1px solid #262b34;" +
            "border-radius:9px;margin-bottom:8px;background:#1e222a}" +
            ".row .t{color:#e8e8e8;font-size:13.5px;text-decoration:none}" +
            ".row .u{color:#6d7480;font-size:11.5px}" +
            ".row .ts{color:#5b626d;font-size:11px;white-space:nowrap}" +
            ".empty{color:#6d7480;padding:40px;text-align:center}" +
            ".btn{display:inline-block;border:1px solid #2b6cb0;background:#2b6cb0;color:#fff;border-radius:7px;" +
            "padding:8px 14px;font-size:13px;cursor:pointer;text-decoration:none}" +
            ".btn.ghost{background:transparent;border-color:#333844;color:#c7ccd4}" +
            ".kv{display:flex;gap:12px;padding:10px 0;border-bottom:1px solid #23272f}" +
            ".kv .k{color:#8a909b;width:220px;font-size:12.5px}.kv .v{color:#e8e8e8;font-size:12.5px;word-break:break-all}" +
            ".pill{display:inline-block;border:1px solid #2c7a4b;background:#16351f;color:#7fd6a0;border-radius:999px;padding:3px 10px;font-size:11px;margin-right:6px}" +
            ".big{font-size:30px;font-weight:700;color:#7fd6a0}" +
            "a{color:#6aa9e9}";
        private const string PageFoot = "</div></body></html>";

        private static string StartPageHtml()
        {
            return @"<!doctype html><html><head><meta charset='utf-8'><meta name='rec-internal' content='1'><title>Recognition — Start</title><style>
html,body{height:100%;margin:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:radial-gradient(1200px 600px at 50% -10%,#242833,#191c22 60%);
     color:#e8e8e8;display:flex;flex-direction:column;align-items:center;justify-content:center}
.logo{font-size:44px;line-height:1}
h1{font-weight:600;letter-spacing:.5px;margin:14px 0 2px;font-size:26px}
.sub{color:#7f8794;margin-bottom:30px;font-size:12.5px}
form{display:flex;width:min(640px,82vw);box-shadow:0 8px 30px rgba(0,0,0,.35);border-radius:10px}
input{flex:1;padding:15px 18px;border:1px solid #333844;border-right:none;border-radius:10px 0 0 10px;
      background:#0e1116;color:#e8e8e8;font-size:15px;outline:none}
input::placeholder{color:#5c626d}
button{padding:0 26px;border:1px solid #2b6cb0;border-radius:0 10px 10px 0;background:#2b6cb0;color:#fff;font-size:15px;cursor:pointer}
button:hover{background:#3480ce}
.pills{margin-top:26px;display:flex;gap:10px;flex-wrap:wrap;justify-content:center}
.pill{border:1px solid #2c313b;background:#1c2027;color:#9aa1ac;border-radius:999px;padding:6px 12px;font-size:11.5px}
.foot{position:fixed;bottom:18px;color:#4f545e;font-size:11px}
</style></head><body>
<div class='logo'>&#128274;</div><h1>Recognition</h1>
<div class='sub'>Governed browser &middot; identity-bound &middot; deterministic evidence</div>
<form id='f'><input id='q' autofocus autocomplete='off' spellcheck='false' placeholder='Search DuckDuckGo or type a URL'>
<button type='submit'>Search</button></form>
<div class='pills'><span class='pill'>&#128737; Tracker &amp; ad blocking</span><span class='pill'>HTTPS-first</span>
<span class='pill'>No autofill</span><span class='pill'>No telemetry</span><span class='pill'>Sleeping tabs</span></div>
<div class='foot'>every session is exportable as a signed, hash-chained evidence packet</div>
<script>
document.getElementById('f').addEventListener('submit',function(e){e.preventDefault();
var v=(document.getElementById('q').value||'').trim();if(!v)return;
if(/^[a-z][a-z0-9+.\-]*:\/\//i.test(v)){location.href=v;}
else if(v.indexOf('.')>-1&&v.indexOf(' ')===-1){location.href='https://'+v;}
else{location.href='https://duckduckgo.com/?q='+encodeURIComponent(v);}});
</script></body></html>";
        }

        private string PrivateStartPageHtml()
        {
            var vpnPill = _privateVpnOn
                ? "<span class='pill' style='border-color:#2c7a4b;background:#16351f;color:#7fd6a0'>&#127760; VPN on" + (string.IsNullOrEmpty(_privateVpnRegion) ? "" : " &middot; " + Esc(_privateVpnRegion)) + "</span>"
                : "<span class='pill' style='border-color:#7a5a2c;background:#352a16;color:#d6b87f'>&#127760; VPN: add an endpoint in Settings</span>";
            var head = @"<!doctype html><html><head><meta charset='utf-8'><meta name='rec-internal' content='1'><title>Recognition — Private</title><style>
html,body{height:100%;margin:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:radial-gradient(1200px 600px at 50% -10%,#2a2540,#17151f 60%);
     color:#e8e8e8;display:flex;flex-direction:column;align-items:center;justify-content:center}
.logo{font-size:44px;line-height:1}
h1{font-weight:600;letter-spacing:.5px;margin:14px 0 2px;font-size:26px}
.sub{color:#a99fce;margin-bottom:30px;font-size:12.5px}
form{display:flex;width:min(640px,82vw);box-shadow:0 8px 30px rgba(0,0,0,.4);border-radius:10px}
input{flex:1;padding:15px 18px;border:1px solid #3b3550;border-right:none;border-radius:10px 0 0 10px;
      background:#12101a;color:#e8e8e8;font-size:15px;outline:none}
input::placeholder{color:#6a6480}
button{padding:0 26px;border:1px solid #6b4bd6;border-radius:0 10px 10px 0;background:#6b4bd6;color:#fff;font-size:15px;cursor:pointer}
button:hover{background:#7d5ee6}
.pills{margin-top:26px;display:flex;gap:10px;flex-wrap:wrap;justify-content:center}
.pill{border:1px solid #40395a;background:#211d30;color:#b9b0d8;border-radius:999px;padding:6px 12px;font-size:11.5px}
.foot{position:fixed;bottom:18px;color:#5a5470;font-size:11px}
</style></head><body>
<div class='logo'>&#128374;</div><h1>Private tab</h1>
<div class='sub'>Nothing here is written to history, bookmarks, or the governed profile</div>
<form id='f'><input id='q' autofocus autocomplete='off' spellcheck='false' placeholder='Search DuckDuckGo or type a URL'>
<button type='submit'>Search</button></form>
<div class='pills'>" + vpnPill + @"<span class='pill'>&#128374; Ephemeral profile</span><span class='pill'>&#128737; Tracker blocking on</span>
<span class='pill'>No history</span><span class='pill'>Erased on close</span></div>
<div class='foot'>a fresh, isolated profile that is deleted when the last private tab closes</div>
<script>
document.getElementById('f').addEventListener('submit',function(e){e.preventDefault();
var v=(document.getElementById('q').value||'').trim();if(!v)return;
if(/^[a-z][a-z0-9+.\-]*:\/\//i.test(v)){location.href=v;}
else if(v.indexOf('.')>-1&&v.indexOf(' ')===-1){location.href='https://'+v;}
else{location.href='https://duckduckgo.com/?q='+encodeURIComponent(v);}});
</script></body></html>";
            return head;
        }

        private string HistoryHtml()
        {
            var sb = new StringBuilder(PageHead);
            sb.Append("<title>History</title><h1>History</h1>");
            sb.Append("<div class='muted'>Governed, append-only, hash-chained &mdash; " + _history.Items.Count +
                      " entr" + (_history.Items.Count == 1 ? "y" : "ies") +
                      ". <a class='btn ghost' onclick=\"send('clear-history')\">Clear history</a></div>");
            if (_history.Items.Count == 0) sb.Append("<div class='empty'>No history yet.</div>");
            else
                foreach (var h in Enumerable.Reverse(_history.Items).Take(500))
                    sb.Append("<div class='row'><div><a class='t' href='" + Attr(h.Url) + "'>" + Esc(string.IsNullOrEmpty(h.Title) ? h.Url : h.Title) +
                              "</a><div class='u'>" + Esc(h.Url) + "</div></div><div class='ts'>" + Esc(h.Ts) + "</div></div>");
            sb.Append(SendScript()).Append(PageFoot);
            return sb.ToString();
        }

        private string BookmarksHtml()
        {
            var sb = new StringBuilder(PageHead);
            sb.Append("<title>Bookmarks</title><h1>Bookmarks</h1><div class='muted'>Encrypted at rest in runtime\\bookmarks.v1.enc (DPAPI) &mdash; " +
                      _bookmarks.Count + " saved.</div>");
            if (_bookmarks.Count == 0) sb.Append("<div class='empty'>No bookmarks yet. Click the &#9734; in the address bar to save a page.</div>");
            else
                foreach (var b in Enumerable.Reverse(_bookmarks))
                    sb.Append("<div class='row'><div><a class='t' href='" + Attr(b.Url) + "'>" + Esc(string.IsNullOrEmpty(b.Title) ? b.Url : b.Title) +
                              "</a><div class='u'>" + Esc(b.Url) + "</div></div>" +
                              "<div class='ts'><a class='btn ghost' onclick=\"send('rmbookmark:" + Attr(b.Url) + "')\">Remove</a></div></div>");
            sb.Append(SendScript()).Append(PageFoot);
            return sb.ToString();
        }

        private string DownloadsHtml()
        {
            var sb = new StringBuilder(PageHead);
            sb.Append("<title>Downloads</title><h1>Downloads</h1><div class='muted'>Encrypted at rest in runtime\\downloads.v1.enc (DPAPI).</div>");
            if (_downloads.Count == 0) sb.Append("<div class='empty'>No downloads yet.</div>");
            else
                foreach (var d in Enumerable.Reverse(_downloads).Take(500))
                    sb.Append("<div class='row'><div><div class='t'>" + Esc(Path.GetFileName(d.Path)) + "  <span class='u'>[" + Esc(d.State) + "]</span></div>" +
                              "<div class='u'>" + Esc(d.Path) + "</div><div class='u'>" + Esc(d.Url) + "</div></div><div class='ts'>" + Esc(d.Ts) + "</div></div>");
            sb.Append(SendScript()).Append(PageFoot);
            return sb.ToString();
        }

        private string SettingsHtml()
        {
            var (rid, idPath) = ReadIdentityId();
            var profile = Path.Combine(_repoRoot, "runtime", "browser_profile");
            var sb = new StringBuilder(PageHead);
            sb.Append("<title>Settings</title><h1>Settings</h1><div class='muted'>Governance is enforced by the runtime laws; a few conveniences are toggleable here.</div>");

            sb.Append("<h1 style='font-size:16px;margin-top:8px'>Privacy &amp; tracking</h1>");
            sb.Append("<div class='row'><div><div class='t'>Tracker &amp; ad blocking</div>" +
                      "<div class='u'>Blocks known analytics, ad, and session-replay hosts at the network layer (" + _blockHosts.Count + " rules).</div></div>" +
                      "<div class='ts'><a class='btn" + (_blockingEnabled ? "" : " ghost") + "' onclick=\"send('toggle-blocking')\">" +
                      (_blockingEnabled ? "ON" : "OFF") + "</a></div></div>");
            sb.Append("<div class='row'><div><div class='t'>Strip tracking parameters</div>" +
                      "<div class='u'>Removes utm_*, fbclid, gclid and similar tracking parameters from links you open (not on redirects or form posts). " + _paramsStripped + " removed this session.</div></div>" +
                      "<div class='ts'><a class='btn" + (_stripTracking ? "" : " ghost") + "' onclick=\"send('toggle-strip')\">" + (_stripTracking ? "ON" : "OFF") + "</a></div></div>");
            sb.Append("<div class='row'><div><div class='t'>Global Privacy Control / Do Not Track</div>" +
                      "<div class='u'>Sends Sec-GPC: 1 and DNT: 1 with every request. A legal opt-out signal in some regions; it does not stop fingerprinting.</div></div>" +
                      "<div class='ts'><a class='btn" + (_sendGpc ? "" : " ghost") + "' onclick=\"send('toggle-gpc')\">" + (_sendGpc ? "ON" : "OFF") + "</a></div></div>");
            sb.Append("<div class='row'><div><div class='t'>HTTPS-only</div>" +
                      "<div class='u'>Plain http links are upgraded to https automatically (only loopback addresses such as localhost are exempt).</div></div>" +
                      "<div class='ts'><span class='pill'>always on</span></div></div>");
            sb.Append("<div class='row'><div><div class='t'>Blocked this session</div><div class='u'>Across all tabs since launch.</div></div>" +
                      "<div class='ts'><span class='big'>" + _blockedSession + "</span></div></div>");
            sb.Append("<div class='row'><div><div class='t'>Local data encryption</div>" +
                      "<div class='u'>History, bookmarks &amp; downloads are encrypted at rest (Windows DPAPI, per-user) &mdash; ciphertext on disk, bound to your account.</div></div>" +
                      "<div class='ts'><span class='pill'>&#128274; at rest</span></div></div>");
            sb.Append("<div class='row'><div><div class='t'>Passkeys / WebAuthn</div>" +
                      "<div class='u'>Sign in with platform passkeys (Windows Hello) or security keys, on HTTPS origins. No passwords are stored by the browser.</div></div>" +
                      "<div class='ts'><span class='pill'>supported</span></div></div>");
            sb.Append("<div style='margin:8px 0 20px'><span class='pill'>&#128737; Blocking</span><span class='pill'>HTTPS-first</span>" +
                      "<span class='pill'>No password autosave</span><span class='pill'>No general autofill</span>" +
                      "<span class='pill'>No telemetry</span><span class='pill'>Sleeping tabs</span><span class='pill'>Encrypted at rest</span></div>");

            sb.Append(AppearanceSectionHtml());

            sb.Append("<h1 style='font-size:16px'>Network / VPN (&sect;5.3 / &sect;29)</h1>");
            bool netWarn = _netMode == "proxy" && !string.IsNullOrWhiteSpace(_netProxy) && _netProxyDown;
            if (netWarn)
                sb.Append("<div class='row' style='border:1px solid #E0B44C;background:#2a2410'><div><div class='t' style='color:#E0B44C'>&#9888; Configured exit unreachable &mdash; running DIRECT this session</div>" +
                          "<div class='u'>The exit <code>" + Esc(_netProxy) + "</code> (" + Esc(_netExitRegion ?? "") + ") did not answer. Browsing still works, unproxied. " +
                          "Bring that exit online (your proxy / WireGuard, or Tor for tor-local), pick another exit below, or set it Off.</div></div></div>");
            sb.Append("<div class='row'><div><div class='t'>Tunnel</div><div class='u'>" +
                      (NetActive() ? ("ON &mdash; " + Esc(_netMode) + (string.IsNullOrEmpty(_netExitRegion) ? "" : " &middot; " + Esc(_netExitRegion)))
                                   : (netWarn ? "DIRECT (configured exit unreachable)" : "OFF (direct connection)")) +
                      "</div></div><div class='ts'><a class='btn" + (NetActive() ? " ghost" : "") + "' onclick=\"send('vpn-off')\">Off</a></div></div>");
            foreach (var ep in _netEndpoints)
            {
                var label = string.IsNullOrEmpty(ep.Region) ? ep.Name : ep.Region;
                var active = (_netMode == "proxy" && _netProxy == ep.Proxy);
                sb.Append("<div class='row'><div><div class='t'>" + Esc(label) + (active ? " <span class='pill'>active</span>" : "") + "</div>" +
                          "<div class='u'>" + Esc(ep.Proxy) + "</div></div>" +
                          "<div class='ts'><a class='btn ghost' onclick=\"send('vpn-pick:" + Attr(ep.Name) + "')\">Use</a></div></div>");
            }
            if (_netEndpoints.Count > 0)
                sb.Append("<div style='margin:10px 0 6px'><a class='btn' onclick=\"send('vpn-optimize')\">Auto-optimize (best placement)</a></div>");
            else
                sb.Append("<div class='muted'>Add exit endpoints to <code>config\\network.v1.json</code> (name / region / proxy, e.g. <code>socks5://host:1080</code>) to choose one or auto-optimize. Recognition runs no exit servers &mdash; bring your own (self-hosted, a provider proxy, WireGuard, or Tor).</div>");
            sb.Append("<div style='margin:8px 0 6px'><a class='btn' onclick=\"send('vpn-apply')\">Apply changes now (restart)</a></div>");
            sb.Append("<div class='muted' style='margin:6px 0 6px'>Routing changes apply on next launch (the engine proxy is set at startup) &mdash; use <b>Apply changes now</b> to restart immediately. Egress: HTTPS-first, trackers/ads blocked, no telemetry &mdash; all requests user-initiated. Recognition runs no exit servers; every exit above is one you bring (self-hosted, a provider proxy, WireGuard, or Tor).</div>");
            if (!string.IsNullOrWhiteSpace(_netExitCheckUrl))
                sb.Append("<div style='margin:2px 0 18px'><a class='btn ghost' onclick=\"send('verify-exit')\">Verify exit IP</a> <span class='u'>&nbsp;opens " + Esc(_netExitCheckUrl) + " (only when you click)</span></div>");

            sb.Append("<h1 style='font-size:16px'>Web engine</h1>");
            sb.Append(EngineHtmlRow());
            sb.Append("<h1 style='font-size:16px'>Extensions</h1>");
            sb.Append("<div class='kv'><div class='k'>Chromium extensions</div><div class='v'>" + (_extEnabled ? ("enabled &mdash; " + (_extPaths.Count + _extState.Items.Count) + " configured") : "off") + " &middot; <a class='t' href='recognition:extensions'>manage extensions</a>" + "</div></div>");
            sb.Append("<div class='muted' style='margin:6px 0 18px'>Configured in <code>config\\extensions.v1.json</code>: an unpacked folder, a <code>.zip</code>, or a <code>.crx</code> (universal adapter — all three are normalized to an unpacked folder). Every extension must ALSO pass the governance load gate (<code>recognition_extension_governance_v1.ps1</code>): its current bytes are hashed and checked against a ledger decision an operator recorded explicitly via <code>-Action register</code>. Nothing loads on first sight, on a tamper, or on a review/deny decision &mdash; refusals are receipted like any other action.</div>");

            sb.Append("<h1 style='font-size:16px'>Site Permissions &amp; Policy (&sect;53.1/&sect;54.1)</h1>");
            var curOrigin = (Active != null && !Active.IsInternal) ? TryHost(Active.CurrentUrl) : "";
            if (string.IsNullOrEmpty(curOrigin))
                sb.Append("<div class='muted' style='margin:6px 0 10px'>Open a site in another tab to manage its permissions and tracker-blocking exemption here.</div>");
            else
            {
                sb.Append("<div class='muted' style='margin:6px 0 6px'>Current site: <b>" + Esc(curOrigin) + "</b>. Every camera/microphone/geolocation/notification request is <b>denied by default</b> until explicitly allowed here &mdash; there is no interactive popup prompt. Every decision is receipted.</div>");
                foreach (var kind in new[] { "Camera", "Microphone", "Geolocation", "Notifications" })
                {
                    var dec = SitePolicyGet(curOrigin, "perm." + kind, "deny");
                    sb.Append("<div class='row'><div><div class='t'>" + kind + "</div><div class='u'>current: " + (dec == "allow" ? "allowed" : "denied") + "</div></div>" +
                              "<div class='ts'>" +
                              "<a class='btn" + (dec == "allow" ? "" : " ghost") + "' onclick=\"send('site-perm:" + Attr(curOrigin) + ":" + kind + ":allow')\">Allow</a> " +
                              "<a class='btn" + (dec == "allow" ? " ghost" : "") + "' onclick=\"send('site-perm:" + Attr(curOrigin) + ":" + kind + ":deny')\">Deny</a>" +
                              "</div></div>");
                }
                var trackDec = SitePolicyGet(curOrigin, "tracker_blocking", "inherit");
                sb.Append("<div class='row'><div><div class='t'>Tracker/ad blocking for this site</div><div class='u'>" +
                          (trackDec == "off" ? "exempted (off for this site only)" : "inherits the global setting") + "</div></div>" +
                          "<div class='ts'><a class='btn ghost' onclick=\"send('site-track:" + Attr(curOrigin) + ":" +
                          (trackDec == "off" ? "inherit" : "off") + "')\">" + (trackDec == "off" ? "Remove exemption" : "Exempt this site") + "</a></div></div>");
            }
            if (_sitePolicyState.Count > 0)
            {
                sb.Append("<div class='muted' style='margin:10px 0 4px'>All recorded per-origin decisions (" + _sitePolicyState.Count + "):</div>");
                foreach (var kv in _sitePolicyState.OrderBy(p => p.Key, StringComparer.OrdinalIgnoreCase))
                {
                    var sep = kv.Key.IndexOf('|');
                    var k = sep >= 0 ? kv.Key.Substring(0, sep) : kv.Key;
                    var org = sep >= 0 ? kv.Key.Substring(sep + 1) : "";
                    sb.Append("<div class='kv'><div class='k'>" + Esc(org) + " &mdash; " + Esc(k) + "</div><div class='v'>" + Esc(kv.Value) + "</div></div>");
                }
            }
            bool spOk = _sitePolicy != null && _sitePolicy.Verify(out int spVerified);
            sb.Append("<div class='muted' style='margin:6px 0 18px'>Policy ledger: " + (_sitePolicy?.Count ?? 0) + " receipts, chain " +
                      (spOk ? "<span style='color:#7fd6a0'>verified</span>" : "<span style='color:#e06c6c'>TAMPERED / broken</span>") +
                      ". Same hash-chained, DPAPI-encrypted format as action receipts &mdash; the current state above is a pure replay (latest decision per site/permission wins).</div>");

            sb.Append("<h1 style='font-size:16px'>TLS Certificate Errors (Certificate Manager, &sect;54)</h1>");
            if (_certErrors.Count == 0)
                sb.Append("<div class='muted' style='margin:6px 0 10px'>No certificate errors seen this session. Every TLS certificate error is refused by default (fail-closed) unless the exact certificate (pinned by subject/issuer/validity, not just host) has been explicitly trusted. Mutual-TLS client certificate requests are always refused automatically — no client certificate is ever auto-presented.</div>");
            else
            {
                foreach (var kv in _certErrors)
                {
                    bool trusted = SitePolicyGet(kv.Key, "cert." + kv.Value.Fp, "deny") == "allow";
                    sb.Append("<div class='row'><div><div class='t'>" + Esc(kv.Key) + (trusted ? " <span class='pill'>trusted</span>" : "") + "</div>" +
                              "<div class='u'>" + Esc(kv.Value.Err) + " &mdash; fingerprint " + Esc(kv.Value.Fp) + "</div></div>" +
                              "<div class='ts'><a class='btn ghost' onclick=\"send('cert-trust:" + Attr(kv.Key) + ":" + Attr(kv.Value.Fp) + ":" + (trusted ? "deny" : "allow") + "')\">" +
                              (trusted ? "Revoke trust" : "Trust this certificate") + "</a></div></div>");
                }
                sb.Append("<div class='muted' style='margin:6px 0 18px'>Trust is pinned to the exact certificate above — if this host later presents a different certificate, it is refused again until separately trusted. Client certificate requests are always refused automatically.</div>");
            }

            sb.Append("<h1 style='font-size:16px'>Updates (governed updater, &sect;54)</h1>");
            sb.Append("<div class='kv'><div class='k'>Installed version</div><div class='v'>" + Esc(InstalledVersion()) + "</div></div>");
            sb.Append("<div class='muted' style='margin:6px 0 10px'>Recognition never checks for or downloads updates on its own. Choose an update package folder you obtained yourself: it is applied only if its signature verifies against the pinned trust root, every file hash matches, no path escapes the install or touches <code>runtime\\</code> / the trust root, and the version is strictly newer (no downgrade). Replaced files are backed up and rolled back automatically on any failure.</div>");
            sb.Append("<div style='margin:0 0 18px;display:flex;gap:10px;flex-wrap:wrap'>" +
                      "<a class='btn ghost' onclick=\"send('update-verify')\">Verify an update package…</a>" +
                      "<a class='btn' onclick=\"send('update-apply')\">Apply an update package…</a></div>");

            sb.Append("<h1 style='font-size:16px'>Software integrity</h1>");
            var (sidState, sidId) = SoftwareIdState();
            var sidColor = sidState == "verified authentic" ? "#7fd6a0" : (sidState.StartsWith("MISMATCH") ? "#e06c6c" : "#c9a24a");
            sb.Append("<div class='kv'><div class='k'>SoftwareID (SHA-256 of this build)</div><div class='v'>" + Esc(sidId) + "</div></div>");
            sb.Append("<div class='kv'><div class='k'>Attestation</div><div class='v' style='color:" + sidColor + "'>" + Esc(sidState) +
                      "</div></div>");
            sb.Append("<div class='muted' style='margin:6px 0 18px'>Verified at every launch against a signed record (Ed25519, pinned trust root). " +
                      "A modified binary is refused before the browser opens.</div>");

            sb.Append("<h1 style='font-size:16px'>Cookies (&sect;23)</h1>");
            bool cookOk = _cookies != null && _cookies.Verify(out int cookVerified);
            sb.Append("<div class='kv'><div class='k'>Governed receipts</div><div class='v'>" + (_cookies?.Count ?? 0) + "</div></div>");
            sb.Append("<div class='kv'><div class='k'>Chain</div><div class='v' style='color:" + (cookOk ? "#7fd6a0" : "#e06c6c") + "'>" + (cookOk ? "verified" : "TAMPERED / broken") + "</div></div>");
            sb.Append("<div class='muted' style='margin:6px 0 10px'>Cookie values are already encrypted at rest by the engine's own profile store (OS-protected). Recognition additionally keeps its own encrypted, hash-chained witness of cookie adds/changes per domain (name+value stored as SHA-256 only, never cleartext) and every clear action.</div>");
            sb.Append("<div style='margin:0 0 18px;display:flex;gap:10px;flex-wrap:wrap'>" +
                      "<a class='btn ghost' onclick=\"send('cookies-clear-site')\">Clear cookies for this site</a>" +
                      "<a class='btn ghost' onclick=\"send('cookies-clear-all')\">Clear all cookies</a></div>");

            sb.Append("<h1 style='font-size:16px'>Action receipts (prove-it-in-every-action)</h1>");
            bool actOk = _actions != null && _actions.Verify(out int actVerified2);
            int actCount = _actions?.Count ?? 0;
            var actColor = actOk ? "#7fd6a0" : "#e06c6c";
            sb.Append("<div class='kv'><div class='k'>Receipts this profile</div><div class='v'>" + actCount + "</div></div>");
            sb.Append("<div class='kv'><div class='k'>Chain</div><div class='v' style='color:" + actColor + "'>" + (actOk ? "verified — sound, ordered, unbroken" : "TAMPERED / broken") + "</div></div>");
            sb.Append("<div class='kv'><div class='k'>Head hash</div><div class='v'>" + Esc(_actions?.Head ?? "") + "</div></div>");
            sb.Append("<div class='muted' style='margin:6px 0 18px'>Every meaningful action (navigate, download, bookmark, VPN switch, export, clear) appends an append-only, hash-chained, DPAPI-encrypted receipt. URLs and paths are stored as SHA-256 only, never cleartext. Any edit, reorder, or deletion breaks the chain. Verified in the release gate and included in every exported packet.</div>");

            sb.Append("<h1 style='font-size:16px'>Identity &amp; governance</h1>");
            sb.Append("<div class='kv'><div class='k'>Identity (recognition_identity_id)</div><div class='v'>" + Esc(rid) + "</div></div>");
            sb.Append("<div class='kv'><div class='k'>Identity descriptor</div><div class='v'>" + Esc(idPath) + "</div></div>");
            sb.Append("<div class='kv'><div class='k'>Session id</div><div class='v'>" + Esc(_sessionId) + "</div></div>");
            sb.Append("<div class='kv'><div class='k'>Governed profile</div><div class='v'>" + Esc(profile) + "</div></div>");
            sb.Append("<div class='kv'><div class='k'>Repo root</div><div class='v'>" + Esc(_repoRoot) + "</div></div>");
            sb.Append("<div style='margin-top:22px;display:flex;gap:10px;flex-wrap:wrap'>" +
                      "<a class='btn' onclick=\"send('export-session')\">Export Session</a>" +
                      "<a class='btn ghost' onclick=\"send('open-profile')\">Open profile folder</a>" +
                      "<a class='btn ghost' onclick=\"send('open-packets')\">Open packets folder</a>" +
                      "<a class='btn ghost' onclick=\"send('clear-history')\">Clear history</a></div>");
            sb.Append(SendScript()).Append(PageFoot);
            return sb.ToString();
        }

        private string AppearanceSectionHtml()
        {
            var a = _appearance;
            string Opt(string[] vals, string cur, string key, Func<string, string> label)
            {
                var o = new StringBuilder("<select onchange=\"send('appearance-set:" + key + ":'+this.value)\" style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:6px 8px'>");
                foreach (var v in vals) o.Append("<option value='" + Attr(v) + "'" + (v == cur ? " selected" : "") + ">" + Esc(label(v)) + "</option>");
                return o.Append("</select>").ToString();
            }
            string Color(string key, string cur) =>
                "<input type='color' value='" + Attr(cur) + "' onchange=\"send('appearance-set:" + key + ":'+this.value)\" style='width:44px;height:30px;border:0;background:none;cursor:pointer'>";
            string Row(string title, string sub, string control) =>
                "<div class='row'><div><div class='t'>" + title + "</div><div class='u'>" + sub + "</div></div><div class='ts'>" + control + "</div></div>";

            var sb = new StringBuilder();
            sb.Append("<h1 style='font-size:16px'>Appearance &amp; preferences</h1>");
            sb.Append(Row("Colour scheme", "Theme of Recognition's own pages (Settings, History, ...) and the colour scheme sites are told you prefer.",
                Opt(AppearanceSettings.Themes, a.Theme, "theme", v => v == "system" ? "Follow system" : char.ToUpper(v[0]) + v.Substring(1))));
            sb.Append(Row("Dark mode for websites", "<b>Prefer dark</b> asks sites for their own dark theme. <b>Smart invert</b> darkens every page. <b>Custom colours</b> forces the colours below on every page.",
                Opt(AppearanceSettings.DarkStyles, a.DarkStyle, "darkstyle", v => v switch { "off" => "Off", "prefer" => "Prefer dark (sites that support it)", "invert" => "Smart invert (all sites)", _ => "Custom colours (all sites)" })));
            sb.Append(Row("Page background", "Used by Custom colours.", Color("bg", a.PageBg)));
            sb.Append(Row("Text colour", "Used by Custom colours.", Color("text", a.PageText)));
            sb.Append(Row("Link colour", "Used by Custom colours.", Color("link", a.LinkColor)));
            sb.Append(Row("Font", "Applies to Recognition's own pages; turn on the option below to apply it to websites too.",
                Opt(AppearanceSettings.Fonts, a.Font, "font", v => v == "default" ? "Default" : v)));
            sb.Append(Row("Use this font on websites", "Overrides the fonts sites choose (code blocks keep a monospace font).",
                "<a class='btn" + (a.OverrideSiteFonts ? "" : " ghost") + "' onclick=\"send('appearance-set:overridefonts:" + (a.OverrideSiteFonts ? "off" : "on") + "')\">" + (a.OverrideSiteFonts ? "ON" : "OFF") + "</a>"));
            sb.Append("<div style='margin:6px 0 18px'><a class='btn ghost' onclick=\"send('appearance-reset')\">Reset appearance to defaults</a> " +
                      "<span class='u'>&nbsp;Browser window chrome (toolbar, tabs) keeps its dark style.</span></div>");
            return sb.ToString();
        }

        private static string SendScript() =>
            "<script>function send(c){window.chrome.webview.postMessage(c);}" +
            "document.addEventListener('click',function(e){var a=e.target.closest('a.t');" +
            "if(a){e.preventDefault();window.chrome.webview.postMessage('open:'+a.getAttribute('href'));}});</script>";

        private void OnWebMessage(BrowserTab tab, CoreWebView2WebMessageReceivedEventArgs e)
        {
            string msg;
            try { msg = e.TryGetWebMessageAsString(); } catch { return; }
            if (string.IsNullOrEmpty(msg)) return;

            // SECURITY GATE: every page (including hostile websites and cross-origin iframes) can call
            // window.chrome.webview.postMessage. Only the browser's own internal pages may send commands;
            // web content may only send allowlisted keyboard shortcuts (rate-limited for tab-opening ones).
            string msgSource = ""; try { msgSource = e.Source ?? ""; } catch { }
            var verdict = MessageGate.Classify(tab.IsInternal, msgSource, msg);
            if (verdict == MessageVerdict.Deny)
            {
                if (!tab.Private) _actions?.Append("bridge.refused", PasswordRules.OriginOf(msgSource) ?? "(non-web)");
                return;
            }
            if (verdict == MessageVerdict.Shortcut)
            {
                var sc = msg.Substring(3);
                if (MessageGate.IsTabShortcut(sc) && (DateTime.UtcNow - _lastTabShortcutUtc).TotalMilliseconds < 600) return;
                if (MessageGate.IsTabShortcut(sc)) _lastTabShortcutUtc = DateTime.UtcNow;
                HandleShortcut(sc); return;
            }
            if (msg.StartsWith("open:")) { NavigateTab(tab, msg.Substring(5)); return; }
            if (msg.StartsWith("rmbookmark:"))
            {
                var url = msg.Substring("rmbookmark:".Length);
                _bookmarks.RemoveAll(b => b.Url == url); SaveBookmarks();
                if (tab.Internal == "bookmarks") LoadInternal(tab, "bookmarks");
                var a = Active; if (a != null) UpdateStar(a);
                return;
            }
            switch (msg)
            {
                case "toggle-blocking":
                    _blockingEnabled = !_blockingEnabled; SaveSettings(); UpdateShield();
                    if (tab.Internal == "settings") LoadInternal(tab, "settings");
                    Status("tracker/ad blocking " + (_blockingEnabled ? "ON" : "OFF"));
                    break;
                case "toggle-strip":
                    _stripTracking = !_stripTracking; SaveSettings(); _actions?.Append("privacy.strip_params." + (_stripTracking ? "on" : "off"));
                    if (tab.Internal == "settings") LoadInternal(tab, "settings"); break;
                case "toggle-gpc":
                    _sendGpc = !_sendGpc; SaveSettings(); _actions?.Append("privacy.gpc." + (_sendGpc ? "on" : "off"));
                    if (tab.Internal == "settings") LoadInternal(tab, "settings"); break;
                case "clear-history":
                    _history.Clear();
                    _actions?.Append("history.clear");
                    if (tab.Internal is "history" or "settings") LoadInternal(tab, tab.Internal);
                    Status("history cleared");
                    break;
                case "export-session": Export_Click(this, new RoutedEventArgs()); break;
                case "verify-exit": if (!string.IsNullOrWhiteSpace(_netExitCheckUrl)) NavigateTab(tab, _netExitCheckUrl); break;
                case "open-profile": OpenFolder(Path.Combine(_repoRoot, "runtime", "browser_profile")); break;
                case "open-packets": OpenFolder(Path.Combine(_repoRoot, "packets")); break;
                case "vpn-off": SetVpnOff(); break;
                case "vpn-optimize": Status("probing endpoints for best placement…"); _ = OptimizeVpnAsync(tab); break;
                case "vpn-apply": RestartToApply(); break;
                case "update-verify": UpdateFlow(tab, false); break;
                case "update-apply": UpdateFlow(tab, true); break;
                case "cookies-clear-all": ClearAllCookies(); if (tab.Internal == "settings") LoadInternal(tab, "settings"); break;
                case "cookies-clear-site": ClearSiteCookies(); if (tab.Internal == "settings") LoadInternal(tab, "settings"); break;
            }
            if (msg.StartsWith("vpn-pick:"))
            {
                var ep = _netEndpoints.FirstOrDefault(x => x.Name == msg.Substring("vpn-pick:".Length));
                if (ep != null) _ = SetVpnEndpoint(ep);
            }
            else if (msg.StartsWith("site-perm:"))
            {
                var parts = msg.Substring("site-perm:".Length).Split(':');
                if (parts.Length == 3)
                {
                    SitePolicySet(parts[0], "perm." + parts[1], parts[2]);
                    Status((parts[2] == "allow" ? "allowed " : "denied ") + parts[1] + " for " + parts[0]);
                    if (tab.Internal == "settings") LoadInternal(tab, "settings");
                }
            }
            else if (msg.StartsWith("site-track:"))
            {
                var parts = msg.Substring("site-track:".Length).Split(':');
                if (parts.Length == 2)
                {
                    SitePolicySet(parts[0], "tracker_blocking", parts[1]);
                    Status("tracker blocking for " + parts[0] + ": " + (parts[1] == "off" ? "exempted" : "inherits global setting"));
                    if (tab.Internal == "settings") LoadInternal(tab, "settings");
                }
            }
            else if (msg.StartsWith("net-")) HandleNetMessage(msg);
            else if (msg.StartsWith("setup-") && tab.Internal == "setup") HandleSetupMessage(msg);
            else if (msg.StartsWith("pw-") && tab.Internal == "passwords") HandlePwMessage(msg);
            else if (msg.StartsWith("tools-") && tab.Internal == "tools") HandleToolsMessage(msg);
            else if ((msg.StartsWith("flt-") || msg.StartsWith("shield-")) && tab.Internal == "shield") HandleShieldMessage(msg);
            else if (msg.StartsWith("pk-") && tab.Internal == "passkeys") HandlePasskeyMessage(msg);
            else if (msg.StartsWith("ext-") && tab.Internal == "extensions") HandleExtMessage(msg);
            else if (msg.StartsWith("appearance-set:"))
            {
                var parts = msg.Substring("appearance-set:".Length).Split(new[] { ':' }, 2);
                if (parts.Length == 2 && _appearance.Set(parts[0], parts[1]))
                {
                    SaveSettings(); ApplyAppearanceAll();
                    _actions?.Append("appearance." + parts[0], parts[1]);
                    Status("appearance updated: " + parts[0]);
                    if (tab.Internal == "settings") LoadInternal(tab, "settings");
                }
                else Status("appearance change rejected (invalid value)");
            }
            else if (msg == "appearance-reset")
            {
                _appearance.Reset(); SaveSettings(); ApplyAppearanceAll();
                _actions?.Append("appearance.reset");
                Status("appearance reset to defaults");
                if (tab.Internal == "settings") LoadInternal(tab, "settings");
            }
            else if (msg.StartsWith("cert-trust:"))
            {
                var parts = msg.Substring("cert-trust:".Length).Split(':');
                if (parts.Length == 3)
                {
                    SitePolicySet(parts[0], "cert." + parts[1], parts[2]);
                    _actions?.Append(parts[2] == "allow" ? "cert.trust" : "cert.untrust", parts[0]);
                    Status((parts[2] == "allow" ? "trusted certificate " : "revoked trust for certificate ") + parts[1] + " on " + parts[0]);
                    if (tab.Internal == "settings") LoadInternal(tab, "settings");
                }
            }
        }

        // Pick the lowest-latency configured endpoint (user-initiated; no hidden calls).
        private async Task OptimizeVpnAsync(BrowserTab tab)
        {
            NetEndpoint? best = null; double bestMs = double.MaxValue;
            foreach (var ep in _netEndpoints)
            {
                var (host, port) = ParseHostPort(ep.Proxy); if (host == null) continue;
                var ms = await ProbeAsync(host, port);
                if (ms >= 0 && ms < bestMs) { bestMs = ms; best = ep; }
            }
            if (best != null)
            {
                _netMode = "proxy"; _netProxy = best.Proxy; _netExitRegion = string.IsNullOrEmpty(best.Region) ? best.Name : best.Region; _netProxyDown = false;
                SaveNetworkConfig(); UpdateVpn();
                _actions?.Append("vpn.optimize", best.Proxy);
                Status($"best placement: {_netExitRegion} ({Math.Round(bestMs)} ms) — applies on next launch");
            }
            else Status("no reachable endpoint found");
            if (tab.Internal == "settings") LoadInternal(tab, "settings");
        }
        private static (string?, int) ParseHostPort(string proxy)
        {
            try { var u = new Uri(proxy.Contains("://") ? proxy : "tcp://" + proxy); return (u.Host, u.Port > 0 ? u.Port : 1080); }
            catch { return (null, 0); }
        }
        private static async Task<double> ProbeAsync(string host, int port)
        {
            try
            {
                using var c = new System.Net.Sockets.TcpClient();
                var sw = System.Diagnostics.Stopwatch.StartNew();
                var t = c.ConnectAsync(host, port);
                if (await Task.WhenAny(t, Task.Delay(1500)) != t) return -1;
                await t; sw.Stop(); return sw.Elapsed.TotalMilliseconds;
            }
            catch { return -1; }
        }

        // ---- governed cookies (§23): encrypted-at-rest ledger of cookie state changes ---
        // WebView2/Chromium already encrypts cookie VALUES at rest in its own profile store
        // (OS-protected). This adds Recognition's own governed witness: a deterministic,
        // append-only, hash-chained, DPAPI-encrypted receipt for every cookie ADD/CHANGE we
        // observe (via CookieManager.GetCookiesAsync on each navigation) and every clear
        // action, with the cookie's name+value stored only as a SHA-256 (never cleartext) —
        // same privacy stance as the action/history ledgers. Domain is kept in the action
        // label since it's already visible elsewhere (downloads/bookmarks store raw URLs).
        private async Task SnapshotCookiesAsync(BrowserTab tab, string url)
        {
            try
            {
                var mgr = tab.Web.CoreWebView2.CookieManager;
                if (mgr == null) return;
                var cookies = await mgr.GetCookiesAsync(url);
                foreach (var c in cookies)
                {
                    var key = c.Domain + "|" + c.Name;
                    var valSha = Sha256Hex(c.Name + "" + c.Value);
                    if (_cookieLastSeen.TryGetValue(key, out var prevSha) && prevSha == valSha) continue;   // unchanged — skip
                    bool isNew = !_cookieLastSeen.ContainsKey(key);
                    _cookieLastSeen[key] = valSha;
                    _cookies.Append((isNew ? "cookie.new:" : "cookie.change:") + c.Domain, c.Name + "" + c.Value);
                }
            }
            catch { /* cookie governance is best-effort witness; never blocks browsing */ }
        }

        private void ClearAllCookies()
        {
            try
            {
                var a = Active;
                if (a == null || !a.Ready) { Status("no active tab to clear cookies from"); return; }
                a.Web.CoreWebView2.CookieManager.DeleteAllCookies();
                _cookieLastSeen.Clear();
                _cookies.Append("cookies.clear_all");
                Status("all cookies cleared");
            }
            catch (Exception ex) { Status("clear cookies error: " + ex.Message); }
        }

        private async void ClearSiteCookies()
        {
            try
            {
                var a = Active; if (a == null || !a.Ready || a.IsInternal || string.IsNullOrEmpty(a.CurrentUrl)) return;
                var mgr = a.Web.CoreWebView2.CookieManager;
                var cookies = await mgr.GetCookiesAsync(a.CurrentUrl);
                foreach (var c in cookies) { mgr.DeleteCookie(c); _cookieLastSeen.Remove(c.Domain + "|" + c.Name); }
                var host = TryHost(a.CurrentUrl);
                _cookies.Append("cookies.clear_site:" + host, host);
                Status("cookies cleared for " + host);
            }
            catch (Exception ex) { Status("clear site cookies error: " + ex.Message); }
        }

        private static string TryHost(string url) { try { return new Uri(url).Host; } catch { return url; } }

        private void OpenFolder(string path)
        {
            try { Directory.CreateDirectory(path); Process.Start(new ProcessStartInfo("explorer.exe", "\"" + path + "\"") { UseShellExecute = true }); }
            catch (Exception ex) { Status("open folder error: " + ex.Message); }
        }

        // ---- downloads ----------------------------------------------------------

        private sealed class DownloadRec { public string Url = ""; public string Path = ""; public string State = ""; public string Ts = ""; }

        private void OnDownloadStarting(CoreWebView2DownloadStartingEventArgs e)
        {
            try
            {
                var op = e.DownloadOperation;
                // Drive-by protection: files that can run code, or whose name hides its real type, need an explicit yes.
                var risk = DownloadRules.Assess(Path.GetFileName(op.ResultFilePath));
                if (risk != DownloadRisk.None)
                {
                    var fname = Path.GetFileName(op.ResultFilePath);
                    var answer = MessageBox.Show(this,
                        (risk == DownloadRisk.DeceptiveName ? "This download has a file name that disguises its real type." : "This download is a file type that can run code on your PC.") +
                        "\n\nFile: " + fname + "\nFrom: " + (TryHost(op.Uri) ?? op.Uri) + "\n\nOnly keep it if you expected this download and trust the site. Keep it?",
                        "Recognition — risky download", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
                    if (answer != MessageBoxResult.Yes)
                    {
                        e.Cancel = true; _actions?.Append("download.refused", op.Uri); Status("download refused: " + fname);
                        return;
                    }
                    _actions?.Append("download.risky_allowed", op.Uri);
                }
                var rec = new DownloadRec { Url = op.Uri, Path = op.ResultFilePath, State = op.State.ToString(), Ts = Iso(DateTime.UtcNow) };
                _downloads.Add(rec);
                SaveDownloads();
                _actions?.Append("download.start", op.Uri);
                Status("download started: " + System.IO.Path.GetFileName(rec.Path));
                op.StateChanged += (o, __) => Dispatcher.Invoke(() =>
                {
                    rec.State = op.State.ToString(); rec.Path = op.ResultFilePath; SaveDownloads();
                    if (op.State == CoreWebView2DownloadState.Completed) _actions?.Append("download.complete", op.Uri);
                    else if (op.State == CoreWebView2DownloadState.Interrupted) _actions?.Append("download.interrupted", op.Uri);
                    var a = Active; if (a != null && a.Internal == "downloads") LoadInternal(a, "downloads");
                });
            }
            catch (Exception ex) { Status("download error: " + ex.Message); }
        }

        private string DownloadsPath() => Path.Combine(_repoRoot, "runtime", "downloads.v1.enc");
        private void LoadDownloads()
        {
            _downloads.Clear();
            var legacy = Path.Combine(_repoRoot, "runtime", "downloads.v1.ndjson");
            var text = ReadSecure(DownloadsPath());
            bool migrated = false;
            if (text.Length == 0 && File.Exists(legacy)) { text = File.ReadAllText(legacy); migrated = true; }
            foreach (var line in text.Split('\n'))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try { using var d = JsonDocument.Parse(line); var r = d.RootElement;
                      _downloads.Add(new DownloadRec { Url = Get(r, "url"), Path = Get(r, "path"), State = Get(r, "state"), Ts = Get(r, "ts_utc") }); }
                catch { }
            }
            if (migrated) { SaveDownloads(); try { File.Delete(legacy); } catch { } }
        }

        private void SaveDownloads()
        {
            var sb = new StringBuilder();
            foreach (var r in _downloads)
                sb.Append("{" + J("schema") + ":" + J("recognition.download.v1") + "," + J("ts_utc") + ":" + J(r.Ts) + "," +
                          J("url") + ":" + J(r.Url) + "," + J("path") + ":" + J(r.Path) + "," + J("state") + ":" + J(r.State) + "}\n");
            WriteSecure(DownloadsPath(), sb.ToString());
        }

        // ---- navigation ---------------------------------------------------------

        private void OnNavStarting(BrowserTab tab, CoreWebView2NavigationStartingEventArgs e)
        {
            // HTTPS-only: plain http to anything but loopback is upgraded (host parsed properly, so
            // http://localhost.evil.com is NOT treated as local).
            var upgraded = PrivacyRules.HttpsUpgrade(e.Uri);
            if (upgraded != null)
            {
                e.Cancel = true;
                NavigateTab(tab, upgraded);
                return;
            }
            // Strip known tracking parameters (utm_*, fbclid, gclid, ...). Never on redirects (OAuth/SSO flows)
            // or form posts, so nothing functional is rewritten.
            if (_stripTracking && !e.IsRedirected && !e.RequestHeaders.Contains("Content-Type"))
            {
                var clean = PrivacyRules.StripTrackingParams(e.Uri, out var nStripped);
                if (nStripped > 0)
                {
                    e.Cancel = true; _paramsStripped += nStripped;
                    if (!tab.Private) _actions?.Append("privacy.strip_params", e.Uri);   // private tabs leave no persisted trace
                    try { tab.Web.CoreWebView2.Navigate(clean); } catch { }
                    return;
                }
            }
            if (e.Uri.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                e.Uri.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                tab.Internal = "";
                tab.TopNavUrl = e.Uri;   // the filter engine needs the page being LOADED, not the previous page
                tab.Fp.Clear();
                if (!e.IsRedirected) { tab.Blocked = 0; if (ReferenceEquals(tab, Active)) UpdateShield(); }
            }
            if (ReferenceEquals(tab, Active)) Status("loading…");
        }

        private void OnSourceChanged(BrowserTab tab)
        {
            if (tab.IsInternal) return;
            var src = tab.Web.CoreWebView2.Source;
            if (src.StartsWith("data:") || src.StartsWith("about:")) return;
            tab.CurrentUrl = src;
            if (ReferenceEquals(tab, Active)) { SetAddress(tab); UpdateStar(tab); }
        }

        private void OnNavCompleted(BrowserTab tab, CoreWebView2NavigationCompletedEventArgs e)
        {
            if (!e.IsSuccess) { if (ReferenceEquals(tab, Active)) Status("navigation failed"); return; }
            var url = tab.Web.CoreWebView2.Source;
            if (tab.IsInternal || url.StartsWith("data:") || url.StartsWith("about:")) return;

            var title = tab.Web.CoreWebView2.DocumentTitle ?? "";
            tab.CurrentUrl = url; tab.CurrentTitle = title;
            tab.Visits.Add((url, title, DateTime.UtcNow));
            if (!tab.Private) { _history.Append(url, title); _actions.Append("navigate", url); _ = SnapshotCookiesAsync(tab, url); }   // private tabs leave no persisted trace
            SetHeader(tab, title);
            if (ReferenceEquals(tab, Active)) { SetAddress(tab); UpdateStar(tab); UpdateShield(); Status($"visited {TotalVisits()}: {title}"); }
        }

        private int TotalVisits() { int n = 0; foreach (var t in _tabs) n += t.Visits.Count; return n; }

        private void NavigateTab(BrowserTab tab, string input)
        {
            if (!tab.Ready) return;
            input = (input ?? "").Trim();
            if (input.StartsWith("recognition:", StringComparison.OrdinalIgnoreCase))
            {
                var name = input.Substring("recognition:".Length).ToLowerInvariant();
                LoadInternal(tab, name is "history" or "downloads" or "bookmarks" or "settings" or "network" or "setup" or "passwords" or "tools" or "shield" or "passkeys" or "extensions" or "start" ? name : "start");
                return;
            }
            tab.Internal = "";
            try { tab.Web.CoreWebView2.Navigate(ToUrl(input)); } catch (Exception ex) { Status("nav error: " + ex.Message); }
        }

        private static string ToUrl(string input)
        {
            input = (input ?? "").Trim();
            if (input.Length == 0) return "https://duckduckgo.com/";
            if (Regex.IsMatch(input, @"^[a-zA-Z][a-zA-Z0-9+.\-]*://")) return input;
            if (input.Contains('.') && !input.Contains(' ')) return "https://" + input;
            return "https://duckduckgo.com/?q=" + Uri.EscapeDataString(input);
        }

        private void Back_Click(object sender, RoutedEventArgs e){ var a=Active; if(a!=null && a.Ready && a.Web.CoreWebView2.CanGoBack) a.Web.CoreWebView2.GoBack(); }
        private void Forward_Click(object sender, RoutedEventArgs e){ var a=Active; if(a!=null && a.Ready && a.Web.CoreWebView2.CanGoForward) a.Web.CoreWebView2.GoForward(); }
        private void Reload_Click(object sender, RoutedEventArgs e){ var a=Active; if(a!=null && a.Ready){ if(a.IsInternal) LoadInternal(a,a.Internal); else a.Web.CoreWebView2.Reload(); } }
        private void Go_Click(object sender, RoutedEventArgs e){ HideSuggest(); var a=Active; if(a!=null) NavigateTab(a, AddressBar.Text); }

        // ---- omnibox suggestions ------------------------------------------------

        public sealed class Suggestion
        {
            public string Icon { get; set; } = "";
            public string Primary { get; set; } = "";
            public string Secondary { get; set; } = "";
            public string Target { get; set; } = "";
        }

        private void Address_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (_suppressSuggest) return;
            var q = AddressBar.Text.Trim();
            if (q.Length == 0) { HideSuggest(); return; }
            var items = BuildSuggestions(q);
            SuggestList.ItemsSource = items;
            if (items.Count > 0) { SuggestList.SelectedIndex = -1; SuggestPopup.IsOpen = true; } else HideSuggest();
        }

        private List<Suggestion> BuildSuggestions(string q)
        {
            var list = new List<Suggestion>();
            bool looksUrl = Regex.IsMatch(q, @"^[a-zA-Z][a-zA-Z0-9+.\-]*://") || (q.Contains('.') && !q.Contains(' '));
            if (looksUrl) list.Add(new Suggestion { Icon = "→", Primary = q, Secondary = "Open site", Target = q });
            list.Add(new Suggestion { Icon = "\U0001F50D", Primary = q, Secondary = "Search DuckDuckGo", Target = "ddg:" + q });

            var seen = new HashSet<string>();
            foreach (var b in _bookmarks)
            {
                if (list.Count >= 9) break;
                if (string.IsNullOrEmpty(b.Url) || !seen.Add(b.Url)) continue;
                if (Match(q, b.Url, b.Title))
                    list.Add(new Suggestion { Icon = "★", Primary = string.IsNullOrEmpty(b.Title) ? b.Url : b.Title, Secondary = b.Url, Target = b.Url });
            }
            foreach (var h in Enumerable.Reverse(_history.Items))
            {
                if (list.Count >= 9) break;
                if (string.IsNullOrEmpty(h.Url) || !seen.Add(h.Url)) continue;
                if (Match(q, h.Url, h.Title))
                    list.Add(new Suggestion { Icon = "↺", Primary = string.IsNullOrEmpty(h.Title) ? h.Url : h.Title, Secondary = h.Url, Target = h.Url });
            }
            return list;
        }
        private static bool Match(string q, string url, string title) =>
            (url ?? "").IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0 ||
            (title ?? "").IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0;

        private void AcceptSuggestion(Suggestion s)
        {
            HideSuggest();
            var a = Active; if (a == null) return;
            if (s.Target.StartsWith("ddg:")) NavigateTab(a, "https://duckduckgo.com/?q=" + Uri.EscapeDataString(s.Target.Substring(4)));
            else NavigateTab(a, s.Target);
        }

        private void Suggest_Click(object sender, MouseButtonEventArgs e)
        {
            if (SuggestList.SelectedItem is Suggestion s) AcceptSuggestion(s);
            else if ((e.OriginalSource as FrameworkElement)?.DataContext is Suggestion s2) AcceptSuggestion(s2);
        }

        private void Address_KeyDown(object sender, KeyEventArgs e)
        {
            if (SuggestPopup.IsOpen && SuggestList.Items.Count > 0)
            {
                if (e.Key == Key.Down) { SuggestList.SelectedIndex = Math.Min(SuggestList.SelectedIndex + 1, SuggestList.Items.Count - 1); e.Handled = true; return; }
                if (e.Key == Key.Up)   { SuggestList.SelectedIndex = Math.Max(SuggestList.SelectedIndex - 1, 0); e.Handled = true; return; }
                if (e.Key == Key.Escape) { HideSuggest(); e.Handled = true; return; }
            }
            if (e.Key == Key.Enter)
            {
                if (SuggestPopup.IsOpen && SuggestList.SelectedItem is Suggestion s) AcceptSuggestion(s);
                else { HideSuggest(); var a = Active; if (a != null) NavigateTab(a, AddressBar.Text); }
                e.Handled = true;
            }
        }

        private void Address_GotFocus(object sender, RoutedEventArgs e)
        {
            if (!_suppressSuggest && AddressBar.Text.Trim().Length > 0) Address_TextChanged(sender, null!);
        }
        private void Address_LostFocus(object sender, RoutedEventArgs e)
        {
            if (SuggestPopup.IsOpen && (SuggestList.IsMouseOver || SuggestPopup.IsMouseOver)) return;
            HideSuggest();
        }
        private void HideSuggest() { SuggestPopup.IsOpen = false; }

        // ---- session export (5.4) ----------------------------------------------

        private void Export_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dir = Path.Combine(_repoRoot, "payload", "session_export");
                Directory.CreateDirectory(dir);
                int total = TotalVisits();

                WriteLf(Path.Combine(dir, "session.json"),
                    "{" + J("schema") + ":" + J("recognition.session.v1") + "," + J("session_id") + ":" + J(_sessionId) + "," +
                          J("started_utc") + ":" + J(Iso(_startedUtc)) + "," + J("exported_utc") + ":" + J(Iso(DateTime.UtcNow)) + "," +
                          J("tab_count") + ":" + _tabs.Count + "," + J("visit_count") + ":" + total + "," +
                          J("blocked_session") + ":" + _blockedSession + "," + J("blocking_enabled") + ":" + (_blockingEnabled ? "true" : "false") + "}");

                var tb = new StringBuilder("{" + J("schema") + ":" + J("recognition.tabs.v1") + "," + J("tabs") + ":[");
                for (int i = 0; i < _tabs.Count; i++)
                {
                    var t = _tabs[i];
                    var url = t.Private ? "recognition:private" : (t.IsInternal ? ("recognition:" + t.Internal) : t.CurrentUrl);
                    var ttl = t.Private ? "Private tab" : (t.IsInternal ? InternalTitle(t.Internal) : t.CurrentTitle);
                    if (i > 0) tb.Append(",");
                    tb.Append("{" + J("index") + ":" + i + "," + J("url_sha256") + ":" + J(Sha256Hex(url)) + "," +
                              J("title") + ":" + J(ttl) + "," +
                              J("blocked") + ":" + t.Blocked + "," + J("internal") + ":" + (t.IsInternal ? "true" : "false") + "," +
                              J("private") + ":" + (t.Private ? "true" : "false") + "}");
                }
                tb.Append("]}");
                WriteLf(Path.Combine(dir, "tabs.json"), tb.ToString());

                var sb = new StringBuilder(); int seq = 0;
                for (int i = 0; i < _tabs.Count; i++)
                {
                    if (_tabs[i].Private) continue;   // private tabs leave no exported trace
                    foreach (var v in _tabs[i].Visits)
                    {
                        seq++;
                        sb.Append("{" + J("seq") + ":" + seq + "," + J("tab_index") + ":" + i + "," + J("ts_utc") + ":" + J(Iso(v.Ts)) + "," +
                                  J("type") + ":" + J("navigation") + "," + J("url_sha256") + ":" + J(Sha256Hex(v.Url)) + "," + J("title") + ":" + J(v.Title) + "}\n");
                    }
                }
                WriteLf(Path.Combine(dir, "events.ndjson"), sb.ToString());

                WriteLf(Path.Combine(dir, "vpn_state.json"),
                    "{" + J("schema") + ":" + J("recognition.vpn_state.v1") + "," +
                          J("connected") + ":" + (NetActive() ? "true" : "false") + "," +
                          J("mode") + ":" + J(_netMode) + "," +
                          J("proxy_configured") + ":" + ((_netMode == "proxy" && !string.IsNullOrWhiteSpace(_netProxy)) ? "true" : "false") + "," +
                          J("provider") + ":null," +
                          J("exit_region") + ":" + (string.IsNullOrEmpty(_netExitRegion) ? "null" : J(_netExitRegion)) + "," +
                          J("since_utc") + ":null," + J("policy") + ":" + J("canonical") + "," +
                          J("https_first") + ":true," + J("telemetry") + ":false," +
                          J("tracker_blocking") + ":" + (_blockingEnabled ? "true" : "false") + "," +
                          J("blocked_session") + ":" + _blockedSession + "}");

                bool actOk = _actions.Verify(out int actVerified);
                WriteLf(Path.Combine(dir, "action_receipts.json"),
                    "{" + J("schema") + ":" + J("recognition.action_receipts.v1") + "," +
                          J("count") + ":" + _actions.Count + "," +
                          J("verified") + ":" + actVerified + "," +
                          J("chain_ok") + ":" + (actOk ? "true" : "false") + "," +
                          J("head_hash") + ":" + J(_actions.Head) + "}");

                bool cookChainOk = _cookies.Verify(out int cookChainVerified);
                WriteLf(Path.Combine(dir, "cookie_receipts.json"),
                    "{" + J("schema") + ":" + J("recognition.cookie_receipts.v1") + "," +
                          J("count") + ":" + _cookies.Count + "," +
                          J("verified") + ":" + cookChainVerified + "," +
                          J("chain_ok") + ":" + (cookChainOk ? "true" : "false") + "," +
                          J("head_hash") + ":" + J(_cookies.Head) + "}");

                bool spChainOk = _sitePolicy.Verify(out int spChainVerified);
                WriteLf(Path.Combine(dir, "site_policy_receipts.json"),
                    "{" + J("schema") + ":" + J("recognition.site_policy_receipts.v1") + "," +
                          J("count") + ":" + _sitePolicy.Count + "," +
                          J("verified") + ":" + spChainVerified + "," +
                          J("chain_ok") + ":" + (spChainOk ? "true" : "false") + "," +
                          J("distinct_decisions") + ":" + _sitePolicyState.Count + "," +
                          J("head_hash") + ":" + J(_sitePolicy.Head) + "}");

                var script = Path.Combine(_repoRoot, "scripts", "recognition_export_session_packet_v1.ps1");
                var psi = new ProcessStartInfo("powershell.exe",
                    $"-NoProfile -ExecutionPolicy Bypass -File \"{script}\" -RepoRoot \"{_repoRoot}\"")
                { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
                var p = Process.Start(psi)!;
                string outp = p.StandardOutput.ReadToEnd(); string err = p.StandardError.ReadToEnd(); p.WaitForExit();

                var m = Regex.Match(outp, @"EXPORT_OK:\s*(?<d>.+)");
                if (m.Success)
                {
                    var pkt = m.Groups["d"].Value.Trim();
                    _actions?.Append("session.export", pkt);
                    Status("Exported governed packet: " + Path.GetFileName(pkt));
                    MessageBox.Show(this, "Session exported as a governed evidence packet:\n\n" + pkt,
                        "Recognition — Export", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    Status("Export failed");
                    MessageBox.Show(this, "Export failed.\n\nSTDOUT:\n" + outp + "\n\nSTDERR:\n" + err,
                        "Recognition — Export", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex) { Status("export error: " + ex.Message); }
        }

        // ---- identity read ------------------------------------------------------

        private (string rid, string path) ReadIdentityId()
        {
            var path = Path.Combine(_repoRoot, "proofs", "identity", "identity.json");
            try
            {
                if (File.Exists(path))
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(path));
                    if (doc.RootElement.TryGetProperty("recognition_identity_id", out var v))
                        return (v.GetString() ?? "(unset)", path);
                }
            }
            catch { }
            return ("(not established yet)", path);
        }

        // ---- helpers ------------------------------------------------------------

        private static string Get(JsonElement r, string k) => r.TryGetProperty(k, out var v) ? (v.GetString() ?? "") : "";
        private static string Sha256Hex(string s)
        {
            var h = SHA256.HashData(Encoding.UTF8.GetBytes(s ?? ""));
            var sb = new StringBuilder(); foreach (var b in h) sb.Append(b.ToString("x2")); return sb.ToString();
        }
        private static string Iso(DateTime t) => t.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        private static string J(string s) => "\"" + (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
        private static string Esc(string s) => System.Net.WebUtility.HtmlEncode(s ?? "");
        private static string Attr(string s) => System.Net.WebUtility.HtmlEncode(s ?? "").Replace("'", "&#39;");
        private static void WriteLf(string path, string text)
        {
            text = (text ?? "").Replace("\r\n", "\n").Replace("\r", "\n");
            if (!text.EndsWith("\n")) text += "\n";
            File.WriteAllText(path, text, new UTF8Encoding(false));
        }

        // ---- at-rest encryption: Windows DPAPI, per-user (§23/§25/§26) -----------
        // History/bookmarks/downloads are ciphertext on disk, bound to the Windows
        // user account; the blob is useless on another account or machine. No passphrase.
        private static readonly UTF8Encoding EncNoBom = new(false);
        private static void WriteSecure(string path, string text)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var blob = ProtectedData.Protect(EncNoBom.GetBytes(text ?? ""), null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(path, blob);
        }
        private static string ReadSecure(string path)
        {
            if (!File.Exists(path)) return "";
            var bytes = File.ReadAllBytes(path);
            try { return EncNoBom.GetString(ProtectedData.Unprotect(bytes, null, DataProtectionScope.CurrentUser)); }
            catch { try { return EncNoBom.GetString(bytes); } catch { return ""; } }   // legacy plaintext (pre-encryption)
        }

        private void Status(string s) => StatusText.Text = s;

        // ---- governed, append-only, hash-chained history (§24) ------------------

        private sealed class GovernedHistory
        {
            public sealed class Item { public int Seq; public string Ts = ""; public string Url = ""; public string Title = ""; }
            public readonly List<Item> Items = new();
            private readonly List<string> _lines = new();     // exact ndjson lines (with hashes)
            private readonly string _path;
            private readonly string _legacy;
            private string _head = new string('0', 64);
            private static readonly UTF8Encoding Enc = new(false);

            public GovernedHistory(string path, string legacy) { _path = path; _legacy = legacy; }

            public void Load()
            {
                Items.Clear(); _lines.Clear(); _head = new string('0', 64);
                var text = ReadSecure(_path);
                bool migrated = false;
                if (text.Length == 0 && File.Exists(_legacy)) { text = File.ReadAllText(_legacy); migrated = true; }
                foreach (var raw in text.Split('\n'))
                {
                    var line = raw.Trim();
                    if (line.Length == 0) continue;
                    try
                    {
                        using var doc = JsonDocument.Parse(line);
                        var r = doc.RootElement;
                        Items.Add(new Item
                        {
                            Seq = r.TryGetProperty("seq", out var sq) ? sq.GetInt32() : Items.Count + 1,
                            Ts = GetS(r, "ts_utc"), Url = GetS(r, "url"), Title = GetS(r, "title")
                        });
                        _lines.Add(line);
                        if (r.TryGetProperty("hash", out var hv)) _head = hv.GetString() ?? _head;
                    }
                    catch { }
                }
                if (migrated) { Save(); try { File.Delete(_legacy); } catch { } }   // encrypt-in-place, drop plaintext
            }

            public void Append(string url, string title)
            {
                if (string.IsNullOrEmpty(url)) return;
                var seq = Items.Count + 1;
                var ts = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
                var body = "{" + JJ("seq") + ":" + seq + "," + JJ("ts_utc") + ":" + JJ(ts) + "," +
                           JJ("url") + ":" + JJ(url) + "," + JJ("title") + ":" + JJ(title ?? "") + "," + JJ("prev_hash") + ":" + JJ(_head) + "}";
                var hash = HashHex(body);
                var line = body.Substring(0, body.Length - 1) + "," + JJ("hash") + ":" + JJ(hash) + "}";
                _head = hash;
                Items.Add(new Item { Seq = seq, Ts = ts, Url = url, Title = title ?? "" });
                _lines.Add(line);
                Save();   // rewrite the whole DPAPI-encrypted file (chain preserved in-memory)
            }

            private void Save()
            {
                var sb = new StringBuilder();
                foreach (var l in _lines) { sb.Append(l); sb.Append('\n'); }
                WriteSecure(_path, sb.ToString());
            }

            public void Clear()
            {
                try { if (File.Exists(_path)) File.Delete(_path); } catch { }
                try { if (File.Exists(_legacy)) File.Delete(_legacy); } catch { }
                Items.Clear(); _lines.Clear(); _head = new string('0', 64);
            }

            private static string HashHex(string s)
            {
                var h = SHA256.HashData(Enc.GetBytes(s));
                var sb = new StringBuilder(); foreach (var b in h) sb.Append(b.ToString("x2")); return sb.ToString();
            }
            private static string JJ(string s) => "\"" + (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
            private static string GetS(JsonElement r, string k) => r.TryGetProperty(k, out var v) ? (v.GetString() ?? "") : "";
        }
    }
}
