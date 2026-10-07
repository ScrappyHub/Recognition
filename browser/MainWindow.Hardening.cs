using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Web.WebView2.Core;

namespace Recognition.Browser
{
    // Browser-level hardening found by the audit (see docs\proposals\THREAT_MODEL_V1.md): pop-ups, external app launches,
    // the engine's own tracking prevention, and the engine version check. The decisions are in RuntimeCheck.cs (executed by tests).
    public partial class MainWindow
    {
        private int _popupsBlocked, _externalBlocked;
        private string _trackingLevel = "balanced";                 // off | basic | balanced | strict (persisted in browser_settings.json)
        private string _runtimeVersion = "";
        private RuntimeCheck.Verdict _runtimeVerdict = RuntimeCheck.Verdict.Unknown;

        // ---- pop-ups -------------------------------------------------------------------------------------------------------
        private void OnNewWindowRequested(object? sender, CoreWebView2NewWindowRequestedEventArgs e)
        {
            e.Handled = true;   // the engine never opens its own window; we decide here
            var origin = _tabs.FirstOrDefault(t => t.Web?.CoreWebView2 != null && ReferenceEquals(t.Web.CoreWebView2, sender));
            var uri = e.Uri ?? "";
            var pageHost = origin == null ? "" : TryHost(PageUrlFor(origin));
            bool siteAllows = !string.IsNullOrEmpty(pageHost) && SitePolicyGet(pageHost, "popups", "inherit") == "allow";
            switch (PopupRules.Decide(uri, e.IsUserInitiated, siteAllows))
            {
                case PopupVerdict.BlockedScheme:
                    _popupsBlocked++; Status("blocked a pop-up to a non-web address (" + ExternalUriRules.SchemeOf(uri) + ":)"); return;
                case PopupVerdict.BlockedNoGesture:
                    _popupsBlocked++; Status("blocked a pop-up that " + (string.IsNullOrEmpty(pageHost) ? "a page" : pageHost) + " opened without a click (allow it under Shield > Pop-ups)"); return;
            }
            bool priv = origin?.Private ?? false;   // a link opened from a private tab stays private
            bool blank = uri.Length == 0 || uri.StartsWith("about:", StringComparison.OrdinalIgnoreCase);
            _ = Dispatcher.InvokeAsync(async () =>
            {
                var t = await NewTabCoreAsync(priv ? "Private" : "New tab", priv);
                if (t == null) return;
                Tabs.SelectedItem = t.Item; ShowActiveWebView();
                if (blank) LoadInternal(t, "start"); else NavigateTab(t, uri);
            });
        }

        // ---- links that start other programs -----------------------------------------------------------------------------
        // Hooked through reflection so that an engine SDK without this event can never stop the browser from compiling or starting.
        private sealed class ExternalUriHook
        {
            private readonly MainWindow _w; private readonly BrowserTab _tab;
            public ExternalUriHook(MainWindow w, BrowserTab tab) { _w = w; _tab = tab; }
            public void Handle(object? sender, object args)
            {
                try
                {
                    var t = args.GetType();
                    var uri = t.GetProperty("Uri")?.GetValue(args) as string;
                    var user = t.GetProperty("IsUserInitiated")?.GetValue(args) is true;
                    _w.OnExternalUri(_tab, uri, user, () => t.GetProperty("Cancel")?.SetValue(args, true));
                }
                catch { }
            }
        }

        private void HookExternalUri(CoreWebView2 core, BrowserTab tab)
        {
            try
            {
                var ev = core.GetType().GetEvent("LaunchingExternalUriScheme");
                if (ev?.EventHandlerType == null) return;
                var del = Delegate.CreateDelegate(ev.EventHandlerType, new ExternalUriHook(this, tab), typeof(ExternalUriHook).GetMethod("Handle")!);
                ev.AddEventHandler(core, del);
            }
            catch { }
        }

        private void OnExternalUri(BrowserTab tab, string? uri, bool userInitiated, Action cancel)
        {
            if (ExternalUriRules.Allowed(uri, userInitiated)) return;   // mailto:/tel: you clicked: Windows' own confirmation still applies
            cancel(); _externalBlocked++;
            var scheme = ExternalUriRules.SchemeOf(uri);
            if (!tab.Private) _actions?.Append("external_uri.blocked", scheme);
            Status("blocked a page from opening another program (" + scheme + ":)");
        }

        // ---- the engine's tracking prevention (cookie and storage partitioning for known trackers) ------------------------------
        // Set through reflection: the property belongs to the engine's profile object in recent SDKs, and a missing property must
        // never stop the browser from starting.
        private void ApplyTrackingPrevention(CoreWebView2 core)
        {
            try
            {
                var prop = core.Profile.GetType().GetProperty("PreferredTrackingPreventionLevel");
                if (prop == null || !prop.PropertyType.IsEnum) return;
                var name = _trackingLevel switch { "off" => "None", "basic" => "Basic", "strict" => "Strict", _ => "Balanced" };
                prop.SetValue(core.Profile, Enum.Parse(prop.PropertyType, name, true));
            }
            catch { }
        }

        private void ApplyTrackingPreventionAll()
        {
            foreach (var t in _tabs.ToList()) if (t.Ready && t.Web?.CoreWebView2 != null) ApplyTrackingPrevention(t.Web.CoreWebView2);
        }

        // ---- engine version --------------------------------------------------------------------------------------------------
        private void CheckRuntimeVersion()
        {
            try
            {
                _runtimeVersion = CoreWebView2Environment.GetAvailableBrowserVersionString() ?? "";
                _runtimeVerdict = RuntimeCheck.Assess(_runtimeVersion);
                if (_runtimeVerdict == RuntimeCheck.Verdict.TooOld)
                {
                    _actions?.Append("engine.outdated", _runtimeVersion);
                    Status("WARNING: the web engine (WebView2 " + _runtimeVersion + ") is out of date and may be missing security fixes. See Settings.");
                }
            }
            catch { _runtimeVerdict = RuntimeCheck.Verdict.Unknown; }
        }

        private string EngineHtmlRow()
        {
            var v = string.IsNullOrEmpty(_runtimeVersion) ? "unknown" : Esc(_runtimeVersion);
            var note = _runtimeVerdict switch
            {
                RuntimeCheck.Verdict.TooOld => " &mdash; <b style='color:#e57373'>out of date.</b> The engine renders every page and is patched by Microsoft; update the WebView2 Runtime (Windows Update or <a class='t' href='" + RuntimeCheck.InstallerUrl + "'>Microsoft's installer</a>).",
                RuntimeCheck.Verdict.Ok => " &mdash; recent enough (minimum accepted: " + RuntimeCheck.MinSupportedMajor + ")",
                _ => " &mdash; could not be read"
            };
            return "<div class='kv'><div class='k'>Web engine</div><div class='v'>WebView2 " + v + note + "</div></div>";
        }
    }
}
