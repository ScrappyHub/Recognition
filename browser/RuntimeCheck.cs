using System;
using System.Globalization;
using System.Linq;

namespace Recognition.Browser
{
    // Web engine (WebView2 runtime) freshness. The engine does all page rendering and carries almost all of the browser's attack
    // surface, and it is patched by Microsoft, not by Recognition. An engine that is years behind is the biggest inherited risk, so the
    // browser reads the installed version and warns when it is below a floor. The floor is a conservative lower bound (about two years
    // of Chromium releases): raise it with each release of Recognition.
    // Pop-ups: a page may open a new tab only in response to your click or key press. Scripted pop-ups are blocked unless you allowed
    // that site. A pop-up may only go to an http(s) address (never file:, data:, javascript:, ms-*: and the like), and a pop-up opened
    // from a private tab stays private.
    internal enum PopupVerdict { Allow, BlockedNoGesture, BlockedScheme }

    internal static class PopupRules
    {
        public static PopupVerdict Decide(string? uri, bool userInitiated, bool siteAllowsScripted)
        {
            var u = (uri ?? "").Trim();
            bool blank = u.Length == 0 || string.Equals(u, "about:blank", StringComparison.OrdinalIgnoreCase);
            bool web = u.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || u.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
            if (!blank && !web) return PopupVerdict.BlockedScheme;
            if (!userInitiated && !siteAllowsScripted) return PopupVerdict.BlockedNoGesture;
            return PopupVerdict.Allow;
        }
    }

    // Links that ask Windows to start another program (mailto:, ms-msdt:, search-ms:, ...). Only mail and phone links are allowed,
    // and only when you clicked them.
    internal static class ExternalUriRules
    {
        public static bool Allowed(string? uri, bool userInitiated)
        {
            if (!userInitiated) return false;
            var u = (uri ?? "").Trim(); int c = u.IndexOf(':');
            if (c <= 0 || c > 12) return false;
            var scheme = u.Substring(0, c).ToLowerInvariant();
            return scheme == "mailto" || scheme == "tel";
        }
        public static string SchemeOf(string? uri) { var u = (uri ?? "").Trim(); int c = u.IndexOf(':'); return c > 0 && c <= 24 ? u.Substring(0, c).ToLowerInvariant() : "unknown"; }
    }

    internal static class RuntimeCheck
    {
        public const int MinSupportedMajor = 128;
        public const string InstallerUrl = "https://developer.microsoft.com/microsoft-edge/webview2/";

        // "141.0.3537.57" or "142.0.3595.3 canary" -> [141,0,3537,57]. Returns null when it does not look like a version.
        public static int[]? Parse(string? version)
        {
            if (string.IsNullOrWhiteSpace(version)) return null;
            var first = version.Trim().Split(' ', '\t')[0];
            var parts = first.Split('.');
            if (parts.Length < 1 || parts.Length > 6) return null;
            var nums = new int[parts.Length];
            for (int i = 0; i < parts.Length; i++)
                if (!int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out nums[i]) || nums[i] < 0) return null;
            return nums;
        }

        public static int Compare(int[] a, int[] b)
        {
            int n = Math.Max(a.Length, b.Length);
            for (int i = 0; i < n; i++)
            {
                int x = i < a.Length ? a[i] : 0, y = i < b.Length ? b[i] : 0;
                if (x != y) return x < y ? -1 : 1;
            }
            return 0;
        }

        public enum Verdict { Unknown, Ok, TooOld }

        public static Verdict Assess(string? installedVersion, int minMajor = MinSupportedMajor)
        {
            var v = Parse(installedVersion);
            if (v == null) return Verdict.Unknown;
            return v[0] < minMajor ? Verdict.TooOld : Verdict.Ok;
        }
    }
}
