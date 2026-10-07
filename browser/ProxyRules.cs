using System;
using System.Linq;

namespace Recognition.Browser
{
    // Rules for the exits (proxies) a person adds to the VPN / proxy page. Everything typed there is checked here before it is stored or
    // handed to the web engine as a --proxy-server argument, so a typo or a pasted trick cannot add extra engine arguments.
    internal static class ProxyRules
    {
        public const int MaxExits = 40;

        // type: "socks5" or "http". Returns false with a plain-words reason.
        public static bool TryBuild(string? type, string? host, string? portText, out string proxy, out string error)
        {
            proxy = ""; error = "";
            var t = (type ?? "").Trim().ToLowerInvariant();
            if (t is not ("socks5" or "http")) { error = "Choose SOCKS5 or HTTP."; return false; }
            var h = (host ?? "").Trim().ToLowerInvariant();
            if (h.Length == 0 || h.Length > 253 || !NetParsers.IsSafeHost(h) || h.Contains(':')) { error = "Enter a host name or IPv4 address (letters, digits, dots and hyphens only)."; return false; }
            if (h.StartsWith("-", StringComparison.Ordinal) || h.EndsWith("-", StringComparison.Ordinal) || h.Contains("..")) { error = "That host name is not valid."; return false; }
            if (!int.TryParse((portText ?? "").Trim(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var port) || port < 1 || port > 65535) { error = "The port must be a number from 1 to 65535."; return false; }
            proxy = t + "://" + h + ":" + port;
            return true;
        }

        // A short label: letters, digits, space and a few marks. Anything else is dropped.
        public static string CleanName(string? name)
        {
            var s = new string((name ?? "").Where(c => char.IsAsciiLetterOrDigit(c) || c is ' ' or '-' or '_' or '.' or '(' or ')').ToArray()).Trim();
            return s.Length > 40 ? s.Substring(0, 40).Trim() : s;
        }

        // "socks5://host:1080" -> "SOCKS5 host:1080". Unknown shapes are shown as they are.
        public static string Describe(string? proxy)
        {
            var p = proxy ?? "";
            int i = p.IndexOf("://", StringComparison.Ordinal);
            if (i <= 0) return p;
            return p.Substring(0, i).ToUpperInvariant() + " " + p.Substring(i + 3);
        }

        // true when the exit is on this computer (a local VPN client's proxy)
        public static bool IsLocal(string? proxy)
        {
            var p = (proxy ?? "").ToLowerInvariant();
            int i = p.IndexOf("://", StringComparison.Ordinal); if (i >= 0) p = p.Substring(i + 3);
            return p.StartsWith("127.0.0.1:", StringComparison.Ordinal) || p.StartsWith("localhost:", StringComparison.Ordinal);
        }

        // A name that is unused (adds " 2", " 3"... when needed).
        public static string UniqueName(string name, Func<string, bool> exists)
        {
            if (!exists(name)) return name;
            for (int i = 2; i < 1000; i++) { var n = name + " " + i; if (!exists(n)) return n; }
            return name + " " + Guid.NewGuid().ToString("N").Substring(0, 6);
        }
    }
}
