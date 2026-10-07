using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;

namespace Recognition.Browser
{
    // Pure privacy rules (no WPF/WebView2): HTTPS upgrade decision and tracking-parameter stripping.
    // Executed by browser.tests. Behaviour is deliberately conservative: strip only well-known pure-tracking
    // query parameters, keep everything else byte-for-byte (order, encoding, fragment), never touch redirects
    // or form posts (handled by the caller), and never upgrade loopback addresses.
    internal static class PrivacyRules
    {
        private static readonly HashSet<string> TrackingParams = new(StringComparer.Ordinal)
        {
            "fbclid", "gclid", "gclsrc", "dclid", "gbraid", "wbraid", "msclkid", "yclid", "twclid", "ttclid", "li_fat_id",
            "igshid", "mc_cid", "mc_eid", "_hsenc", "_hsmi", "hsctatracking", "mkt_tok", "vero_id", "oly_enc_id", "oly_anon_id",
            "ref_src", "s_kwcid", "ef_id", "_ga", "_gl", "mibextid"
        };

        public static bool IsLoopbackHost(string? host)
        {
            if (string.IsNullOrEmpty(host)) return false;
            var h = host.Trim().TrimStart('[').TrimEnd(']').ToLowerInvariant();
            if (h == "localhost" || h.EndsWith(".localhost", StringComparison.Ordinal)) return true;
            return IPAddress.TryParse(h, out var ip) && IPAddress.IsLoopback(ip);
        }

        // If url is plain http to a non-loopback host, returns the https equivalent; otherwise null (no upgrade).
        // Parses the URL properly: "http://localhost.evil.com/" is NOT loopback and IS upgraded.
        public static string? HttpsUpgrade(string? url)
        {
            if (string.IsNullOrEmpty(url) || !Uri.TryCreate(url, UriKind.Absolute, out var u)) return null;
            if (u.Scheme != Uri.UriSchemeHttp || IsLoopbackHost(u.Host)) return null;
            var b = new UriBuilder(u) { Scheme = Uri.UriSchemeHttps, Port = u.IsDefaultPort ? -1 : u.Port };
            return b.Uri.AbsoluteUri;
        }

        public static bool IsTrackingParam(string name)
        {
            var n = name.ToLowerInvariant();
            return n.StartsWith("utm_", StringComparison.Ordinal) || TrackingParams.Contains(n);
        }

        // Removes known tracking parameters. Returns the original string unchanged when there is nothing to remove.
        public static string StripTrackingParams(string? url, out int removed)
        {
            removed = 0;
            if (string.IsNullOrEmpty(url)) return url ?? "";
            if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps)) return url;
            int hash = url.IndexOf('#'); string frag = hash >= 0 ? url.Substring(hash) : ""; string noFrag = hash >= 0 ? url.Substring(0, hash) : url;
            int q = noFrag.IndexOf('?'); if (q < 0) return url;
            string basePart = noFrag.Substring(0, q), query = noFrag.Substring(q + 1);
            var kept = new List<string>();
            foreach (var part in query.Split('&'))
            {
                if (part.Length == 0) { kept.Add(part); continue; }
                int eq = part.IndexOf('=');
                var rawName = eq >= 0 ? part.Substring(0, eq) : part;
                string name; try { name = Uri.UnescapeDataString(rawName.Replace('+', ' ')); } catch { name = rawName; }
                if (IsTrackingParam(name)) { removed++; continue; }
                kept.Add(part);
            }
            if (removed == 0) return url;
            var q2 = string.Join("&", kept.Where(k => k.Length > 0));
            return basePart + (q2.Length > 0 ? "?" + q2 : "") + frag;
        }
    }
}
