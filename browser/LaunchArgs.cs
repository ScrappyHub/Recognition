using System;
using System.IO;
using System.Linq;

namespace Recognition.Browser
{
    // Addresses handed to Recognition from outside: the command line (Windows passes the link or file you opened when Recognition is
    // your default browser) and the message a second launch sends to the running one. Both are untrusted input from other programs,
    // so only two kinds of address are accepted:
    //  * an http or https link with a host and no user name or password in it (the "https://bank.com@evil.com" trick), and
    //  * a local .htm / .html / .xhtml file that exists (opened as a file address).
    // Everything else (javascript:, data:, ms-*:, file shares, other schemes, control characters, huge strings) is ignored.
    internal static class LaunchArgs
    {
        public const int MaxLen = 4096;

        public static string? Parse(string? arg, Func<string, bool>? fileExists = null)
        {
            if (string.IsNullOrWhiteSpace(arg)) return null;
            var a = arg.Trim();
            if (a.Length > MaxLen || a.Any(c => c < 32 || c == 127)) return null;

            if (Uri.TryCreate(a, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps))
            {
                if (u.UserInfo.Length > 0 || string.IsNullOrEmpty(u.Host)) return null;
                return u.AbsoluteUri;
            }

            // a local file: a drive path (not a UNC share), with a web-page extension, that exists
            if (a.Length >= 4 && char.IsAsciiLetter(a[0]) && a[1] == ':' && (a[2] == '\\' || a[2] == '/'))
            {
                var ext = Path.GetExtension(a).ToLowerInvariant();
                if ((ext is ".htm" or ".html" or ".xhtml") && fileExists != null && fileExists(a) && Uri.TryCreate(a, UriKind.Absolute, out var f) && f.IsFile && !f.IsUnc)
                    return f.AbsoluteUri;
            }
            return null;
        }

        // The first argument that is an acceptable address. Switches (starting with - or /) are ignored.
        public static string? FromArgs(string[]? args, Func<string, bool>? fileExists = null)
        {
            if (args == null) return null;
            foreach (var a in args.Take(16))
            {
                if (a == null) continue;
                if (a.StartsWith("-", StringComparison.Ordinal) || (a.StartsWith("/", StringComparison.Ordinal) && !a.StartsWith("//", StringComparison.Ordinal) && a.IndexOf(':') < 0)) continue;
                var r = Parse(a, fileExists);
                if (r != null) return r;
            }
            return null;
        }
    }
}
