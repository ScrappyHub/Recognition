using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Recognition.Browser
{
    // Password manager core. Pure logic (no WPF/WebView2) so browser.tests executes every rule here.
    //
    // Design rules:
    //  - Storage is injected; in the browser it is SecureStore (Windows DPAPI, current user). Honest limit:
    //    DPAPI protects the file at rest and from other Windows users, NOT from other programs running as you.
    //  - Passwords never leave the host process except (a) injected into the ONE matching page on an explicit
    //    Fill click, (b) the clipboard on an explicit Copy (auto-cleared), (c) the page for a few seconds on
    //    an explicit Reveal. They are never in receipts, logs, snapshots, or the list view.
    //  - Matching is exact: https (or http only for localhost), same host and port. No subdomain or
    //    "similar site" matching, so a look-alike or sibling origin never receives a credential.

    internal sealed class VaultEntry
    {
        public string Id = "", Origin = "", Username = "", Password = "", Note = "", CreatedUtc = "", UpdatedUtc = "";
    }

    internal static class PasswordGenerator
    {
        public const string Lower = "abcdefghijklmnopqrstuvwxyz", Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", Digits = "0123456789",
                            Symbols = "!@#$%^&*()-_=+[]{};:,.?";
        public const string Ambiguous = "O0oIl1|`'\"";

        public static string Generate(int length, bool lower = true, bool upper = true, bool digits = true, bool symbols = true, bool avoidAmbiguous = true)
        {
            var classes = new List<string>();
            string F(string s) => avoidAmbiguous ? new string(s.Where(c => Ambiguous.IndexOf(c) < 0).ToArray()) : s;
            if (lower) classes.Add(F(Lower)); if (upper) classes.Add(F(Upper)); if (digits) classes.Add(F(Digits)); if (symbols) classes.Add(F(Symbols));
            if (classes.Count == 0) throw new ArgumentException("choose at least one character type");
            if (length < 8 || length > 128) throw new ArgumentException("length must be 8 to 128");
            var all = string.Concat(classes);
            var chars = new List<char>();
            foreach (var c in classes) chars.Add(c[RandomNumberGenerator.GetInt32(c.Length)]);       // at least one of each chosen type
            while (chars.Count < length) chars.Add(all[RandomNumberGenerator.GetInt32(all.Length)]);   // GetInt32 is unbiased
            for (int i = chars.Count - 1; i > 0; i--) { int j = RandomNumberGenerator.GetInt32(i + 1); (chars[i], chars[j]) = (chars[j], chars[i]); }
            return new string(chars.ToArray());
        }
    }

    internal static class PasswordRules
    {
        private static readonly Regex HostRx = new(@"^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*(:[0-9]{1,5})?$", RegexOptions.Compiled);
        private static readonly string[] Common = { "password", "123456", "12345678", "qwerty", "letmein", "welcome", "admin", "iloveyou", "abc123", "111111", "passw0rd", "dragon", "monkey", "football" };

        // origin is "host" or "host:port", lower-case. Returns a normalised origin or null.
        public static string? NormalizeOrigin(string? s)
        {
            var o = (s ?? "").Trim().ToLowerInvariant();
            if (o.Length == 0 || o.Length > 260 || !HostRx.IsMatch(o)) return null;
            var i = o.LastIndexOf(':');
            if (i >= 0 && (!int.TryParse(o.Substring(i + 1), out var port) || port < 1 || port > 65535)) return null;
            return o;
        }

        // The origin of a page URL as the vault stores it: host, plus :port when it is not the scheme default.
        public static string? OriginOf(string? url)
        {
            if (string.IsNullOrEmpty(url) || !Uri.TryCreate(url, UriKind.Absolute, out var u)) return null;
            if (u.Scheme != Uri.UriSchemeHttps && u.Scheme != Uri.UriSchemeHttp) return null;
            if (u.UserInfo.Length > 0) return null;                       // https://example.com@evil.com/ and friends
            return u.IsDefaultPort ? u.Host.ToLowerInvariant() : u.Host.ToLowerInvariant() + ":" + u.Port;
        }

        // May a credential saved for entryOrigin be filled into the page at pageUrl? Exact match only.
        public static bool MayFill(string entryOrigin, string? pageUrl)
        {
            var eo = NormalizeOrigin(entryOrigin); var po = OriginOf(pageUrl);
            if (eo == null || po == null || eo != po) return false;
            var u = new Uri(pageUrl!);
            bool local = u.Host == "localhost" || u.Host == "127.0.0.1" || u.Host == "[::1]" || u.Host.EndsWith(".localhost");
            return u.Scheme == Uri.UriSchemeHttps || (u.Scheme == Uri.UriSchemeHttp && local);   // never fill over plain http on the internet
        }

        public static bool CleanField(string? s, int max, bool allowNewline = false) =>
            s != null && s.Length <= max && !s.Any(c => char.IsControl(c) && !(allowNewline && (c == '\n' || c == '\r' || c == '\t')));

        // Rough entropy estimate in bits (pool size from character classes, minus penalties). A guide, not a proof.
        public static double EntropyBits(string? p)
        {
            if (string.IsNullOrEmpty(p)) return 0;
            int pool = 0;
            if (p.Any(char.IsLower)) pool += 26; if (p.Any(char.IsUpper)) pool += 26; if (p.Any(char.IsDigit)) pool += 10;
            if (p.Any(c => !char.IsLetterOrDigit(c))) pool += 32;
            double bits = p.Length * Math.Log2(Math.Max(pool, 2));
            double distinct = p.Distinct().Count(); bits *= Math.Min(1.0, distinct / Math.Max(1, p.Length) * 1.5);      // heavy repetition
            if (Common.Any(c => p.ToLowerInvariant().Contains(c))) bits = Math.Min(bits, 20);
            int run = 1, seq = 0; for (int i = 1; i < p.Length; i++) { if (Math.Abs(p[i] - p[i - 1]) == 1) { run++; if (run >= 4) seq++; } else run = 1; }
            bits -= seq * 4;
            return Math.Max(0, bits);
        }
        public static string Strength(string? p) { var b = EntropyBits(p); return b < 40 ? "weak" : b < 60 ? "fair" : b < 80 ? "good" : "strong"; }
    }

    internal sealed record AuditIssue(string Id, string Kind);

    internal sealed class PasswordVault
    {
        private readonly string _path; private readonly Func<string, string> _read; private readonly Action<string, string> _write;
        private readonly List<VaultEntry> _items = new();
        public PasswordVault(string path, Func<string, string>? read = null, Action<string, string>? write = null)
        { _path = path; _read = read ?? SecureStore.ReadSecure; _write = write ?? SecureStore.WriteSecure; }

        public IReadOnlyList<VaultEntry> Entries => _items;

        // Tolerant: damaged records are skipped, not fatal. Returns the number skipped.
        public int Load()
        {
            _items.Clear(); int skipped = 0;
            var text = _read(_path);
            if (string.IsNullOrWhiteSpace(text)) return 0;
            try
            {
                using var d = JsonDocument.Parse(text);
                if (d.RootElement.ValueKind != JsonValueKind.Object || !d.RootElement.TryGetProperty("entries", out var arr) || arr.ValueKind != JsonValueKind.Array) return 1;
                foreach (var e in arr.EnumerateArray())
                {
                    string S(string k) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
                    var en = new VaultEntry { Id = S("id"), Origin = S("origin"), Username = S("username"), Password = S("password"), Note = S("note"), CreatedUtc = S("created_utc"), UpdatedUtc = S("updated_utc") };
                    if (en.Id.Length < 8 || PasswordRules.NormalizeOrigin(en.Origin) == null || en.Password.Length == 0 || _items.Any(x => x.Id == en.Id)) { skipped++; continue; }
                    _items.Add(en);
                }
            }
            catch { _items.Clear(); return 1; }
            return skipped;
        }

        private void Save()
        {
            var json = JsonSerializer.Serialize(new
            {
                schema = "recognition.vault.v1",
                entries = _items.Select(e => new { id = e.Id, origin = e.Origin, username = e.Username, password = e.Password, note = e.Note, created_utc = e.CreatedUtc, updated_utc = e.UpdatedUtc })
            });
            _write(_path, json);
        }

        private static string? Validate(string? origin, string? username, string? password, string? note, out string normOrigin)
        {
            normOrigin = PasswordRules.NormalizeOrigin(origin) ?? "";
            if (normOrigin.Length == 0) return "site must be a host name like example.com (no https://, no path)";
            if (!PasswordRules.CleanField(username, 320)) return "username is too long or contains control characters";
            if (string.IsNullOrEmpty(password) || !PasswordRules.CleanField(password, 1024)) return "password is empty, too long, or contains control characters";
            if (!PasswordRules.CleanField(note, 2000, allowNewline: true)) return "note is too long or contains control characters";
            return null;
        }

        // Returns null on success, else a human-readable error. One entry per (origin, username).
        public string? Add(string? origin, string? username, string? password, string? note, DateTime nowUtc, out VaultEntry? added)
        {
            added = null;
            var err = Validate(origin, username, password, note, out var o); if (err != null) return err;
            if (_items.Any(x => x.Origin == o && string.Equals(x.Username, username, StringComparison.Ordinal))) return "an entry for this site and username already exists (edit it instead)";
            var ts = nowUtc.ToUniversalTime().ToString("o");
            added = new VaultEntry { Id = Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant(), Origin = o, Username = username ?? "", Password = password!, Note = note ?? "", CreatedUtc = ts, UpdatedUtc = ts };
            _items.Add(added); Save(); return null;
        }

        public string? Update(string id, string? username, string? password, string? note, DateTime nowUtc)
        {
            var e = _items.FirstOrDefault(x => x.Id == id); if (e == null) return "no such entry";
            var err = Validate(e.Origin, username, password, note, out _); if (err != null) return err;
            if (_items.Any(x => x != e && x.Origin == e.Origin && string.Equals(x.Username, username, StringComparison.Ordinal))) return "another entry for this site already uses that username";
            e.Username = username ?? ""; e.Password = password!; e.Note = note ?? ""; e.UpdatedUtc = nowUtc.ToUniversalTime().ToString("o");
            Save(); return null;
        }

        public bool Remove(string id) { var n = _items.RemoveAll(x => x.Id == id); if (n > 0) Save(); return n > 0; }
        public VaultEntry? Get(string id) => _items.FirstOrDefault(x => x.Id == id);

        // Entries whose origin exactly matches the page (used for Fill).
        public List<VaultEntry> ForPage(string? pageUrl) => _items.Where(e => PasswordRules.MayFill(e.Origin, pageUrl)).ToList();

        public List<AuditIssue> Audit()
        {
            var r = new List<AuditIssue>();
            foreach (var e in _items)
            {
                if (PasswordRules.EntropyBits(e.Password) < 40) r.Add(new AuditIssue(e.Id, "weak"));
                if (_items.Count(x => x.Password == e.Password) > 1) r.Add(new AuditIssue(e.Id, "reused"));
            }
            return r;
        }
    }

    internal static class FillScript
    {
        // JS run in the matching page on an explicit Fill. Values are embedded as JSON string literals (no
        // concatenation of raw text). Fills the first visible password field and the closest visible
        // username-like field before it; fires input/change events so frameworks notice. Returns a status string.
        public static string Build(string username, string password) =>
            "(function(u,p){function vis(e){var r=e.getBoundingClientRect();var s=getComputedStyle(e);return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none'&&!e.disabled&&!e.readOnly}" +
            "function set(e,v){var d=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value');d.set.call(e,v);e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}))}" +
            "var pws=[].slice.call(document.querySelectorAll('input[type=password]')).filter(vis);if(!pws.length)return 'no-password-field';var pw=pws[0];" +
            "var scope=pw.form||document;var us=[].slice.call(scope.querySelectorAll('input')).filter(function(e){var t=(e.type||'text').toLowerCase();return vis(e)&&(t==='text'||t==='email'||t==='tel')});" +
            "var uf=null;for(var i=0;i<us.length;i++){if(us[i].compareDocumentPosition(pw)&Node.DOCUMENT_POSITION_FOLLOWING)uf=us[i];}" +
            "if(u&&uf)set(uf,u);set(pw,p);return uf||!u?'ok':'ok-password-only';})(" +
            JsonSerializer.Serialize(username) + "," + JsonSerializer.Serialize(password) + ")";
    }
}
