using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Recognition.Browser
{
    // Setup snapshot: a portable, encrypted copy of how Recognition is set up (appearance, preferences,
    // bookmarks, optionally site decisions) that opens on another device with a TEMPORARY code. No account,
    // no server: the snapshot travels as a file or a pasted text blob; the code travels separately.
    // Pure logic (no WPF/WebView2) so browser.tests executes every rule below.
    //
    // Security properties (and honest limits):
    //  - AES-256-GCM, key = PBKDF2-SHA256(code, random salt, 600k iterations). The header (schema, KDF,
    //    iterations, salt) is bound as GCM associated data, so tampering with ANY part fails authentication.
    //  - The code is 100 bits of randomness (20 symbols) — safe to brute-force-resist even offline.
    //  - Nothing is kept on the source device: a snapshot exists only when the user asks for one, and the
    //    code is shown once. A snapshot can be applied any number of times (any device) until it expires.
    //    Expiry is enforced by the honest client; it cannot stop someone who holds BOTH the file and the
    //    code from decrypting it offline with modified software. Treat file + code like a password and
    //    send them by different routes.
    //  - Everything imported is re-validated (URLs http/https only, colours #rrggbb, ledger keys/values from
    //    fixed grammars) — a hostile or corrupted snapshot can't inject script, CSS or arbitrary policy.

    internal static class SetupCode
    {
        // Crockford base32 (no I, L, O, U): easy to read aloud / type, no ambiguous characters.
        private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        public const int Length = 20;

        public static string Generate()
        {
            var sb = new StringBuilder();
            for (int i = 0; i < Length; i++)
            {
                if (i > 0 && i % 5 == 0) sb.Append('-');
                sb.Append(Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)]);
            }
            return sb.ToString();
        }

        // Accepts any case, spaces/hyphens, and Crockford's O->0, I/L->1 corrections. "" when invalid.
        public static string Normalize(string? s)
        {
            var sb = new StringBuilder();
            foreach (var ch0 in (s ?? "").ToUpperInvariant())
            {
                if (ch0 == '-' || char.IsWhiteSpace(ch0)) continue;
                var ch = ch0 == 'O' ? '0' : (ch0 == 'I' || ch0 == 'L') ? '1' : ch0;
                if (Alphabet.IndexOf(ch) < 0) return "";
                sb.Append(ch);
            }
            return sb.Length == Length ? sb.ToString() : "";
        }
        public static bool IsValid(string? s) => Normalize(s).Length == Length;
    }

    internal sealed record OpenResult(bool Ok, string Reason, string PayloadJson, string SnapshotId, DateTime CreatedUtc, DateTime ExpiresUtc);

    internal static class SetupBlob
    {
        public const string Prefix = "RSETUP1:";
        public const string Schema = "recognition.setup.v1";
        public const int Iterations = 600_000;

        private static string B64Url(byte[] b) => Convert.ToBase64String(b).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        private static byte[] FromB64Url(string s)
        {
            s = s.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; case 1: throw new FormatException(); }
            return Convert.FromBase64String(s);
        }
        private static byte[] Aad(int iter, string saltB64) => Encoding.UTF8.GetBytes(Schema + "|pbkdf2-sha256|" + iter + "|" + saltB64);
        private static byte[] Key(string normCode, byte[] salt, int iter) =>
            Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(normCode), salt, iter, HashAlgorithmName.SHA256, 32);

        public static string Seal(string payloadJson, string code, int iterations = Iterations)
        {
            var norm = SetupCode.Normalize(code);
            if (norm.Length == 0) throw new ArgumentException("invalid setup code");
            var salt = RandomNumberGenerator.GetBytes(16);
            var nonce = RandomNumberGenerator.GetBytes(12);
            var saltB64 = Convert.ToBase64String(salt);
            var plain = Encoding.UTF8.GetBytes(payloadJson);
            var ct = new byte[plain.Length]; var tag = new byte[16];
            using (var aes = new AesGcm(Key(norm, salt, iterations), 16)) aes.Encrypt(nonce, plain, ct, tag, Aad(iterations, saltB64));
            var env = JsonSerializer.Serialize(new
            {
                schema = Schema, kdf = "pbkdf2-sha256", iter = iterations, salt = saltB64,
                nonce = Convert.ToBase64String(nonce), ct = Convert.ToBase64String(ct), tag = Convert.ToBase64String(tag)
            });
            return Prefix + B64Url(Encoding.UTF8.GetBytes(env));
        }

        // Never throws; every failure is a Reason. A wrong code and damaged data are indistinguishable on purpose.
        public static OpenResult Open(string blobText, string code, DateTime nowUtc, int maxIterations = 2_000_000)
        {
            OpenResult Fail(string why) => new(false, why, "", "", default, default);
            try
            {
                var t = new string((blobText ?? "").Where(c => !char.IsWhiteSpace(c)).ToArray());
                if (!t.StartsWith(Prefix, StringComparison.Ordinal)) return Fail("not a Recognition setup snapshot");
                var norm = SetupCode.Normalize(code);
                if (norm.Length == 0) return Fail("the code is not in the right format (20 letters/digits)");
                using var env = JsonDocument.Parse(FromB64Url(t.Substring(Prefix.Length)));
                var r = env.RootElement;
                if (r.GetProperty("schema").GetString() != Schema || r.GetProperty("kdf").GetString() != "pbkdf2-sha256") return Fail("unsupported snapshot version");
                int iter = r.GetProperty("iter").GetInt32();
                if (iter < 100_000 || iter > maxIterations) return Fail("snapshot uses unacceptable key-derivation settings");
                var saltB64 = r.GetProperty("salt").GetString() ?? "";
                var salt = Convert.FromBase64String(saltB64);
                var nonce = Convert.FromBase64String(r.GetProperty("nonce").GetString() ?? "");
                var ct = Convert.FromBase64String(r.GetProperty("ct").GetString() ?? "");
                var tag = Convert.FromBase64String(r.GetProperty("tag").GetString() ?? "");
                if (salt.Length != 16 || nonce.Length != 12 || tag.Length != 16 || ct.Length > 8 * 1024 * 1024) return Fail("damaged snapshot");
                var plain = new byte[ct.Length];
                try { using var aes = new AesGcm(Key(norm, salt, iter), 16); aes.Decrypt(nonce, ct, tag, plain, Aad(iter, saltB64)); }
                catch (CryptographicException) { return Fail("wrong code, or the snapshot was damaged or altered"); }

                var json = Encoding.UTF8.GetString(plain);
                using var doc = JsonDocument.Parse(json);
                var p = doc.RootElement;
                if (p.GetProperty("schema").GetString() != "recognition.setup.payload.v1") return Fail("unsupported snapshot contents");
                var id = p.GetProperty("snapshot_id").GetString() ?? "";
                var created = DateTime.Parse(p.GetProperty("created_utc").GetString()!, null, System.Globalization.DateTimeStyles.RoundtripKind).ToUniversalTime();
                var expires = DateTime.Parse(p.GetProperty("expires_utc").GetString()!, null, System.Globalization.DateTimeStyles.RoundtripKind).ToUniversalTime();
                if (id.Length < 8) return Fail("damaged snapshot id");
                if (nowUtc > expires) return new OpenResult(false, "this snapshot expired at " + expires.ToString("u") + " — create a new one on the source device", json, id, created, expires);
                return new OpenResult(true, "", json, id, created, expires);
            }
            catch { return Fail("damaged or unreadable snapshot"); }
        }
    }

    internal static class SetupPayload
    {
        public const string Schema = "recognition.setup.payload.v1";
        public static string Build(string snapshotId, DateTime createdUtc, DateTime expiresUtc, IDictionary<string, object> categories) =>
            JsonSerializer.Serialize(new
            {
                schema = Schema, snapshot_id = snapshotId,
                created_utc = createdUtc.ToUniversalTime().ToString("o"), expires_utc = expiresUtc.ToUniversalTime().ToString("o"),
                categories
            });
    }

    // Validators for everything that arrives inside a snapshot. Imported data is treated as hostile.
    internal static class SetupValidate
    {
        public static bool IsSafeUrl(string? u)
        {
            if (string.IsNullOrEmpty(u) || u.Length > 2048 || u.Any(char.IsControl)) return false;
            return Uri.TryCreate(u, UriKind.Absolute, out var x) && (x.Scheme == Uri.UriSchemeHttp || x.Scheme == Uri.UriSchemeHttps);
        }
        public static string CleanTitle(string? t)
        {
            var s = new string((t ?? "").Where(c => !char.IsControl(c)).ToArray()).Trim();
            return s.Length > 300 ? s.Substring(0, 300) : s;
        }
        public static bool IsSafeHome(string? u) => u == "recognition:start" || IsSafeUrl(u);

        private static readonly Regex OriginRx = new(@"^([a-z0-9]([a-z0-9.\-]{0,251}[a-z0-9])?|\[[0-9a-f:]+\])$", RegexOptions.Compiled);
        private static readonly Regex NetKeyRx = new(@"^net-[0-9a-f]{16}$", RegexOptions.Compiled);

        // Category of a site-policy key, or "" if it is not a key we ever export/import.
        public static string SiteCategory(string key)
        {
            if (key == "tracker_blocking" || Regex.IsMatch(key, @"^perm\.[A-Za-z]{3,30}$")) return "site_permissions";
            if (Regex.IsMatch(key, @"^cert\.(der|meta)-[0-9a-f]{16,64}$")) return "cert_trust";
            if (key == "netlabel") return "network_labels";
            return "";
        }

        public static bool IsValidSiteEntry(string? key, string? origin, string? value)
        {
            if (key == null || origin == null || value == null) return false;
            var cat = SiteCategory(key);
            if (cat == "") return false;
            if (cat == "network_labels") return NetKeyRx.IsMatch(origin) && (value is "none" or "trusted" or "guest" or "blocked");
            if (cat == "cert_trust") return OriginRx.IsMatch(origin) && (value is "allow" or "deny");
            if (!OriginRx.IsMatch(origin)) return false;
            return key == "tracker_blocking" ? value is "off" or "inherit" : value is "allow" or "deny";
        }
    }

    // The validated, ready-to-apply form of a snapshot. Anything invalid is dropped and counted.
    internal sealed class SetupPlan
    {
        public AppearanceSettings? Appearance;
        public string? HomeUrl; public bool? BlockingEnabled;
        public List<(string Url, string Title)> Bookmarks = new(); public int BookmarksRejected;
        public List<(string Key, string Origin, string Value, string Category)> SiteEntries = new(); public int SiteRejected;
        public List<string> UnknownCategories = new();

        public static SetupPlan Parse(string payloadJson)
        {
            var plan = new SetupPlan();
            using var doc = JsonDocument.Parse(payloadJson);
            if (!doc.RootElement.TryGetProperty("categories", out var cats) || cats.ValueKind != JsonValueKind.Object) return plan;
            foreach (var c in cats.EnumerateObject())
            {
                switch (c.Name)
                {
                    case "appearance":
                        if (c.Value.ValueKind == JsonValueKind.Object) { plan.Appearance = new AppearanceSettings(); plan.Appearance.FromJson(c.Value); }
                        break;
                    case "preferences":
                        if (c.Value.ValueKind != JsonValueKind.Object) break;
                        if (c.Value.TryGetProperty("home_url", out var hu) && hu.ValueKind == JsonValueKind.String && SetupValidate.IsSafeHome(hu.GetString())) plan.HomeUrl = hu.GetString();
                        if (c.Value.TryGetProperty("blocking_enabled", out var be) && (be.ValueKind == JsonValueKind.True || be.ValueKind == JsonValueKind.False)) plan.BlockingEnabled = be.GetBoolean();
                        break;
                    case "bookmarks":
                        if (c.Value.ValueKind != JsonValueKind.Array) break;
                        foreach (var b in c.Value.EnumerateArray())
                        {
                            var url = b.ValueKind == JsonValueKind.Object && b.TryGetProperty("url", out var u) && u.ValueKind == JsonValueKind.String ? u.GetString() : null;
                            var title = b.ValueKind == JsonValueKind.Object && b.TryGetProperty("title", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() : "";
                            if (SetupValidate.IsSafeUrl(url)) plan.Bookmarks.Add((url!, SetupValidate.CleanTitle(title))); else plan.BookmarksRejected++;
                        }
                        break;
                    case "site_permissions": case "cert_trust": case "network_labels":
                        if (c.Value.ValueKind != JsonValueKind.Array) break;
                        foreach (var e in c.Value.EnumerateArray())
                        {
                            string? K(string n) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
                            var key = K("key"); var origin = K("origin"); var value = K("value");
                            // the entry must also belong to the category it was filed under
                            if (SetupValidate.IsValidSiteEntry(key, origin, value) && SetupValidate.SiteCategory(key!) == c.Name) plan.SiteEntries.Add((key!, origin!, value!, c.Name));
                            else plan.SiteRejected++;
                        }
                        break;
                    default: plan.UnknownCategories.Add(c.Name); break;
                }
            }
            return plan;
        }
    }

}
