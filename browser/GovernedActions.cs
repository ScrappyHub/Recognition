using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Recognition.Browser
{
    // At-rest encryption: Windows DPAPI, per-user (§23/§25/§26). Ciphertext on disk, bound to
    // the Windows account; useless on another account/machine. No passphrase.
    internal static class SecureStore
    {
        private static readonly UTF8Encoding EncNoBom = new(false);
        public static void WriteSecure(string path, string text)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var blob = ProtectedData.Protect(EncNoBom.GetBytes(text ?? ""), null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(path, blob);
        }
        public static string ReadSecure(string path)
        {
            if (!File.Exists(path)) return "";
            var bytes = File.ReadAllBytes(path);
            try { return EncNoBom.GetString(ProtectedData.Unprotect(bytes, null, DataProtectionScope.CurrentUser)); }
            catch { try { return EncNoBom.GetString(bytes); } catch { return ""; } }   // legacy plaintext (pre-encryption)
        }
    }

    // Governed action receipts (§13/§15): prove-it-in-every-action.
    // Every meaningful browser action appends one append-only, hash-chained, DPAPI-encrypted
    // receipt. Sensitive detail (URLs, paths) is stored ONLY as a SHA-256, never cleartext. The
    // chain links seq -> prev_hash -> hash so nothing can be modified, reordered, missing, or
    // forged without Verify() failing. Also the ledger used for cookie, site-policy and
    // certificate-trust decisions.
    //
    // This class lives in its own file (no WPF dependency) so the SAME source is compiled into
    // the browser AND into browser.tests, which executes it directly — the selftests no longer
    // rely only on a PowerShell mirror of the algorithm. Storage is injectable for testing;
    // the default is DPAPI.
    internal sealed class GovernedActions
    {
        public sealed class Rec { public int Seq; public string Ts = ""; public string Action = ""; public string DetailSha = ""; public string Hash = ""; }
        public readonly List<Rec> Items = new();
        private readonly List<string> _lines = new();
        private readonly string _path;
        private readonly Func<string, string> _read;
        private readonly Action<string, string> _write;
        private string _head = new string('0', 64);
        private static readonly UTF8Encoding Enc = new(false);
        public string Head => _head;
        public int Count => Items.Count;
        // Raw record lines, exactly as persisted (used by tests to tamper / compare to golden vectors).
        public IReadOnlyList<string> RawLines => _lines;

        public GovernedActions(string path, Func<string, string>? read = null, Action<string, string>? write = null)
        {
            _path = path;
            _read = read ?? SecureStore.ReadSecure;
            _write = write ?? SecureStore.WriteSecure;
        }

        public void Load()
        {
            Items.Clear(); _lines.Clear(); _head = new string('0', 64);
            var text = _read(_path);
            foreach (var raw in text.Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0) continue;
                try
                {
                    using var doc = JsonDocument.Parse(line);
                    var r = doc.RootElement;
                    Items.Add(new Rec
                    {
                        Seq = r.TryGetProperty("seq", out var sq) ? sq.GetInt32() : Items.Count + 1,
                        Ts = GetS(r, "ts_utc"), Action = GetS(r, "action"), DetailSha = GetS(r, "detail_sha256"),
                        Hash = GetS(r, "hash")
                    });
                    _lines.Add(line);
                    if (r.TryGetProperty("hash", out var hv)) _head = hv.GetString() ?? _head;
                }
                catch { }
            }
        }

        // detail is hashed here; callers pass cleartext and it never touches disk.
        public void Append(string action, string detail = "") => AppendAt(action, detail, DateTime.UtcNow);

        // Same as Append but with an explicit timestamp (deterministic, for golden-vector tests).
        public void AppendAt(string action, string detail, DateTime tsUtc)
        {
            if (string.IsNullOrEmpty(action)) return;
            var seq = Items.Count + 1;
            var ts = tsUtc.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            var detailSha = string.IsNullOrEmpty(detail) ? "" : HashHex(detail);
            var body = "{" + JJ("seq") + ":" + seq + "," + JJ("ts_utc") + ":" + JJ(ts) + "," +
                       JJ("action") + ":" + JJ(action) + "," + JJ("detail_sha256") + ":" + JJ(detailSha) + "," +
                       JJ("prev_hash") + ":" + JJ(_head) + "}";
            var hash = HashHex(body);
            var line = body.Substring(0, body.Length - 1) + "," + JJ("hash") + ":" + JJ(hash) + "}";
            _head = hash;
            Items.Add(new Rec { Seq = seq, Ts = ts, Action = action, DetailSha = detailSha, Hash = hash });
            _lines.Add(line);
            Save();
        }

        // Recompute the chain: every record's body-hash must match, prev_hash must link to the
        // prior record's hash, and seq must be contiguous. Returns false on any tamper / reorder /
        // missing / forged record. The body is recovered by text surgery on the raw line (not by
        // re-serializing parsed JSON fields) so the recomputed hash input is byte-identical to what
        // Append() actually hashed.
        public bool Verify(out int verified)
        {
            verified = 0;
            var prev = new string('0', 64);
            int expectSeq = 1;
            var marker = "," + JJ("hash") + ":";
            foreach (var line in _lines)
            {
                try
                {
                    using var doc = JsonDocument.Parse(line);
                    var r = doc.RootElement;
                    int seq = r.GetProperty("seq").GetInt32();
                    string ph = GetS(r, "prev_hash"), h = GetS(r, "hash");
                    if (seq != expectSeq) return false;
                    if (ph != prev) return false;
                    int idx = line.LastIndexOf(marker, StringComparison.Ordinal);
                    if (idx < 0) return false;
                    var body = line.Substring(0, idx) + "}";
                    if (HashHex(body) != h) return false;
                    prev = h; expectSeq++; verified++;
                }
                catch { return false; }
            }
            return true;
        }

        private void Save()
        {
            var sb = new StringBuilder();
            foreach (var l in _lines) { sb.Append(l); sb.Append('\n'); }
            _write(_path, sb.ToString());
        }

        public void Clear()
        {
            try { if (File.Exists(_path)) File.Delete(_path); } catch { }
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
