using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Recognition.Browser
{
    // C# implementation of the same extension governance that scripts\_lib_recognition_extension_governance_v1.ps1 defines:
    //   extension_id = SHA-256( canonical JSON of [ the path-sorted [{path, sha256, size}] list ] )   (note the extra outer array)
    //   decision     = deterministic function of (manifest, id, policy)
    //   ledger       = hash-chained NDJSON (record_hash over the canonical record, prev_hash links), genesis = 64 zeros
    // The browser needs this natively because the load gate must not depend on PowerShell being installed. The two implementations
    // read and write the SAME ledger file (proofs\receipts\recognition.extension_governance.v1.ndjson), so a record written here
    // passes the PowerShell verify-chain and the other way round. browser.tests checks this against an independently produced ledger.
    //
    // The browser never decides to trust something by itself. Installing is a user action that appends a record; loading re-computes
    // the identity from the bytes on disk and refuses unless the latest record for those exact bytes says "allow".
    internal sealed class ExtGovException : Exception { public ExtGovException(string m) : base(m) { } }

    internal sealed record ExtFile(string Path, string Sha256, long Size);

    internal sealed class ExtIdentity
    {
        public string Id = "";
        public List<ExtFile> Files = new();
        public long TotalBytes;
    }

    internal sealed class ExtManifest
    {
        public string Name = "", Version = "", Description = "";
        public int ManifestVersion;
        public List<string> Permissions = new();        // API permissions (the PowerShell reader's "permissions")
        public List<string> HostPermissions = new();    // host_permissions plus URL-looking entries from permissions
        public List<string> ContentScriptMatches = new();   // shown to the user; the policy (like the PowerShell one) does not score these
        public List<string> OptionalPermissions = new();    // shown to the user; not scored
    }

    internal sealed class ExtPolicy
    {
        public int MaxManifestVersion = 3, MinManifestVersion = 2;
        public HashSet<string> Denied = new(StringComparer.Ordinal), Review = new(StringComparer.Ordinal), Allowed = new(StringComparer.Ordinal);
        public HashSet<string> Allowlist = new(StringComparer.Ordinal), Blocklist = new(StringComparer.Ordinal);
    }

    internal sealed record ExtDecision(string Decision, List<string> Reasons);

    internal sealed class ExtLedgerRecord
    {
        public long Seq;
        public string ExtensionId = "", Name = "", Version = "", PolicyDecision = "", RecordHash = "", PrevHash = "", TsUtc = "";
        public List<string> Reasons = new();
    }

    internal static class ExtGovernance
    {
        public const int MaxFiles = 20000;
        public const long MaxTotalBytes = 300L * 1024 * 1024;
        public static readonly string Genesis = new string('0', 64);
        public const string Schema = "recognition.extension_governance.v1";

        // ---- canonical JSON (matches RCE-CanonJson: keys sorted, no whitespace, only quote, backslash and control characters escaped) ----
        public static string JsonEscape(string s)
        {
            var sb = new StringBuilder();
            foreach (var ch in s)
            {
                switch (ch)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (ch < 32) sb.Append("\\u").Append(((int)ch).ToString("x4", CultureInfo.InvariantCulture)); else sb.Append(ch);
                        break;
                }
            }
            return sb.ToString();
        }

        public static string Canon(object? v)
        {
            var sb = new StringBuilder(); Emit(v, sb); return sb.ToString();
        }

        private static void Emit(object? v, StringBuilder sb)
        {
            switch (v)
            {
                case null: sb.Append("null"); return;
                case bool b: sb.Append(b ? "true" : "false"); return;
                case string s: sb.Append('"').Append(JsonEscape(s)).Append('"'); return;
                case int or long or short or byte or uint or ulong or ushort or sbyte: sb.Append(Convert.ToString(v, CultureInfo.InvariantCulture)); return;
                case double or float or decimal: sb.Append(Convert.ToString(v, CultureInfo.InvariantCulture)); return;
                case IDictionary<string, object?> d:
                {
                    sb.Append('{'); bool first = true;
                    foreach (var k in d.Keys.OrderBy(x => x, StringComparer.Ordinal))
                    {
                        if (!first) sb.Append(','); first = false;
                        sb.Append('"').Append(JsonEscape(k)).Append("\":"); Emit(d[k], sb);
                    }
                    sb.Append('}'); return;
                }
                case System.Collections.IEnumerable e:
                {
                    sb.Append('['); bool first = true;
                    foreach (var it in e) { if (!first) sb.Append(','); first = false; Emit(it, sb); }
                    sb.Append(']'); return;
                }
                default: sb.Append('"').Append(JsonEscape(Convert.ToString(v, CultureInfo.InvariantCulture) ?? "")).Append('"'); return;
            }
        }

        public static string Sha256Hex(string s) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
        private static string Sha256Hex(byte[] b) => Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();

        // JsonElement -> plain objects (long for integers, like the PowerShell parser), so records can be re-canonicalised.
        public static object? ToObj(JsonElement e)
        {
            switch (e.ValueKind)
            {
                case JsonValueKind.Object: { var d = new Dictionary<string, object?>(StringComparer.Ordinal); foreach (var p in e.EnumerateObject()) d[p.Name] = ToObj(p.Value); return d; }
                case JsonValueKind.Array: { var l = new List<object?>(); foreach (var it in e.EnumerateArray()) l.Add(ToObj(it)); return l; }
                case JsonValueKind.String: return e.GetString();
                case JsonValueKind.Number: return e.TryGetInt64(out var n) ? n : e.GetDecimal();
                case JsonValueKind.True: return true;
                case JsonValueKind.False: return false;
                default: return null;
            }
        }

        // ---- identity -------------------------------------------------------------------------------------------------------------
        public static ExtIdentity ComputeIdentity(string root)
        {
            if (!Directory.Exists(root)) throw new ExtGovException("EXT_ROOT_MISSING");
            var full = Path.GetFullPath(root);
            var files = new List<ExtFile>(); long total = 0;
            foreach (var f in Directory.EnumerateFiles(full, "*", new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = 0, IgnoreInaccessible = false, MatchType = MatchType.Simple }))
            {
                var rel = Path.GetRelativePath(full, f).Replace('\\', '/');
                if (("/" + rel).Contains("/.git/", StringComparison.Ordinal)) continue;
                var fi = new FileInfo(f);
                if ((fi.Attributes & FileAttributes.ReparsePoint) != 0) throw new ExtGovException("EXT_HAS_LINK: " + rel);
                for (var dir = fi.Directory; dir != null && dir.FullName.Length > full.Length; dir = dir.Parent)
                    if ((dir.Attributes & FileAttributes.ReparsePoint) != 0) throw new ExtGovException("EXT_HAS_LINK: " + rel);
                if (files.Count >= MaxFiles) throw new ExtGovException("EXT_TOO_MANY_FILES");
                total += fi.Length; if (total > MaxTotalBytes) throw new ExtGovException("EXT_TOO_LARGE");
                files.Add(new ExtFile(rel, Sha256Hex(File.ReadAllBytes(f)), fi.Length));
            }
            if (files.Count == 0) throw new ExtGovException("EXT_EMPTY");
            files.Sort((a, b) => string.CompareOrdinal(a.Path, b.Path));
            // NB: the PowerShell reference hashes `RCE-CanonJson (,$sorted)`, i.e. the file list wrapped in ONE more array: [[{...},{...}]].
            // That is part of the identity definition (the real ledger records were produced this way), so it is reproduced exactly.
            var list = files.Select(x => (object?)new Dictionary<string, object?> { ["path"] = x.Path, ["sha256"] = x.Sha256, ["size"] = x.Size }).ToList();
            var canon = Canon(new List<object?> { list });
            return new ExtIdentity { Id = Sha256Hex(canon), Files = files, TotalBytes = total };
        }

        // ---- manifest -------------------------------------------------------------------------------------------------------------
        private static List<string> Strings(JsonElement root, string name)
        {
            var l = new List<string>();
            if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out var a) && a.ValueKind == JsonValueKind.Array)
                foreach (var it in a.EnumerateArray()) { var s = it.ValueKind == JsonValueKind.String ? it.GetString() : it.ToString(); if (!string.IsNullOrWhiteSpace(s)) l.Add(s!); }
            return l;
        }

        public static ExtManifest ReadManifest(string root)
        {
            var mp = Path.Combine(root, "manifest.json");
            if (!File.Exists(mp)) throw new ExtGovException("EXT_NO_MANIFEST");
            var text = File.ReadAllText(mp, Encoding.UTF8).TrimStart('﻿');
            JsonDocument doc;
            try { doc = JsonDocument.Parse(text, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true }); }
            catch (JsonException) { throw new ExtGovException("EXT_BAD_MANIFEST"); }
            using (doc)
            {
                var r = doc.RootElement;
                if (r.ValueKind != JsonValueKind.Object) throw new ExtGovException("EXT_BAD_MANIFEST");
                var m = new ExtManifest();
                string S(string k) => r.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
                m.Name = S("name"); m.Version = S("version"); m.Description = S("description");
                if (r.TryGetProperty("manifest_version", out var mv) && mv.ValueKind == JsonValueKind.Number && mv.TryGetInt32(out var mvi)) m.ManifestVersion = mvi;
                var hostFromPerms = new List<string>();
                foreach (var ps in Strings(r, "permissions"))
                {
                    if (ps.Contains("://", StringComparison.Ordinal) || ps == "<all_urls>" || ps.StartsWith("*", StringComparison.Ordinal)) hostFromPerms.Add(ps); else m.Permissions.Add(ps);
                }
                m.HostPermissions = Strings(r, "host_permissions").Concat(hostFromPerms).ToList();
                m.OptionalPermissions = Strings(r, "optional_permissions").Concat(Strings(r, "optional_host_permissions")).ToList();
                if (r.TryGetProperty("content_scripts", out var cs) && cs.ValueKind == JsonValueKind.Array)
                    foreach (var c in cs.EnumerateArray()) foreach (var x in Strings(c, "matches")) if (!m.ContentScriptMatches.Contains(x)) m.ContentScriptMatches.Add(x);
                return m;
            }
        }

        // ---- policy ---------------------------------------------------------------------------------------------------------------
        public static ExtPolicy ParsePolicy(string json)
        {
            JsonDocument doc;
            try { doc = JsonDocument.Parse(json); } catch (JsonException) { throw new ExtGovException("POLICY_BAD"); }
            using (doc)
            {
                var r = doc.RootElement; var p = new ExtPolicy();
                if (r.TryGetProperty("max_manifest_version", out var a) && a.TryGetInt32(out var ai)) p.MaxManifestVersion = ai;
                if (r.TryGetProperty("min_manifest_version", out var b) && b.TryGetInt32(out var bi)) p.MinManifestVersion = bi;
                p.Denied = Strings(r, "denied_permissions").ToHashSet(StringComparer.Ordinal);
                p.Review = Strings(r, "review_permissions").ToHashSet(StringComparer.Ordinal);
                p.Allowed = Strings(r, "allowed_permissions").ToHashSet(StringComparer.Ordinal);
                p.Allowlist = Strings(r, "allowlist").ToHashSet(StringComparer.Ordinal);
                p.Blocklist = Strings(r, "blocklist").ToHashSet(StringComparer.Ordinal);
                return p;
            }
        }

        // Same rules, same order of reasons as RG-Decide.
        public static ExtDecision Decide(ExtManifest m, string extId, ExtPolicy pol)
        {
            var reasons = new List<string>(); bool deny = false, review = false;
            if (pol.Blocklist.Contains(extId)) { deny = true; reasons.Add("blocklisted"); }
            bool allowlisted = pol.Allowlist.Contains(extId);
            if (allowlisted) reasons.Add("allowlisted");
            if (m.ManifestVersion > pol.MaxManifestVersion || m.ManifestVersion < pol.MinManifestVersion) { deny = true; reasons.Add("manifest_version_out_of_range:" + m.ManifestVersion.ToString(CultureInfo.InvariantCulture)); }
            foreach (var p in m.Permissions.Concat(m.HostPermissions))
            {
                if (string.IsNullOrWhiteSpace(p)) continue;
                if (pol.Denied.Contains(p)) { deny = true; reasons.Add("denied_permission:" + p); continue; }
                if (pol.Review.Contains(p)) { review = true; reasons.Add("review_permission:" + p); continue; }
                if (!pol.Allowed.Contains(p)) { review = true; reasons.Add("unknown_permission:" + p); }
            }
            var decision = deny ? "deny" : (review && !allowlisted) ? "review" : "allow";
            return new ExtDecision(decision, reasons);
        }

        // ---- ledger ---------------------------------------------------------------------------------------------------------------
        public static string RecordHash(IDictionary<string, object?> recWithoutHash) => Sha256Hex(Canon(recWithoutHash));

        public static Dictionary<string, object?> BuildRecord(long seq, string extId, ExtManifest m, IReadOnlyList<ExtFile> files, string decision, IEnumerable<string> reasons, string prevHash, DateTime utcNow)
        {
            if (prevHash.Length != 64 || prevHash.Any(c => !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))) throw new ExtGovException("REC_BAD_PREV_HASH");
            var rec = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["schema"] = Schema,
                ["record_id"] = "extgov-" + seq.ToString("D6", CultureInfo.InvariantCulture),
                ["seq"] = seq,
                ["ts_utc"] = utcNow.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture),
                ["extension_id"] = extId,
                ["name"] = m.Name, ["version"] = m.Version, ["manifest_version"] = (long)m.ManifestVersion,
                ["permissions"] = m.Permissions.Cast<object?>().ToList(),
                ["host_permissions"] = m.HostPermissions.Cast<object?>().ToList(),
                ["file_count"] = (long)files.Count,
                ["files"] = files.Select(f => (object?)new Dictionary<string, object?> { ["path"] = f.Path, ["sha256"] = f.Sha256, ["size"] = f.Size }).ToList(),
                ["policy_decision"] = decision,
                ["reasons"] = reasons.Cast<object?>().ToList(),
                ["prev_hash"] = prevHash
            };
            rec["record_hash"] = RecordHash(rec);
            return rec;
        }

        public static List<string> ReadChainLines(string path)
        {
            if (!File.Exists(path)) return new List<string>();
            return File.ReadAllLines(path, Encoding.UTF8).Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
        }

        private static Dictionary<string, object?> ParseRecord(string line)
        {
            try { using var d = JsonDocument.Parse(line); return (ToObj(d.RootElement) as Dictionary<string, object?>) ?? throw new ExtGovException("LEDGER_BAD_LINE"); }
            catch (JsonException) { throw new ExtGovException("LEDGER_BAD_LINE"); }
        }
        private static string Str(Dictionary<string, object?> r, string k) => r.TryGetValue(k, out var v) ? Convert.ToString(v, CultureInfo.InvariantCulture) ?? "" : "";

        // Throws ExtGovException on any break. Returns (record count, head hash).
        public static (int Count, string Head) VerifyLedger(string path)
        {
            string prev = Genesis; long pseq = 0; int count = 0;
            foreach (var line in ReadChainLines(path))
            {
                var r = ParseRecord(line);
                if (Str(r, "schema") != Schema) throw new ExtGovException("LEDGER_BAD_SCHEMA seq=" + Str(r, "seq"));
                var claimed = Str(r, "record_hash"); r.Remove("record_hash");
                if (RecordHash(r) != claimed) throw new ExtGovException("LEDGER_HASH_MISMATCH seq=" + Str(r, "seq"));
                if (!long.TryParse(Str(r, "seq"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var seq) || seq != pseq + 1) throw new ExtGovException("LEDGER_SEQ_BREAK at " + Str(r, "seq"));
                if (Str(r, "prev_hash") != prev) throw new ExtGovException("LEDGER_PREV_LINK_BROKEN seq=" + Str(r, "seq"));
                prev = claimed; pseq = seq; count++;
            }
            return (count, prev);
        }

        // The tail must itself verify before anything is appended after it.
        public static (long Seq, string Head) LedgerTail(string path)
        {
            var lines = ReadChainLines(path);
            if (lines.Count == 0) return (0, Genesis);
            var last = ParseRecord(lines[^1]); var claimed = Str(last, "record_hash"); last.Remove("record_hash");
            if (RecordHash(last) != claimed) throw new ExtGovException("LEDGER_HEAD_TAMPERED");
            return (long.Parse(Str(last, "seq"), CultureInfo.InvariantCulture), claimed);
        }

        public static void AppendRecord(string path, Dictionary<string, object?> rec)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
            File.AppendAllText(path, Canon(rec) + "\n", new UTF8Encoding(false));
        }

        // Verifies the chain, then appends a record for the extension at its current bytes.
        public static ExtLedgerRecord Record(string ledgerPath, string extId, ExtManifest m, IReadOnlyList<ExtFile> files, string decision, IEnumerable<string> reasons, DateTime utcNow)
        {
            VerifyLedger(ledgerPath);
            var (seq, head) = LedgerTail(ledgerPath);
            var rec = BuildRecord(seq + 1, extId, m, files, decision, reasons, head, utcNow);
            AppendRecord(ledgerPath, rec);
            return ToRecord(rec);
        }

        private static ExtLedgerRecord ToRecord(Dictionary<string, object?> r) => new()
        {
            Seq = long.TryParse(Str(r, "seq"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var s) ? s : 0,
            ExtensionId = Str(r, "extension_id"), Name = Str(r, "name"), Version = Str(r, "version"), PolicyDecision = Str(r, "policy_decision"),
            RecordHash = Str(r, "record_hash"), PrevHash = Str(r, "prev_hash"), TsUtc = Str(r, "ts_utc"),
            Reasons = (r.TryGetValue("reasons", out var rs) && rs is List<object?> l) ? l.Select(x => Convert.ToString(x, CultureInfo.InvariantCulture) ?? "").ToList() : new List<string>()
        };

        // The load gate. The latest record for these exact bytes must say "allow", and the chain must verify.
        public static (bool Ok, string Note) Gate(string ledgerPath, string extId)
        {
            try
            {
                VerifyLedger(ledgerPath);
                ExtLedgerRecord? found = null;
                foreach (var line in ReadChainLines(ledgerPath)) { var r = ParseRecord(line); if (Str(r, "extension_id") == extId) found = ToRecord(r); }
                if (found == null) return (false, "not registered for these exact bytes (changed since install, or never installed)");
                if (found.PolicyDecision != "allow") return (false, "latest decision is '" + found.PolicyDecision + "'" + (found.Reasons.Count > 0 ? " (" + string.Join("; ", found.Reasons) + ")" : ""));
                return (true, "allow");
            }
            catch (ExtGovException ex) { return (false, ex.Message); }
            catch (Exception ex) { return (false, "governance check error: " + ex.Message); }
        }

        public static List<ExtLedgerRecord> ReadAll(string ledgerPath)
        {
            var l = new List<ExtLedgerRecord>();
            foreach (var line in ReadChainLines(ledgerPath)) { try { l.Add(ToRecord(ParseRecord(line))); } catch { } }
            return l;
        }
    }

    // Getting an extension's files into a folder safely. Everything here treats the package as hostile.
    internal static class ExtPackage
    {
        public const int MaxPackageBytes = 100 * 1024 * 1024;

        // CRX2: "Cr24" ver=2 pubKeyLen sigLen pubKey sig ZIP.   CRX3: "Cr24" ver=3 headerLen header ZIP.
        // Only the position of the ZIP is needed: trust comes from the governance ledger, not from the CRX signature.
        public static byte[] CrxPayload(byte[] b)
        {
            if (b == null || b.Length < 16 || b[0] != 'C' || b[1] != 'r' || b[2] != '2' || b[3] != '4') throw new ExtGovException("not a CRX file");
            uint ver = BitConverter.ToUInt32(b, 4); long start;
            if (ver == 3) { uint hl = BitConverter.ToUInt32(b, 8); start = 12L + hl; }
            else if (ver == 2) { uint pk = BitConverter.ToUInt32(b, 8), sg = BitConverter.ToUInt32(b, 12); start = 16L + pk + sg; }
            else throw new ExtGovException("unsupported CRX version " + ver);
            if (start < 12 || start >= b.Length) throw new ExtGovException("CRX header length out of range");
            var zip = new byte[b.Length - start]; Array.Copy(b, start, zip, 0, zip.Length); return zip;
        }

        public static bool IsSafeEntryName(string name)
        {
            if (string.IsNullOrEmpty(name) || name.Length > 400) return false;
            if (name.StartsWith("/", StringComparison.Ordinal) || name.StartsWith("\\", StringComparison.Ordinal)) return false;
            if (name.Contains('\\') || name.Contains(':') || name.Contains('\0')) return false;
            foreach (var seg in name.Split('/')) { if (seg == ".." || seg == ".") return false; if (seg.Length > 0 && (seg.TrimEnd(' ', '.').Length != seg.Length)) return false; }
            return true;
        }

        // Extracts a ZIP with limits: entry count, total uncompressed size, name safety, and a compression-ratio guard.
        public static void ExtractZip(byte[] zip, string destDir)
        {
            if (zip.Length > MaxPackageBytes) throw new ExtGovException("package is larger than " + MaxPackageBytes / 1024 / 1024 + " MB");
            Directory.CreateDirectory(destDir);
            var destFull = Path.GetFullPath(destDir).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            using var ms = new MemoryStream(zip);
            ZipArchive za;
            try { za = new ZipArchive(ms, ZipArchiveMode.Read, false); } catch (InvalidDataException) { throw new ExtGovException("not a valid ZIP file"); }
            using (za)
            {
                if (za.Entries.Count > ExtGovernance.MaxFiles) throw new ExtGovException("too many files in package");
                long total = 0;
                foreach (var e in za.Entries) { total += e.Length; if (total > ExtGovernance.MaxTotalBytes) throw new ExtGovException("package expands to more than " + ExtGovernance.MaxTotalBytes / 1024 / 1024 + " MB"); }
                if (total > 50L * 1024 * 1024 && total > (long)zip.Length * 200) throw new ExtGovException("suspicious compression ratio");
                foreach (var e in za.Entries)
                {
                    if (!IsSafeEntryName(e.FullName)) throw new ExtGovException("unsafe path in package: " + e.FullName);
                    var target = Path.GetFullPath(Path.Combine(destFull, e.FullName));
                    if (!target.StartsWith(destFull, StringComparison.OrdinalIgnoreCase)) throw new ExtGovException("unsafe path in package: " + e.FullName);
                    if (e.FullName.EndsWith("/", StringComparison.Ordinal)) { Directory.CreateDirectory(target); continue; }
                    Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                    using var src = e.Open(); using var dst = File.Create(target);
                    var buf = new byte[81920]; long written = 0; int n;
                    while ((n = src.Read(buf, 0, buf.Length)) > 0) { written += n; if (written > e.Length + 1024) throw new ExtGovException("entry larger than declared"); dst.Write(buf, 0, n); }
                }
            }
        }

        // GitHub-style archives wrap everything in one folder: use that folder when the manifest is not at the top.
        public static string ResolveRoot(string dir)
        {
            if (File.Exists(Path.Combine(dir, "manifest.json"))) return dir;
            var subs = Directory.GetDirectories(dir);
            var files = Directory.GetFiles(dir);
            if (subs.Length == 1 && files.Length == 0 && File.Exists(Path.Combine(subs[0], "manifest.json"))) return subs[0];
            throw new ExtGovException("EXT_NO_MANIFEST (manifest.json must be at the top of the package)");
        }

        // CRX/ZIP bytes -> unpacked folder under destDir. Returns the extension root folder.
        public static string Unpack(byte[] package, string destDir)
        {
            var isCrx = package.Length > 4 && package[0] == 'C' && package[1] == 'r' && package[2] == '2' && package[3] == '4';
            var zip = isCrx ? CrxPayload(package) : package;
            if (zip.Length < 4 || zip[0] != 'P' || zip[1] != 'K') throw new ExtGovException("not a CRX or ZIP package");
            ExtractZip(zip, destDir);
            return ResolveRoot(destDir);
        }

        public static void CopyDirectory(string src, string dst)
        {
            Directory.CreateDirectory(dst);
            foreach (var d in Directory.GetDirectories(src, "*", SearchOption.AllDirectories)) Directory.CreateDirectory(Path.Combine(dst, Path.GetRelativePath(src, d)));
            foreach (var f in Directory.GetFiles(src, "*", SearchOption.AllDirectories)) File.Copy(f, Path.Combine(dst, Path.GetRelativePath(src, f)), true);
        }
    }
}
