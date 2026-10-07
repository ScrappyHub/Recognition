using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;

namespace Recognition.Browser
{
    // Optional link to SoteriaVault (service id "privacy-sector"). This file is pure: it reads two small JSON files that SoteriaVault
    // publishes under its own versioned connector contract and decides what the link may be. It starts no process, opens no network
    // connection and never touches any secret.
    //
    // Boundaries (docs\proposals\SOTERIA_INTEGRATION_V1.md):
    //  * Standalone first, both ways. Recognition works with no SoteriaVault. SoteriaVault works with no Recognition.
    //  * The link is explicit: you choose the SoteriaVault folder; nothing is searched for or assumed.
    //  * SoteriaVault's own contract decides when the bridge is live. While it says "contract_only" or "enabled: false", Recognition
    //    reports that and exchanges nothing.
    //  * This version never receives secrets from SoteriaVault, whatever its state. Passwords, photos and keys stay in SoteriaVault.
    //  * A contract that breaks SoteriaVault's own rules (required for standalone, hard dependency, secret release allowed) is rejected.
    internal enum SoteriaState { NotConfigured, Unavailable, Invalid, ContractOnly, Ready }

    internal sealed record SoteriaStatus(SoteriaState State, string Reason, string ContractSha256, string[] Capabilities);

    internal static class SoteriaBridge
    {
        public const string ContractSchema = "soteriavault.connector_contract.v1";
        public const string RegistrySchema = "soteriavault.connector_registry.v1";
        public const string ContractRel = "connectors\\contracts\\recognition.contract.v1.json";
        public const string RegistryRel = "connectors\\connector_registry.json";
        public const int MaxFileBytes = 64 * 1024;

        // An absolute local drive path only: no UNC or device paths, no relative parts, no control characters.
        public static bool IsSafeRoot(string? root)
        {
            if (string.IsNullOrWhiteSpace(root)) return false;
            var r = root.Trim();
            if (r.Length < 4 || r.Length > 240) return false;
            if (r.Any(c => c < 32 || c == '"' || c == '<' || c == '>' || c == '|' || c == '*' || c == '?')) return false;
            if (!(char.IsAsciiLetter(r[0]) && r[1] == ':' && (r[2] == '\\' || r[2] == '/'))) return false;
            foreach (var part in r.Substring(3).Split('\\', '/'))
                if (part == ".." || part == "." ) return false;
            if (r.IndexOf(':', 2) >= 0) return false;   // alternate data streams
            return true;
        }

        // read(relativePath) returns the file bytes, or null when the file does not exist.
        public static SoteriaStatus Evaluate(string? root, Func<string, byte[]?> read)
        {
            if (string.IsNullOrWhiteSpace(root)) return new SoteriaStatus(SoteriaState.NotConfigured, "No SoteriaVault folder chosen.", "", Array.Empty<string>());
            if (!IsSafeRoot(root)) return new SoteriaStatus(SoteriaState.Invalid, "The folder is not an absolute local path.", "", Array.Empty<string>());

            byte[]? contract, registry;
            try { contract = read(ContractRel); registry = read(RegistryRel); }
            catch (Exception ex) { return new SoteriaStatus(SoteriaState.Unavailable, "SoteriaVault files could not be read: " + ex.GetType().Name, "", Array.Empty<string>()); }
            if (contract == null) return new SoteriaStatus(SoteriaState.Unavailable, "SoteriaVault was not found there (no Recognition connector contract).", "", Array.Empty<string>());
            var sha = Convert.ToHexString(SHA256.HashData(contract)).ToLowerInvariant();
            if (contract.Length > MaxFileBytes || (registry != null && registry.Length > MaxFileBytes))
                return Bad("A SoteriaVault contract file is too large to be trusted.", sha);
            if (registry == null) return Bad("SoteriaVault's connector registry is missing.", sha);

            try
            {
                using var reg = JsonDocument.Parse(registry);
                var rr = reg.RootElement;
                if (rr.ValueKind != JsonValueKind.Object || Str(rr, "schema") != RegistrySchema) return Bad("The connector registry has an unknown schema.", sha);
                if (!Bool(rr, "standalone_first", false)) return Bad("SoteriaVault does not declare itself standalone-first.", sha);
                if (Bool(rr, "hard_external_dependencies_allowed", true)) return Bad("SoteriaVault allows hard external dependencies; the link is refused.", sha);

                using var doc = JsonDocument.Parse(contract);
                var c = doc.RootElement;
                if (c.ValueKind != JsonValueKind.Object) return Bad("The contract is not an object.", sha);
                if (Str(c, "schema") != ContractSchema) return Bad("The contract has an unknown schema or version.", sha);
                if (Str(c, "name") != "recognition") return Bad("The contract is not for Recognition.", sha);
                if (Str(c, "kind") != "browser_password_manager_bridge") return Bad("The contract kind is not the browser bridge.", sha);
                if (Bool(c, "required_for_standalone", true)) return Bad("The contract would make SoteriaVault depend on Recognition.", sha);
                if (Str(c, "dependency_policy") != "must_not_fail_if_absent") return Bad("The contract does not let SoteriaVault run without Recognition.", sha);
                var forbidden = StrList(c, "forbidden_before_standalone_seal");
                if (!forbidden.Contains("secret_release_to_external_runtime") || !forbidden.Contains("hard_runtime_dependency"))
                    return Bad("The contract does not forbid secret release and hard dependencies.", sha);

                var caps = StrList(c, "allowed_now").Where(s => s.Length is > 0 and <= 64 && s.All(ch => char.IsAsciiLetterLower(ch) || ch == '_')).Take(16).ToArray();
                bool enabled = Bool(c, "enabled", false);
                var phase = Str(c, "phase");
                if (!enabled || phase == "contract_only")
                    return new SoteriaStatus(SoteriaState.ContractOnly, "SoteriaVault declares the Recognition link but has not turned it on. Nothing is exchanged.", sha, caps);
                return new SoteriaStatus(SoteriaState.Ready, "SoteriaVault has turned the link on. This version of Recognition still receives no secrets from it.", sha, caps);
            }
            catch (JsonException) { return Bad("A SoteriaVault contract file is not valid JSON.", sha); }
        }

        private static SoteriaStatus Bad(string reason, string sha) => new(SoteriaState.Invalid, reason, sha, Array.Empty<string>());
        private static string Str(JsonElement o, string name) => o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        private static bool Bool(JsonElement o, string name, bool dflt)
        {
            if (!o.TryGetProperty(name, out var v)) return dflt;
            return v.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => dflt };
        }
        private static List<string> StrList(JsonElement o, string name)
        {
            var l = new List<string>();
            if (o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array)
                foreach (var e in v.EnumerateArray()) if (e.ValueKind == JsonValueKind.String && e.GetString() is { } s) l.Add(s);
            return l;
        }
    }
}
