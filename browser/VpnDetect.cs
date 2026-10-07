using System;
using System.Collections.Generic;
using System.Linq;

namespace Recognition.Browser
{
    // Recognises a VPN app that is running on this computer from the list of network adapters (name, description, type, up/down).
    // This is a hint, not proof: an adapter that looks like a VPN says a VPN program is connected, not that all traffic uses it.
    internal sealed record AdapterInfo(string Name, string Description, string Type, bool Up);

    internal sealed record VpnFound(string Name, string Kind);   // Kind: "vpn" or "mesh"

    internal static class VpnDetect
    {
        // adapters that are never a VPN, even if their name contains a keyword
        private static readonly string[] Ignore =
        {
            "loopback", "teredo", "isatap", "6to4", "hyper-v", "vethernet", "vmware", "virtualbox", "vbox", "wi-fi direct",
            "bluetooth", "wan miniport", "kernel debugger", "npcap", "docker", "wsl"
        };

        // product names. "mesh" ones link your own devices; they do not hide your traffic unless set up as an exit node.
        private static readonly string[] Mesh = { "tailscale", "zerotier", "netbird", "nebula" };
        private static readonly string[] Vpn =
        {
            "wireguard", "wintun", "openvpn", "tap-windows", "tap0901", "nordlynx", "nordvpn", "protonvpn", "proton vpn", "mullvad", "expressvpn",
            "surfshark", "cyberghost", "private internet access", "windscribe", "tunnelbear", "hotspot shield", "ipvanish", "hide.me", "vyprvpn",
            "softether", "anyconnect", "cisco", "forticlient", "fortinet", "globalprotect", "palo alto", "pulse secure", "juniper", "sonicwall",
            "checkpoint", "check point", "openconnect", "strongswan", "vpn"
        };

        public static VpnFound? Find(IEnumerable<AdapterInfo>? adapters)
        {
            if (adapters == null) return null;
            VpnFound? mesh = null;
            foreach (var a in adapters)
            {
                if (a == null || !a.Up) continue;
                var text = ((a.Name ?? "") + " " + (a.Description ?? "")).ToLowerInvariant();
                if (Ignore.Any(text.Contains)) continue;
                var label = string.IsNullOrWhiteSpace(a.Description) ? (a.Name ?? "") : a.Description;
                if (label.Length > 80) label = label.Substring(0, 80);
                if (Mesh.Any(text.Contains)) { mesh ??= new VpnFound(label, "mesh"); continue; }
                if (Vpn.Any(text.Contains)) return new VpnFound(label, "vpn");
                // Windows' own VPN connections (IKEv2, L2TP, SSTP, PPTP) show up as point-to-point adapters
                if (string.Equals(a.Type, "Ppp", StringComparison.OrdinalIgnoreCase)) return new VpnFound(label, "vpn");
            }
            return mesh;
        }

        public static string Describe(VpnFound? f) =>
            f == null ? "No VPN app detected on this computer."
            : f.Kind == "vpn" ? "A VPN app looks active on this computer: " + f.Name + "."
            : f.Name + " is active. It links your own devices; it does not hide your traffic unless you set it up as an exit.";
    }
}
