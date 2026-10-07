using System;
using System.Net;
using System.Text.Json;

namespace Recognition.Browser
{
    // Rules for Tor tabs. A Tor tab runs in its own engine profile (a separate engine process group), so it can have its own proxy
    // while normal tabs stay as they are. Recognition does not bundle or start Tor: it uses Tor that is already running on this
    // computer (Tor Browser on port 9150 or the Tor service on 9050). Everything here is pure so tests can execute it.
    internal static class TorRules
    {
        public const int BrowserPort = 9150, ServicePort = 9050;

        // Tor Browser's port is preferred when both answer. 0 = nothing is listening.
        public static int ChoosePort(bool browserUp, bool serviceUp) => browserUp ? BrowserPort : (serviceUp ? ServicePort : 0);

        public static string ProxyUrl(int port) => "socks5://127.0.0.1:" + ValidPort(port);

        private static int ValidPort(int port)
        {
            if (port != BrowserPort && port != ServicePort) throw new ArgumentOutOfRangeException(nameof(port), "not a Tor port");
            return port;
        }

        // Engine arguments for the Tor profile:
        //  - the SOCKS5 exit, with website names looked up through Tor (a SOCKS5 proxy does that, and the resolver rule makes any local
        //    lookup fail instead of leaking);
        //  - WebRTC may only use the proxy (no direct UDP, so no local or public address is exposed);
        //  - QUIC (UDP) off, because UDP does not go through Tor.
        public static string EngineArgs(int port)
        {
            return "--proxy-server=\"" + ProxyUrl(port) + "\" " +
                   "--host-resolver-rules=\"MAP * ~NOTFOUND , EXCLUDE 127.0.0.1\" " +
                   "--force-webrtc-ip-handling-policy=disable_non_proxied_udp " +
                   "--disable-quic " +
                   "--lang=en-US";
        }

        // Runs before any page script in a Tor tab: removes the WebRTC and device APIs that can expose an address or hardware.
        public const string GuardScript =
            "(function(){try{var kill=function(n){try{Object.defineProperty(window,n,{value:undefined,configurable:false,writable:false});}catch(e){try{delete window[n];}catch(_){}}};" +
            "['RTCPeerConnection','webkitRTCPeerConnection','RTCDataChannel','RTCSessionDescription','RTCIceCandidate','RTCRtpReceiver','RTCRtpSender'].forEach(kill);" +
            "try{if(navigator.mediaDevices){navigator.mediaDevices.getUserMedia=function(){return Promise.reject(new DOMException('blocked','NotAllowedError'));};" +
            "navigator.mediaDevices.enumerateDevices=function(){return Promise.resolve([]);};}}catch(e){}" +
            "try{Object.defineProperty(navigator,'getBattery',{value:undefined});}catch(e){}" +
            "try{Object.defineProperty(navigator,'connection',{value:undefined});}catch(e){}" +
            "}catch(e){}})();";

        // Script a leak check runs inside a Tor tab. Returns "ok" only when the WebRTC objects are gone.
        public const string WebRtcProbeScript =
            "(function(){try{return (typeof RTCPeerConnection==='undefined'&&typeof webkitRTCPeerConnection==='undefined')?'ok':'exposed';}catch(e){return 'ok';}})()";

        // Parses https://check.torproject.org/api/ip, e.g. {"IsTor":true,"IP":"203.0.113.7"}.
        public static bool ParseTorApi(string? json, out bool isTor, out string ip)
        {
            isTor = false; ip = "";
            if (string.IsNullOrWhiteSpace(json) || json.Length > 4096) return false;
            try
            {
                using var d = JsonDocument.Parse(json);
                var r = d.RootElement; if (r.ValueKind != JsonValueKind.Object) return false;
                if (!r.TryGetProperty("IsTor", out var t) || (t.ValueKind != JsonValueKind.True && t.ValueKind != JsonValueKind.False)) return false;
                isTor = t.GetBoolean();
                if (r.TryGetProperty("IP", out var p) && p.ValueKind == JsonValueKind.String && IPAddress.TryParse(p.GetString(), out var a)) ip = a.ToString();
                return true;
            }
            catch { return false; }
        }

        // One plain sentence for the top of the leak-check page.
        public static string Verdict(bool torReachable, bool apiOk, bool isTor, string webrtc)
        {
            if (!torReachable) return "Tor is not running on this computer, so Tor tabs cannot load pages. Start Tor Browser (leave it open) or the Tor service.";
            if (!apiOk) return "Tor is running, but the Tor Project check could not be reached through it. Try again in a minute.";
            if (!isTor) return "Something answered on the Tor port but traffic is not coming out of the Tor network. Do not use Tor tabs for anything sensitive.";
            if (webrtc == "exposed") return "Traffic goes through Tor, but WebRTC is exposed in the Tor tab. Close it and open a new Tor tab.";
            if (webrtc == "unknown") return "Traffic goes through Tor. Open a Tor tab and run the check again to test WebRTC.";
            return "Traffic goes through Tor and WebRTC is blocked in Tor tabs.";
        }

        // The ready-made exits that Recognition lists for Tor. Hidden from the VPN page when Tor features are off.
        public static bool IsTorExit(string? name, bool user) => !user && name != null && name.StartsWith("tor-", StringComparison.OrdinalIgnoreCase);
    }
}
