using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Recognition.Browser
{
    // Pure helpers behind the Network panel (no WPF / WebView2 / OS calls): parsers for `netsh wlan`
    // output, link-rate and ping statistics, connection-history roll-ups, and strict validators for any
    // user-supplied name/host before it is ever handed to a process. Compiled into browser.tests and
    // executed there against canned inputs. NOTE: the netsh parsers match the English Windows output.
    internal static class NetParsers
    {
        // `netsh wlan show profiles` -> saved Wi-Fi network names ("All User Profile" / "User Profile" lines).
        public static List<string> ParseWlanProfiles(string output)
        {
            var res = new List<string>();
            foreach (var line in (output ?? "").Split('\n'))
            {
                var m = Regex.Match(line, @"^\s*(?:All User Profile|User Profile)\s*:\s*(.+?)\s*$");
                if (m.Success && !res.Contains(m.Groups[1].Value)) res.Add(m.Groups[1].Value);
            }
            return res;
        }

        // `netsh wlan show interfaces` -> key/value pairs of the FIRST interface block. Netsh separates
        // key and value with " : " (spaces both sides), so values that contain colons (BSSID) stay intact.
        public static Dictionary<string, string> ParseWlanInterface(string output)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var raw in (output ?? "").Split('\n'))
            {
                var m = Regex.Match(raw.TrimEnd('\r'), @"^\s*([^:]+?)\s+:\s+(.*?)\s*$");
                if (!m.Success) continue;
                var k = m.Groups[1].Value;
                if (k.Equals("Name", StringComparison.OrdinalIgnoreCase) && d.ContainsKey("Name")) break;   // second interface: stop
                if (!d.ContainsKey(k)) d[k] = m.Groups[2].Value;
            }
            return d;
        }

        // Stable, record-format-safe key for a network name (SSIDs may contain '|' or other separators).
        public static string SsidKey(string ssid) =>
            "net-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(ssid ?? ""))).ToLowerInvariant().Substring(0, 16);

        // A saved-network name is passed to `netsh` through an argument list (never a shell string), but is
        // still validated: 1..255 chars, no control characters.
        public static bool IsSafeNetworkName(string? n) =>
            !string.IsNullOrEmpty(n) && n.Length <= 255 && !n.Any(char.IsControl);

        // Hostname or IP literal for the ping box: letters/digits/dots/hyphens, or an IPv6 literal.
        public static bool IsSafeHost(string? h)
        {
            if (string.IsNullOrWhiteSpace(h) || h.Length > 253) return false;
            if (Regex.IsMatch(h, @"^[A-Za-z0-9]([A-Za-z0-9\-\.]*[A-Za-z0-9])?$")) return true;
            return Regex.IsMatch(h, @"^[0-9A-Fa-f:]+$") && h.Contains(':');
        }
    }

    // Bytes-per-second from successive interface byte counters. A counter that goes backwards
    // (adapter reset / wrap) yields 0 for that interval rather than a huge bogus rate.
    internal sealed class RateCalc
    {
        private long _rx, _tx; private DateTime _t; private bool _has;
        public (double rxBps, double txBps) Sample(long rxBytes, long txBytes, DateTime tUtc)
        {
            double rx = 0, tx = 0;
            if (_has)
            {
                var dt = (tUtc - _t).TotalSeconds;
                if (dt > 0)
                {
                    if (rxBytes >= _rx) rx = (rxBytes - _rx) / dt;
                    if (txBytes >= _tx) tx = (txBytes - _tx) / dt;
                }
            }
            _rx = rxBytes; _tx = txBytes; _t = tUtc; _has = true;
            return (rx, tx);
        }
    }

    internal static class PingStats
    {
        public sealed record Result(int Sent, int Received, double LossPct, long Min, double Avg, long Max, double Jitter);

        // rtts: round-trip milliseconds, null = lost. Jitter = mean absolute difference of consecutive replies.
        public static Result Summarize(IReadOnlyList<long?> rtts)
        {
            int sent = rtts.Count;
            var ok = rtts.Where(x => x.HasValue).Select(x => x!.Value).ToList();
            if (ok.Count == 0) return new Result(sent, 0, sent == 0 ? 0 : 100, 0, 0, 0, 0);
            double jitter = 0;
            if (ok.Count > 1) jitter = Enumerable.Range(1, ok.Count - 1).Average(i => Math.Abs(ok[i] - ok[i - 1]));
            return new Result(sent, ok.Count, Math.Round(100.0 * (sent - ok.Count) / sent, 1), ok.Min(), Math.Round(ok.Average(), 1), ok.Max(), Math.Round(jitter, 1));
        }
    }

    // Rolls connect/disconnect events ("net.connect|<ssid>" / "net.disconnect|<ssid>") up into per-network
    // totals: how many times connected, total connected time, and when last seen.
    internal static class NetHistory
    {
        public sealed record Row(string Ssid, int Connections, double TotalSeconds, DateTime LastSeenUtc);
        public const string ConnectPrefix = "net.connect|";
        public const string DisconnectPrefix = "net.disconnect|";

        public static List<Row> Summarize(IEnumerable<(DateTime TsUtc, string Action)> events, DateTime nowUtc)
        {
            var count = new Dictionary<string, int>(); var secs = new Dictionary<string, double>(); var last = new Dictionary<string, DateTime>();
            string? cur = null; DateTime start = default;
            void Close(DateTime at)
            {
                if (cur == null) return;
                secs[cur] = secs.GetValueOrDefault(cur) + Math.Max(0, (at - start).TotalSeconds);
                last[cur] = at; cur = null;
            }
            foreach (var (ts, action) in events)
            {
                if (action.StartsWith(ConnectPrefix, StringComparison.Ordinal))
                {
                    Close(ts);   // a missed disconnect: end the previous session where the next one begins
                    cur = action.Substring(ConnectPrefix.Length); start = ts;
                    count[cur] = count.GetValueOrDefault(cur) + 1; last[cur] = ts;
                }
                else if (action.StartsWith(DisconnectPrefix, StringComparison.Ordinal))
                {
                    if (cur != null && cur == action.Substring(DisconnectPrefix.Length)) Close(ts);
                }
            }
            if (cur != null) { var c = cur; secs[c] = secs.GetValueOrDefault(c) + Math.Max(0, (nowUtc - start).TotalSeconds); last[c] = nowUtc; }
            return count.Keys.Select(k => new Row(k, count[k], Math.Round(secs.GetValueOrDefault(k), 1), last[k]))
                             .OrderByDescending(r => r.TotalSeconds).ThenBy(r => r.Ssid, StringComparer.Ordinal).ToList();
        }
    }
}
