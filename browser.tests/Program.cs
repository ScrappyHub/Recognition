using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Recognition.Browser;

// Executes the REAL GovernedActions (same source file as the browser). Golden hashes were derived
// independently (Python re-implementation of the record format) and match the PowerShell mirror
// used by _selftest_recognition_action_receipts_v1.ps1, so C# == PS == Python for the chain format.

int pass = 0, fail = 0;
void Check(bool c, string label)
{
    if (c) { pass++; Console.WriteLine("  ok  - " + label); }
    else { fail++; Console.WriteLine("  FAIL- " + label); }
}

var store = new Dictionary<string, string>();
string Read(string p) => store.TryGetValue(p, out var v) ? v : "";
void Write(string p, string t) => store[p] = t;
GovernedActions Fresh(string path = "mem://actions") => new GovernedActions(path, Read, Write);
DateTime T(int ms) => new DateTime(2026, 1, 1, 0, 0, 0, ms, DateTimeKind.Utc);

var golden = new[]
{
    "91f29ead6e10d25d011444e7d862af9e7e14c4ff76ac9f967156b91ae031954e",
    "8dc7214854dff357299bb4d9b59a88d0667fded37fafb8ee97ac262bfb1207eb",
    "e0e9f334f83a35e01b9f969e3f2d7ec031e6b837d467ba0ce79ca747ef71ca6f",
    "35615956e86146cf7aeb6cf5e64c52055b199a8284a95ce3705831e7a24f6291",
};

Console.WriteLine("=== GovernedActions (executed C#) ===");

var g = Fresh();
g.AppendAt("session.start", "", T(1));
g.AppendAt("navigate", "https://example.com/a", T(2));
g.AppendAt("vpn.pick", "socks5://127.0.0.1:9050", T(3));
g.AppendAt("quote\"back\\slash|x", "detail \"q\" \\ end", T(4));   // exercises JSON escaping + the '|' used by site-policy records

for (int i = 0; i < 4; i++) Check(g.Items[i].Hash == golden[i], $"record {i + 1} hash equals the independently derived golden vector");
Check(g.Head == golden[3], "head hash equals the golden head");
Check(g.Verify(out int vcount) && vcount == 4, "4-record chain verifies");

var persisted = store["mem://actions"];
Check(!persisted.Contains("example.com/a") && !persisted.Contains("9050"), "cleartext detail (URL, proxy) is absent from the persisted ledger");

var reloaded = Fresh(); reloaded.Load();
Check(reloaded.Count == 4 && reloaded.Head == golden[3] && reloaded.Verify(out int rcount) && rcount == 4, "reload from storage reproduces the same chain and head");
reloaded.AppendAt("after.reload", "x", T(5));
Check(reloaded.Verify(out _) && reloaded.Count == 5, "appending after a reload keeps the chain valid");

// helpers to build a tampered store from the persisted lines
string[] Lines() => persisted.Split('\n', StringSplitOptions.RemoveEmptyEntries);
bool VerifiesAfter(Func<string[], string[]> mutate)
{
    var s2 = new Dictionary<string, string> { ["p"] = string.Join("\n", mutate(Lines())) + "\n" };
    var x = new GovernedActions("p", p => s2.TryGetValue(p, out var v) ? v : "", (p, t) => s2[p] = t);
    x.Load();
    return x.Verify(out _);
}

Check(!VerifiesAfter(l => { var c = (string[])l.Clone(); c[1] = c[1].Replace("navigate", "evil.exfil"); return c; }), "tampered action content fails verification");
Check(!VerifiesAfter(l => new[] { l[1], l[0], l[2], l[3] }), "reordered records fail verification");
Check(!VerifiesAfter(l => { var c = (string[])l.Clone(); c[2] = System.Text.RegularExpressions.Regex.Replace(c[2], "\"hash\":\"[0-9a-f]{64}\"", "\"hash\":\"" + new string('0', 64) + "\""); return c; }), "forged hash fails verification");
Check(!VerifiesAfter(l => new[] { l[0], l[2], l[3] }), "deleted middle record fails verification");
Check(!VerifiesAfter(l => new[] { l[0], l[1], l[2] }.Concat(new[] { l[3].Replace("\"seq\":4", "\"seq\":9") }).ToArray()), "non-contiguous sequence number fails verification");
Check(VerifiesAfter(l => l), "control: the unmodified lines still verify (the negative vectors are not trivially failing)");

var empty = Fresh("mem://empty"); empty.Load();
Check(empty.Count == 0 && empty.Verify(out int ec) && ec == 0 && empty.Head == new string('0', 64), "empty ledger verifies with the zero head");

// Site-policy / certificate-trust records are ordinary GovernedActions records whose ACTION encodes the decision.
var sp = Fresh("mem://site_policy");
sp.AppendAt("site_policy.set|perm.Camera|example.com|allow", "", T(1));
sp.AppendAt("site_policy.set|perm.Camera|example.com|deny", "", T(2));
Check(sp.Verify(out _) && sp.Items[^1].Action == "site_policy.set|perm.Camera|example.com|deny", "decision records round-trip with their action text intact");

Console.WriteLine();
Console.WriteLine("=== AppearanceSettings (executed C#) ===");

var ap = new AppearanceSettings();
Check(ap.PageCss() == "" && ap.PreferredScheme() == 0 && ap.InternalPageCss() == "", "defaults inject nothing and follow the system scheme");
Check(ap.Set("theme", "dark") && ap.PreferredScheme() == 2, "dark theme asks sites for dark");
Check(ap.Set("theme", "light") && ap.PreferredScheme() == 1 && ap.InternalPageCss().Contains("#f4f5f7"), "light theme restyles internal pages and asks sites for light");
Check(ap.Set("darkstyle", "prefer") && ap.PreferredScheme() == 2 && ap.PageCss() == "", "'prefer dark' only changes the requested scheme, injects no CSS");
Check(ap.Set("darkstyle", "invert") && ap.PageCss().Contains("invert(1)") && ap.PageCss().Contains("img,video"), "smart invert darkens pages and protects media");
Check(ap.Set("darkstyle", "custom") && ap.Set("bg", "#112233") && ap.Set("text", "#EEEEEE") && ap.Set("link", "#00ff88"), "custom colours accepted (#rrggbb)");
var css = ap.PageCss();
Check(css.Contains("#112233") && css.Contains("#eeeeee") && css.Contains("#00ff88"), "custom CSS carries the chosen colours (normalised to lower case)");

// injection / validation negatives: nothing but #rrggbb colours and allowlisted fonts may reach the CSS
var before = ap.ToJson();
Check(!ap.Set("bg", "red;}body{display:none"), "CSS-injection attempt in a colour is rejected");
Check(!ap.Set("bg", "#12345"), "short hex is rejected");
Check(!ap.Set("bg", "#12345g"), "non-hex digit is rejected");
Check(!ap.Set("text", "url(javascript:alert(1))"), "url() in a colour is rejected");
Check(!ap.Set("font", "Arial';}*{display:none}/*"), "font outside the allowlist is rejected");
Check(!ap.Set("theme", "purple") && !ap.Set("darkstyle", "x") && !ap.Set("overridefonts", "maybe") && !ap.Set("nonsense", "1"), "unknown theme / style / toggle / key is rejected");
Check(ap.ToJson() == before, "rejected changes leave the settings byte-identical");

Check(ap.Set("font", "Georgia") && ap.Set("overridefonts", "on") && ap.PageCss().Contains("'Georgia', sans-serif"), "allowlisted font + override applies to pages");
Check(ap.InternalPageCss().Contains("'Georgia'"), "chosen font also applies to internal pages");
Check(ap.Set("overridefonts", "off") && !ap.PageCss().Contains("Georgia"), "override off removes the font from pages");

var js = ap.InjectScript();
Check(js.Contains("__rec_style") && js.Contains("rec-internal") && js.Contains("DOMContentLoaded"), "inject script is idempotent, skips internal pages, waits for the DOM");
Check(!js.Contains("\n"), "inject script is a single line (safe to embed)");
var clear = new AppearanceSettings().InjectScript();
Check(clear.Contains("var css='';"), "with nothing to apply the script carries an empty stylesheet and just removes the style element");

// JSON round-trip, including hostile persisted values being ignored
using (var doc = JsonDocument.Parse(ap.ToJson()))
{
    var back = new AppearanceSettings(); back.FromJson(doc.RootElement);
    Check(back.ToJson() == ap.ToJson(), "settings survive a JSON round-trip");
}
using (var doc = JsonDocument.Parse("{\"theme\":\"dark\",\"page_bg\":\"red;}body{display:none\",\"font\":\"Evil'Font\",\"dark_style\":\"custom\"}"))
{
    var hostile = new AppearanceSettings(); hostile.FromJson(doc.RootElement);
    Check(hostile.Theme == "dark" && hostile.DarkStyle == "custom" && hostile.PageBg == "#1b1d22" && hostile.Font == "default", "a tampered settings file keeps valid fields and ignores the malicious ones");
}
ap.Reset();
Check(ap.PageCss() == "" && ap.Theme == "system" && ap.Font == "default", "reset restores defaults");

Console.WriteLine();
Console.WriteLine("=== Network panel logic (executed C#) ===");

var profilesOut = "\r\nProfiles on interface Wi-Fi:\r\n\r\nGroup policy profiles (read only)\r\n---------------------------------\r\n    <None>\r\n\r\nUser profiles\r\n-------------\r\n    All User Profile     : HomeNet\r\n    All User Profile     : Coffee Shop : Guest\r\n    User Profile         : Office-5G\r\n    All User Profile     : HomeNet\r\n";
var profiles = NetParsers.ParseWlanProfiles(profilesOut);
Check(profiles.Count == 3 && profiles[0] == "HomeNet" && profiles[1] == "Coffee Shop : Guest" && profiles[2] == "Office-5G", "saved networks parsed (names with spaces/colons kept, duplicates removed)");
Check(NetParsers.ParseWlanProfiles("").Count == 0 && NetParsers.ParseWlanProfiles("There is no wireless interface on the system.").Count == 0, "no profiles / no wireless interface parses to an empty list");

var ifOut = "There is 1 interface on the system:\r\n\r\n    Name                   : Wi-Fi\r\n    Description            : Intel(R) Wi-Fi 6 AX201\r\n    Physical address       : aa:bb:cc:dd:ee:ff\r\n    State                  : connected\r\n    SSID                   : HomeNet\r\n    BSSID                  : 11:22:33:44:55:66\r\n    Radio type             : 802.11ax\r\n    Authentication         : WPA2-Personal\r\n    Channel                : 36\r\n    Receive rate (Mbps)    : 866.7\r\n    Transmit rate (Mbps)   : 700\r\n    Signal                 : 94%\r\n    Profile                : HomeNet\r\n\r\n    Name                   : Wi-Fi 2\r\n    State                  : disconnected\r\n";
var wi = NetParsers.ParseWlanInterface(ifOut);
Check(wi["State"] == "connected" && wi["SSID"] == "HomeNet" && wi["BSSID"] == "11:22:33:44:55:66" && wi["Signal"] == "94%", "wireless interface fields parsed (colon-containing BSSID intact)");
Check(wi["Receive rate (Mbps)"] == "866.7" && wi["Transmit rate (Mbps)"] == "700" && wi["Channel"] == "36" && wi["Radio type"] == "802.11ax", "link rates / channel / radio parsed");
Check(wi["Name"] == "Wi-Fi", "only the first interface block is used");
Check(NetParsers.ParseWlanInterface("The Wireless AutoConfig Service (wlansvc) is not running.").Count == 0, "unparseable output yields no fields");

Check(NetParsers.SsidKey("HomeNet") == NetParsers.SsidKey("HomeNet") && NetParsers.SsidKey("HomeNet") != NetParsers.SsidKey("homenet"), "ssid key is deterministic and case-sensitive");
Check(!NetParsers.SsidKey("a|b\"c").Contains("|") && NetParsers.SsidKey("x").StartsWith("net-") && NetParsers.SsidKey("x").Length == 20, "ssid key never contains record separators");
Check(NetParsers.IsSafeNetworkName("Coffee Shop : Guest") && !NetParsers.IsSafeNetworkName("") && !NetParsers.IsSafeNetworkName("a\nb") && !NetParsers.IsSafeNetworkName(new string('x', 256)), "network-name validator: ok / empty / control char / too long");
Check(NetParsers.IsSafeHost("example.com") && NetParsers.IsSafeHost("8.8.8.8") && NetParsers.IsSafeHost("fe80::1") && NetParsers.IsSafeHost("my-host.local"), "host validator accepts hostnames and IP literals");
Check(!NetParsers.IsSafeHost("8.8.8.8; calc") && !NetParsers.IsSafeHost("a b") && !NetParsers.IsSafeHost("host&whoami") && !NetParsers.IsSafeHost("-bad.com") && !NetParsers.IsSafeHost("") && !NetParsers.IsSafeHost("a|b"), "host validator rejects shell metacharacters, spaces, leading hyphen, empty");

var rc = new RateCalc();
var t0 = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
var r0 = rc.Sample(1000, 500, t0);
var r1 = rc.Sample(3000, 1500, t0.AddSeconds(2));
var r2 = rc.Sample(100, 100, t0.AddSeconds(3));   // counters went backwards (adapter reset)
var r3 = rc.Sample(1100, 600, t0.AddSeconds(4));
Check(r0 == (0, 0), "first sample has no baseline, so the rate is 0");
Check(r1 == (1000, 500), "2000 bytes rx / 1000 bytes tx over 2 s = 1000 / 500 B/s");
Check(r2 == (0, 0), "a counter that goes backwards gives 0, not a huge bogus rate");
Check(r3 == (1000, 500), "rates resume correctly after a counter reset");

var ps = PingStats.Summarize(new long?[] { 10, 20, null, 40 });
Check(ps.Sent == 4 && ps.Received == 3 && ps.LossPct == 25 && ps.Min == 10 && ps.Max == 40 && Math.Abs(ps.Avg - 23.3) < 0.001, "ping summary: sent/received/loss/min/avg/max");
Check(Math.Abs(ps.Jitter - 15) < 0.001, "jitter is the mean absolute difference of consecutive replies (|20-10|,|40-20| -> 15)");
var allLost = PingStats.Summarize(new long?[] { null, null });
Check(allLost.Received == 0 && allLost.LossPct == 100 && allLost.Avg == 0, "all packets lost -> 100% loss, no bogus averages");
Check(PingStats.Summarize(Array.Empty<long?>()).LossPct == 0, "no pings sent -> 0% (no divide-by-zero)");

var ev = new List<(DateTime, string)>
{
    (t0, "net.connect|HomeNet"),
    (t0.AddSeconds(100), "net.disconnect|HomeNet"),
    (t0.AddSeconds(200), "net.connect|Cafe"),
    (t0.AddSeconds(260), "net.connect|HomeNet"),            // Cafe disconnect was missed: closed at the next connect
    (t0.AddSeconds(300), "net.disconnect|OtherNet"),         // unrelated disconnect is ignored
};
var hist = NetHistory.Summarize(ev, t0.AddSeconds(400));
var home = hist.First(h => h.Ssid == "HomeNet"); var cafe = hist.First(h => h.Ssid == "Cafe");
Check(home.Connections == 2 && Math.Abs(home.TotalSeconds - 240) < 0.01, "HomeNet: 2 connections, 100 s + 140 s still-open session = 240 s");
Check(cafe.Connections == 1 && Math.Abs(cafe.TotalSeconds - 60) < 0.01, "Cafe: a missed disconnect is closed at the next connect (60 s)");
Check(hist[0].Ssid == "HomeNet" && NetHistory.Summarize(new List<(DateTime, string)>(), t0).Count == 0, "history is ordered by time connected; empty history is empty");

Console.WriteLine();
Console.WriteLine("=== Setup snapshot (executed C#) ===");
{
    var now = new DateTime(2026, 10, 7, 12, 0, 0, DateTimeKind.Utc);
    var code = SetupCode.Generate();
    Check(Regex.IsMatch(code, "^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){3}$"), "generated code is 20 Crockford-base32 symbols in 4 groups");
    Check(Enumerable.Range(0, 50).Select(_ => SetupCode.Generate()).Distinct().Count() == 50, "50 generated codes are all distinct");
    Check(SetupCode.Normalize("abcde-fghjk mnpqr-stvwx") == "ABCDEFGHJKMNPQRSTVWX", "normalize: case, spaces and hyphens are ignored");
    Check(SetupCode.Normalize("0O0O0-1I1L1-00000-00000") == "00000" + "11111" + "00000" + "00000","normalize: O->0 and I/L->1 corrections");
    Check(SetupCode.Normalize("ABCDE-FGHJK-MNPQR-STVW") == "" && SetupCode.Normalize("ABCDE-FGHJK-MNPQR-STVWU") == "" && SetupCode.Normalize(null) == "", "normalize: wrong length / illegal symbol (U) / null rejected");

    var cats = new Dictionary<string, object>
    {
        ["appearance"] = new { theme = "dark", dark_style = "custom", page_bg = "#101010", page_text = "#eeeeee", link_color = "#88aaff", font = "Georgia", override_site_fonts = true },
        ["preferences"] = new { home_url = "https://example.com/", blocking_enabled = false },
        ["bookmarks"] = new object[] { new { url = "https://a.example/x", title = "A" }, new { url = "javascript:alert(1)", title = "evil" }, new { url = "file:///c:/x", title = "f" }, new { url = "https://b.example/", title = "B\u0001\u0002" } },
        ["site_permissions"] = new object[] { new { key = "perm.Camera", origin = "meet.example", value = "allow" }, new { key = "perm.Camera", origin = "x;y", value = "allow" }, new { key = "perm.Camera", origin = "ok.example", value = "maybe" }, new { key = "cert.der-0123456789abcdef", origin = "h.example", value = "allow" } },
        ["network_labels"] = new object[] { new { key = "netlabel", origin = "net-0123456789abcdef", value = "trusted" }, new { key = "netlabel", origin = "HomeNet", value = "trusted" } },
        ["cert_trust"] = new object[] { new { key = "cert.der-0123456789abcdef0123456789abcdef", origin = "h.example", value = "allow" }, new { key = "cert.der-zz", origin = "h.example", value = "allow" } },
        ["mystery"] = new { a = 1 },
    };
    var payload = SetupPayload.Build("0123456789abcdef01234567", now, now.AddHours(1), cats);
    var blob = SetupBlob.Seal(payload, code, 100_000);
    Check(blob.StartsWith("RSETUP1:") && !blob.Contains("example.com") && !blob.Contains("Georgia"), "sealed blob is prefixed and leaks no plaintext");
    var ok = SetupBlob.Open(blob, code, now.AddMinutes(5));
    Check(ok.Ok && ok.SnapshotId == "0123456789abcdef01234567" && ok.PayloadJson == payload, "round trip: correct code opens and returns the exact payload");
    Check(SetupBlob.Open(blob, code.ToLowerInvariant().Replace("-", " "), now).Ok, "code typed in lower case with spaces still opens");
    Check(SetupBlob.Seal(payload, code, 100_000) != blob, "sealing twice gives different ciphertext (fresh salt and nonce)");
    var wrong = SetupBlob.Open(blob, "AAAAA-AAAAA-AAAAA-AAAAA", now);
    Check(!wrong.Ok && wrong.Reason.Contains("wrong code") && wrong.PayloadJson == "", "wrong code fails and reveals nothing");
    Check(!SetupBlob.Open(blob, "short", now).Ok && !SetupBlob.Open("hello", code, now).Ok && !SetupBlob.Open("", code, now).Ok && !SetupBlob.Open(null!, code, now).Ok, "malformed code / non-snapshot / empty / null never throw, all fail");
    var exp = SetupBlob.Open(blob, code, now.AddHours(1).AddSeconds(1));
    Check(!exp.Ok && exp.Reason.Contains("expired"), "expired snapshot is refused");
    Check(SetupBlob.Open(blob, code, now.AddHours(1)).Ok, "snapshot is still valid exactly at its expiry instant");

    // tamper: flip one character at several positions of the base64 body -> every one must fail authentication/parsing
    var body = blob.Substring("RSETUP1:".Length);
    string Rewrap(string env) => "RSETUP1:" + Convert.ToBase64String(Encoding.UTF8.GetBytes(env)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    var envJson = Encoding.UTF8.GetString(Convert.FromBase64String(body.Replace('-', '+').Replace('_', '/').PadRight((body.Length + 3) / 4 * 4, '=')));
    int tamperFail = 0, tamperTotal = 0;
    foreach (var field in new[] { "ct", "tag", "nonce", "salt" })
    {
        var d = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(envJson)!;
        var raw = Convert.FromBase64String(d[field].GetString()!);
        raw[0] ^= 0x01;
        var m = d.ToDictionary(kv => kv.Key, kv => (object)(kv.Key == field ? Convert.ToBase64String(raw) : kv.Value.ValueKind == JsonValueKind.Number ? kv.Value.GetInt32() : kv.Value.GetString()!));
        var tampered = JsonSerializer.Serialize(m);
        tamperTotal++; if (!SetupBlob.Open(Rewrap(tampered), code, now).Ok) tamperFail++;
    }
    Check(tamperFail == tamperTotal, $"flipping one bit in ciphertext, tag, nonce or salt is detected ({tamperFail}/{tamperTotal})");

    // header downgrade: rewrite iter in the envelope (bound as associated data) -> must fail
    var downgraded = envJson.Replace("\"iter\":100000", "\"iter\":100001");
    var dgBlob = Rewrap(downgraded);
    Check(downgraded != envJson && !SetupBlob.Open(dgBlob, code, now).Ok, "changing the KDF iteration count in the header fails (header is authenticated)");
    var weak = envJson.Replace("\"iter\":100000", "\"iter\":1");
    var weakBlob = Rewrap(weak);
    var weakRes = SetupBlob.Open(weakBlob, code, now);
    Check(!weakRes.Ok && weakRes.Reason.Contains("key-derivation"), "absurdly weak or huge iteration counts are rejected before any key derivation");
    Check(SetupBlob.Open("  " + blob.Substring(0, 30) + "\r\n" + blob.Substring(30) + "  ", code, now).Ok, "whitespace and line wrapping from copy/paste or email is tolerated");

    // plan: hostile / invalid content is dropped and counted, valid content is kept
    var plan = SetupPlan.Parse(ok.PayloadJson);
    Check(plan.Appearance != null && plan.Appearance.Theme == "dark" && plan.Appearance.DarkStyle == "custom" && plan.Appearance.PageBg == "#101010" && plan.Appearance.Font == "Georgia" && plan.Appearance.OverrideSiteFonts, "plan: appearance values carried over");
    Check(plan.HomeUrl == "https://example.com/" && plan.BlockingEnabled == false, "plan: home URL and blocking preference carried over");
    Check(plan.Bookmarks.Count == 2 && plan.BookmarksRejected == 2 && plan.Bookmarks.All(b => b.Url.StartsWith("http")), "plan: javascript: and file: bookmarks rejected, http(s) kept");
    Check(plan.Bookmarks[1].Title == "B", "plan: control characters stripped from titles");
    Check(plan.SiteEntries.Count(e => e.Category == "site_permissions") == 1 && plan.SiteEntries.Any(e => e.Key == "perm.Camera" && e.Origin == "meet.example"), "plan: only the valid permission entry survives (bad origin, bad value, wrong-category key dropped)");
    Check(plan.SiteEntries.Count(e => e.Category == "network_labels") == 1 && plan.SiteEntries.Count(e => e.Category == "cert_trust") == 1, "plan: network label needs a net-hash id; cert entry needs a hex fingerprint key");
    Check(plan.SiteRejected == 5 && plan.UnknownCategories.SequenceEqual(new[] { "mystery" }), "plan: rejected entries counted (5) and unknown categories reported, not applied");

    var evilAp = SetupPlan.Parse(SetupPayload.Build("0123456789abcdef", now, now.AddHours(1), new Dictionary<string, object> { ["appearance"] = new { theme = "dark", page_bg = "red;}body{display:none", font = "Evil'Font" }, ["preferences"] = new { home_url = "javascript:alert(1)", blocking_enabled = "yes" } }));
    Check(evilAp.Appearance != null && evilAp.Appearance.PageBg == "#1b1d22" && evilAp.Appearance.Font == "default" && evilAp.Appearance.Theme == "dark", "plan: CSS-injection colour and non-allowlisted font fall back to defaults");
    Check(evilAp.HomeUrl == null && evilAp.BlockingEnabled == null, "plan: javascript: home URL and non-boolean blocking value ignored");
    Check(SetupValidate.IsSafeHome("recognition:start") && !SetupValidate.IsSafeUrl("ftp://x/") && !SetupValidate.IsSafeUrl("https://x/\u0007") && !SetupValidate.IsSafeUrl(new string('a', 3000)), "validators: start page ok; ftp, control chars and over-long URLs rejected");

    // reusable: the same snapshot + code opens any number of times (on any device) until it expires
    Check(Enumerable.Range(0, 3).All(i => SetupBlob.Open(blob, code, now.AddMinutes(i * 10)).Ok), "re-apply: the same snapshot and code open repeatedly until expiry");
}

Console.WriteLine();
Console.WriteLine($"checks passed: {pass}  failed: {fail}");
if (fail > 0) { Console.Error.WriteLine("BROWSER_GOVERNED_ACTIONS_TESTS_FAIL: " + fail); return 1; }
Console.WriteLine("SELFTEST_RECOGNITION_BROWSER_GOVERNED_ACTIONS_V1_OK");
return 0;
