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
Console.WriteLine("=== Code highlighter (executed C#) ===");
{
    string HlJoin(List<List<(string Cls, string Text)>> ls) => string.Join("\n", ls.Select(x => string.Concat(x.Select(t => t.Text))));
    bool HlHas(List<(string Cls, string Text)> line, string cls, string text) => line.Any(t => t.Cls == cls && t.Text == text);
    Check(CodeHighlighter.LanguageFor("Program.CS") == "csharp" && CodeHighlighter.LanguageFor(@"C:\x\run.ps1") == "powershell" && CodeHighlighter.LanguageFor("Makefile") == "text" && CodeHighlighter.LanguageFor(null) == "text" && CodeHighlighter.LanguageFor("a.json") == "json" && CodeHighlighter.IsCodeFile("x.py") && !CodeHighlighter.IsCodeFile("x.exe"), "language detection by extension (case-insensitive, unknown/null -> text)");

    var cs = CodeHighlighter.Highlight("public class Foo { // hi\n  string s = \"a\\\"b\"; int x = 42; Bar(1); }", "csharp");
    Check(cs.Count == 2 && HlHas(cs[0], "kw", "public") && HlHas(cs[0], "kw", "class") && HlHas(cs[0], "type", "Foo") && cs[0].Any(t => t.Cls == "com" && t.Text == "// hi"), "C#: keywords, type name and line comment");
    Check(HlHas(cs[1], "kw", "string") && HlHas(cs[1], "str", "\"a\\\"b\"") && HlHas(cs[1], "num", "42") && HlHas(cs[1], "fn", "Bar"), "C#: string with escaped quote stays one token; number and call recognised");

    var blk = CodeHighlighter.Highlight("/* a\nb */ int x;", "csharp");
    Check(blk.Count == 2 && blk[0].Count == 1 && blk[0][0] == ("com", "/* a") && blk[1][0] == ("com", "b */") && HlHas(blk[1], "kw", "int"), "a block comment spanning lines is cut per line and highlighting resumes after it");

    var unterminated = CodeHighlighter.Highlight("var s = \"abc\nint x = 1;", "csharp");
    Check(unterminated.Count == 2 && HlHas(unterminated[1], "kw", "int") && HlHas(unterminated[1], "num", "1"), "an unterminated string ends at the line end and never swallows the rest of the file");

    var verb = CodeHighlighter.Highlight("var p = @\"C:\\dir\\\" + x;", "csharp");
    Check(verb[0].Any(t => t.Cls == "str" && t.Text == "@\"C:\\dir\\\""), "C# verbatim string: backslash before the closing quote is not an escape");

    var py = CodeHighlighter.Highlight("\"\"\"doc\nstring\"\"\"\nx = 1  # c", "python");
    Check(py.Count == 3 && py[0][0].Cls == "str" && py[1][0].Cls == "str" && HlHas(py[2], "num", "1") && py[2].Any(t => t.Cls == "com"), "Python: triple-quoted string across lines, number, # comment");

    var jsonT = CodeHighlighter.Highlight("{\"name\": \"v\", \"n\": 1, \"ok\": true}", "json");
    Check(HlHas(jsonT[0], "attr", "\"name\"") && HlHas(jsonT[0], "str", "\"v\"") && HlHas(jsonT[0], "num", "1") && HlHas(jsonT[0], "kw", "true"), "JSON: keys vs string values, numbers, literals");

    var psT = CodeHighlighter.Highlight("$x = 'it''s' # c\n<# block\n#> if ($x) {}", "powershell");
    Check(HlHas(psT[0], "var", "$x") && HlHas(psT[0], "str", "'it''s'") && psT[0].Any(t => t.Cls == "com") && psT.Count == 3 && psT[1][0].Cls == "com" && HlHas(psT[2], "kw", "if"), "PowerShell: variables, doubled-quote string, comments, block comment, keywords");

    var sql = CodeHighlighter.Highlight("SELECT * FROM t WHERE id = 1 -- hi", "sql");
    Check(HlHas(sql[0], "kw", "SELECT") && HlHas(sql[0], "kw", "FROM") && HlHas(sql[0], "num", "1") && sql[0].Any(t => t.Cls == "com"), "SQL: keywords are case-insensitive, -- comments");

    var htm = CodeHighlighter.Highlight("<!-- c -->\n<a href=\"x\" id='y'>t</a>", "html");
    Check(htm[0][0].Cls == "com" && HlHas(htm[1], "kw", "a") && HlHas(htm[1], "attr", "href") && HlHas(htm[1], "str", "\"x\"") && HlHas(htm[1], "kw", "a"), "HTML: comment, tag names, attribute names, quoted values");

    var cssT = CodeHighlighter.Highlight("a:hover { color: #fff; margin: 4px; }", "css");
    Check(!HlHas(cssT[0], "attr", "a") && HlHas(cssT[0], "attr", "color") && HlHas(cssT[0], "num", "#fff") && HlHas(cssT[0], "num", "4px"), "CSS: properties are highlighted inside rules, selectors like a:hover are not");

    var crlf = CodeHighlighter.Highlight("a\r\nb\r\n", "text");
    Check(crlf.Count == 3 && crlf.All(x => x.All(t => !t.Text.Contains('\r'))), "CRLF input: no stray carriage returns in any line");
    Check(CodeHighlighter.Render("a\nb\n", "text").Split("class='l'").Length - 1 == 2, "render: a trailing newline does not add an extra empty line");
    Check(CodeHighlighter.Render("", "csharp").Contains("id='L1'") && CodeHighlighter.Render(null, null).Contains("id='L1'"), "empty and null input render one empty line without throwing");

    var evil = "'\"><img src=x onerror=alert(1)></script><svg onload=alert(1)>";
    Check(CodeHighlighter.Languages.All(lg => { var h = CodeHighlighter.Render(evil + "\n/* " + evil + " */\n\"" + evil + "\"", lg); return !h.Contains("<img") && !h.Contains("<svg") && !h.Contains("</script"); }), "render: hostile markup in the source is HTML-encoded for every language (no tag can be injected)");

    var corpus = new[] { "", "\n", "x", "a\n\nb", "\"\"\"\n", "'''a", "/*", "/* a */ b /* c", "<<<", "<a href=\"x", "<!-- ", "@\"abc", "$@\"a\"\"b\"", "`multi\nline`", "// c\n# d\n-- e", "\t \t\n", "é漢字😀 \"ü\"", "{ \"a\": [1, 2.5e3, -4, true, null] }", "a.b.c(d)(e)", "0x1F 1_000 .5 5." };
    bool roundTrip = true;
    foreach (var lg in CodeHighlighter.Languages) foreach (var src in corpus) if (HlJoin(CodeHighlighter.Highlight(src, lg)) != src) { roundTrip = false; Console.WriteLine("    roundtrip mismatch: " + lg + " / " + src.Replace("\n", "\\n")); }
    Check(roundTrip, "round trip: concatenating all tokens reproduces the input exactly for every language and every corpus sample (nothing lost or duplicated)");

    Check(CodeHighlighter.LooksBinary(new byte[] { 0x4D, 0x5A, 0x00, 0x01 }) && !CodeHighlighter.LooksBinary(Encoding.UTF8.GetBytes("plain text\n")) && !CodeHighlighter.LooksBinary(Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes("hi")).ToArray()) && !CodeHighlighter.LooksBinary(null) && !CodeHighlighter.LooksBinary(new byte[0]), "binary detection: NUL bytes mean binary, UTF-16 with a BOM is still text, null/empty are not binary");
    Check(CodeHighlighter.DecodeText(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes("é漢")).ToArray()) == "é漢" && CodeHighlighter.DecodeText(Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes("é漢")).ToArray()) == "é漢" && CodeHighlighter.DecodeText(Encoding.BigEndianUnicode.GetPreamble().Concat(Encoding.BigEndianUnicode.GetBytes("é漢")).ToArray()) == "é漢" && CodeHighlighter.DecodeText(null) == "", "decode: UTF-8, UTF-16 LE and BE byte-order marks are honoured and removed");
    Check(CodeHighlighter.DecodeText(new byte[] { 0x61, 0xFF, 0xFE, 0x62 }.Skip(0).Take(1).Concat(new byte[] { 0xC3 }).ToArray()).StartsWith("a"), "decode: invalid UTF-8 never throws (replacement characters)");
    var big = string.Concat(Enumerable.Repeat("int x = \"a\"; // note\n", 60000));
    var sw = System.Diagnostics.Stopwatch.StartNew();
    var bigHl = CodeHighlighter.Highlight(big, "csharp");
    sw.Stop();
    Check(bigHl.Count == 60001 && sw.ElapsedMilliseconds < 8000, "performance: 60,000 lines (~1.4 MB) highlight in well under 8 s (measured " + sw.ElapsedMilliseconds + " ms)");
    var hostile = string.Concat(Enumerable.Repeat("\"/*'`<#", 40000));
    sw.Restart();
    foreach (var lg in new[] { "csharp", "javascript", "powershell", "html", "python" }) CodeHighlighter.Highlight(hostile, lg);
    sw.Stop();
    Check(sw.ElapsedMilliseconds < 15000, "performance: 280 KB of quote/comment-opener garbage stays linear across 5 languages (measured " + sw.ElapsedMilliseconds + " ms)");
    foreach (var run in new[] { "(", "$", "@", "<", "\"", "\\", "a" })
    {
        var longRun = new string(run[0], 1_000_000);
        sw.Restart();
        foreach (var lg in new[] { "csharp", "powershell", "html", "css" }) CodeHighlighter.Highlight(longRun, lg);
        sw.Stop();
        Check(sw.ElapsedMilliseconds < 20000, "performance: a single 1,000,000-character run of '" + run + "' across 4 languages stays linear (measured " + sw.ElapsedMilliseconds + " ms)");
    }
}

Console.WriteLine();
Console.WriteLine("=== PDF page tools (executed C#, PDFsharp) ===");
{
    byte[] MakePdf(string prefix, int n)
    {
        var d = new PdfSharp.Pdf.PdfDocument();
        for (int i = 1; i <= n; i++) { var p = d.AddPage(); p.Elements.SetString("/Marker", prefix + i); }
        using var ms = new MemoryStream(); d.Save(ms, false); return ms.ToArray();
    }
    List<string> Markers(byte[] pdf)
    {
        using var d = PdfSharp.Pdf.IO.PdfReader.Open(new MemoryStream(pdf), PdfSharp.Pdf.IO.PdfDocumentOpenMode.Import);
        return Enumerable.Range(0, d.PageCount).Select(i => d.Pages[i].Elements.GetString("/Marker")).ToList();
    }
    bool PdfFails(Action a) { try { a(); return false; } catch (PdfToolException) { return true; } }
    string Sha(byte[] b) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(b));
    string J(IEnumerable<string> x) => string.Join(",", x);

    var pdfA = MakePdf("a", 5);
    Check(PdfTools.PageCount(pdfA) == 5 && J(Markers(pdfA)) == "a1,a2,a3,a4,a5", "test PDFs: 5 tagged pages read back in order");

    string? perr;
    Check(J(PdfTools.ParseRange("1-3,5", 5, out perr)!.Select(i => i + 1).Select(i => i.ToString())) == "1,2,3,5" && perr == null, "range: '1-3,5' -> pages 1,2,3,5");
    Check(J(PdfTools.ParseRange("2-", 5, out _)!.Select(i => (i + 1).ToString())) == "2,3,4,5" && J(PdfTools.ParseRange("-2", 5, out _)!.Select(i => (i + 1).ToString())) == "1,2", "range: open-ended '2-' and '-2'");
    Check(J(PdfTools.ParseRange("5-3", 5, out _)!.Select(i => (i + 1).ToString())) == "5,4,3" && J(PdfTools.ParseRange(" 1 , 3 ", 5, out _)!.Select(i => (i + 1).ToString())) == "1,3", "range: descending ranges allowed, whitespace tolerated");
    var badSpecs = new[] { "", "  ", "0", "6", "a", "1-2-3", "1,,2", ",", "9999999999", "3-1x", "-", "1--2", "+1", "1.5" };
    var notRejected = badSpecs.Where(s => PdfTools.ParseRange(s, 5, out var e3) != null).ToList();
    Check(notRejected.Count == 0, "range: invalid specs all rejected with a message" + (notRejected.Count > 0 ? " (accepted: " + string.Join(" | ", notRejected) + ")" : ""));

    var pdfSha0 = Sha(pdfA);
    Check(J(Markers(PdfTools.Extract(pdfA, "2,4-5"))) == "a2,a4,a5", "extract: pages 2, 4, 5 in that order");
    Check(J(Markers(PdfTools.Extract(pdfA, "5-1"))) == "a5,a4,a3,a2,a1", "reorder: '5-1' reverses the document");
    Check(J(Markers(PdfTools.Extract(pdfA, "3,1,2,4,5"))) == "a3,a1,a2,a4,a5" && J(Markers(PdfTools.Extract(pdfA, "1,1"))) == "a1,a1", "reorder: arbitrary order; duplicates allowed");
    Check(J(Markers(PdfTools.Delete(pdfA, "2-3"))) == "a1,a4,a5", "delete: pages 2-3 removed, rest keep their order");
    Check(PdfFails(() => PdfTools.Delete(pdfA, "1-5")) && PdfFails(() => PdfTools.Extract(pdfA, "7")) && PdfFails(() => PdfTools.Extract(pdfA, "")), "delete-all, out-of-range and empty page lists are refused");
    var pdfB = MakePdf("b", 2);
    Check(J(Markers(PdfTools.Merge(new[] { MakePdf("a", 3), pdfB }))) == "a1,a2,a3,b1,b2", "merge: documents joined in the order given");
    Check(PdfFails(() => PdfTools.Merge(new[] { pdfB })) && PdfFails(() => PdfTools.Merge(new[] { pdfB, new byte[] { 1, 2, 3 } })), "merge: needs two PDFs; a non-PDF in the set is refused");
    var split = PdfTools.SplitEach(pdfA);
    Check(split.Count == 5 && Enumerable.Range(0, 5).All(i => J(Markers(split[i])) == "a" + (i + 1)), "split: one single-page PDF per page");
    var rot = PdfTools.Rotate(pdfA, "1,3", 90);
    Check(J(PdfTools.Rotations(rot).Select(x => x.ToString())) == "90,0,90,0,0" && J(Markers(rot)) == "a1,a2,a3,a4,a5", "rotate: only the listed pages turn; order and content unchanged");
    Check(J(PdfTools.Rotations(PdfTools.Rotate(rot, "1", 270)).Select(x => x.ToString())) == "0,0,90,0,0" && J(PdfTools.Rotations(PdfTools.Rotate(pdfA, "2", -90)).Select(x => x.ToString())) == "0,270,0,0,0", "rotate: rotation adds to the existing angle and wraps (90+270=0, -90=270)");
    Check(PdfFails(() => PdfTools.Rotate(pdfA, "1", 45)) && PdfFails(() => PdfTools.Rotate(pdfA, "1", 0)), "rotate: only multiples of 90 are accepted");
    Check(Sha(pdfA) == pdfSha0, "operations never modify the input bytes");
    Check(PdfFails(() => PdfTools.PageCount(new byte[0])) && PdfFails(() => PdfTools.PageCount(Encoding.ASCII.GetBytes("this is definitely not a pdf file at all"))) && PdfFails(() => PdfTools.Extract(pdfA.Take(pdfA.Length / 2).ToArray(), "1")), "empty, non-PDF and truncated input fail with a clear PdfToolException instead of crashing");
    var rnd = new Random(7); var junk = new byte[4096]; rnd.NextBytes(junk);
    Check(PdfFails(() => PdfTools.PageCount(junk)), "random bytes are refused");
}

Console.WriteLine();
Console.WriteLine("=== Image maths (executed C#) ===");
{
    int w, h; string? ie;
    Check(ImageMath.TryTarget(1000, 500, "percent", 50, 0, out w, out h, out ie) && w == 500 && h == 250, "resize: 50% of 1000x500 = 500x250");
    Check(ImageMath.TryTarget(1000, 500, "width", 400, 0, out w, out h, out ie) && w == 400 && h == 200 && ImageMath.TryTarget(1000, 500, "height", 100, 0, out w, out h, out ie) && w == 200 && h == 100, "resize: by width or height keeps the aspect ratio");
    Check(ImageMath.TryTarget(4000, 3000, "fit", 800, 800, out w, out h, out ie) && w == 800 && h == 600 && ImageMath.TryTarget(3000, 4000, "fit", 800, 800, out w, out h, out ie) && w == 600 && h == 800, "resize: fit within a box, either orientation");
    Check(ImageMath.TryTarget(100, 100, "fit", 800, 800, out w, out h, out ie) && w == 800 && h == 800, "resize: fit may enlarge when asked");
    Check(ImageMath.TryTarget(1000, 500, "exact", 300, 300, out w, out h, out ie) && w == 300 && h == 300, "resize: exact size ignores the aspect ratio");
    Check(ImageMath.TryTarget(3, 1, "percent", 10, 0, out w, out h, out ie) && w == 1 && h == 1, "resize: never rounds down to zero pixels");
    Check(new[] { ("percent", 0.0, 0.0), ("percent", -5.0, 0.0), ("percent", 100000.0, 0.0), ("width", 0.0, 0.0), ("width", 99999.0, 0.0), ("exact", 10.0, 0.0), ("fit", 0.0, 10.0), ("bogus", 10.0, 10.0), ("width", double.NaN, 0.0), ("height", double.PositiveInfinity, 0.0) }.All(c => !ImageMath.TryTarget(1000, 500, c.Item1, c.Item2, c.Item3, out _, out _, out var e4) && !string.IsNullOrEmpty(e4)), "resize: zero, negative, absurd, NaN, infinite or unknown inputs are refused with a message");
    Check(!ImageMath.TryTarget(0, 500, "percent", 50, 0, out _, out _, out _), "resize: an image with no size is refused");
    Check(!ImageMath.TryTarget(5000, 4000, "percent", 300, 0, out w, out h, out ie) && w == 0 && h == 0 && ie != null && ie.Contains("limit"), "resize: 15000x12000 (180 megapixels) is refused by the pixel limit");
    Check(ImageMath.TryTarget(5000, 4000, "percent", 200, 0, out w, out h, out ie) && w == 10000 && h == 8000, "resize: 10000x8000 (80 megapixels) is within the limit");
    Check(ImageMath.NormalizeRotation(90) == 90 && ImageMath.NormalizeRotation(-90) == 270 && ImageMath.NormalizeRotation(450) == 90 && ImageMath.NormalizeRotation(45) == -1 && ImageMath.NormalizeRotation(0) == 0, "rotation: normalised to 0/90/180/270; non-multiples of 90 rejected");
    Check(ImageMath.AfterRotation(1000, 500, 90) == (500, 1000) && ImageMath.AfterRotation(1000, 500, 180) == (1000, 500) && ImageMath.AfterRotation(1000, 500, 270) == (500, 1000), "rotation: width and height swap on 90/270");
    Check(ImageMath.ClampQuality(0) == 1 && ImageMath.ClampQuality(500) == 100 && ImageMath.ClampQuality(85) == 85, "JPEG quality is clamped to 1..100");
    Check(ImageMath.FormatFor("PNG") == "png" && ImageMath.FormatFor("jpeg") == "jpg" && ImageMath.FormatFor("jpg") == "jpg" && ImageMath.FormatFor("bmp") == "bmp" && ImageMath.FormatFor("tiff") == "tiff" && ImageMath.FormatFor("exe") == null && ImageMath.FormatFor(null) == null, "output formats are an allowlist (png, jpg, bmp, tiff, gif)");
    Check(ImageMath.IsImageFile("a.JPG") && ImageMath.IsImageFile("a.webp") && !ImageMath.IsImageFile("a.pdf") && !ImageMath.IsImageFile("a"), "image file detection by extension");
}

Console.WriteLine();
Console.WriteLine("=== Host message gate and download rules (executed C#) ===");
{
    // The privilege boundary: web content must never reach the command handlers.
    string[] commands = { "site-perm:evil.com:Camera:allow", "cert-trust:evil.com:der-0123456789abcdef:allow", "cookies-clear-all", "update-apply", "net-forget:Home", "toggle-blocking", "vpn-off", "export-session", "open-profile", "appearance-set:bg:#000000", "pw-reveal:abc", "setup-apply:{}", "tools-pdf-run:{}", "rmbookmark:https://x/", "open:https://evil.example/" };
    Check(commands.All(c => MessageGate.Classify(false, "https://evil.example/", c) == MessageVerdict.Deny), "gate: a normal web tab cannot send ANY command, whatever its origin");
    Check(commands.All(c => MessageGate.Classify(true, "https://evil.example/", c) == MessageVerdict.Deny), "gate: even in an 'internal' tab, a message that comes from an http(s) document is refused (tab navigated away, cross-origin frame)");
    Check(commands.All(c => new[] { "http://x/", "file:///c:/x.html", "ftp://x/", "ws://x/", "wss://x/", "blob:https://x/1", "filesystem:https://x/t/a", "HTTPS://X/", "  https://x/" }.All(s => MessageGate.Classify(true, s, c) == MessageVerdict.Deny)), "gate: every web-like source scheme (http, https, file, ftp, ws, wss, blob, filesystem, any case or leading space) is refused");
    Check(commands.All(c => MessageGate.Classify(true, "about:blank", c) == MessageVerdict.Command && MessageGate.Classify(true, "data:text/html;charset=utf-8,x", c) == MessageVerdict.Command && MessageGate.Classify(true, "", c) == MessageVerdict.Command && MessageGate.Classify(true, null, c) == MessageVerdict.Command), "gate: the browser's own internal pages (about:, data: or empty source) can still send commands");
    Check(commands.All(c => MessageGate.Classify(false, "about:blank", c) == MessageVerdict.Deny && MessageGate.Classify(false, null, c) == MessageVerdict.Deny), "gate: a non-internal tab is refused even with an about:blank or empty source");
    Check(MessageGate.Classify(false, "https://evil.example/", "sc:newtab") == MessageVerdict.Shortcut && MessageGate.Classify(true, "about:blank", "sc:reload") == MessageVerdict.Shortcut, "gate: keyboard shortcuts (sc:) are the only thing web content may send; they use a separate allowlist");
    Check(MessageGate.Classify(true, "about:blank", "") == MessageVerdict.Deny && MessageGate.Classify(true, "about:blank", null) == MessageVerdict.Deny, "gate: empty messages are refused");
    Check(MessageGate.Classify(true, "about:blank", "SC:newtab") == MessageVerdict.Command, "gate: prefix matching is case-sensitive ('SC:' is not a shortcut, it is just an unknown command)");
    Check(MessageGate.IsTabShortcut("newtab") && MessageGate.IsTabShortcut("newprivate") && MessageGate.IsTabShortcut("closetab") && !MessageGate.IsTabShortcut("reload") && !MessageGate.IsTabShortcut("find"), "gate: tab-creating/closing shortcuts are the rate-limited set");

    Check(DownloadRules.Assess("setup.exe") == DownloadRisk.Executable && DownloadRules.Assess("INSTALL.MSI") == DownloadRisk.Executable && DownloadRules.Assess("run.ps1") == DownloadRisk.Executable && DownloadRules.Assess("x.bat") == DownloadRisk.Executable && DownloadRules.Assess("a.lnk") == DownloadRisk.Executable && DownloadRules.Assess("a.hta") == DownloadRisk.Executable && DownloadRules.Assess("a.jar") == DownloadRisk.Executable, "downloads: programs, installers, scripts and shortcuts need confirmation");
    Check(DownloadRules.Assess("invoice.pdf.exe") == DownloadRisk.Executable && DownloadRules.Assess("setup.exe.") == DownloadRisk.Executable && DownloadRules.Assess("setup.exe  ") == DownloadRisk.Executable && DownloadRules.Assess("setup.exe . ") == DownloadRisk.Executable, "downloads: double extensions and trailing dots/spaces (which Windows ignores) are still recognised");
    Check(DownloadRules.Assess("report.pdf") == DownloadRisk.None && DownloadRules.Assess("photo.jpg") == DownloadRisk.None && DownloadRules.Assess("data.csv") == DownloadRisk.None && DownloadRules.Assess("archive.zip") == DownloadRisk.None && DownloadRules.Assess("notes") == DownloadRisk.None && DownloadRules.Assess("") == DownloadRisk.None && DownloadRules.Assess(null) == DownloadRisk.None, "downloads: documents, images, data files, archives and extension-less names are not prompted");
    Check(DownloadRules.Assess("photo\u202Egpj.exe") == DownloadRisk.DeceptiveName && DownloadRules.Assess("a\u202Etxt.js") == DownloadRisk.DeceptiveName && DownloadRules.Assess("x\u200Fy.pdf") == DownloadRisk.DeceptiveName, "downloads: right-to-left override and other direction-control characters in a name are flagged as deceptive");
}

Console.WriteLine();
Console.WriteLine("=== Privacy rules (executed C#) ===");
{
    Check(PrivacyRules.HttpsUpgrade("http://example.com/a?b=1#c") == "https://example.com/a?b=1#c", "https upgrade: plain http becomes https, path/query/fragment kept");
    Check(PrivacyRules.HttpsUpgrade("http://example.com:8080/x") == "https://example.com:8080/x", "https upgrade: non-default port is kept");
    Check(PrivacyRules.HttpsUpgrade("https://example.com/") == null && PrivacyRules.HttpsUpgrade("ftp://example.com/") == null && PrivacyRules.HttpsUpgrade("not a url") == null && PrivacyRules.HttpsUpgrade(null) == null, "https upgrade: https, other schemes, garbage and null are left alone");
    Check(PrivacyRules.HttpsUpgrade("http://localhost:3000/") == null && PrivacyRules.HttpsUpgrade("http://127.0.0.1/") == null && PrivacyRules.HttpsUpgrade("http://127.5.5.5:81/") == null && PrivacyRules.HttpsUpgrade("http://[::1]:8080/") == null && PrivacyRules.HttpsUpgrade("http://app.localhost/") == null, "https upgrade: loopback (localhost, 127.x, ::1, *.localhost) is exempt");
    Check(PrivacyRules.HttpsUpgrade("http://localhost.evil.com/") != null && PrivacyRules.HttpsUpgrade("http://127.0.0.1.evil.com/") != null && PrivacyRules.HttpsUpgrade("http://localhostevil.com/") != null, "https upgrade: look-alike hosts (localhost.evil.com, 127.0.0.1.evil.com) are NOT exempt (regression: old prefix check let these through)");
    Check(PrivacyRules.StripTrackingParams("https://a.example/p?utm_source=x&id=7&fbclid=abc#top", out var n1) == "https://a.example/p?id=7#top" && n1 == 2, "strip: tracking params removed, real params and fragment kept");
    Check(PrivacyRules.StripTrackingParams("https://a.example/p?gclid=1&UTM_Medium=m", out var n2) == "https://a.example/p" && n2 == 2, "strip: all params tracking -> no dangling '?'; matching is case-insensitive");
    var same = "https://a.example/p?q=a%20b&x=1&&y";
    Check(PrivacyRules.StripTrackingParams(same, out var n3) == same && n3 == 0, "strip: URL without tracking params is returned byte-for-byte unchanged");
    Check(PrivacyRules.StripTrackingParams("https://a.example/p?%75tm_source=x&k=v", out var n4) == "https://a.example/p?k=v" && n4 == 1, "strip: percent-encoded parameter names are decoded before matching");
    Check(PrivacyRules.StripTrackingParams("https://a.example/p?utmx=1&my_utm_source=2&ref=news&q=gclid", out var n5) == "https://a.example/p?utmx=1&my_utm_source=2&ref=news&q=gclid" && n5 == 0, "strip: near-miss names and values containing tracking words are not touched");
    Check(PrivacyRules.StripTrackingParams("javascript:alert(1)?utm_source=x", out var n6) == "javascript:alert(1)?utm_source=x" && PrivacyRules.StripTrackingParams("file:///c:/a?utm_source=x", out _) == "file:///c:/a?utm_source=x" && PrivacyRules.StripTrackingParams(null, out _) == "" && n6 == 0, "strip: only http(s) URLs are ever rewritten");
    Check(PrivacyRules.StripTrackingParams("https://a.example/p?a=1&mc_eid=9&b=2&_ga=3", out var n7) == "https://a.example/p?a=1&b=2" && n7 == 2, "strip: order of the remaining parameters is preserved");
}

Console.WriteLine();
Console.WriteLine("=== Password vault (executed C#) ===");
{
    var nowV = new DateTime(2026, 10, 7, 12, 0, 0, DateTimeKind.Utc);
    // generator
    var gen = PasswordGenerator.Generate(24);
    Check(gen.Length == 24 && gen.Any(char.IsLower) && gen.Any(char.IsUpper) && gen.Any(char.IsDigit) && gen.Any(c => PasswordGenerator.Symbols.Contains(c)), "generator: requested length and at least one of each chosen character type");
    Check(Enumerable.Range(0, 200).All(_ => { var x = PasswordGenerator.Generate(8); return x.Any(char.IsLower) && x.Any(char.IsUpper) && x.Any(char.IsDigit) && x.Any(c => PasswordGenerator.Symbols.Contains(c)); }), "generator: 200 minimum-length passwords all contain every chosen type");
    Check(Enumerable.Range(0, 200).All(_ => PasswordGenerator.Generate(40).All(c => PasswordGenerator.Ambiguous.IndexOf(c) < 0)), "generator: ambiguous characters (O 0 o I l 1 | quotes) excluded when asked");
    Check(Enumerable.Range(0, 100).All(_ => PasswordGenerator.Generate(30, true, false, true, false).All(c => char.IsLower(c) || char.IsDigit(c))), "generator: unchecked types never appear");
    Check(Enumerable.Range(0, 100).Select(_ => PasswordGenerator.Generate(20)).Distinct().Count() == 100, "generator: 100 passwords are all distinct");
    var digitsOnly = string.Concat(Enumerable.Range(0, 100).Select(_ => PasswordGenerator.Generate(128, false, false, true, false, false)));
    var counts = digitsOnly.GroupBy(c => c).ToDictionary(x => x.Key, x => x.Count());
    Check(counts.Count == 10 && counts.Values.All(n => n > 1100 && n < 1460), "generator: digit frequencies over 12,800 draws are near-uniform (expected 1280 each)");
    Check(Throws(() => PasswordGenerator.Generate(7)) && Throws(() => PasswordGenerator.Generate(129)) && Throws(() => PasswordGenerator.Generate(16, false, false, false, false)), "generator: length outside 8..128 and no character types are refused");
    bool Throws(Action a) { try { a(); return false; } catch (ArgumentException) { return true; } }

    // origins
    Check(PasswordRules.NormalizeOrigin(" Example.COM ") == "example.com" && PasswordRules.NormalizeOrigin("example.com:8443") == "example.com:8443", "origin: trimmed, lower-cased, port kept");
    Check(new[] { "https://example.com", "example.com/path", "exa mple.com", "", "-bad.com", "example.com:99999", "a@b.com", "ex\u0001.com" }.All(s => PasswordRules.NormalizeOrigin(s) == null), "origin: scheme, path, spaces, userinfo, bad port, control characters all rejected");
    Check(PasswordRules.OriginOf("https://Example.com/login?x=1") == "example.com" && PasswordRules.OriginOf("https://example.com:8443/") == "example.com:8443" && PasswordRules.OriginOf("http://example.com:80/") == "example.com", "origin of URL: default ports dropped, others kept");
    Check(PasswordRules.OriginOf("https://example.com@evil.com/") == null && PasswordRules.OriginOf("javascript:alert(1)") == null && PasswordRules.OriginOf("file:///c:/x") == null && PasswordRules.OriginOf(null) == null, "origin of URL: userinfo trick, javascript:, file:, null refused");
    Check(PasswordRules.MayFill("example.com", "https://example.com/login"), "fill: exact https origin allowed");
    Check(!PasswordRules.MayFill("example.com", "https://login.example.com/") && !PasswordRules.MayFill("example.com", "https://example.com.evil.com/") && !PasswordRules.MayFill("example.com", "https://evilexample.com/") && !PasswordRules.MayFill("example.com", "https://example.com:8443/"), "fill: subdomain, suffix look-alike, prefix look-alike and other port all refused");
    Check(!PasswordRules.MayFill("example.com", "http://example.com/") && !PasswordRules.MayFill("example.com", "https://example.com@evil.com/"), "fill: plain http on the internet and userinfo trick refused");
    Check(PasswordRules.MayFill("localhost:3000", "http://localhost:3000/app") && !PasswordRules.MayFill("localhost:3000", "http://localhost:3001/"), "fill: http allowed only for localhost, and the port must match");

    // vault
    var vs = new Dictionary<string, string>();
    PasswordVault NewVault() => new PasswordVault("mem://vault", p => vs.TryGetValue(p, out var v) ? v : "", (p, t) => vs[p] = t);
    PasswordVault Loaded() { var x = NewVault(); x.Load(); return x; }
    var vault = NewVault();
    Check(vault.Load() == 0 && vault.Entries.Count == 0, "vault: empty store loads as empty");
    Check(vault.Add("Example.com", "alice", "S3cret!pass-word", "note", nowV, out var e1) == null && e1 != null && e1.Origin == "example.com" && e1.Id.Length == 24, "vault: add normalises the origin and assigns a random id");
    Check(vault.Add("example.com", "alice", "other", "", nowV, out _) != null, "vault: duplicate (site, username) refused");
    Check(vault.Add("example.com", "bob", "pw-for-bob-123!", "", nowV, out var e2) == null, "vault: a second username on the same site is fine");
    Check(vault.Add("https://example.com", "x", "y", "", nowV, out _) != null && vault.Add("example.com", "x", "", "", nowV, out _) != null && vault.Add("example.com", "x\u0000", "y", "", nowV, out _) != null && vault.Add("example.com", "x", "y", new string('n', 3000), nowV, out _) != null, "vault: bad origin, empty password, control char, oversized note all refused");
    var v2 = NewVault();
    Check(v2.Load() == 0 && v2.Entries.Count == 2 && v2.Get(e1!.Id)!.Password == "S3cret!pass-word" && v2.Get(e1.Id)!.Note == "note", "vault: entries survive a reload from storage");
    Check(v2.ForPage("https://example.com/login").Count == 2 && v2.ForPage("https://login.example.com/").Count == 0 && v2.ForPage("http://example.com/").Count == 0, "vault: ForPage returns only exact-origin entries");
    Check(v2.Update(e2!.Id, "bob", "NewPass-987654!x", "", nowV.AddMinutes(1)) == null && Loaded().Get(e2.Id)!.Password == "NewPass-987654!x", "vault: update persists");
    Check(v2.Update(e2.Id, "alice", "NewPass-987654!x", "", nowV) != null && v2.Update("nope", "a", "b", "", nowV) != null, "vault: update cannot collide with another username, unknown id refused");
    Check(v2.Remove(e1.Id) && !v2.Remove(e1.Id) && Loaded().Entries.Count == 1, "vault: remove persists, removing twice is a no-op");

    // damaged storage
    vs["mem://vault"] = "{ not json";
    var dmg = NewVault();
    Check(dmg.Load() == 1 && dmg.Entries.Count == 0, "vault: unreadable storage loads empty and reports the damage instead of throwing");
    vs["mem://vault"] = "{\"schema\":\"recognition.vault.v1\",\"entries\":[{\"id\":\"aaaaaaaaaaaaaaaaaaaaaaaa\",\"origin\":\"ok.example\",\"username\":\"u\",\"password\":\"pw\"},{\"id\":\"short\",\"origin\":\"ok.example\",\"password\":\"pw\"},{\"id\":\"bbbbbbbbbbbbbbbbbbbbbbbb\",\"origin\":\"https://bad/\",\"password\":\"pw\"},{\"id\":\"cccccccccccccccccccccccc\",\"origin\":\"ok.example\",\"password\":\"\"},{\"id\":\"aaaaaaaaaaaaaaaaaaaaaaaa\",\"origin\":\"dup.example\",\"password\":\"pw\"}]}";
    var part = NewVault();
    Check(part.Load() == 4 && part.Entries.Count == 1 && part.Entries[0].Origin == "ok.example", "vault: damaged records (short id, bad origin, empty password, duplicate id) skipped, the good one kept");

    // strength and audit
    Check(PasswordRules.Strength("password1!") == "weak" && PasswordRules.Strength("aaaaaaaaaaaa") == "weak" && PasswordRules.Strength("") == "weak", "strength: common words, heavy repetition and empty are weak");
    Check(PasswordRules.Strength("Tr0ub4dor&3") != "weak" && PasswordRules.Strength(PasswordGenerator.Generate(20)) == "strong", "strength: mixed 11-char is not weak, a generated 20-char password is strong");
    var av = new PasswordVault("mem://audit", _ => "", (_, __) => { });
    av.Add("a.example", "u", "Zq7!mK2-vXw9#Lp4", "", nowV, out var a1); av.Add("b.example", "u", "Zq7!mK2-vXw9#Lp4", "", nowV, out var a2);
    av.Add("c.example", "u", "123456", "", nowV, out var a3); av.Add("d.example", "u", PasswordGenerator.Generate(24), "", nowV, out var a4);
    var aud = av.Audit();
    Check(aud.Count(i => i.Kind == "reused") == 2 && aud.Any(i => i.Id == a1!.Id && i.Kind == "reused") && aud.Any(i => i.Id == a2!.Id && i.Kind == "reused"), "audit: reused password flagged on both entries");
    Check(aud.Any(i => i.Id == a3!.Id && i.Kind == "weak") && !aud.Any(i => i.Id == a4!.Id), "audit: weak password flagged, strong unique one is clean");

    // fill script
    var fs = FillScript.Build("al\"ice</script>'", "p\\w'd\u2028\"x");
    Check(!fs.Contains('\n') && fs.Contains("al\\u0022ice") && fs.Contains("\\u003C/script\\u003E") && fs.EndsWith(")"), "fill script: a single line; values are JSON-escaped literals (</script>, quotes, backslash, U+2028 cannot break out)");
    Check(fs.Contains("input[type=password]") && fs.Contains("dispatchEvent"), "fill script: targets password fields and notifies the page");
}

Console.WriteLine();
Console.WriteLine($"checks passed: {pass}  failed: {fail}");
if (fail > 0) { Console.Error.WriteLine("BROWSER_GOVERNED_ACTIONS_TESTS_FAIL: " + fail); return 1; }
Console.WriteLine("SELFTEST_RECOGNITION_BROWSER_GOVERNED_ACTIONS_V1_OK");
return 0;
