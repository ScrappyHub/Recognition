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
    // Pages are identified by their MediaBox width (custom dictionary keys are not carried over by PDFsharp's page import,
    // but the page geometry is): prefix 'a' -> widths 101..., 'b' -> 201..., so "a3" is a page 103 points wide.
    byte[] MakePdf(string prefix, int n)
    {
        var d = new PdfSharp.Pdf.PdfDocument();
        int baseW = (prefix[0] - 'a' + 1) * 100;
        for (int i = 1; i <= n; i++) { var p = d.AddPage(); p.Width = PdfSharp.Drawing.XUnit.FromPoint(baseW + i); p.Height = PdfSharp.Drawing.XUnit.FromPoint(200); }
        using var ms = new MemoryStream(); d.Save(ms, false); return ms.ToArray();
    }
    List<string> Markers(byte[] pdf)
    {
        using var d = PdfSharp.Pdf.IO.PdfReader.Open(new MemoryStream(pdf), PdfSharp.Pdf.IO.PdfDocumentOpenMode.Import);
        return Enumerable.Range(0, d.PageCount).Select(i => { int w = (int)Math.Round(d.Pages[i].MediaBox.Width); return (char)('a' + w / 100 - 1) + (w % 100).ToString(); }).ToList();
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
Console.WriteLine("=== Filter engine (executed C#) ===");
{
    FilterEngine Fe(params string[] lines) { var e = new FilterEngine(); e.AddList(string.Join("\n", lines), "t"); return e; }
    bool Blk(FilterEngine e, string url, string page = "https://page.example/", ResType t = ResType.Script) => e.Match(url, page, t).Blocked;

    var feA = Fe("||ads.example.com^");
    Check(Blk(feA, "https://ads.example.com/x.js") && Blk(feA, "https://sub.ads.example.com/a") && Blk(feA, "https://ads.example.com:8443/a") && Blk(feA, "https://ads.example.com"), "domain rule ||ads.example.com^ blocks the host, its subdomains, explicit ports and the bare host");
    Check(!Blk(feA, "https://example.com/x.js") && !Blk(feA, "https://ads.example.com.evil.com/x.js") && !Blk(feA, "https://notads.example.com/x.js") && !Blk(feA, "https://example.com/ads.example.com/x"), "domain rule does not match the parent, a look-alike suffix, a longer label, or the text appearing in a path");
    Check(Blk(feA, "https://good.com@ads.example.com/x") && !Blk(feA, "https://ads.example.com@good.com/x") && !Blk(feA, "https://good.com:pw@good.com/ads.example.com"), "userinfo tricks: the real host is what is matched");
    var feB = Fe("||example.com/path");
    Check(Blk(feB, "https://example.com/path/x") && Blk(feB, "https://www.example.com/path?q=1") && !Blk(feB, "https://example.com/other"), "domain + path rule");
    var feC = Fe("/banner/ad_", "||tracker.net/*/pixel.gif", "|https://exact.example/ad.js|");
    Check(Blk(feC, "https://x.test/banner/ad_1.png", t: ResType.Image) && !Blk(feC, "https://x.test/banners/ad_1.png", t: ResType.Image), "plain path rule needs the whole token ('/banner/' matches, '/banners/' does not)");
    Check(Blk(feC, "https://tracker.net/a/b/pixel.gif", t: ResType.Image) && !Blk(feC, "https://tracker.net/pixel.gif", t: ResType.Image), "wildcard rule: '*' spans path parts, literal slashes still required");
    Check(Blk(feC, "https://exact.example/ad.js") && !Blk(feC, "https://exact.example/ad.js?x=1") && !Blk(feC, "http://exact.example/ad.js") && !Blk(feC, "https://sub.exact.example/ad.js"), "start and end anchors (|...|) match exactly");
    var feD = Fe("||cdn.example.com^$script", "||tp.example^$third-party", "||fp.example^$~third-party", "||both.example^$image,script", "||notimg.example^$~image");
    Check(Blk(feD, "https://cdn.example.com/a.js", t: ResType.Script) && !Blk(feD, "https://cdn.example.com/a.png", t: ResType.Image), "type option: $script blocks scripts only");
    Check(Blk(feD, "https://tp.example/x", "https://news.test/") && !Blk(feD, "https://tp.example/x", "https://www.tp.example/") && !Blk(feD, "https://tp.example/x", "https://tp.example/"), "$third-party blocks only across sites (same registrable domain is first-party)");
    Check(!Blk(feD, "https://fp.example/x", "https://news.test/") && Blk(feD, "https://fp.example/x", "https://fp.example/"), "$~third-party blocks only first-party requests");
    Check(Blk(feD, "https://both.example/a", t: ResType.Image) && Blk(feD, "https://both.example/a", t: ResType.Script) && !Blk(feD, "https://both.example/a", t: ResType.Font), "several types in one rule");
    Check(Blk(feD, "https://notimg.example/a", t: ResType.Script) && !Blk(feD, "https://notimg.example/a", t: ResType.Image), "negated type $~image");
    var feE = Fe("||widget.test^$domain=news.com|~sports.news.com");
    Check(Blk(feE, "https://widget.test/w.js", "https://news.com/a") && Blk(feE, "https://widget.test/w.js", "https://www.news.com/a") && !Blk(feE, "https://widget.test/w.js", "https://sports.news.com/a") && !Blk(feE, "https://widget.test/w.js", "https://other.com/a"), "domain= option includes, excludes and covers subdomains of the page host");
    var feF = Fe("||ads.example.com^", "@@||ads.example.com/allowed^", "||hard.example^$important", "@@||hard.example^");
    var mAllow = feF.Match("https://ads.example.com/allowed/x.js", "https://p.test/", ResType.Script);
    Check(!mAllow.Blocked && mAllow.Rule != null && mAllow.Rule.StartsWith("@@") && Blk(feF, "https://ads.example.com/other.js"), "exception rule (@@) overrides a block only for what it names");
    Check(Blk(feF, "https://hard.example/x.js"), "$important blocks even when an exception matches");
    var feG = Fe("||page.test^", "||doc.test^$document");
    Check(!Blk(feG, "https://page.test/", t: ResType.Document) && Blk(feG, "https://page.test/", t: ResType.Subdocument) && Blk(feG, "https://doc.test/", t: ResType.Document), "rules do not block top-level navigation unless they say $document");
    var feH = Fe("0.0.0.0 evil.example # comment", "127.0.0.1 localhost", "0.0.0.0 0.0.0.0", "0.0.0.0\ttab.example", "127.0.0.1 two words.example", "0.0.0.0 bad_host");
    Check(Blk(feH, "https://evil.example/x") && Blk(feH, "https://sub.evil.example/x") && Blk(feH, "https://tab.example/x") && !Blk(feH, "https://localhost/x"), "hosts-file lines become host rules; localhost is never blocked");
    Check(feH.Rejected >= 3, "malformed hosts lines are counted as rejected (" + feH.Rejected + ")");
    var feI = Fe("! comment", "[Adblock Plus 2.0]", "/regex\\d+/", "||x.example^$redirect=noopjs", "||y.example^$csp=script-src 'none'", "example.com##+js(abort-on-property-read, x)", "example.com#?#div:has-text(Ad)", "||z.example^$badfilter", "||w.example^$unknownoption", "||ok.example^");
    Check(feI.NetworkRules == 1 && feI.Unsupported >= 6 && Blk(feI, "https://ok.example/x") && !Blk(feI, "https://x.example/x") && !Blk(feI, "https://y.example/x") && !Blk(feI, "https://z.example/x") && !Blk(feI, "https://w.example/x"), "unsupported syntax (regex, redirect, csp, scriptlets, procedural, badfilter, unknown options) is skipped and counted, never guessed (" + feI.Unsupported + " unsupported)");
    var feJ = Fe("*", "||", "$script", "|", "$third-party", "^", "||*", "$image,domain=a.test");
    Check(!Blk(feJ, "https://anything.example/x") && feJ.NetworkRules <= 1, "rules that would block everything (empty or all-wildcard patterns) are refused");
    Check(Blk(feJ, "https://anything.example/x", "https://a.test/", ResType.Image) == (feJ.NetworkRules == 1), "...except when restricted to named domains by domain=");

    // base-list style host entries, including a path entry that the old host-only list could never match
    var feK = new FilterEngine(); foreach (var h in new[] { "doubleclick.net", "facebook.com/tr", "t.co", "bad host!" }) feK.AddHostBlock(h, "base");
    Check(Blk(feK, "https://ad.doubleclick.net/x") && Blk(feK, "https://www.facebook.com/tr?id=1") && !Blk(feK, "https://www.facebook.com/home") && Blk(feK, "https://t.co/abc") && feK.Rejected == 1, "AddHostBlock: host entries and host/path entries both work (the path entry matches only that path); junk is rejected");

    // cosmetic
    var feL = Fe("##.ad-banner", "example.com##.promo", "~example.com##.sponsored", "example.com#@#.ad-banner", "##div[class^=\"ad-\"]", "a{}body{display:none}##x", "##x;y", "##a/*", "##url(x)", "example.com##.x:has-text(Buy)", "##a:-abp-has(b)", "##@import x", "##.ok > .child");
    var cssEx = feL.CosmeticCssFor("www.example.com"); var cssOther = feL.CosmeticCssFor("other.org");
    Check(cssEx.Contains(".promo{display:none!important}") && !cssEx.Contains(".ad-banner") && !cssEx.Contains(".sponsored") && cssEx.Contains("div[class^=\"ad-\"]{display:none!important}"), "cosmetic: domain rules apply to subdomains, #@# unhides, ~domain excludes the generic rule");
    Check(cssOther.Contains(".ad-banner{display:none!important}") && cssOther.Contains(".sponsored{display:none!important}") && !cssOther.Contains(".promo") && cssOther.Contains(".ok > .child{display:none!important}"), "cosmetic: generic rules apply elsewhere; child combinators allowed");
    Check(!cssOther.Contains("body{display:none}") && !cssOther.Contains("x;y") && !cssOther.Contains("/*") && !cssOther.Contains("url(") && !cssOther.Contains("@import") && !cssOther.Contains("has-text") && !cssOther.Contains("-abp-"), "cosmetic: selectors that could escape the CSS rule, or need procedural matching, are rejected");
    Check(feL.CosmeticCssFor("") == "" && feL.CosmeticCssFor(null) == "" && feL.CosmeticCssFor("EXAMPLE.COM").Contains(".promo"), "cosmetic: empty host gives no CSS; host matching is case-insensitive");
    Check(new[] { "div[class^=\"ad-\"]", "a[href*=\"/ads/\"]", "#sidebar > .ad", ".a, .b", "ul li:nth-child(2n+1)" }.All(FilterEngine.IsSafeSelector) && new[] { "a{}", "a;b", "a\\b", "a/*b", "url(javascript:x)", "x:has-text(a)", "", "  ", "a<b", "@media x", "a\nb", new string('a', 500) }.All(s => !FilterEngine.IsSafeSelector(s)), "selector safety: valid selectors accepted, injection attempts and oversized/empty ones rejected");

    // public suffix / third-party
    var psl = new PublicSuffixList();
    Check(psl.Registrable("a.b.example.co.uk") == "example.co.uk" && psl.Registrable("www.example.com") == "example.com" && psl.Registrable("example.com") == "example.com" && psl.Registrable("foo.github.io") == "foo.github.io" && psl.Registrable("x.y.github.io") == "y.github.io", "registrable domain: multi-part suffixes and private suffixes (github.io) are respected");
    Check(psl.Registrable("localhost") == "localhost" && psl.Registrable("127.0.0.1") == "127.0.0.1" && psl.Registrable("[::1]") == "[::1]" && psl.Registrable("co.uk") == "co.uk" && psl.Registrable("") == "" && psl.Registrable(null) == "" && psl.Registrable("Example.COM.") == "example.com", "registrable domain: single labels, IPs, a bare public suffix, empty/null, case and trailing dot");
    Check(psl.Registrable("a.b.compute.amazonaws.com") == "a.b.compute.amazonaws.com", "registrable domain: wildcard suffix rule (*.compute.amazonaws.com)");
    psl.Parse("*.ck !www.ck");
    Check(psl.Registrable("a.b.ck") == "a.b.ck" && psl.Registrable("www.ck") == "www.ck", "registrable domain: PSL wildcard and exception rules");

    // hostile input and pathological matching
    var feM = new FilterEngine();
    var junk = new StringBuilder(); var rng = new Random(11);
    for (int i = 0; i < 3000; i++) { var b = new char[rng.Next(1, 300)]; for (int j = 0; j < b.Length; j++) b[j] = (char)rng.Next(0, 300); junk.Append(new string(b).Replace('\n', ' ')).Append('\n'); }
    junk.Append(new string('a', 100000)).Append('\n').Append("||").Append(new string('*', 5000)).Append('\n').Append("$").Append(new string(',', 1000)).Append('\n');
    bool junkOk = true; try { feM.AddList(junk.ToString(), "junk"); feM.Match("https://a.example/" + new string('x', 3000), "https://b.example/", ResType.Script); } catch { junkOk = false; }
    Check(junkOk, "a hostile list (random characters, 100,000-character line, 5,000 wildcards) loads without throwing");
    var feN = Fe("*a*a*a*a*a*a*a*a*a*a*b", "||x.test/*a*a*a*a*a*a*c");
    var swF = System.Diagnostics.Stopwatch.StartNew(); bool anyBlocked = false;
    for (int i = 0; i < 2000; i++) anyBlocked |= Blk(feN, "https://x.test/" + new string('a', 3000));
    swF.Stop();
    Check(!anyBlocked && swF.ElapsedMilliseconds < 5000, "worst-case wildcard rules against 3,000-character URLs stay fast (2,000 lookups in " + swF.ElapsedMilliseconds + " ms)");
    Check(!Blk(feA, new string('a', 5000)) && !Blk(feA, "") && !Blk(feA, null!) && !Blk(feA, "not a url") && !Blk(feA, "https://"), "malformed, empty, null and over-long URLs never throw and are not blocked");

    // performance at EasyList scale
    var perf = new FilterEngine(); var sbp = new StringBuilder();
    for (int i = 0; i < 60000; i++) sbp.Append("||host").Append(i).Append(".example^\n");
    for (int i = 0; i < 30000; i++) sbp.Append("/ad").Append(i).Append("/banner_$image\n");
    for (int i = 0; i < 20000; i++) sbp.Append("||trk").Append(i).Append(".test/*/track").Append(i).Append(".js\n");
    for (int i = 0; i < 10000; i++) sbp.Append("##.promo-box-").Append(i).Append('\n');
    var swL = System.Diagnostics.Stopwatch.StartNew(); perf.AddList(sbp.ToString(), "perf"); swL.Stop();
    Check(perf.NetworkRules == 110000 && perf.CosmeticRules == 4000 && swL.ElapsedMilliseconds < 20000, "loads a 120,000-rule list (" + perf.NetworkRules + " network, " + perf.CosmeticRules + " cosmetic: 10,000 offered, generic hiding capped at 4,000 per page) in " + swL.ElapsedMilliseconds + " ms");
    var urls = new List<string>(); for (int i = 0; i < 60000; i++) urls.Add(i % 3 == 0 ? "https://host" + (i * 7 % 70000) + ".example/p/" + i + ".js" : i % 3 == 1 ? "https://site" + i + ".org/ad" + (i % 40000) + "/banner_" + i + ".png" : "https://cdn" + i + ".net/assets/app." + i + ".js?v=" + i);
    int hits = 0; var swM = System.Diagnostics.Stopwatch.StartNew();
    foreach (var u in urls) if (perf.Match(u, "https://page.example/", u.EndsWith(".png") ? ResType.Image : ResType.Script).Blocked) hits++;
    swM.Stop();
    Check(hits > 15000 && swM.ElapsedMilliseconds < 8000, "60,000 lookups against 110,000 network rules: " + hits + " blocked, " + swM.ElapsedMilliseconds + " ms total (" + (swM.Elapsed.TotalMilliseconds * 1000 / urls.Count).ToString("0.0") + " µs per request)");
    Check(perf.Match("https://host5.example/x.js", "https://p.test/", ResType.Script).Blocked && perf.Match("https://x.org/ad77/banner_1.png", "https://p.test/", ResType.Image).Blocked && perf.Match("https://trk9.test/a/b/track9.js", "https://p.test/", ResType.Script).Blocked && perf.Match("https://host5.example/x.png", "https://p.test/", ResType.Image).Blocked && !perf.Match("https://host99999999.example/x.js", "https://p.test/", ResType.Script).Blocked, "performance set: spot checks of each rule kind behave correctly");
}

Console.WriteLine();
Console.WriteLine("=== Full-page screenshot to PDF (executed C#) ===");
{
    byte[] FpJpeg(int w, int h, int comps = 3, int precision = 8, int sof = 0xC0)
    {
        var l = new List<byte> { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0x00, 0x00, 0xFF, (byte)sof };
        int len = 8 + 3 * comps; l.Add((byte)(len >> 8)); l.Add((byte)len); l.Add((byte)precision);
        l.Add((byte)(h >> 8)); l.Add((byte)h); l.Add((byte)(w >> 8)); l.Add((byte)w); l.Add((byte)comps);
        for (int i = 0; i < comps; i++) { l.Add((byte)(i + 1)); l.Add(0x11); l.Add(0); }
        l.Add(0xFF); l.Add(0xD9); return l.ToArray();
    }
    // layout planning
    var fpA = PagePlanner.Plan(1190, 5000, "a4", 8000);
    Check(fpA.Tiles.Count == 1 && fpA.Pages.Count == 3, "A4: 1190x5000 css -> 1 tile, 3 pages (got " + fpA.Tiles.Count + "/" + fpA.Pages.Count + ")");
    Check(Math.Abs(fpA.PtPerCss - 0.5002) < 0.001, "A4 scale fits the paper width");
    Check(fpA.Pages.All(p => Math.Abs(p.WidthPt - 595.28) < 0.01 && Math.Abs(p.HeightPt - 841.89) < 0.01), "A4 pages are paper sized");
    Check(fpA.Pages.Sum(p => p.Height) == 5000 && fpA.Pages[0].Top == 0 && fpA.Pages[1].Top == fpA.Pages[0].Height, "page slices tile the page exactly, no gap or overlap");
    var fpL = PagePlanner.Plan(1000, 2000, "letter", 8000);
    Check(Math.Abs(fpL.Pages[0].WidthPt - 612) < 0.01 && Math.Abs(fpL.Pages[0].HeightPt - 792) < 0.01, "Letter paper size");
    var fpS = PagePlanner.Plan(1000, 3000, "single", 8000);
    Check(fpS.Pages.Count == 1 && Math.Abs(fpS.Pages[0].WidthPt - 750) < 0.01 && Math.Abs(fpS.Pages[0].HeightPt - 2250) < 0.01, "single page is actual size (0.75 pt per css px)");
    var fpT = PagePlanner.Plan(1000, 20000, "single", 8000);
    Check(fpT.Pages[0].HeightPt <= PagePlanner.MaxPdfPt + 0.001 && fpT.Pages[0].HeightPt > 14000, "single page is shrunk to stay under the PDF size limit");
    var fpTall = PagePlanner.Plan(1000, 20000, "a4", 8000);
    Check(fpTall.Tiles.Count == 3 && fpTall.Tiles.Sum(t => t.Height) == 20000 && fpTall.Tiles[1].Top == 8000, "20000 px is cut into 3 capture tiles that add up");
    var fpBig = PagePlanner.Plan(9000, 90000, "a4", 8000);
    Check(fpBig.Truncated && fpBig.WidthCss == PagePlanner.MaxWidthCss && fpBig.HeightCss == PagePlanner.MaxHeightCss, "oversized pages are clamped and flagged");
    bool fpThrew = false; try { PagePlanner.Plan(0, 10, "a4", 8000); } catch (ImagePdfException) { fpThrew = true; } Check(fpThrew, "zero-size page refused");
    fpThrew = false; try { PagePlanner.Plan(100, 60000, "a4", 8000); } catch (ImagePdfException) { fpThrew = true; } Check(fpThrew, "a plan needing over 300 pages is refused (use the single layout)");
    Check(PagePlanner.Plan(500, 500, "bogus", 8000).Layout == "a4", "unknown layout falls back to A4");
    // every css pixel is covered by exactly one page slice and by at least one tile placed on that page
    {
        var pl = PagePlanner.Plan(1234, 12345, "a4", 5000); bool covered = true;
        foreach (var pg in pl.Pages)
        {
            var pls = PagePlanner.Placements(pl, pg);
            for (int y = pg.Top; y < pg.Top + pg.Height; y += 37)
                if (!pls.Any(q => pl.Tiles[q.Tile].Top <= y && y < pl.Tiles[q.Tile].Top + pl.Tiles[q.Tile].Height)) covered = false;
        }
        Check(covered, "every row of every page is covered by a placed tile");
    }
    // JPEG header parsing
    Check(ImagePdf.ParseJpeg(FpJpeg(800, 600)) == new JpegInfo(800, 600, 3), "JPEG size read");
    Check(ImagePdf.ParseJpeg(FpJpeg(70, 9000, 1)) == new JpegInfo(70, 9000, 1), "grey JPEG, 16-bit height");
    Check(ImagePdf.ParseJpeg(FpJpeg(10, 10, 3, 8, 0xC2)).Width == 10, "progressive JPEG accepted");
    foreach (var (bad, why) in new (byte[], string)[] { (FpJpeg(10, 10, 4), "CMYK"), (FpJpeg(10, 10, 3, 12), "12-bit"), (FpJpeg(10, 10, 3, 8, 0xC3), "lossless"), (new byte[] { 1, 2, 3, 4, 5 }, "not a JPEG"), (Array.Empty<byte>(), "empty"), (new byte[] { 0xFF, 0xD8, 0xFF, 0xD9 }, "no frame header"), (FpJpeg(0, 10), "zero width") })
    {
        fpThrew = false; try { ImagePdf.ParseJpeg(bad); } catch (ImagePdfException) { fpThrew = true; } Check(fpThrew, "bad JPEG refused: " + why);
    }
    // the PDF itself
    var fpPlan = PagePlanner.Plan(1190, 5000, "a4", 2000);   // 3 tiles, 3 pages: tile edges fall inside pages
    var fpTiles = fpPlan.Tiles.Select(t => FpJpeg(1190, t.Height)).ToList();
    var fpPdf = ImagePdf.Build(fpPlan, fpTiles, "Täst — page ✓", "https://example.com/", new DateTime(2026, 10, 7, 12, 0, 0, DateTimeKind.Utc));
    var fpText = System.Text.Encoding.Latin1.GetString(fpPdf);
    Check(fpText.StartsWith("%PDF-1.4") && fpText.TrimEnd().EndsWith("%%EOF"), "PDF header and trailer");
    {
        int sx = fpText.LastIndexOf("startxref", StringComparison.Ordinal);
        long xo = long.Parse(fpText.Substring(sx + 10).Split('\n')[0]);
        Check(fpText.Substring((int)xo, 4) == "xref", "startxref points at the xref table");
        var lines = fpText.Substring((int)xo).Split('\n');
        int count = int.Parse(lines[1].Split(' ')[1]); bool offsetsOk = true;
        for (int n = 1; n < count; n++)
        {
            long off = long.Parse(lines[2 + n].Substring(0, 10));
            if (!fpText.Substring((int)off).StartsWith(n + " 0 obj")) offsetsOk = false;
        }
        Check(offsetsOk && count == 1 + 3 + 3 + 3 * 2, "every xref offset points at its object (" + count + " entries)");
    }
    Check(System.Text.RegularExpressions.Regex.Matches(fpText, "/Subtype /Image").Count == 3, "each tile is embedded once even though tiles span pages");
    Check(fpText.Contains("/Filter /DCTDecode") && fpText.Contains("/DeviceRGB"), "JPEG embedded as DCT data");
    Check(fpText.Contains("/Title <FEFF") && !fpText.Contains("Täst"), "title stored as UTF-16 hex");
    Check(fpText.Contains("(D:20261007120000Z)"), "creation date");
    {
        using var rd = PdfSharp.Pdf.IO.PdfReader.Open(new MemoryStream(fpPdf), PdfSharp.Pdf.IO.PdfDocumentOpenMode.Import);
        Check(rd.PageCount == 3, "PDFsharp reads 3 pages");
        Check(Math.Abs(rd.Pages[0].MediaBox.Width - 595.28) < 0.1 && Math.Abs(rd.Pages[0].MediaBox.Height - 841.89) < 0.1, "PDFsharp reads the A4 media box");
        // the new file is a normal PDF for the existing page tools
        Check(PdfTools.PageCount(fpPdf) == 3, "page tools can open a screenshot PDF");
        Check(PdfTools.PageCount(PdfTools.Extract(fpPdf, "2-3")) == 2, "page tools can extract pages from a screenshot PDF");
    }
    fpThrew = false; try { ImagePdf.Build(fpPlan, fpTiles.Take(2).ToList(), "t", "s", DateTime.UtcNow); } catch (ImagePdfException) { fpThrew = true; } Check(fpThrew, "tile count mismatch refused");
    fpThrew = false; try { var junk = fpTiles.ToList(); junk[1] = new byte[] { 9, 9, 9, 9 }; ImagePdf.Build(fpPlan, junk, "t", "s", DateTime.UtcNow); } catch (ImagePdfException) { fpThrew = true; } Check(fpThrew, "non-JPEG tile refused");
    var fpOne = PagePlanner.Plan(800, 1000, "single", 8000);
    var fpOnePdf = ImagePdf.Build(fpOne, new List<byte[]> { FpJpeg(800, 1000) }, "t", "", DateTime.UtcNow);
    using (var rd1 = PdfSharp.Pdf.IO.PdfReader.Open(new MemoryStream(fpOnePdf), PdfSharp.Pdf.IO.PdfDocumentOpenMode.Import))
        Check(rd1.PageCount == 1 && Math.Abs(rd1.Pages[0].MediaBox.Width - 600) < 0.1 && Math.Abs(rd1.Pages[0].MediaBox.Height - 750) < 0.1, "single-page PDF has the actual-size media box");
    var fpTime = System.Diagnostics.Stopwatch.StartNew();
    var fpHuge = PagePlanner.Plan(1200, 60000, "single", 8000);
    var fpHugePdf = ImagePdf.Build(fpHuge, fpHuge.Tiles.Select(t => FpJpeg(1200, t.Height)).ToList(), "t", "", DateTime.UtcNow);
    Check(fpTime.ElapsedMilliseconds < 2000 && fpHuge.Tiles.Count == 8, "a 60000 px page plans and writes quickly (" + fpTime.ElapsedMilliseconds + " ms)");
}

Console.WriteLine();
Console.WriteLine("=== Extension governance (executed C#) ===");
{
    string? egRoot = null;
    for (var egd = new DirectoryInfo(AppContext.BaseDirectory); egd != null; egd = egd.Parent)
        if (File.Exists(Path.Combine(egd.FullName, "samples", "extensions", "hello-good", "manifest.json"))) { egRoot = egd.FullName; break; }
    Check(egRoot != null, "repository root with samples\\extensions found from the test binary");
    if (egRoot != null)
    {
        var egGood = Path.Combine(egRoot, "samples", "extensions", "hello-good"); var egRev = Path.Combine(egRoot, "samples", "extensions", "hello-review");
        // A copy of a ledger written by the PowerShell tool is committed as a fixture (proofs\receipts is git-ignored, so a fresh clone or CI has no real ledger).
        var egLedgerReal = Path.Combine(egRoot, "browser.tests", "fixtures", "extension_governance.powershell_written.v1.ndjson");
        Check(File.Exists(egLedgerReal), "PowerShell-written ledger fixture present");
        // identity must equal what the PowerShell implementation recorded for the same bytes
        var egIdGood = ExtGovernance.ComputeIdentity(egGood); var egIdRev = ExtGovernance.ComputeIdentity(egRev);
        Check(egIdGood.Id == "c719f88b943a8307a5e6f06f6fd0f7b26fdb4ed07c5f170d76f3e40b7c666b11", "C# identity of hello-good equals the PowerShell ledger id");
        Check(egIdRev.Id == "7d2fd7563cba40f93bacaf53040f577f626e0c2fa39a9c117b680641fdf22254", "C# identity of hello-review equals the PowerShell ledger id");
        // the real PowerShell-written ledger verifies in C#
        var egVer = ExtGovernance.VerifyLedger(egLedgerReal);
        Check(egVer.Count >= 4, "PowerShell-written ledger verifies in C# (" + egVer.Count + " records)");
        Check(ExtGovernance.Gate(egLedgerReal, egIdGood.Id).Ok, "load gate: hello-good is allowed");
        var egGateRev = ExtGovernance.Gate(egLedgerReal, egIdRev.Id);
        Check(!egGateRev.Ok && egGateRev.Note.Contains("review"), "load gate: hello-review is refused (decision review)");
        Check(!ExtGovernance.Gate(egLedgerReal, new string('a', 64)).Ok, "load gate: unknown bytes are refused");
        // policy decisions
        var egPol = ExtGovernance.ParsePolicy(File.ReadAllText(Path.Combine(egRoot, "config", "extension_policy.v1.json")));
        Check(ExtGovernance.Decide(ExtGovernance.ReadManifest(egGood), egIdGood.Id, egPol).Decision == "allow", "policy: storage+alarms -> allow");
        var egDecRev = ExtGovernance.Decide(ExtGovernance.ReadManifest(egRev), egIdRev.Id, egPol);
        Check(egDecRev.Decision == "review" && egDecRev.Reasons.SequenceEqual(new[] { "review_permission:tabs" }), "policy: tabs -> review with the exact reason");
        // tampering with a copy of the real ledger
        var egTmp = Path.Combine(Path.GetTempPath(), "rb-egtest-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(egTmp);
        try
        {
            var egLines = File.ReadAllLines(egLedgerReal).Where(l => l.Trim().Length > 0).ToList();
            void EgExpectBreak(List<string> lines, string label)
            {
                var p = Path.Combine(egTmp, Guid.NewGuid().ToString("N") + ".ndjson"); File.WriteAllLines(p, lines);
                bool broke = false; try { ExtGovernance.VerifyLedger(p); } catch (ExtGovException) { broke = true; }
                Check(broke, "ledger break detected: " + label);
            }
            EgExpectBreak(egLines.Select((l, i) => i == 1 ? l.Replace("\"review\"", "\"allow\"") : l).ToList(), "decision flipped from review to allow");
            EgExpectBreak(egLines.Where((l, i) => i != 1).ToList(), "a record removed");
            EgExpectBreak(new List<string> { egLines[1], egLines[0] }.Concat(egLines.Skip(2)).ToList(), "records reordered");
            EgExpectBreak(egLines.Select((l, i) => i == 2 ? l.Replace("\"name\":\"", "\"name\":\"x") : l).ToList(), "a field edited");
            EgExpectBreak(egLines.Concat(new[] { "{not json" }).ToList(), "a garbage line");
            var egPTamp = Path.Combine(egTmp, "tamp.ndjson"); File.WriteAllLines(egPTamp, egLines.Select((l, i) => i == 1 ? l.Replace("\"review\"", "\"allow\"") : l));
            Check(!ExtGovernance.Gate(egPTamp, egIdGood.Id).Ok, "a tampered ledger refuses everything, even previously allowed bytes");

            // golden fixture: files with unicode, hidden file, nested folder; .git ignored
            var egFx = Path.Combine(egTmp, "fx"); Directory.CreateDirectory(Path.Combine(egFx, "sub", "dir")); Directory.CreateDirectory(Path.Combine(egFx, ".git"));
            File.WriteAllBytes(Path.Combine(egFx, "manifest.json"), System.Text.Encoding.UTF8.GetBytes("{\"manifest_version\":3,\"name\":\"Sample\",\"version\":\"1.2.3\",\"permissions\":[\"storage\",\"tabs\"],\"host_permissions\":[\"https://example.com/*\"],\"content_scripts\":[{\"matches\":[\"https://example.com/*\"],\"js\":[\"cs.js\"]}]}"));
            File.WriteAllBytes(Path.Combine(egFx, "cs.js"), System.Text.Encoding.UTF8.GetBytes("console.log(\"hi \u00e9\");\n"));
            File.WriteAllBytes(Path.Combine(egFx, "sub", "dir", "a.txt"), Enumerable.Repeat((byte)'A', 1000).ToArray());
            File.WriteAllBytes(Path.Combine(egFx, ".hidden"), new[] { (byte)'x' });
            File.WriteAllText(Path.Combine(egFx, ".git", "config"), "ignored");
            var egFxId = ExtGovernance.ComputeIdentity(egFx);
            Check(egFxId.Id == "0358279f2b4109d4937062d5a43e3dc399f2533377d8e651cd7268ba4eb0d088" && egFxId.Files.Count == 4, "golden identity (unicode, hidden file, nested folder, .git ignored)");
            File.AppendAllText(Path.Combine(egFx, "cs.js"), " ");
            Check(ExtGovernance.ComputeIdentity(egFx).Id != egFxId.Id, "one changed byte changes the identity");
            File.WriteAllBytes(Path.Combine(egFx, "cs.js"), System.Text.Encoding.UTF8.GetBytes("console.log(\"hi \u00e9\");\n"));
            Check(ExtGovernance.ComputeIdentity(egFx).Id == egFxId.Id, "restoring the byte restores the identity");

            // manifest facts
            var egMan = ExtGovernance.ReadManifest(egFx);
            Check(egMan.Name == "Sample" && egMan.ManifestVersion == 3 && egMan.Permissions.SequenceEqual(new[] { "storage", "tabs" }) && egMan.HostPermissions.SequenceEqual(new[] { "https://example.com/*" }) && egMan.ContentScriptMatches.Count == 1, "manifest read (permissions, hosts, content script matches)");
            File.WriteAllText(Path.Combine(egFx, "manifest.json"), "\uFEFF{ // comment\n \"manifest_version\": 2, \"name\": \"Old\", \"version\": \"0.1\", \"permissions\": [\"<all_urls>\", \"*://*/*\", \"storage\", \"http://a.test/*\",], }");
            var egOld = ExtGovernance.ReadManifest(egFx);
            Check(egOld.Name == "Old" && egOld.Permissions.SequenceEqual(new[] { "storage" }) && egOld.HostPermissions.Count == 3, "manifest tolerates BOM, comments and trailing commas; host patterns split out of permissions");
            Check(ExtGovernance.Decide(egOld, "x", egPol).Decision == "deny" && ExtGovernance.Decide(egOld, "x", egPol).Reasons.Contains("denied_permission:<all_urls>"), "policy: <all_urls> is denied");
            var egMv4 = new ExtManifest { Name = "n", ManifestVersion = 4 };
            Check(ExtGovernance.Decide(egMv4, "x", egPol).Reasons.Contains("manifest_version_out_of_range:4"), "policy: manifest version out of range is denied");
            var egUnk = new ExtManifest { Name = "n", ManifestVersion = 3, Permissions = { "somethingNew" } };
            Check(ExtGovernance.Decide(egUnk, "x", egPol).Decision == "review", "policy: unknown permission -> review (conservative)");
            var egPol2 = ExtGovernance.ParsePolicy("{\"allowlist\":[\"x\"],\"blocklist\":[\"y\"],\"allowed_permissions\":[\"storage\"],\"review_permissions\":[\"tabs\"],\"denied_permissions\":[\"debugger\"]}");
            Check(ExtGovernance.Decide(egUnk, "x", egPol2).Decision == "allow", "policy: an allowlisted id turns review into allow");
            Check(ExtGovernance.Decide(egUnk, "y", egPol2).Decision == "deny", "policy: blocklisted id is denied");
            Check(ExtGovernance.Decide(new ExtManifest { ManifestVersion = 3, Permissions = { "debugger" } }, "x", egPol2).Decision == "deny", "policy: a denied permission beats the allowlist");
            bool egBadMan = false; File.WriteAllText(Path.Combine(egFx, "manifest.json"), "{ nope"); try { ExtGovernance.ReadManifest(egFx); } catch (ExtGovException) { egBadMan = true; } Check(egBadMan, "unparseable manifest refused");

            // writing records: install, approve, revoke
            var egLedger = Path.Combine(egTmp, "mine", "ledger.ndjson");
            var egM = new ExtManifest { Name = "Sample \"Q\" \\ \u00e9", Version = "1.0", ManifestVersion = 3, Permissions = { "storage", "tabs" } };
            var egFiles = new List<ExtFile> { new("manifest.json", new string('b', 64), 10), new("a.js", new string('c', 64), 5) };
            var egR1 = ExtGovernance.Record(egLedger, new string('e', 64), egM, egFiles, "review", new[] { "review_permission:tabs" }, new DateTime(2026, 10, 7, 1, 2, 3, 456, DateTimeKind.Utc));
            Check(egR1.Seq == 1 && egR1.PrevHash == ExtGovernance.Genesis && egR1.TsUtc == "2026-10-07T01:02:03.456Z", "first record: seq 1, genesis link, timestamp format");
            Check(!ExtGovernance.Gate(egLedger, new string('e', 64)).Ok, "a review record does not open the gate");
            var egR2 = ExtGovernance.Record(egLedger, new string('e', 64), egM, egFiles, "allow", new[] { "review_permission:tabs", "user_approved_review" }, DateTime.UtcNow);
            Check(egR2.Seq == 2 && egR2.PrevHash == egR1.RecordHash && ExtGovernance.Gate(egLedger, new string('e', 64)).Ok, "user approval appends an allow record and opens the gate");
            var egR3 = ExtGovernance.Record(egLedger, new string('e', 64), egM, egFiles, "deny", new[] { "user_removed" }, DateTime.UtcNow);
            Check(!ExtGovernance.Gate(egLedger, new string('e', 64)).Ok && egR3.Seq == 3, "removing appends a deny record and closes the gate again");
            Check(ExtGovernance.VerifyLedger(egLedger).Count == 3, "the ledger written by C# verifies");
            var egText = File.ReadAllText(egLedger);
            Check(!egText.Contains('\r') && egText.EndsWith("\n"), "records are LF terminated like the PowerShell writer");
            Check(egText.Split('\n', StringSplitOptions.RemoveEmptyEntries).All(l => { using var dj = System.Text.Json.JsonDocument.Parse(l); return ExtGovernance.Canon(ExtGovernance.ToObj(dj.RootElement)) == l; }), "every written line is already in canonical form");
            File.WriteAllText(egLedger, egText.Replace("user_removed", "user_kept"));
            bool egRefused = false; try { ExtGovernance.Record(egLedger, new string('e', 64), egM, egFiles, "allow", Array.Empty<string>(), DateTime.UtcNow); } catch (ExtGovException) { egRefused = true; } Check(egRefused, "nothing is appended to a ledger that does not verify");

            // packages
            byte[] EgZip(params (string Name, string Body)[] entries)
            {
                using var ms = new MemoryStream();
                using (var za = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, true))
                    foreach (var (n, b) in entries) { var e = za.CreateEntry(n); using var w = new StreamWriter(e.Open()); w.Write(b); }
                return ms.ToArray();
            }
            var egOk = EgZip(("manifest.json", "{\"manifest_version\":3,\"name\":\"z\",\"version\":\"1\"}"), ("js/a.js", "1"));
            var egOut = Path.Combine(egTmp, "u1"); Check(ExtPackage.Unpack(egOk, egOut) == egOut && File.Exists(Path.Combine(egOut, "js", "a.js")), "ZIP unpacks");
            var egWrap = EgZip(("repo-main/manifest.json", "{}"), ("repo-main/a.js", "1"));
            Check(Path.GetFileName(ExtPackage.Unpack(egWrap, Path.Combine(egTmp, "u2"))) == "repo-main", "a single wrapping folder (GitHub archive) is resolved");
            foreach (var bad in new[] { "../evil.txt", "..\\evil.txt", "/abs.txt", "C:/x.txt", "a/../../b.txt", "a\\b.txt", "x./y", "con .txt " })
            {
                bool refused = false; try { ExtPackage.Unpack(EgZip(("manifest.json", "{}"), (bad, "x")), Path.Combine(egTmp, "u3-" + Guid.NewGuid().ToString("N"))); } catch (ExtGovException) { refused = true; }
                Check(refused, "unsafe package path refused: " + bad);
            }
            Check(!File.Exists(Path.Combine(egTmp, "evil.txt")), "nothing was written outside the destination");
            bool egNoMan = false; try { ExtPackage.Unpack(EgZip(("a.js", "1")), Path.Combine(egTmp, "u4")); } catch (ExtGovException) { egNoMan = true; } Check(egNoMan, "package without a top-level manifest refused");
            bool egNotZip = false; try { ExtPackage.Unpack(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, Path.Combine(egTmp, "u5")); } catch (ExtGovException) { egNotZip = true; } Check(egNotZip, "random bytes refused");
            // CRX3 and CRX2 wrappers
            byte[] EgCrx(int ver, byte[] zip)
            {
                var hdr = new List<byte>(System.Text.Encoding.ASCII.GetBytes("Cr24")); hdr.AddRange(BitConverter.GetBytes((uint)ver));
                if (ver == 3) { hdr.AddRange(BitConverter.GetBytes((uint)5)); hdr.AddRange(new byte[5]); }
                else { hdr.AddRange(BitConverter.GetBytes((uint)3)); hdr.AddRange(BitConverter.GetBytes((uint)4)); hdr.AddRange(new byte[7]); }
                hdr.AddRange(zip); return hdr.ToArray();
            }
            Check(File.Exists(Path.Combine(ExtPackage.Unpack(EgCrx(3, egOk), Path.Combine(egTmp, "u6")), "manifest.json")), "CRX3 unpacks");
            Check(File.Exists(Path.Combine(ExtPackage.Unpack(EgCrx(2, egOk), Path.Combine(egTmp, "u7")), "manifest.json")), "CRX2 unpacks");
            var egBadCrx = EgCrx(3, egOk); BitConverter.GetBytes(uint.MaxValue).CopyTo(egBadCrx, 8);
            bool egCrxBad = false; try { ExtPackage.Unpack(egBadCrx, Path.Combine(egTmp, "u8")); } catch (ExtGovException) { egCrxBad = true; } Check(egCrxBad, "CRX with an out-of-range header length refused");
            Check(ExtPackage.IsSafeEntryName("a/b/c.js") && ExtPackage.IsSafeEntryName("dir/") && !ExtPackage.IsSafeEntryName("") && !ExtPackage.IsSafeEntryName(new string('a', 500)), "entry-name rules");
        }
        finally { try { Directory.Delete(egTmp, true); } catch { } }
    }
}

Console.WriteLine();
Console.WriteLine("=== Engine version, pop-up and external-link rules (executed C#) ===");
{
    Check(RuntimeCheck.Parse("141.0.3537.57")!.SequenceEqual(new[] { 141, 0, 3537, 57 }) && RuntimeCheck.Parse("142.0.3595.3 canary")![0] == 142 && RuntimeCheck.Parse("109")!.Length == 1, "engine version parsing");
    Check(RuntimeCheck.Parse(null) == null && RuntimeCheck.Parse("") == null && RuntimeCheck.Parse("abc") == null && RuntimeCheck.Parse("1.2.x") == null && RuntimeCheck.Parse("-1.2") == null && RuntimeCheck.Parse("1..2") == null && RuntimeCheck.Parse("1.2.3.4.5.6.7") == null, "garbage version strings are rejected, not guessed");
    Check(RuntimeCheck.Compare(new[] { 141, 0, 1, 1 }, new[] { 141, 0, 1, 2 }) < 0 && RuntimeCheck.Compare(new[] { 142 }, new[] { 141, 9, 9, 9 }) > 0 && RuntimeCheck.Compare(new[] { 141, 0 }, new[] { 141, 0, 0, 0 }) == 0, "version comparison");
    Check(RuntimeCheck.Assess("109.0.1518.78") == RuntimeCheck.Verdict.TooOld && RuntimeCheck.Assess("127.9.9.9") == RuntimeCheck.Verdict.TooOld && RuntimeCheck.Assess("128.0.0.0") == RuntimeCheck.Verdict.Ok && RuntimeCheck.Assess("150.1.2.3") == RuntimeCheck.Verdict.Ok && RuntimeCheck.Assess("nonsense") == RuntimeCheck.Verdict.Unknown, "engine freshness verdict around the floor");
    Check(PopupRules.Decide("https://a.test/", true, false) == PopupVerdict.Allow && PopupRules.Decide("http://a.test/", true, false) == PopupVerdict.Allow && PopupRules.Decide("about:blank", true, false) == PopupVerdict.Allow && PopupRules.Decide("", true, false) == PopupVerdict.Allow, "a pop-up from your click to a web address is allowed");
    Check(PopupRules.Decide("https://a.test/", false, false) == PopupVerdict.BlockedNoGesture && PopupRules.Decide("about:blank", false, false) == PopupVerdict.BlockedNoGesture, "a scripted pop-up is blocked");
    Check(PopupRules.Decide("https://a.test/", false, true) == PopupVerdict.Allow, "a scripted pop-up is allowed for a site you allowed");
    foreach (var u in new[] { "file:///C:/Windows/win.ini", "javascript:alert(1)", "data:text/html,<b>x", "ms-msdt:/id", "search-ms:query=x", "chrome-extension://abc/page.html", "blob:https://a.test/1", "ftp://a.test/", "  FILE:///x" })
        Check(PopupRules.Decide(u, true, true) == PopupVerdict.BlockedScheme, "pop-up to a non-web scheme is always blocked: " + u);
    Check(PopupRules.Decide(null, true, false) == PopupVerdict.Allow, "null address is treated as blank");
    Check(ExternalUriRules.Allowed("mailto:a@b.test", true) && ExternalUriRules.Allowed("TEL:+123", true) && !ExternalUriRules.Allowed("mailto:a@b.test", false), "mailto:/tel: pass only when you clicked");
    foreach (var u in new[] { "ms-msdt:/id PCWDiagnostic", "search-ms:query=a", "ms-officecmd:x", "calculator:", "steam://run/1", "vscode://file/x", "javascript:x", "", "nocolon", ":x", "x" })
        Check(!ExternalUriRules.Allowed(u, true), "external program launch is blocked: '" + u + "'");
    Check(ExternalUriRules.SchemeOf("MS-MSDT:/x") == "ms-msdt" && ExternalUriRules.SchemeOf("nocolon") == "unknown" && ExternalUriRules.SchemeOf(null) == "unknown", "scheme extraction for the status line");
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

// ---- SoteriaVault link: the contract is checked against SoteriaVault's own rules, and nothing else is trusted --------------------------
{
    const string svContract = "{\"schema\":\"soteriavault.connector_contract.v1\",\"name\":\"recognition\",\"kind\":\"browser_password_manager_bridge\",\"phase\":\"contract_only\",\"enabled\":false,\"required_for_standalone\":false,\"preferred_after_standalone\":false,\"dependency_policy\":\"must_not_fail_if_absent\",\"purpose\":\"x\",\"allowed_now\":[\"declare_contract\",\"emit_readiness\",\"emit_receipts\",\"remain_absent_without_failure\"],\"forbidden_before_standalone_seal\":[\"hard_runtime_dependency\",\"secret_release_to_external_runtime\",\"required_external_verification\",\"engine_failure_if_missing\"],\"future_allowed_after_standalone\":[\"signed_receipt_witness\"]}";
    const string svRegistry = "{\"schema\":\"soteriavault.connector_registry.v1\",\"standalone_first\":true,\"hard_external_dependencies_allowed\":false,\"missing_connectors_must_not_fail_engine\":true,\"connectors\":[]}";
    Func<string?, string?, Func<string, byte[]?>> svFiles = (svc, svr) => svrel => svrel == SoteriaBridge.ContractRel ? (svc == null ? null : System.Text.Encoding.UTF8.GetBytes(svc)) : svrel == SoteriaBridge.RegistryRel ? (svr == null ? null : System.Text.Encoding.UTF8.GetBytes(svr)) : null;
    const string svRoot = "C:\\dev\\privacy-sector";

    var svNone = SoteriaBridge.Evaluate("", svFiles(svContract, svRegistry));
    Check(svNone.State == SoteriaState.NotConfigured, "soteria: no folder chosen -> not configured (nothing is searched for)");
    var svOk = SoteriaBridge.Evaluate(svRoot, svFiles(svContract, svRegistry));
    Check(svOk.State == SoteriaState.ContractOnly && svOk.Capabilities.Contains("emit_receipts") && svOk.ContractSha256.Length == 64, "soteria: the real contract (contract_only, disabled) -> declared, not switched on, with a fingerprint");
    var svOk2 = SoteriaBridge.Evaluate(svRoot, svFiles(svContract, svRegistry));
    Check(svOk.ContractSha256 == svOk2.ContractSha256, "soteria: the fingerprint is deterministic");
    var svLive = SoteriaBridge.Evaluate(svRoot, svFiles(svContract.Replace("\"phase\":\"contract_only\"", "\"phase\":\"active\"").Replace("\"enabled\":false", "\"enabled\":true"), svRegistry));
    Check(svLive.State == SoteriaState.Ready && svLive.ContractSha256 != svOk.ContractSha256, "soteria: switched on by SoteriaVault -> ready, and the fingerprint changes with the file");
    Check(SoteriaBridge.Evaluate(svRoot, svFiles(svContract.Replace("\"enabled\":false", "\"enabled\":true"), svRegistry)).State == SoteriaState.ContractOnly, "soteria: enabled but still contract_only -> still not switched on");
    Check(SoteriaBridge.Evaluate(svRoot, svFiles(null, svRegistry)).State == SoteriaState.Unavailable, "soteria: no contract file -> unavailable (the link fails soft)");
    Check(SoteriaBridge.Evaluate(svRoot, svFiles(svContract, null)).State == SoteriaState.Invalid, "soteria: contract without a registry -> refused");
    Check(SoteriaBridge.Evaluate(svRoot, svrel1 => throw new IOException("denied")).State == SoteriaState.Unavailable, "soteria: unreadable files -> unavailable, never an exception");
    foreach (var (svLabel, svBad) in new[]
    {
        ("required for standalone", svContract.Replace("\"required_for_standalone\":false", "\"required_for_standalone\":true")),
        ("hard dependency policy", svContract.Replace("must_not_fail_if_absent", "fail_if_absent")),
        ("secret release not forbidden", svContract.Replace("\"secret_release_to_external_runtime\",", "")),
        ("hard dependency not forbidden", svContract.Replace("\"hard_runtime_dependency\",", "")),
        ("wrong name", svContract.Replace("\"name\":\"recognition\"", "\"name\":\"rebound\"")),
        ("wrong kind", svContract.Replace("browser_password_manager_bridge", "other")),
        ("future schema", svContract.Replace("connector_contract.v1", "connector_contract.v2")),
        ("missing required_for_standalone", svContract.Replace("\"required_for_standalone\":false,", "")),
        ("not json", "{ nope"),
        ("array root", "[]"),
        ("empty", ""),
    })
        Check(SoteriaBridge.Evaluate(svRoot, svFiles(svBad, svRegistry)).State == SoteriaState.Invalid, "soteria: contract refused when it breaks SoteriaVault's own rules (" + svLabel + ")");
    foreach (var (svLabel2, svBadReg) in new[]
    {
        ("hard external dependencies allowed", svRegistry.Replace("\"hard_external_dependencies_allowed\":false", "\"hard_external_dependencies_allowed\":true")),
        ("not standalone-first", svRegistry.Replace("\"standalone_first\":true", "\"standalone_first\":false")),
        ("unknown registry schema", svRegistry.Replace("registry.v1", "registry.v9")),
        ("registry not json", "oops"),
    })
        Check(SoteriaBridge.Evaluate(svRoot, svFiles(svContract, svBadReg)).State == SoteriaState.Invalid, "soteria: registry refused (" + svLabel2 + ")");
    Check(SoteriaBridge.Evaluate(svRoot, svrel2 => new byte[SoteriaBridge.MaxFileBytes + 1]).State == SoteriaState.Invalid, "soteria: an oversized contract file is not trusted");
    var svOdd = SoteriaBridge.Evaluate(svRoot, svFiles(svContract.Replace("\"emit_receipts\"", "\"Emit Receipts; rm -rf\""), svRegistry));
    Check(svOdd.State == SoteriaState.ContractOnly && !svOdd.Capabilities.Any(svcap => svcap.Contains(' ') || svcap.Contains(';')), "soteria: capability names from the file are filtered before they reach the page");

    foreach (var svGood in new[] { "C:\\dev\\privacy-sector", "D:/tools/sv", "c:\\x\\y\\" }) Check(SoteriaBridge.IsSafeRoot(svGood), "soteria: accepted folder " + svGood);
    var svBadList = new[] { "", "   ", "privacy-sector", "..\\x", "\\\\server\\share\\sv", "\\\\?\\C:\\sv", "C:\\a\\..\\b", "C:\\a\\.\\b", "C:sv", "C:\\a:stream", "C:\\a|b", "C:\\a\"b", "C:\\a\u0000b", "C:\\" + new string('a', 300) };
    foreach (var svBad2 in svBadList)
        Check(!SoteriaBridge.IsSafeRoot(svBad2), "soteria: refused folder #" + Array.IndexOf(svBadList, svBad2));
}

// ---- addresses that arrive from other programs (default browser, second launch) -----------------------------------------------------
{
    Func<string, bool> laExists = pth => pth == "C:\\pages\\a.html" || pth == "C:\\pages\\b.txt" || pth == "C:\\pages\\c.HTM";
    Check(LaunchArgs.Parse("https://example.com/a?b=1#c") == "https://example.com/a?b=1#c", "launch: an https link is accepted unchanged");
    Check(LaunchArgs.Parse("  HTTP://Example.COM  ") == "http://example.com/", "launch: http link is trimmed and normalised");
    foreach (var laBad in new[] { "https://bank.com@evil.com/", "https://someone@example.com/", "javascript:alert(1)", "data:text/html,x", "ftp://example.com/x", "file:///C:/pages/a.html",
                                  "ms-msdt:/id", "search-ms:query=x", "mailto:a@b.c", "\\\\srv\\share\\a.html", "http://", "https:///x", "about:blank", "", "   ", "not a url", "https://a.example/\u0001x", "https://a.example/\u007fx" })
        Check(LaunchArgs.Parse(laBad, laExists) == null, "launch: refused " + (laBad.Length > 28 ? laBad.Substring(0, 28) : laBad).Replace("\u0001", "\\x01").Replace("\u007f", "\\x7f"));
    Check(LaunchArgs.Parse("https://a.example/" + new string('a', 5000)) == null, "launch: an oversized address is refused");
    Check(LaunchArgs.Parse(null) == null, "launch: null is refused");
    Check(LaunchArgs.Parse("C:\\pages\\a.html", laExists) == "file:///C:/pages/a.html", "launch: an existing local .html file opens as a file address");
    Check(LaunchArgs.Parse("C:\\pages\\c.HTM", laExists) != null, "launch: the extension check ignores case");
    Check(LaunchArgs.Parse("C:\\pages\\b.txt", laExists) == null && LaunchArgs.Parse("C:\\pages\\zzz.html", laExists) == null && LaunchArgs.Parse("C:\\pages\\a.html") == null, "launch: wrong extension, missing file, or no file check -> refused");
    Check(LaunchArgs.FromArgs(new[] { "--flag", "/x", "https://ok.example/" }) == "https://ok.example/", "launch: switches are skipped, the first good address wins");
    Check(LaunchArgs.FromArgs(new[] { "javascript:1", "https://a.example/", "https://b.example/" }) == "https://a.example/", "launch: a bad argument is skipped, not trusted");
    Check(LaunchArgs.FromArgs(new string[0]) == null && LaunchArgs.FromArgs(null) == null && LaunchArgs.FromArgs(new[] { "-x", "/y" }) == null, "launch: no address -> null");
    Check(LaunchArgs.FromArgs(Enumerable.Repeat("junk", 40).Concat(new[] { "https://late.example/" }).ToArray()) == null, "launch: only the first 16 arguments are looked at");
}

// ---- QR code encoder: matrices must match the reference implementation exactly (hash of the module grid) ---------------------------
{
    string QrHash(string txt, out int qv, out int qm, out int qn)
    {
        var g = QrCode.Encode(txt, out qv, out qm); qn = g.GetLength(0);
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(QrCode.ToText(g)))).ToLowerInvariant();
    }
    var qrPacket = "recognition:packet:v1:bc87ef19a7e5b5fa44f6e918ff2ddab49cccf8997864d9ccd62c005a8c5df366";
    var qh1 = QrHash("hi", out var qv1, out var qm1, out var qn1);
    Check(qh1 == "05d7684a6c56e7dc2ecf2c1270f67ba4cc2f3f45ed6935ea9b3cf71ac3a5ef50" && qv1 == 1 && qn1 == 21 && qm1 == 2, "qr: version 1 symbol matches the reference");
    var qh2 = QrHash(qrPacket, out var qv2, out var qm2, out var qn2);
    Check(qh2 == "5571d30357fd3bf79869b8010bf6ef7ed33e8921e26f83fb364d9beaee40a0ca" && qv2 == 6 && qn2 == 41 && qm2 == 2, "qr: the packet-fingerprint symbol (version 6) matches the reference");
    var qh3 = QrHash(new string('A', 213), out var qv3, out var qm3, out var qn3);
    Check(qh3 == "e8b49c67b8bce64d5bdc3343e6ea0a1846d3fe057a8671da15d3af52044de366" && qv3 == 10 && qn3 == 57 && qm3 == 3, "qr: a full version 10 symbol (multiple blocks, version info) matches the reference");
    var qh4 = QrHash("Привет €", out var qv4, out var qm4, out var qn4);
    Check(qh4 == "a37814387e6855fbba63b99fa1e71583ad9002c56784e0c46c31ac83adb78fca" && qv4 == 2 && qn4 == 25, "qr: non-ASCII text is encoded as UTF-8 and matches the reference");
    bool qrLong = false; try { QrCode.Encode(new string('x', 214), out _, out _); } catch (ArgumentException) { qrLong = true; }
    Check(qrLong, "qr: more than 213 bytes is refused");
    var qg = QrCode.Encode("", out var qv5, out _);
    Check(qv5 == 1 && qg.GetLength(0) == 21, "qr: empty text still produces a valid version 1 symbol");
    var qpath = QrCode.ToSvgPath(QrCode.Encode("hi", out _, out _));
    Check(qpath.Length > 100 && qpath.StartsWith("M") && qpath.All(ch => char.IsDigit(ch) || ch is 'M' or 'h' or 'v' or 'z' or '-' or ' '), "qr: the SVG path holds only drawing commands and numbers");
}

// ---- exits (proxies) typed on the VPN page: validated before they can reach the engine's command line -----------------------------------
{
    Check(ProxyRules.TryBuild("socks5", "Proxy.Example.com", "1080", out var pxA, out _) && pxA == "socks5://proxy.example.com:1080", "proxy: a SOCKS5 exit is built, host lower-cased");
    Check(ProxyRules.TryBuild(" HTTP ", "10.0.0.5", " 8080 ", out var pxB, out _) && pxB == "http://10.0.0.5:8080", "proxy: an HTTP exit on an IPv4 address is built, spaces trimmed");
    foreach (var (pxT, pxH, pxP) in new[]
    {
        ("ftp", "a.example", "21"), ("", "a.example", "1080"), ("socks5", "", "1080"), ("socks5", "a b.example", "1080"), ("socks5", "a.example --no-sandbox", "1080"),
        ("socks5", "a.example\" --evil=1 \"", "1080"), ("socks5", "a.example/path", "1080"), ("socks5", "user@a.example", "1080"), ("socks5", "-a.example", "1080"),
        ("socks5", "a.example-", "1080"), ("socks5", "a..example", "1080"), ("socks5", "::1", "1080"), ("socks5", "[::1]", "1080"), ("socks5", new string('a', 254), "1080"),
        ("socks5", "a.example", "0"), ("socks5", "a.example", "65536"), ("socks5", "a.example", "-1"), ("socks5", "a.example", "10 80"), ("socks5", "a.example", "1e3"), ("socks5", "a.example", ""), ("socks5", "a.example", "99999999999"),
    })
        Check(!ProxyRules.TryBuild(pxT, pxH, pxP, out var pxBad, out var pxErr) && pxBad == "" && pxErr.Length > 0, "proxy: refused type='" + pxT + "' host='" + (pxH.Length > 20 ? pxH.Substring(0, 20) : pxH).Replace("\"", "'") + "' port='" + pxP + "'");
    Check(!ProxyRules.TryBuild(null, null, null, out _, out _), "proxy: nulls are refused");
    Check(ProxyRules.CleanName("My <b>VPN</b>; rm -rf") == "My bVPNb rm -rf" && ProxyRules.CleanName("   ") == "" && ProxyRules.CleanName(new string('x', 100)).Length == 40, "proxy: names keep letters, digits and a few marks only, 40 characters at most");
    Check(ProxyRules.Describe("socks5://127.0.0.1:9050") == "SOCKS5 127.0.0.1:9050" && ProxyRules.Describe("weird") == "weird" && ProxyRules.Describe(null) == "", "proxy: described in plain words");
    Check(ProxyRules.IsLocal("socks5://127.0.0.1:9050") && ProxyRules.IsLocal("http://localhost:8080") && !ProxyRules.IsLocal("socks5://127.0.0.1.evil.com:1") && !ProxyRules.IsLocal("socks5://10.0.0.1:1080") && !ProxyRules.IsLocal(null), "proxy: only 127.0.0.1 and localhost count as on this computer");
    var pxTaken = new HashSet<string> { "Work", "Work 2" };
    Check(ProxyRules.UniqueName("Home", n => pxTaken.Contains(n)) == "Home" && ProxyRules.UniqueName("Work", n => pxTaken.Contains(n)) == "Work 3", "proxy: duplicate names get a number");
}

// ---- stress: the filter engine at real-list scale, adversarial input, and PDF/extension abuse ------------------------------------
{
    var stSw = System.Diagnostics.Stopwatch.StartNew();
    var stSb = new System.Text.StringBuilder(); var stRnd = new Random(12345);
    for (int i = 0; i < 150000; i++)
    {
        switch (i % 4)
        {
            case 0: stSb.Append("||ads").Append(i).Append(".tracker").Append(i % 977).Append(".example^\n"); break;
            case 1: stSb.Append("/banner").Append(i).Append("/*$script,third-party\n"); break;
            case 2: stSb.Append("##.ad-").Append(i).Append("\n"); break;
            default: stSb.Append("@@||ok").Append(i).Append(".example^\n"); break;
        }
    }
    var stE = new FilterEngine(); stE.AddList(stSb.ToString(), "big");
    var stLoad = stSw.ElapsedMilliseconds;
    Check(stE.NetworkRules > 100000, "stress: a 150,000-line list loads (" + stE.NetworkRules + " network rules, " + stLoad + " ms)");
    Check(stLoad < 20000, "stress: loading a 150,000-line list takes under 20 s");
    stSw.Restart(); int stBlocked = 0;
    for (int i = 0; i < 200000; i++)
        if (stE.Match("https://ads" + (i % 150000) + ".tracker" + ((i % 150000) % 977) + ".example/p.js", "https://site.test/", ResType.Script).Blocked) stBlocked++;
    var stMatch = stSw.ElapsedMilliseconds;
    Check(stBlocked > 0, "stress: matching finds blocked requests at scale");
    Check(stMatch < 20000, "stress: 200,000 matches against a 150,000-rule list take under 20 s (" + stMatch + " ms)");
    Check(!stE.Match("https://ok3.example/x.js", "https://site.test/", ResType.Script).Blocked, "stress: an exception rule still works inside a huge list");

    // adversarial: very long urls, pathological patterns, binary junk
    var stAdv = new FilterEngine();
    stAdv.AddList("*a*a*a*a*a*a*a*a*a*b\n||x.example^*a*a*a*a*a*a*a*a*c\n" + new string('*', 5000) + "\n" + new string('a', 100000) + "\n", "adv");
    stSw.Restart();
    var stLong = "https://x.example/" + new string('a', 200000);
    stAdv.Match(stLong, "https://p.test/", ResType.Script);
    stAdv.Match("https://" + new string('a', 100000) + ".example/", "https://p.test/", ResType.Script);
    stAdv.Match("::::" + new string('/', 50000), "", ResType.Other);
    Check(stSw.ElapsedMilliseconds < 5000, "stress: pathological wildcard rules and 200 kB urls do not blow up (" + stSw.ElapsedMilliseconds + " ms)");
    bool stNoThrow = true;
    try { foreach (var junk in new[] { null, "", "\0\0", "http://", "://", "https://[::1", "https://a@b@c/", "data:text/html,x", "javascript:alert(1)" }) stAdv.Match(junk, junk, ResType.Other); }
    catch { stNoThrow = false; }
    Check(stNoThrow, "stress: malformed and hostile urls never throw");
    bool stRuleThrow = false;
    try { var stJ = new FilterEngine(); var jb = new byte[20000]; stRnd.NextBytes(jb); stJ.AddList(System.Text.Encoding.Latin1.GetString(jb), "junk"); }
    catch { stRuleThrow = true; }
    Check(!stRuleThrow, "stress: random binary bytes as a filter list never throw");
    var stCap = new FilterEngine(); stCap.AddList("##a{background:url(x)}\n##a:has(b)\n##a,b{x}\n##}\n##a;color:red\n", "c");
    Check(stCap.CosmeticCssFor("x.example").IndexOf("url(", StringComparison.Ordinal) < 0, "stress: cosmetic rules carrying url() or injected CSS are rejected");

    // PDF: page planner extremes. A plan is produced within the caps or refused with ImagePdfException, never any other failure.
    foreach (var (w, h) in new[] { (1280, 100), (1280, 59999), (1280, 60000), (1280, 1000000), (1, 1), (1, 60000), (8000, 8000), (0, 0), (-5, 10), (int.MaxValue, int.MaxValue) })
        foreach (var lay in new[] { "a4", "letter", "single", "bogus" })
        {
            string res;
            try
            {
                var pl = PagePlanner.Plan(w, h, lay, 4000);
                res = pl.Pages.Count <= PagePlanner.MaxPages && pl.Tiles.Count <= PagePlanner.MaxTiles && pl.Pages.All(q => q.WidthPt <= PagePlanner.MaxPdfPt && q.HeightPt <= PagePlanner.MaxPdfPt) ? "ok" : "over cap";
            }
            catch (ImagePdfException) { res = "ok"; }
            catch (Exception ex) { res = ex.GetType().Name; }
            Check(res == "ok", "stress: page planner " + w + "x" + h + " " + lay + " stays within caps or is refused cleanly (" + res + ")");
        }
}

// ---- Tor tabs (TorRules) ----
{
    Check(TorRules.ChoosePort(true, true) == 9150 && TorRules.ChoosePort(false, true) == 9050 && TorRules.ChoosePort(true, false) == 9150 && TorRules.ChoosePort(false, false) == 0, "tor: port choice prefers Tor Browser, then the service, else none");
    Check(TorRules.ProxyUrl(9150) == "socks5://127.0.0.1:9150" && TorRules.ProxyUrl(9050) == "socks5://127.0.0.1:9050", "tor: proxy address is local SOCKS5");
    foreach (var trBad in new[] { 0, 1, 80, 8080, 65535, -1, 9151 })
    {
        var trRes = "ok"; try { TorRules.ProxyUrl(trBad); } catch (ArgumentOutOfRangeException) { trRes = "refused"; }
        Check(trRes == "refused", "tor: port " + trBad + " is refused (only the two Tor ports are ever used)");
    }
    var trArgs = TorRules.EngineArgs(9150);
    Check(trArgs.Contains("--proxy-server=\"socks5://127.0.0.1:9150\""), "tor: engine args set the Tor proxy");
    Check(trArgs.Contains("--host-resolver-rules=\"MAP * ~NOTFOUND , EXCLUDE 127.0.0.1\""), "tor: local name lookups are made to fail (no DNS leak)");
    Check(trArgs.Contains("--force-webrtc-ip-handling-policy=disable_non_proxied_udp") && trArgs.Contains("--disable-quic"), "tor: WebRTC limited to the proxy and QUIC off");
    Check(!trArgs.Contains("proxy-bypass") && !trArgs.Contains("--no-proxy-server") && !trArgs.Contains("direct://"), "tor: no bypass or direct option in the engine args");
    Check(TorRules.GuardScript.Contains("RTCPeerConnection") && TorRules.GuardScript.Contains("getUserMedia") && !TorRules.GuardScript.Contains("fetch(") && !TorRules.GuardScript.Contains("XMLHttpRequest"), "tor: guard script removes WebRTC and makes no requests");
    Check(TorRules.ParseTorApi("{\"IsTor\":true,\"IP\":\"203.0.113.7\"}", out var trT, out var trIp) && trT && trIp == "203.0.113.7", "tor: Tor Project answer (Tor) is parsed");
    Check(TorRules.ParseTorApi("{\"IsTor\":false,\"IP\":\"2001:db8::1\"}", out var trF, out var trIp6) && !trF && trIp6 == "2001:db8::1", "tor: Tor Project answer (not Tor, IPv6) is parsed");
    foreach (var trJ in new[] { "", "   ", "not json", "[]", "{}", "{\"IsTor\":\"yes\"}", "{\"IsTor\":1}", new string('x', 5000) })
        Check(!TorRules.ParseTorApi(trJ, out var trB, out var trBi) && !trB && trBi == "", "tor: malformed answer refused (" + (trJ.Length > 12 ? "long" : trJ) + ")");
    Check(TorRules.ParseTorApi("{\"IsTor\":true,\"IP\":\"<script>\"}", out var trS, out var trSi) && trS && trSi == "", "tor: a non-address in IP is dropped");
    Check(TorRules.Verdict(false, false, false, "unknown").Contains("not running"), "tor: verdict when Tor is down");
    Check(TorRules.Verdict(true, false, false, "unknown").Contains("could not be reached"), "tor: verdict when the check is unreachable");
    Check(TorRules.Verdict(true, true, false, "ok").Contains("not coming out"), "tor: verdict when traffic is not Tor");
    Check(TorRules.Verdict(true, true, true, "exposed").Contains("exposed"), "tor: verdict when WebRTC is exposed");
    Check(TorRules.Verdict(true, true, true, "unknown").Contains("Open a Tor tab"), "tor: verdict when WebRTC was not tested");
    Check(TorRules.Verdict(true, true, true, "ok").Contains("WebRTC is blocked"), "tor: verdict when everything is fine");
    Check(TorRules.IsTorExit("tor-local", false) && TorRules.IsTorExit("Tor-Browser", false) && !TorRules.IsTorExit("tor-local", true) && !TorRules.IsTorExit("office", false) && !TorRules.IsTorExit(null, false), "tor: only the built-in tor-* exits are hidden when Tor is off");
}

Console.WriteLine();
Console.WriteLine($"checks passed: {pass}  failed: {fail}");
if (fail > 0) { Console.Error.WriteLine("BROWSER_GOVERNED_ACTIONS_TESTS_FAIL: " + fail); return 1; }
Console.WriteLine("SELFTEST_RECOGNITION_BROWSER_GOVERNED_ACTIONS_V1_OK");
return 0;
