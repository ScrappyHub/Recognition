using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Recognition.Browser
{
    // Content-filter engine: Adblock-Plus / EasyList / uBlock-compatible network rules + element-hiding (cosmetic)
    // rules + hosts-file lists. Pure logic (no WPF/WebView2), executed by browser.tests, including a performance test.
    //
    // Supported network syntax:  ||host^  |start  end|  * wildcard  ^ separator  @@ exceptions  $options
    //   options: third-party / ~third-party / 1p / 3p, resource types (script image stylesheet object xhr
    //   subdocument media font websocket ping other document all) and their ~negations, domain=a.com|~b.com,
    //   important, match-case.
    // Supported cosmetic syntax: ##selector, domain##selector, ~domain, #@# exceptions (plain CSS selectors only).
    // NOT supported (counted in Unsupported, never silently guessed): regex rules, $redirect, $removeparam, $csp,
    //   $popup, $badfilter, scriptlets (##+js), procedural cosmetics (:has-text, :xpath, ...), CNAME uncloaking.
    //
    // Safety: lists are untrusted input. Cosmetic selectors that could break out of a CSS rule are rejected, list
    // and rule counts are capped, URL length is capped, and matching uses no regular expressions and no backtracking
    // beyond leftmost-greedy glob matching, so a hostile rule or URL cannot cause catastrophic slowdown.
    [Flags]
    internal enum ResType
    {
        None = 0, Document = 1, Subdocument = 2, Stylesheet = 4, Script = 8, Image = 16, Media = 32, Font = 64,
        Xhr = 128, WebSocket = 256, Ping = 512, Other = 1024, Object = 2048,
        AllButDocument = Subdocument | Stylesheet | Script | Image | Media | Font | Xhr | WebSocket | Ping | Other | Object,
        All = AllButDocument | Document
    }

    internal readonly record struct FilterMatch(bool Blocked, string? Rule, string? ListId);

    // Public-suffix aware "registrable domain" (eTLD+1) used for the third-party decision.
    internal sealed class PublicSuffixList
    {
        private readonly HashSet<string> _normal = new(), _wild = new(), _except = new();

        // A compact built-in set (multi-part country suffixes and common shared-hosting suffixes). Everything else
        // falls back to the standard rule "the last label is the public suffix". Load the full Mozilla list with Parse().
        public const string BuiltIn = @"
co.uk org.uk ac.uk gov.uk me.uk ltd.uk plc.uk net.uk sch.uk
com.au net.au org.au edu.au gov.au id.au co.nz org.nz net.nz govt.nz ac.nz
co.jp ne.jp or.jp ac.jp go.jp co.kr or.kr co.in net.in org.in ac.in gov.in firm.in gen.in ind.in
com.cn net.cn org.cn gov.cn edu.cn com.hk org.hk com.tw org.tw com.sg org.sg com.my com.ph com.vn
com.br net.br org.br gov.br com.ar com.mx org.mx gob.mx com.co com.pe com.ve com.uy cl
co.za org.za web.za com.tr org.tr gen.tr com.ua org.ua com.pl net.pl org.pl com.ru org.ru
co.il org.il com.eg com.sa com.pk com.ng co.ke co.id web.id com.bd
github.io gitlab.io herokuapp.com blogspot.com wordpress.com netlify.app vercel.app pages.dev workers.dev
cloudfront.net azurewebsites.net appspot.com web.app firebaseapp.com s3.amazonaws.com amazonaws.com
fly.dev onrender.com glitch.me repl.co replit.app surge.sh now.sh myshopify.com squarespace.com wixsite.com
blogspot.co.uk blogspot.de blogspot.fr blogspot.in
*.compute.amazonaws.com *.elb.amazonaws.com
";

        public PublicSuffixList() { Parse(BuiltIn); }

        public void Parse(string text)
        {
            foreach (var tok in (text ?? "").Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var t = tok.Trim().ToLowerInvariant();
                if (t.StartsWith("//", StringComparison.Ordinal)) continue;
                if (t.StartsWith("!", StringComparison.Ordinal)) _except.Add(t.Substring(1));
                else if (t.StartsWith("*.", StringComparison.Ordinal)) _wild.Add(t.Substring(2));
                else _normal.Add(t);
            }
        }

        public static bool IsIp(string host) => host.Length > 0 && (host[0] == '[' || host.All(c => char.IsDigit(c) || c == '.'));

        // "a.b.example.co.uk" -> "example.co.uk"; "example.com" -> "example.com"; IPs and single labels unchanged.
        public string Registrable(string? host)
        {
            var h = (host ?? "").Trim().TrimEnd('.').ToLowerInvariant();
            if (h.Length == 0 || IsIp(h) || h.IndexOf('.') < 0) return h;
            var labels = h.Split('.');
            int n = labels.Length, suffixLen = 1;
            for (int k = 0; k < n; k++)
            {
                var s = string.Join(".", labels, k, n - k);
                if (_except.Contains(s)) { suffixLen = n - k - 1; break; }
                int len = 0;
                if (_normal.Contains(s)) len = n - k;
                if (k + 1 < n && _wild.Contains(string.Join(".", labels, k + 1, n - k - 1))) len = Math.Max(len, n - k);
                if (len > 0) { suffixLen = len; break; }   // smallest k = longest suffix
            }
            if (suffixLen >= n) return h;
            return string.Join(".", labels, n - suffixLen - 1, suffixLen + 1);
        }
    }

    internal sealed class FilterEngine
    {
        public const int MaxUrlLength = 4096, MaxRulesPerList = 400_000, MaxSelectorLength = 400;
        // Generic (every-site) hiding selectors are injected as one stylesheet per page, so they are capped.
        public int MaxGenericSelectors { get; set; } = 4000;
        private const ResType DefaultMask = ResType.AllButDocument;

        private sealed class NetRule
        {
            public string Raw = "", ListId = "";
            public bool Exception, Important, AnchorDomain, AnchorStart, AnchorEnd;
            public string[] Segments = Array.Empty<string>();
            public bool StarStart, StarEnd;
            public ResType Mask = DefaultMask;
            public int Party;                       // 0 any, 1 third-party only, 2 first-party only
            public string[]? IncDomains, ExcDomains;
        }

        private readonly Dictionary<string, List<NetRule>> _hostBlock = new(StringComparer.Ordinal), _hostAllow = new(StringComparer.Ordinal);
        private readonly Dictionary<string, List<NetRule>> _tokBlock = new(StringComparer.Ordinal), _tokAllow = new(StringComparer.Ordinal);
        private readonly List<NetRule> _fallbackBlock = new(), _fallbackAllow = new();

        private readonly List<string> _genericHide = new();
        private readonly HashSet<string> _genericSeen = new(StringComparer.Ordinal);
        private readonly Dictionary<string, List<string>> _domainHide = new(StringComparer.Ordinal), _domainUnhide = new(StringComparer.Ordinal);
        private readonly HashSet<string> _genericUnhide = new(StringComparer.Ordinal);

        public PublicSuffixList Suffixes { get; set; } = new();
        public int NetworkRules { get; private set; }
        public int CosmeticRules { get; private set; }
        public int Unsupported { get; private set; }
        public int Rejected { get; private set; }
        public Dictionary<string, int> RulesPerList { get; } = new(StringComparer.Ordinal);

        // ---- loading -----------------------------------------------------------------------------------
        public void AddHostBlock(string host, string listId = "base")
        {
            var h = (host ?? "").Trim().ToLowerInvariant();
            if (h.Length == 0) return;
            if (!h.All(c => char.IsLetterOrDigit(c) || c == '.' || c == '-' || c == '_' || c == '/')) { Rejected++; return; }
            AddLine("||" + (h.Contains('/') ? h : h + "^"), listId);   // "facebook.com/tr" keeps its path; a bare host gets a separator
        }

        public void AddList(string? text, string listId)
        {
            if (string.IsNullOrEmpty(text)) return;
            int count = 0, pos = 0, n = text.Length;
            while (pos < n && count < MaxRulesPerList)
            {
                int e = text.IndexOf('\n', pos); if (e < 0) e = n;
                var line = text.Substring(pos, e - pos).Trim(); pos = e + 1;
                if (line.Length == 0) continue;
                if (AddLine(line, listId)) count++;
            }
            RulesPerList[listId] = (RulesPerList.TryGetValue(listId, out var c) ? c : 0) + count;
        }

        // Returns true when the line became a rule.
        public bool AddLine(string line, string listId)
        {
            if (line.Length == 0 || line[0] == '!' || line[0] == '[') return false;
            if (line.Length > 2000) { Rejected++; return false; }

            // hosts-file format: "0.0.0.0 example.com  # comment"
            if (TryHostsLine(line, out var hostsEntry, out bool hostsMalformed))
            {
                if (hostsMalformed) { Rejected++; return false; }
                return AddLine("||" + hostsEntry + "^", listId);
            }

            int idx;
            if ((idx = line.IndexOf("#@#", StringComparison.Ordinal)) >= 0) return AddCosmetic(line, idx, 3, true);
            if (line.Contains("#?#") || line.Contains("#$#") || line.Contains("#%#") || line.Contains("#@?#") || line.Contains("#@$#")) { Unsupported++; return false; }
            if ((idx = line.IndexOf("##", StringComparison.Ordinal)) >= 0) return AddCosmetic(line, idx, 2, false);
            return AddNetwork(line, listId);
        }

        // Recognises "0.0.0.0 host" / "127.0.0.1 host" (space or tab). malformed = looked like one but the host is unusable.
        private static bool TryHostsLine(string line, out string host, out bool malformed)
        {
            host = ""; malformed = false;
            int ipLen = line.StartsWith("0.0.0.0", StringComparison.Ordinal) ? 7 : line.StartsWith("127.0.0.1", StringComparison.Ordinal) ? 9 : 0;
            if (ipLen == 0 || line.Length <= ipLen || (line[ipLen] != ' ' && line[ipLen] != '\t')) return false;
            var h = line.Substring(ipLen).Trim();
            int hash = h.IndexOf('#'); if (hash >= 0) h = h.Substring(0, hash).Trim();
            h = h.ToLowerInvariant();
            if (h.Length == 0 || h.IndexOfAny(new[] { ' ', '\t' }) >= 0 || h == "localhost" || h == "0.0.0.0" || h.StartsWith("localhost.") || !IsHostName(h)) { malformed = true; return true; }
            host = h; return true;
        }

        private static bool IsHostName(string h) => h.Length <= 253 && h.All(c => char.IsLetterOrDigit(c) || c == '.' || c == '-' || c == '_') && h.Contains('.');

        // ---- cosmetic ------------------------------------------------------------------------------------
        private static readonly string[] ProceduralMarks = { ":has-text(", ":contains(", ":-abp-", ":xpath(", ":matches-css", ":nth-ancestor(", ":upward(", ":remove(", ":style(", ":min-text-length(", ":watch-attr(", ":others(", ":matches-path(", ":matches-media(", "+js(" };

        // A selector is accepted only if it cannot terminate or extend the surrounding CSS rule.
        public static bool IsSafeSelector(string s)
        {
            if (string.IsNullOrWhiteSpace(s) || s.Length > MaxSelectorLength || s.TrimStart().StartsWith("@", StringComparison.Ordinal)) return false;
            foreach (var c in s) if (c == '{' || c == '}' || c == ';' || c == '\\' || c == '<' || c == '\n' || c == '\r' || c == '\0' || char.IsControl(c)) return false;
            var l = s.ToLowerInvariant();
            if (l.Contains("/*") || l.Contains("*/") || l.Contains("url(") || l.Contains("expression(") || l.Contains("@import") || l.Contains("javascript:") || l.Contains("!important")) return false;
            foreach (var m in ProceduralMarks) if (l.Contains(m)) return false;
            return true;
        }

        private bool AddCosmetic(string line, int idx, int sepLen, bool unhide)
        {
            var domainPart = line.Substring(0, idx).Trim(); var sel = line.Substring(idx + sepLen).Trim();
            foreach (var m in ProceduralMarks) if (sel.Contains(m, StringComparison.OrdinalIgnoreCase)) { Unsupported++; return false; }
            if (!IsSafeSelector(sel)) { Rejected++; return false; }
            var domains = domainPart.Length == 0 ? Array.Empty<string>() : domainPart.Split(',').Select(d => d.Trim().ToLowerInvariant()).Where(d => d.Length > 0).ToArray();
            if (domains.Any(d => d.Contains('*'))) { Unsupported++; return false; }
            if (domains.Any(d => { var n = d.TrimStart('~'); return n.Length == 0 || !n.All(c => char.IsLetterOrDigit(c) || c == '.' || c == '-' || c == '_'); })) { Rejected++; return false; }
            var inc = domains.Where(d => !d.StartsWith("~", StringComparison.Ordinal)).ToArray();
            var exc = domains.Where(d => d.StartsWith("~", StringComparison.Ordinal)).Select(d => d.Substring(1)).ToArray();
            if (inc.Length == 0)
            {
                // generic: hide everywhere (except on the ~excluded domains, which become per-domain unhides)
                if (unhide) { _genericUnhide.Add(sel); CosmeticRules++; return true; }
                if (_genericHide.Count >= MaxGenericSelectors) return false;
                if (_genericSeen.Add(sel)) _genericHide.Add(sel);
                foreach (var d in exc) AddTo(_domainUnhide, d, sel);
                CosmeticRules++; return true;
            }
            foreach (var d in inc) AddTo(unhide ? _domainUnhide : _domainHide, d, sel);
            CosmeticRules++; return true;
        }
        private static void AddTo(Dictionary<string, List<string>> map, string key, string sel)
        {
            if (!map.TryGetValue(key, out var l)) map[key] = l = new List<string>();
            if (l.Count < 5000) l.Add(sel);
        }

        // CSS to inject into a page on pageHost: every selector as its own rule (one bad selector must not invalidate the rest).
        public string CosmeticCssFor(string? pageHost)
        {
            var host = (pageHost ?? "").Trim().ToLowerInvariant();
            if (host.Length == 0) return "";
            var unhide = new HashSet<string>(_genericUnhide, StringComparer.Ordinal);
            var specific = new List<string>();
            foreach (var d in HostSuffixes(host))
            {
                if (_domainUnhide.TryGetValue(d, out var u)) foreach (var s in u) unhide.Add(s);
                if (_domainHide.TryGetValue(d, out var h)) specific.AddRange(h);
            }
            var sb = new StringBuilder();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var s in _genericHide.Concat(specific))
                if (!unhide.Contains(s) && seen.Add(s)) sb.Append(s).Append("{display:none!important}\n");
            return sb.ToString();
        }

        private static IEnumerable<string> HostSuffixes(string host)
        {
            yield return host;
            int i = host.IndexOf('.');
            while (i >= 0 && i + 1 < host.Length) { yield return host.Substring(i + 1); i = host.IndexOf('.', i + 1); }
        }

        // ---- network rule parsing ---------------------------------------------------------------------------
        private bool AddNetwork(string line, string listId)
        {
            var r = new NetRule { Raw = line, ListId = listId };
            var p = line;
            if (p.StartsWith("@@", StringComparison.Ordinal)) { r.Exception = true; p = p.Substring(2); }
            int dollar = p.LastIndexOf('$');
            string? opts = null;
            if (dollar >= 0 && !(p.Length > 1 && p[0] == '/' && p.EndsWith("/", StringComparison.Ordinal)))
            {
                opts = p.Substring(dollar + 1); p = p.Substring(0, dollar);
            }
            if (p.Length >= 2 && p[0] == '/' && p[p.Length - 1] == '/') { Unsupported++; return false; }   // regex rule
            if (p.Length == 0 && opts == null) return false;

            if (opts != null && !ParseOptions(r, opts)) { Unsupported++; return false; }

            if (p.StartsWith("||", StringComparison.Ordinal)) { r.AnchorDomain = true; p = p.Substring(2); }
            else if (p.StartsWith("|", StringComparison.Ordinal)) { r.AnchorStart = true; p = p.Substring(1); }
            if (p.EndsWith("|", StringComparison.Ordinal)) { r.AnchorEnd = true; p = p.Substring(0, p.Length - 1); }
            p = p.ToLowerInvariant();
            // a rule with no pattern at all and no usable options would block everything: refuse
            if (p.Length > 1024) { Rejected++; return false; }
            r.StarStart = p.StartsWith("*", StringComparison.Ordinal); r.StarEnd = p.EndsWith("*", StringComparison.Ordinal);
            r.Segments = p.Split('*', StringSplitOptions.RemoveEmptyEntries);
            // A rule with no pattern text blocks everything it is allowed to see: only accept it when it is limited to named domains.
            if (r.Segments.Length == 0 && !(r.IncDomains != null && r.IncDomains.Length > 0)) { Rejected++; return false; }

            // A pattern made only of separators and wildcards (for example "^") matches nearly every URL.
            if (r.Segments.Length > 0 && !p.Any(char.IsLetterOrDigit) && !(r.IncDomains != null && r.IncDomains.Length > 0)) { Rejected++; return false; }

            var (isHostRule, hostKey) = HostKeyOf(r, p);
            if (isHostRule) AddTo(r.Exception ? _hostAllow : _hostBlock, hostKey, r);
            else
            {
                var tokMap = r.Exception ? _tokAllow : _tokBlock;
                var tok = BestToken(r, p, tokMap);
                if (tok != null) AddTo(tokMap, tok, r);
                else (r.Exception ? _fallbackAllow : _fallbackBlock).Add(r);
            }
            NetworkRules++;
            return true;
        }

        private static void AddTo(Dictionary<string, List<NetRule>> map, string key, NetRule r)
        {
            if (!map.TryGetValue(key, out var l)) map[key] = l = new List<NetRule>(1);
            l.Add(r);
        }

        private static bool IsHostChar(char c) => (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-';

        // "||ads.example.com^..." / "||ads.example.com/..." / "||ads.example.com:8080": indexed by the full host.
        private static (bool, string) HostKeyOf(NetRule r, string p)
        {
            if (!r.AnchorDomain) return (false, "");
            int i = 0; while (i < p.Length && IsHostChar(p[i])) i++;
            if (i == 0) return (false, "");
            if (i == p.Length) return (false, "");   // "||example" (prefix) is not a whole-host rule
            char nc = p[i];
            if (nc != '^' && nc != '/' && nc != ':' && nc != '?') return (false, "");
            var key = p.Substring(0, i).Trim('.');
            return key.Length == 0 ? (false, "") : (true, key);
        }

        private static bool IsAlnum(char c) => (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');

        // The longest run of letters/digits that is fully delimited inside the pattern (not touching a '*' or an open end),
        // so that the URL must contain exactly that run as a whole token.
        // Among the valid tokens, prefer the one whose bucket is currently smallest (the rarest token), then the longest:
        // otherwise thousands of rules sharing a common word ("banner", "ads") would all be scanned for every matching URL.
        private static string? BestToken(NetRule r, string p, Dictionary<string, List<NetRule>> map)
        {
            string? best = null; int bestCount = int.MaxValue; int i = 0;
            while (i < p.Length)
            {
                if (!IsAlnum(p[i])) { i++; continue; }
                int s = i; while (i < p.Length && IsAlnum(p[i])) i++;
                int e = i;
                bool leftOk = s > 0 ? p[s - 1] != '*' : (r.AnchorStart || r.AnchorDomain);
                bool rightOk = e < p.Length ? p[e] != '*' : r.AnchorEnd;
                if (!leftOk || !rightOk || e - s < 3) continue;
                var t = p.Substring(s, e - s);
                int count = map.TryGetValue(t, out var l) ? l.Count : 0;
                if (best == null || count < bestCount || (count == bestCount && t.Length > best.Length)) { best = t; bestCount = count; }
            }
            return best;
        }

        private static readonly Dictionary<string, ResType> TypeNames = new(StringComparer.Ordinal)
        {
            ["script"] = ResType.Script, ["image"] = ResType.Image, ["stylesheet"] = ResType.Stylesheet, ["css"] = ResType.Stylesheet,
            ["object"] = ResType.Object, ["object-subrequest"] = ResType.Object, ["xmlhttprequest"] = ResType.Xhr, ["xhr"] = ResType.Xhr,
            ["subdocument"] = ResType.Subdocument, ["frame"] = ResType.Subdocument, ["media"] = ResType.Media, ["font"] = ResType.Font,
            ["websocket"] = ResType.WebSocket, ["ping"] = ResType.Ping, ["other"] = ResType.Other, ["document"] = ResType.Document, ["doc"] = ResType.Document
        };
        private static readonly string[] Ignorable = { "match-case", "first-party-ignored" };
        private static readonly string[] UnsupportedOpts = { "popup", "csp", "redirect", "redirect-rule", "removeparam", "queryprune", "badfilter", "replace", "header", "permissions", "rewrite", "inline-script", "inline-font", "generichide", "elemhide", "specifichide", "genericblock", "denyallow", "to", "from", "method", "cname", "empty", "mp4", "xmlhttprequest-ignored" };

        private bool ParseOptions(NetRule r, string opts)
        {
            ResType pos = ResType.None, neg = ResType.None; bool all = false;
            foreach (var raw in opts.Split(','))
            {
                var o = raw.Trim().ToLowerInvariant(); if (o.Length == 0) continue;
                bool not = o.StartsWith("~", StringComparison.Ordinal); var name = not ? o.Substring(1) : o;
                if (name == "third-party" || name == "3p") { r.Party = not ? 2 : 1; continue; }
                if (name == "first-party" || name == "1p") { r.Party = not ? 1 : 2; continue; }
                if (name == "important") { r.Important = true; continue; }
                if (name == "all") { all = true; continue; }
                if (name == "match-case") continue;
                if (name.StartsWith("domain=", StringComparison.Ordinal))
                {
                    var inc = new List<string>(); var exc = new List<string>();
                    foreach (var d0 in name.Substring(7).Split('|')) { var d = d0.Trim(); if (d.Length == 0) continue; if (d.StartsWith("~", StringComparison.Ordinal)) exc.Add(d.Substring(1)); else inc.Add(d); }
                    r.IncDomains = inc.ToArray(); r.ExcDomains = exc.ToArray(); continue;
                }
                if (TypeNames.TryGetValue(name, out var t)) { if (not) neg |= t; else pos |= t; continue; }
                var eq = name.IndexOf('='); var key = eq >= 0 ? name.Substring(0, eq) : name;
                if (Array.IndexOf(UnsupportedOpts, key) >= 0 || Array.IndexOf(Ignorable, key) < 0) return false;   // unknown option: do not guess
            }
            var mask = all ? ResType.All : (pos != ResType.None ? pos : DefaultMask);
            r.Mask = mask & ~neg;
            return r.Mask != ResType.None;
        }

        // ---- matching ------------------------------------------------------------------------------------------
        public FilterMatch Match(string? url, string? pageUrl, ResType type)
        {
            if (string.IsNullOrEmpty(url) || url.Length > MaxUrlLength) return default;
            if (!TryParse(url, out var urlL, out var host, out int hostStart, out int hostEnd)) return default;
            string pageHost = "";
            if (!string.IsNullOrEmpty(pageUrl) && TryParse(pageUrl, out _, out var ph, out _, out _)) pageHost = ph;
            bool third = pageHost.Length > 0 && !string.Equals(Suffixes.Registrable(host), Suffixes.Registrable(pageHost), StringComparison.Ordinal);

            NetRule? hit = FindBlock(urlL, host, hostStart, hostEnd, pageHost, third, type, out bool important);
            if (hit == null) return default;
            if (!important)
            {
                var allow = FindAllow(urlL, host, hostStart, hostEnd, pageHost, third, type);
                if (allow != null) return new FilterMatch(false, allow.Raw, allow.ListId);   // Raw already carries the leading @@
            }
            return new FilterMatch(true, hit.Raw, hit.ListId);
        }

        private static bool TryParse(string url, out string lower, out string host, out int hostStart, out int hostEnd)
        {
            lower = ""; host = ""; hostStart = hostEnd = 0;
            int s = url.IndexOf("://", StringComparison.Ordinal);
            if (s < 0 || s > 10) return false;
            hostStart = s + 3;
            int auth = hostStart; while (auth < url.Length && url[auth] != '/' && url[auth] != '?' && url[auth] != '#') auth++;   // end of the authority part
            if (auth <= hostStart) return false;
            int at = url.LastIndexOf('@', auth - 1 >= hostStart ? auth - 1 : hostStart, auth - hostStart);
            if (at >= hostStart) hostStart = at + 1;                                                                           // skip "user:pass@" so the real host is matched
            int e = hostStart; while (e < auth && url[e] != ':') e++;
            if (hostStart < auth && url[hostStart] == '[') { int rb = url.IndexOf(']', hostStart); e = rb >= 0 && rb < auth ? rb + 1 : auth; }   // IPv6 literal
            hostEnd = e;
            if (hostEnd <= hostStart) return false;
            lower = url.ToLowerInvariant();
            host = lower.Substring(hostStart, hostEnd - hostStart);
            return true;
        }

        private NetRule? FindBlock(string url, string host, int hs, int he, string pageHost, bool third, ResType type, out bool important)
        {
            bool imp = false; NetRule? found = null;
            void Check(List<NetRule>? list)
            {
                if (list == null) return;
                foreach (var r in list)
                {
                    if (found != null && (found.Important || !r.Important)) continue;
                    if (RuleApplies(r, url, hs, he, pageHost, third, type)) { found = r; imp = r.Important; }
                }
            }
            foreach (var h in HostSuffixes(host)) if (_hostBlock.TryGetValue(h, out var l)) Check(l);
            if (found != null && imp) { important = true; return found; }
            foreach (var tok in Tokens(url)) if (_tokBlock.TryGetValue(tok, out var l)) Check(l);
            Check(_fallbackBlock);
            important = imp;
            return found;
        }

        private NetRule? FindAllow(string url, string host, int hs, int he, string pageHost, bool third, ResType type)
        {
            foreach (var h in HostSuffixes(host))
                if (_hostAllow.TryGetValue(h, out var l)) foreach (var r in l) if (RuleApplies(r, url, hs, he, pageHost, third, type)) return r;
            foreach (var tok in Tokens(url))
                if (_tokAllow.TryGetValue(tok, out var l)) foreach (var r in l) if (RuleApplies(r, url, hs, he, pageHost, third, type)) return r;
            foreach (var r in _fallbackAllow) if (RuleApplies(r, url, hs, he, pageHost, third, type)) return r;
            return null;
        }

        private static IEnumerable<string> Tokens(string url)
        {
            int i = 0, n = url.Length; var seen = new HashSet<string>(StringComparer.Ordinal);
            while (i < n)
            {
                if (!IsAlnum(url[i])) { i++; continue; }
                int s = i; while (i < n && IsAlnum(url[i])) i++;
                if (i - s >= 3) { var t = url.Substring(s, i - s); if (seen.Add(t)) yield return t; }
            }
        }

        private bool RuleApplies(NetRule r, string url, int hs, int he, string pageHost, bool third, ResType type)
        {
            if ((r.Mask & type) == 0) return false;
            if (r.Party == 1 && !third) return false;
            if (r.Party == 2 && third) return false;
            if (r.IncDomains != null || r.ExcDomains != null)
            {
                if (r.ExcDomains != null && r.ExcDomains.Any(d => HostMatchesDomain(pageHost, d))) return false;
                if (r.IncDomains != null && r.IncDomains.Length > 0 && !r.IncDomains.Any(d => HostMatchesDomain(pageHost, d))) return false;
            }
            return PatternMatches(r, url, hs, he);
        }

        private static bool HostMatchesDomain(string host, string domain) =>
            host.Length > 0 && (host == domain || host.EndsWith("." + domain, StringComparison.Ordinal));

        private static bool PatternMatches(NetRule r, string url, int hs, int he)
        {
            var segs = r.Segments;
            if (segs.Length == 0) return true;   // no text to match: the rule is limited by its options (domain=...)
            if (r.AnchorDomain)
            {
                // candidate starts: the beginning of the host and just after every '.' inside it
                if (MatchSegments(segs, true, r.AnchorEnd && !r.StarEnd, url, hs)) return true;
                for (int i = hs; i < he; i++) if (url[i] == '.' && i + 1 < he && MatchSegments(segs, true, r.AnchorEnd && !r.StarEnd, url, i + 1)) return true;
                return false;
            }
            if (r.AnchorStart && !r.StarStart) return MatchSegments(segs, true, r.AnchorEnd && !r.StarEnd, url, 0);
            return MatchSegments(segs, false, r.AnchorEnd && !r.StarEnd, url, 0);
        }

        private static bool IsSeparator(char c) => !(char.IsLetterOrDigit(c) || c == '_' || c == '-' || c == '.' || c == '%');

        // Does seg match url at position p? '^' matches one separator character, or the end of the URL (consuming nothing).
        private static bool MatchAt(string seg, string url, int p, out int end)
        {
            end = p; int u = p;
            foreach (var c in seg)
            {
                if (c == '^') { if (u == url.Length) continue; if (!IsSeparator(url[u])) return false; u++; }
                else { if (u >= url.Length || url[u] != c) return false; u++; }
            }
            end = u; return true;
        }

        private static bool MatchSegments(string[] segs, bool anchoredStart, bool anchoredEnd, string url, int start)
        {
            int pos = start;
            for (int i = 0; i < segs.Length; i++)
            {
                var seg = segs[i]; bool last = i == segs.Length - 1;
                if (i == 0 && anchoredStart)
                {
                    if (last && anchoredEnd) return MatchAt(seg, url, pos, out int e0) && e0 == url.Length;
                    if (!MatchAt(seg, url, pos, out pos)) return false;
                    continue;
                }
                if (last && anchoredEnd)
                {
                    for (int p = Math.Max(pos, url.Length - seg.Length - 1); p <= url.Length; p++) if (p >= pos && MatchAt(seg, url, p, out int e1) && e1 == url.Length) return true;
                    return false;
                }
                int found = -1, foundEnd = 0;
                for (int p = pos; p <= url.Length; p++) if (MatchAt(seg, url, p, out foundEnd)) { found = p; break; }
                if (found < 0) return false;
                pos = foundEnd;
            }
            return true;
        }
    }
}
