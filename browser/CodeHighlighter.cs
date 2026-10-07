using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;

namespace Recognition.Browser
{
    // Syntax highlighter for the file/source viewer. Pure logic (no WPF/WebView2), executed by browser.tests.
    // A single hand-written, linear-time scanner driven by per-language tables: comments, strings (with escape
    // rules, triple quotes, verbatim strings), numbers, keywords, types, functions, attributes/properties,
    // preprocessor lines, and a small HTML/XML tag mode. No regular expressions and no backtracking, so hostile
    // input cannot cause catastrophic slowdowns, and every character of output text is HTML-encoded.
    // Honest scope: this is a lexical highlighter (colours + line numbers), not a language server. It does not
    // parse, resolve symbols, fold regions or highlight code embedded in other code (e.g. script inside HTML).
    internal static class CodeHighlighter
    {
        private sealed class Lang
        {
            public string Id = "";
            public string[] LineComments = Array.Empty<string>();
            public string? BlockStart, BlockEnd;
            public string Quotes = "\"'";
            public bool TripleQuotes, DoubledQuote, BackslashEscape = true, Preproc, PascalTypes, PropColon, DollarVars, CaseInsensitive, CssMode, Markup;
            public HashSet<string> Keywords = new(), Types = new();
        }

        private static HashSet<string> Set(string words, bool ci = false) =>
            new(words.Split(' ', StringSplitOptions.RemoveEmptyEntries), ci ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);

        private const string CommonKw = "if else for while do switch case break continue return default try catch finally throw new this true false null void";
        private static readonly Dictionary<string, Lang> Langs = Build();

        private static Dictionary<string, Lang> Build()
        {
            var d = new Dictionary<string, Lang>(StringComparer.Ordinal);
            d["csharp"] = new Lang { Id = "csharp", LineComments = new[] { "//" }, BlockStart = "/*", BlockEnd = "*/", Preproc = true, PascalTypes = true, TripleQuotes = true,
                Keywords = Set(CommonKw + " abstract as async await base bool byte char checked class const decimal delegate double enum event explicit extern fixed float foreach goto implicit in int interface internal is lock long namespace object operator out override params private protected public readonly ref sbyte sealed short sizeof stackalloc static string struct typeof uint ulong unchecked unsafe ushort using virtual volatile var dynamic record init get set value yield partial where select from let orderby group into when with required file nameof global and or not"),
                Types = Set("String Int32 Int64 Boolean Object Task List Dictionary IEnumerable Exception DateTime Guid Console Math Array") };
            d["javascript"] = new Lang { Id = "javascript", LineComments = new[] { "//" }, BlockStart = "/*", BlockEnd = "*/", Quotes = "\"'`", PascalTypes = true,
                Keywords = Set(CommonKw + " async await class const constructor debugger delete export extends from function get import in instanceof let of set static super typeof var with yield undefined NaN Infinity interface type enum implements public private protected readonly abstract as declare namespace module keyof is any number string boolean never unknown symbol bigint object"),
                Types = Set("Promise Array Object Map Set Date Error JSON Math RegExp Symbol Number String Boolean") };
            d["java"] = new Lang { Id = "java", LineComments = new[] { "//" }, BlockStart = "/*", BlockEnd = "*/", PascalTypes = true, TripleQuotes = true,
                Keywords = Set(CommonKw + " abstract assert boolean byte char class const double enum extends final float goto implements import instanceof int interface long native package private protected public short static strictfp super synchronized throws transient var volatile record sealed permits yield") };
            d["kotlin"] = new Lang { Id = "kotlin", LineComments = new[] { "//" }, BlockStart = "/*", BlockEnd = "*/", PascalTypes = true, TripleQuotes = true,
                Keywords = Set(CommonKw + " as class companion data fun in interface is object open override package private protected public sealed super typealias val var when by init constructor suspend inline lateinit internal abstract enum import") };
            d["c"] = new Lang { Id = "c", LineComments = new[] { "//" }, BlockStart = "/*", BlockEnd = "*/", Preproc = true,
                Keywords = Set(CommonKw + " auto char const double enum extern float goto inline int long register restrict short signed sizeof static struct typedef union unsigned volatile class namespace template typename public private protected virtual override final nullptr bool using operator constexpr noexcept explicit friend mutable delete") };
            d["go"] = new Lang { Id = "go", LineComments = new[] { "//" }, BlockStart = "/*", BlockEnd = "*/", Quotes = "\"'`",
                Keywords = Set("break case chan const continue default defer else fallthrough for func go goto if import interface map package range return select struct switch type var nil true false iota"),
                Types = Set("string int int8 int16 int32 int64 uint uint8 uint16 uint32 uint64 uintptr float32 float64 bool byte rune error any complex64 complex128") };
            d["rust"] = new Lang { Id = "rust", LineComments = new[] { "//" }, BlockStart = "/*", BlockEnd = "*/", PascalTypes = true,
                Keywords = Set("as async await break const continue crate dyn else enum extern false fn for if impl in let loop match mod move mut pub ref return self Self static struct super trait true type unsafe use where while"),
                Types = Set("i8 i16 i32 i64 i128 isize u8 u16 u32 u64 u128 usize f32 f64 bool char str String Vec Option Result Box") };
            d["python"] = new Lang { Id = "python", LineComments = new[] { "#" }, TripleQuotes = true, PascalTypes = true,
                Keywords = Set("and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield None True False self cls match case"),
                Types = Set("int str float bool list dict set tuple bytes object type range Exception") };
            d["powershell"] = new Lang { Id = "powershell", LineComments = new[] { "#" }, BlockStart = "<#", BlockEnd = "#>", DollarVars = true, DoubledQuote = true, BackslashEscape = false, CaseInsensitive = true,
                Keywords = Set("begin break catch class continue data do dynamicparam else elseif end exit filter finally for foreach from function if in param process return switch throw trap try until using var while workflow param function true false null", true) };
            d["shell"] = new Lang { Id = "shell", LineComments = new[] { "#" }, DollarVars = true,
                Keywords = Set("if then else elif fi for while until do done case esac in function select time return exit break continue local export readonly declare unset source alias echo cd set shift trap eval exec") };
            d["sql"] = new Lang { Id = "sql", LineComments = new[] { "--" }, BlockStart = "/*", BlockEnd = "*/", DoubledQuote = true, BackslashEscape = false, CaseInsensitive = true, Quotes = "\"'`",
                Keywords = Set("select from where and or not insert into values update set delete create alter drop table view index database schema join inner left right full outer cross on as group by order having limit offset union all distinct case when then else end null is in exists between like primary key foreign references default constraint unique check begin commit rollback transaction with returning asc desc count sum avg min max", true),
                Types = Set("int integer bigint smallint tinyint varchar char text boolean bool date datetime timestamp float double decimal numeric blob json uuid serial", true) };
            d["json"] = new Lang { Id = "json", Quotes = "\"", PropColon = true, Keywords = Set("true false null") };
            d["yaml"] = new Lang { Id = "yaml", LineComments = new[] { "#" }, PropColon = true, Keywords = Set("true false null yes no on off") };
            d["toml"] = new Lang { Id = "toml", LineComments = new[] { "#" }, Keywords = Set("true false") };
            d["ini"] = new Lang { Id = "ini", LineComments = new[] { ";", "#" }, Keywords = Set("") };
            d["css"] = new Lang { Id = "css", BlockStart = "/*", BlockEnd = "*/", CssMode = true, PropColon = true, Keywords = Set("important inherit initial unset none auto") };
            d["html"] = new Lang { Id = "html", Markup = true, BlockStart = "<!--", BlockEnd = "-->" };
            d["xml"] = new Lang { Id = "xml", Markup = true, BlockStart = "<!--", BlockEnd = "-->" };
            d["text"] = new Lang { Id = "text", Quotes = "", Keywords = Set("") };
            return d;
        }

        private static readonly Dictionary<string, string> Ext = new(StringComparer.OrdinalIgnoreCase)
        {
            [".cs"] = "csharp", [".csx"] = "csharp", [".js"] = "javascript", [".mjs"] = "javascript", [".cjs"] = "javascript", [".jsx"] = "javascript", [".ts"] = "javascript", [".tsx"] = "javascript",
            [".java"] = "java", [".kt"] = "kotlin", [".kts"] = "kotlin", [".c"] = "c", [".h"] = "c", [".cpp"] = "c", [".cc"] = "c", [".hpp"] = "c", [".cxx"] = "c", [".go"] = "go", [".rs"] = "rust",
            [".py"] = "python", [".pyw"] = "python", [".ps1"] = "powershell", [".psm1"] = "powershell", [".psd1"] = "powershell", [".sh"] = "shell", [".bash"] = "shell", [".zsh"] = "shell",
            [".sql"] = "sql", [".json"] = "json", [".jsonc"] = "json", [".ndjson"] = "json", [".yml"] = "yaml", [".yaml"] = "yaml", [".toml"] = "toml", [".ini"] = "ini", [".cfg"] = "ini", [".conf"] = "ini",
            [".css"] = "css", [".html"] = "html", [".htm"] = "html", [".xml"] = "xml", [".xaml"] = "xml", [".csproj"] = "xml", [".props"] = "xml", [".svg"] = "xml", [".config"] = "xml", [".manifest"] = "xml", [".iss"] = "ini",
            [".txt"] = "text", [".md"] = "text", [".log"] = "text", [".csv"] = "text", [".tla"] = "text", [".tsv"] = "text"
        };

        public static string LanguageFor(string? pathOrName)
        {
            var ext = System.IO.Path.GetExtension(pathOrName ?? "");
            return Ext.TryGetValue(ext, out var l) ? l : "text";
        }
        public static bool IsCodeFile(string? pathOrName) => Ext.ContainsKey(System.IO.Path.GetExtension(pathOrName ?? ""));
        public static IEnumerable<string> Languages => Langs.Keys;

        // A file is treated as binary (and not displayed as text) when it contains NUL bytes, unless it starts with a UTF-16 BOM.
        public static bool LooksBinary(byte[]? bytes, int sniff = 8192)
        {
            if (bytes == null || bytes.Length == 0) return false;
            if (bytes.Length >= 2 && ((bytes[0] == 0xFF && bytes[1] == 0xFE) || (bytes[0] == 0xFE && bytes[1] == 0xFF))) return false;
            int n = Math.Min(bytes.Length, sniff);
            for (int i = 0; i < n; i++) if (bytes[i] == 0) return true;
            return false;
        }

        // BOM-aware decoding (UTF-8, UTF-16 LE/BE); anything else is read as UTF-8 with replacement characters. Never throws.
        public static string DecodeText(byte[]? b)
        {
            if (b == null || b.Length == 0) return "";
            if (b.Length >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) return Encoding.UTF8.GetString(b, 3, b.Length - 3);
            if (b.Length >= 2 && b[0] == 0xFF && b[1] == 0xFE) return Encoding.Unicode.GetString(b, 2, b.Length - 2);
            if (b.Length >= 2 && b[0] == 0xFE && b[1] == 0xFF) return Encoding.BigEndianUnicode.GetString(b, 2, b.Length - 2);
            return new UTF8Encoding(false, false).GetString(b);
        }

        public const string KW = "kw", TYPE = "type", STR = "str", NUM = "num", COM = "com", FN = "fn", ATTR = "attr", PRE = "pre", VAR = "var", PLAIN = "";

        // Tokens for the whole text, then split into lines (a token spanning lines, such as a block comment, is cut per line).
        public static List<List<(string Cls, string Text)>> Highlight(string? code, string? lang)
        {
            code ??= "";
            var l = lang != null && Langs.TryGetValue(lang, out var found) ? found : Langs["text"];
            var toks = Scan(code, l);
            var lines = new List<List<(string, string)>> { new() };
            foreach (var (cls, text) in toks)
            {
                int start = 0;
                for (int i = 0; i < text.Length; i++)
                {
                    if (text[i] == '\n')
                    {
                        AddTok(lines[^1], cls, text.Substring(start, i - start));
                        lines.Add(new List<(string, string)>()); start = i + 1;
                    }
                }
                AddTok(lines[^1], cls, text.Substring(start));
            }
            // CRLF: drop the trailing '\r' of each line
            foreach (var ln in lines)
                if (ln.Count > 0 && ln[^1].Item2.EndsWith("\r", StringComparison.Ordinal))
                {
                    var last = ln[^1]; var t = last.Item2.Substring(0, last.Item2.Length - 1);
                    if (t.Length == 0) ln.RemoveAt(ln.Count - 1); else ln[^1] = (last.Item1, t);
                }
            return lines;
        }

        private static void AddTok(List<(string, string)> line, string cls, string text)
        {
            if (text.Length == 0) return;
            if (line.Count > 0 && line[^1].Item1 == cls) line[^1] = (cls, line[^1].Item2 + text); else line.Add((cls, text));
        }

        // HTML fragment: one <div class='l'> per line with a gutter number and coloured spans. All text is encoded.
        public static string Render(string? code, string? lang, int maxLines = 200000)
        {
            var lines = Highlight(code, lang);
            if (lines.Count > 1 && lines[^1].Count == 0) lines.RemoveAt(lines.Count - 1);   // trailing newline is not an extra line
            var sb = new StringBuilder();
            int n = Math.Min(lines.Count, maxLines);
            for (int i = 0; i < n; i++)
            {
                sb.Append("<div class='l' id='L").Append(i + 1).Append("'><a class='n' href='#L").Append(i + 1).Append("'>").Append(i + 1).Append("</a><span class='c'>");
                foreach (var (cls, text) in lines[i])
                {
                    var enc = WebUtility.HtmlEncode(text).Replace("'", "&#39;");
                    if (cls.Length == 0) sb.Append(enc); else sb.Append("<span class='").Append(cls).Append("'>").Append(enc).Append("</span>");
                }
                if (lines[i].Count == 0) sb.Append("&#8203;");   // keeps empty lines at full height
                sb.Append("</span></div>");
            }
            if (lines.Count > n) sb.Append("<div class='l'><span class='c'><span class='com'>… ").Append(lines.Count - n).Append(" more lines not shown</span></span></div>");
            return sb.ToString();
        }

        // ---- scanner --------------------------------------------------------------------------
        private static bool IsIdStart(char c, Lang l) => char.IsLetter(c) || c == '_' || (l.CssMode && c == '-') ;
        private static bool IsIdPart(char c, Lang l) => char.IsLetterOrDigit(c) || c == '_' || (l.CssMode && c == '-');
        private static bool StartsAt(string s, int i, string? what) => what != null && what.Length > 0 && i + what.Length <= s.Length && string.CompareOrdinal(s, i, what, 0, what.Length) == 0;

        private static int NextNonSpace(string s, int i)
        {
            while (i < s.Length && (s[i] == ' ' || s[i] == '\t')) i++;
            return i;
        }

        private static List<(string Cls, string Text)> Scan(string s, Lang l)
        {
            var o = new List<(string, string)>();
            if (l.Markup) return ScanMarkup(s, l);
            int i = 0, n = s.Length, depth = 0; bool lineStart = true;
            void Emit(string cls, int from, int to) { if (to > from) o.Add((cls, s.Substring(from, to - from))); }
            while (i < n)
            {
                char c = s[i];
                if (c == '\n') { Emit(PLAIN, i, i + 1); i++; lineStart = true; continue; }
                if (c == ' ' || c == '\t' || c == '\r') { int j = i; while (j < n && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r')) j++; Emit(PLAIN, i, j); i = j; continue; }
                bool wasLineStart = lineStart; lineStart = false;

                if (StartsAt(s, i, l.BlockStart))
                {
                    int e = s.IndexOf(l.BlockEnd!, i + l.BlockStart!.Length, StringComparison.Ordinal);
                    int to = e < 0 ? n : e + l.BlockEnd!.Length;
                    Emit(COM, i, to); i = to; continue;
                }
                bool lc = false;
                foreach (var m in l.LineComments) if (StartsAt(s, i, m)) { lc = true; break; }
                if (lc) { int e = s.IndexOf('\n', i); int to = e < 0 ? n : e; Emit(COM, i, to); i = to; continue; }
                if (l.Preproc && c == '#' && wasLineStart) { int e = s.IndexOf('\n', i); int to = e < 0 ? n : e; Emit(PRE, i, to); i = to; continue; }

                // C# verbatim / interpolated prefixes: @"..."  $"..."  $@"..."
                if (l.Id == "csharp" && (c == '@' || c == '$') && i + 1 < n)
                {
                    int p = i; bool verbatim = false;
                    while (p < n && p - i < 4 && (s[p] == '@' || s[p] == '$')) { if (s[p] == '@') verbatim = true; p++; }   // bounded: a long run of $/@ must not be rescanned at every position
                    if (p < n && s[p] == '"')
                    {
                        int to = ScanString(s, p, '"', l, verbatim, false);
                        Emit(STR, i, to); i = to; continue;
                    }
                }

                if (l.Quotes.IndexOf(c) >= 0)
                {
                    bool triple = l.TripleQuotes && i + 2 < n && s[i + 1] == c && s[i + 2] == c && (c == '"' || c == '\'');
                    int to = ScanString(s, i, c, l, false, triple);
                    // property key in JSON / YAML ("key": value)
                    string cls = STR;
                    if (l.PropColon) { int k = NextNonSpace(s, to); if (k < n && s[k] == ':') cls = ATTR; }
                    Emit(cls, i, to); i = to; continue;
                }

                if (char.IsDigit(c) || (c == '.' && i + 1 < n && char.IsDigit(s[i + 1])))
                {
                    int j = i + 1;
                    while (j < n && (char.IsLetterOrDigit(s[j]) || s[j] == '_' || (s[j] == '.' && j + 1 < n && char.IsDigit(s[j + 1])))) j++;
                    if (l.CssMode) while (j < n && s[j] == '%') j++;
                    Emit(NUM, i, j); i = j; continue;
                }

                if (l.DollarVars && c == '$' && i + 1 < n && (IsIdStart(s[i + 1], l) || s[i + 1] == '{' || s[i + 1] == '(' || s[i + 1] == '?' || s[i + 1] == '@' ))
                {
                    int j = i + 1;
                    if (s[j] == '{') { int e = s.IndexOf('}', j); j = e < 0 ? n : e + 1; }
                    else if (s[j] == '(') { Emit(VAR, i, i + 1); i++; continue; }
                    else if (!IsIdStart(s[j], l)) j++;
                    else while (j < n && (IsIdPart(s[j], l) || s[j] == ':')) j++;
                    Emit(VAR, i, j); i = j; continue;
                }

                if (l.CssMode && c == '{') { depth++; Emit(PLAIN, i, i + 1); i++; continue; }
                if (l.CssMode && c == '}') { if (depth > 0) depth--; Emit(PLAIN, i, i + 1); i++; continue; }
                if (l.CssMode && c == '@') { int j = i + 1; while (j < n && IsIdPart(s[j], l)) j++; Emit(KW, i, j); i = j; continue; }
                if (l.CssMode && c == '#' && i + 1 < n && Uri.IsHexDigit(s[i + 1])) { int j = i + 1; while (j < n && Uri.IsHexDigit(s[j])) j++; Emit(NUM, i, j); i = j; continue; }

                if (IsIdStart(c, l))
                {
                    int j = i + 1; while (j < n && IsIdPart(s[j], l)) j++;
                    var word = s.Substring(i, j - i);
                    int k = NextNonSpace(s, j);
                    string cls = PLAIN;
                    bool prevDot = i > 0 && s[i - 1] == '.';
                    if (!prevDot && l.Keywords.Contains(word)) cls = KW;
                    else if (l.Types.Contains(word)) cls = TYPE;
                    else if (k < n && s[k] == '(') cls = FN;
                    else if (l.PropColon && k < n && s[k] == ':' && !(k + 1 < n && s[k + 1] == ':') && (!l.CssMode || depth > 0)) cls = ATTR;
                    else if (l.PascalTypes && char.IsUpper(word[0]) && word.Length > 1 && word.Any(char.IsLower)) cls = TYPE;
                    Emit(cls, i, j); i = j; continue;
                }

                Emit(PLAIN, i, i + 1); i++;
            }
            return Merge(o);
        }

        // Returns the index just past the closing delimiter (or the end of the line / text when unterminated).
        private static int ScanString(string s, int start, char q, Lang l, bool verbatim, bool triple)
        {
            int n = s.Length, i = start;
            if (triple) { int e = s.IndexOf(new string(q, 3), i + 3, StringComparison.Ordinal); return e < 0 ? n : e + 3; }
            i++;
            bool multiline = q == '`' || verbatim;
            while (i < n)
            {
                char c = s[i];
                if (c == '\n' && !multiline) return i;                       // unterminated: stop at end of line, never swallow the file
                if (c == q)
                {
                    if ((l.DoubledQuote || verbatim) && i + 1 < n && s[i + 1] == q) { i += 2; continue; }
                    return i + 1;
                }
                if (c == '\\' && l.BackslashEscape && !verbatim && i + 1 < n && s[i + 1] != '\n') { i += 2; continue; }
                if (c == '`' && l.Id == "powershell" && q == '"' && i + 1 < n) { i += 2; continue; }
                i++;
            }
            return n;
        }

        private static List<(string Cls, string Text)> Merge(List<(string, string)> o)
        {
            // StringBuilder accumulation: a very long run of same-class tokens must stay linear (no repeated string concatenation).
            var r = new List<(string, string)>(); StringBuilder? cur = null; string curCls = "";
            foreach (var (cls, text) in o)
            {
                if (cur != null && curCls == cls) { cur.Append(text); continue; }
                if (cur != null) r.Add((curCls, cur.ToString()));
                cur = new StringBuilder(text); curCls = cls;
            }
            if (cur != null) r.Add((curCls, cur.ToString()));
            return r;
        }

        // HTML / XML: comments, tags (name = kw, attribute names = attr, quoted values = str), text is plain.
        private static List<(string Cls, string Text)> ScanMarkup(string s, Lang l)
        {
            var o = new List<(string, string)>(); int i = 0, n = s.Length;
            void Emit(string cls, int from, int to) { if (to > from) o.Add((cls, s.Substring(from, to - from))); }
            while (i < n)
            {
                if (StartsAt(s, i, "<!--")) { int e = s.IndexOf("-->", i + 4, StringComparison.Ordinal); int to = e < 0 ? n : e + 3; Emit(COM, i, to); i = to; continue; }
                if (s[i] == '<' && i + 1 < n && (char.IsLetter(s[i + 1]) || s[i + 1] == '/' || s[i + 1] == '!' || s[i + 1] == '?'))
                {
                    int j = i + 1;
                    Emit(PLAIN, i, j); i = j;
                    if (i < n && (s[i] == '/' || s[i] == '!' || s[i] == '?')) { Emit(PLAIN, i, i + 1); i++; }
                    int ns = i; while (i < n && (char.IsLetterOrDigit(s[i]) || s[i] == '-' || s[i] == '_' || s[i] == ':' || s[i] == '.')) i++;
                    Emit(KW, ns, i);
                    while (i < n && s[i] != '>')
                    {
                        char c = s[i];
                        if (c == '"' || c == '\'') { int e = s.IndexOf(c, i + 1); int to = e < 0 ? n : e + 1; Emit(STR, i, to); i = to; }
                        else if (char.IsLetter(c) || c == '_' || c == ':' || c == '@') { int a = i; while (i < n && (char.IsLetterOrDigit(s[i]) || s[i] == '-' || s[i] == '_' || s[i] == ':' || s[i] == '.' || s[i] == '@')) i++; Emit(ATTR, a, i); }
                        else { Emit(PLAIN, i, i + 1); i++; }
                    }
                    if (i < n) { Emit(PLAIN, i, i + 1); i++; }
                    continue;
                }
                int next = s.IndexOf('<', i + 1); if (next < 0) next = n;
                Emit(PLAIN, i, next); i = next;
            }
            return Merge(o);
        }
    }
}
