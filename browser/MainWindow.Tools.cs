using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Web.WebView2.Core;

namespace Recognition.Browser
{
    // Tools: page snapshot (MHTML + evidence sidecar), print / save as PDF, screenshot, edit-this-page mode,
    // view source, a code viewer (syntax highlighting + line numbers), PDF page tools and image tools.
    // The rules (highlighter, PDF page operations, image maths) live in pure files executed by browser.tests;
    // this file is the WPF/WebView2 glue. Everything is an explicit click, local only, and receipted
    // (names and hashes, never file contents).
    public partial class MainWindow
    {
        private readonly Dictionary<BrowserTab, string> _viewerHtml = new();
        private byte[]? _toolPdf; private string _toolPdfName = "";
        private readonly List<(string Name, byte[] Data)> _toolPdfMany = new();
        private string? _toolImagePath;

        private const long MaxViewBytes = 5 * 1024 * 1024;

        private static string SafeStem(string? s, string fallback = "page")
        {
            var bad = Path.GetInvalidFileNameChars();
            var t = new string((s ?? "").Select(c => bad.Contains(c) || char.IsControl(c) ? '_' : c).ToArray()).Trim(' ', '.', '_');
            if (t.Length > 80) t = t.Substring(0, 80);
            return t.Length == 0 ? fallback : t;
        }
        private static string Sha256Of(byte[] b) => Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();

        private void PostToToolsPage(object payload)
        {
            var t = Active; if (t == null || t.Internal != "tools") return;
            try { t.Web.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(payload)); } catch { }
        }

        // The web tab a page tool acts on: the active one, or (when invoked from the Tools page) the most recent web tab.
        private BrowserTab? TargetWebTab()
        {
            var a = Active;
            if (a != null && !a.IsInternal && a.Web?.CoreWebView2 != null) return a;
            var w = Enumerable.Reverse(_tabs).FirstOrDefault(t => !t.IsInternal && t.Web?.CoreWebView2 != null && t.Ready);
            if (w == null) { Status("open a web page first"); return null; }
            Tabs.SelectedItem = w.Item; ShowActiveWebView();
            return w;
        }

        private void ToolsReport(string text, bool ok = true)
        {
            Status(text);
            PostToToolsPage(new { type = "action", ok, text });
        }

        // ---- menu entry points ---------------------------------------------------------------
        private void MenuTools_Click(object sender, RoutedEventArgs e) => OpenInternalInActiveTab("tools");
        private async void MenuSnapshotPage_Click(object sender, RoutedEventArgs e) => await SnapshotPageAsync();
        private void MenuPrint_Click(object sender, RoutedEventArgs e) => PrintPage();
        private async void MenuSavePdf_Click(object sender, RoutedEventArgs e) => await SavePagePdfAsync();
        private async void MenuScreenshot_Click(object sender, RoutedEventArgs e) => await ScreenshotAsync();
        private async void MenuEditPage_Click(object sender, RoutedEventArgs e) => await ToggleEditPageAsync();
        private async void MenuViewSource_Click(object sender, RoutedEventArgs e) => await ViewSourceAsync();
        private void MenuOpenFile_Click(object sender, RoutedEventArgs e) => OpenFileInViewer();

        // ---- page tools ------------------------------------------------------------------------
        // Snapshot: the page as one MHTML file (what the engine has loaded, including images and CSS), plus a small
        // evidence sidecar (URL, UTC time, SHA-256 of the file, ledger head) and a receipt so the capture can be
        // shown to be unchanged later. Honest limit: it proves the file is unchanged since capture, not that the
        // site really served that content.
        private async Task SnapshotPageAsync()
        {
            var t = TargetWebTab(); if (t == null) return;
            var core = t.Web.CoreWebView2;
            var dlg = new Microsoft.Win32.SaveFileDialog { Title = "Save page snapshot", FileName = SafeStem(t.CurrentTitle) + ".mhtml", Filter = "Web page archive (*.mhtml)|*.mhtml" };
            if (dlg.ShowDialog(this) != true) return;
            try
            {
                var res = await core.CallDevToolsProtocolMethodAsync("Page.captureSnapshot", "{\"format\":\"mhtml\"}");
                using var d = JsonDocument.Parse(res);
                var data = d.RootElement.GetProperty("data").GetString() ?? "";
                var bytes = new UTF8Encoding(false).GetBytes(data);
                File.WriteAllBytes(dlg.FileName, bytes);
                var sha = Sha256Of(bytes);
                var url = t.CurrentUrl;
                if (!t.Private) _actions?.Append("page.snapshot", PasswordRules.OriginOf(url) + ":" + sha);
                var side = "{" + J("schema") + ":" + J("recognition.snapshot.v1") + "," + J("url") + ":" + J(t.Private ? "" : url) + "," + J("title") + ":" + J(t.Private ? "" : t.CurrentTitle) + "," +
                           J("captured_utc") + ":" + J(Iso(DateTime.UtcNow)) + "," + J("file") + ":" + J(Path.GetFileName(dlg.FileName)) + "," + J("sha256") + ":" + J(sha) + "," +
                           J("size") + ":" + bytes.Length + "," + J("ledger_head") + ":" + J(t.Private ? "" : (_actions?.Head ?? "")) + "}\n";
                File.WriteAllText(dlg.FileName + ".recognition.json", side, new UTF8Encoding(false));
                Status("snapshot saved (" + (bytes.Length / 1024) + " KB, sha256 " + sha.Substring(0, 12) + "…) with an evidence sidecar");
            }
            catch (Exception ex) { Status("snapshot failed: " + ex.Message); }
        }

        private void PrintPage()
        {
            var t = TargetWebTab(); if (t == null) return;
            try { t.Web.CoreWebView2.ShowPrintUI(CoreWebView2PrintDialogKind.Browser); if (!t.Private) _actions?.Append("page.print", PasswordRules.OriginOf(t.CurrentUrl) ?? ""); }
            catch (Exception ex) { Status("print failed: " + ex.Message); }
        }

        private async Task SavePagePdfAsync()
        {
            var t = TargetWebTab(); if (t == null) return;
            var dlg = new Microsoft.Win32.SaveFileDialog { Title = "Save page as PDF", FileName = SafeStem(t.CurrentTitle) + ".pdf", Filter = "PDF (*.pdf)|*.pdf" };
            if (dlg.ShowDialog(this) != true) return;
            try
            {
                var ok = await t.Web.CoreWebView2.PrintToPdfAsync(dlg.FileName);
                if (!ok) { Status("save as PDF failed"); return; }
                if (!t.Private) _actions?.Append("page.save_pdf", PasswordRules.OriginOf(t.CurrentUrl) + ":" + Sha256Of(File.ReadAllBytes(dlg.FileName)));
                Status("saved " + Path.GetFileName(dlg.FileName));
            }
            catch (Exception ex) { Status("save as PDF failed: " + ex.Message); }
        }

        private async Task ScreenshotAsync()
        {
            var t = TargetWebTab(); if (t == null) return;
            var dlg = new Microsoft.Win32.SaveFileDialog { Title = "Save screenshot of the visible page", FileName = SafeStem(t.CurrentTitle) + ".png", Filter = "PNG image (*.png)|*.png" };
            if (dlg.ShowDialog(this) != true) return;
            try
            {
                using var ms = new MemoryStream();
                await t.Web.CoreWebView2.CapturePreviewAsync(CoreWebView2CapturePreviewImageFormat.Png, ms);
                File.WriteAllBytes(dlg.FileName, ms.ToArray());
                if (!t.Private) _actions?.Append("page.screenshot", PasswordRules.OriginOf(t.CurrentUrl) + ":" + Sha256Of(ms.ToArray()));
                Status("screenshot saved: " + Path.GetFileName(dlg.FileName));
            }
            catch (Exception ex) { Status("screenshot failed: " + ex.Message); }
        }

        // Edit mode: the page becomes directly editable (type, delete, paste) for clean-up before printing or a
        // screenshot. Edits are local to this view, are not saved to the site, and vanish on reload.
        private async Task ToggleEditPageAsync()
        {
            var t = TargetWebTab(); if (t == null) return;
            try
            {
                var r = await t.Web.CoreWebView2.ExecuteScriptAsync("(function(){var on=document.designMode==='on';document.designMode=on?'off':'on';return !on})()");
                Status(r == "true" ? "edit mode ON: click anywhere in the page to type or delete. Edits are local and vanish on reload. Run this again to turn it off." : "edit mode off");
            }
            catch (Exception ex) { Status("edit mode failed: " + ex.Message); }
        }

        private async Task ViewSourceAsync()
        {
            var t = TargetWebTab(); if (t == null) return;
            try
            {
                var raw = await t.Web.CoreWebView2.ExecuteScriptAsync("document.documentElement.outerHTML");
                var html = JsonSerializer.Deserialize<string>(raw) ?? "";
                bool cut = html.Length > MaxViewBytes; if (cut) html = html.Substring(0, (int)MaxViewBytes);
                var nt = await NewTabCoreAsync("Source");
                if (nt == null) return;
                Tabs.SelectedItem = nt.Item; ShowActiveWebView();
                ShowViewer(nt, "Source: " + (t.CurrentTitle ?? ""), html, "html", "the page as currently rendered (live DOM, not the original download)" + (cut ? "; truncated at 5 MB" : ""));
            }
            catch (Exception ex) { Status("view source failed: " + ex.Message); }
        }

        // ---- code viewer -----------------------------------------------------------------------
        // NavigateToString is limited to about 2 MB of HTML, and highlighted source is many times the size of the
        // text. Small files use NavigateToString (nothing touches disk); large files are written to a private temp
        // file that is deleted when the tab closes and when the browser exits.
        private readonly Dictionary<BrowserTab, string> _viewerFiles = new();
        private static string ViewerTempDir() => Path.Combine(Path.GetTempPath(), "recognition-viewer");

        private void ShowViewer(BrowserTab tab, string title, string text, string lang, string note)
        {
            var html = ViewerHtml(title, text, lang, note);
            tab.CurrentTitle = title;
            if (html.Length <= 1_500_000) { _viewerHtml[tab] = html; LoadInternal(tab, "viewer"); return; }
            try
            {
                Directory.CreateDirectory(ViewerTempDir());
                var f = Path.Combine(ViewerTempDir(), Guid.NewGuid().ToString("N") + ".html");
                File.WriteAllText(f, html, new UTF8Encoding(false));
                _viewerFiles[tab] = f;
                tab.Internal = "viewer"; tab.CurrentUrl = "recognition:viewer";
                SetHeader(tab, title);
                if (ReferenceEquals(tab, Active)) { SetAddress(tab); UpdateStar(tab); }
                tab.Web.CoreWebView2.Navigate(new Uri(f).AbsoluteUri);
            }
            catch (Exception ex) { Status("could not open the viewer: " + ex.Message); }
        }

        private string ViewerReloadHtml(BrowserTab tab) =>
            _viewerHtml.TryGetValue(tab, out var v) ? v
            : PageHead + "<title>Viewer</title><h1>Viewer</h1><div class='muted'>This large file is not kept in memory. Close this tab and open the file again.</div>" + PageFoot;

        private void CleanupViewer(BrowserTab tab)
        {
            _viewerHtml.Remove(tab);
            if (_viewerFiles.TryGetValue(tab, out var f)) { try { File.Delete(f); } catch { } _viewerFiles.Remove(tab); }
        }

        private void CleanupViewerAll()
        {
            try { if (Directory.Exists(ViewerTempDir())) Directory.Delete(ViewerTempDir(), true); } catch { }
        }

        private string ViewerHtml(string title, string text, string lang, string note)
        {
            bool light = _appearance.Theme == "light";
            var lines = Math.Max(1, text.Count(c => c == '\n') + (text.Length > 0 && !text.EndsWith("\n") ? 1 : 0));
            int gutter = lines.ToString().Length + 2;
            var body = CodeHighlighter.Render(text, lang);
            var sb = new StringBuilder();
            sb.Append("<!doctype html><html><head><meta charset='utf-8'><meta name='rec-internal' content='1'><title>").Append(Attr(title)).Append("</title><style>");
            sb.Append(":root{--bg:#1e1e1e;--fg:#d4d4d4;--bar:#252526;--bd:#3c3c3c;--ln:#858585;--hl:#264f78;--kw:#569cd6;--type:#4ec9b0;--str:#ce9178;--num:#b5cea8;--com:#6a9955;--fn:#dcdcaa;--attr:#9cdcfe;--pre:#c586c0;--var:#9cdcfe}");
            sb.Append("body.light{--bg:#ffffff;--fg:#000000;--bar:#f3f3f3;--bd:#d4d4d4;--ln:#237893;--hl:#add6ff;--kw:#0000ff;--type:#267f99;--str:#a31515;--num:#098658;--com:#008000;--fn:#795e26;--attr:#e50000;--pre:#af00db;--var:#001080}");
            sb.Append("html,body{margin:0;background:var(--bg);color:var(--fg)}body{font:13px/1.55 Consolas,'Cascadia Mono','Courier New',monospace}");
            sb.Append(".bar{position:sticky;top:0;z-index:5;display:flex;gap:14px;align-items:center;flex-wrap:wrap;padding:8px 14px;background:var(--bar);border-bottom:1px solid var(--bd);font:12px 'Segoe UI',sans-serif}");
            sb.Append(".bar b{font-size:13px}.bar .m{opacity:.7}.bar a{cursor:pointer;color:var(--attr);text-decoration:none;border:1px solid var(--bd);border-radius:4px;padding:2px 8px}");
            sb.Append(".l{display:flex}.n{flex:none;box-sizing:border-box;width:").Append(gutter).Append("ch;min-width:").Append(gutter).Append("ch;text-align:right;padding:0 10px 0 0;color:var(--ln);text-decoration:none;user-select:none;-webkit-user-select:none}");
            sb.Append(".c{white-space:pre;tab-size:4;flex:1;padding-right:20px}body.wrap .c{white-space:pre-wrap;word-break:break-all}.l:target{background:var(--hl)}.l:hover{background:rgba(128,128,128,.12)}");
            foreach (var k in new[] { "kw", "type", "str", "num", "com", "fn", "attr", "pre", "var" }) sb.Append('.').Append(k).Append("{color:var(--").Append(k).Append(")}");
            sb.Append(".com{font-style:italic}</style></head><body").Append(light ? " class='light'" : "").Append(">");
            sb.Append("<div class='bar'><b>").Append(Attr(title)).Append("</b><span class='m'>").Append(Attr(lang)).Append(" · ").Append(lines).Append(" lines</span>");
            if (!string.IsNullOrEmpty(note)) sb.Append("<span class='m'>").Append(Attr(note)).Append("</span>");
            sb.Append("<span style='flex:1'></span><a onclick=\"document.body.classList.toggle('wrap')\">Wrap</a><a onclick=\"fs(1)\">A+</a><a onclick=\"fs(-1)\">A−</a><a onclick=\"document.body.classList.toggle('light')\">Light/Dark</a></div>");
            sb.Append("<div id='code'>").Append(body).Append("</div>");
            sb.Append("<script>var z=13;function fs(d){z=Math.max(8,Math.min(32,z+d));document.body.style.fontSize=z+'px'}</script></body></html>");
            return sb.ToString();
        }

        private void OpenFileInViewer()
        {
            var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Open a file", Filter = "All supported|*.*|PDF|*.pdf|Images|*.png;*.jpg;*.jpeg;*.gif;*.bmp;*.webp;*.tif;*.tiff;*.ico|Code and text|*.*" };
            if (dlg.ShowDialog(this) != true) return;
            _ = OpenPathAsync(dlg.FileName);
        }

        private async Task OpenPathAsync(string path)
        {
            try
            {
                var name = Path.GetFileName(path); var ext = Path.GetExtension(path).ToLowerInvariant();
                if (ext == ".pdf" || ImageMath.IsImageFile(path))
                {
                    // PDFs and images are rendered by the engine itself (built-in PDF viewer with search, selection, annotate, print).
                    var nt = await NewTabCoreAsync(name); if (nt == null) return;
                    Tabs.SelectedItem = nt.Item; ShowActiveWebView();
                    nt.Internal = ""; nt.Web.CoreWebView2.Navigate(new Uri(path).AbsoluteUri);
                    if (!nt.Private) _actions?.Append("file.open", name);
                    return;
                }
                var fi = new FileInfo(path);
                if (!fi.Exists) { Status("file not found"); return; }
                byte[] bytes;
                using (var fs = File.OpenRead(path)) { var len = (int)Math.Min(fi.Length, MaxViewBytes); bytes = new byte[len]; int read = 0; while (read < len) { int n = fs.Read(bytes, read, len - read); if (n <= 0) break; read += n; } if (read < len) Array.Resize(ref bytes, read); }
                if (CodeHighlighter.LooksBinary(bytes)) { Status("'" + name + "' looks like a binary file, so it is not shown as text"); return; }
                var text = CodeHighlighter.DecodeText(bytes);
                var vt = await NewTabCoreAsync(name); if (vt == null) return;
                Tabs.SelectedItem = vt.Item; ShowActiveWebView();
                var lang = CodeHighlighter.LanguageFor(path);
                ShowViewer(vt, name, text, lang, fi.Length > MaxViewBytes ? "showing the first 5 MB of " + (fi.Length / 1024 / 1024) + " MB" : (fi.Length / 1024.0).ToString("0.#") + " KB");
                _actions?.Append("file.view", name + ":" + Sha256Of(bytes));
            }
            catch (Exception ex) { Status("could not open the file: " + ex.Message); }
        }

        // ---- the Tools page (recognition:tools) ---------------------------------------------------
        private void HandleToolsMessage(string msg)
        {
            string Dec(string s) { try { return Uri.UnescapeDataString(s); } catch { return ""; } }
            if (msg == "tools-state")
            {
                if (_toolPdf != null) { try { PostToToolsPage(new { type = "pdf", name = Path.GetFileName(_toolPdfName), pages = PdfTools.PageCount(_toolPdf) }); } catch { } }
            }
            else if (msg == "tools-open") OpenFileInViewer();
            else if (msg.StartsWith("tools-page:"))
            {
                switch (msg.Substring("tools-page:".Length))
                {
                    case "snapshot": _ = SnapshotPageAsync(); break;
                    case "print": PrintPage(); break;
                    case "pdf": _ = SavePagePdfAsync(); break;
                    case "shot": _ = ScreenshotAsync(); break;
                    case "edit": _ = ToggleEditPageAsync(); break;
                    case "source": _ = ViewSourceAsync(); break;
                    case "fullpng": _ = FullPagePngAsync(); break;
                    case "pdffromtab": _ = PdfFromCurrentTabAsync(); break;
                    case "fullpdf:a4:1": _ = FullPagePdfAsync("a4", 1); break;
                    case "fullpdf:a4:2": _ = FullPagePdfAsync("a4", 2); break;
                    case "fullpdf:letter:1": _ = FullPagePdfAsync("letter", 1); break;
                    case "fullpdf:letter:2": _ = FullPagePdfAsync("letter", 2); break;
                    case "fullpdf:single:1": _ = FullPagePdfAsync("single", 1); break;
                    case "fullpdf:single:2": _ = FullPagePdfAsync("single", 2); break;
                }
            }
            else if (msg == "tools-pdf-pick") PickPdf();
            else if (msg == "tools-pdf-many") PickPdfMany();
            else if (msg.StartsWith("tools-pdf-run:")) RunPdf(Dec(msg.Substring("tools-pdf-run:".Length)));
            else if (msg == "tools-img-pick") PickImage();
            else if (msg.StartsWith("tools-img-run:")) RunImage(Dec(msg.Substring("tools-img-run:".Length)));
        }

        private static byte[]? ReadLimited(string path, long max, out string? err)
        {
            err = null;
            var fi = new FileInfo(path);
            if (!fi.Exists) { err = "file not found"; return null; }
            if (fi.Length > max) { err = "file is larger than the " + (max / 1024 / 1024) + " MB limit"; return null; }
            return File.ReadAllBytes(path);
        }

        private void PickPdf()
        {
            var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Choose a PDF", Filter = "PDF (*.pdf)|*.pdf" };
            if (dlg.ShowDialog(this) != true) return;
            var b = ReadLimited(dlg.FileName, PdfTools.MaxInputBytes, out var err);
            if (b == null) { ToolsReport(err ?? "could not read the file", false); return; }
            try { var n = PdfTools.PageCount(b); _toolPdf = b; _toolPdfName = dlg.FileName; PostToToolsPage(new { type = "pdf", name = Path.GetFileName(dlg.FileName), pages = n }); }
            catch (PdfToolException ex) { _toolPdf = null; ToolsReport(ex.Message, false); }
        }

        private void PickPdfMany()
        {
            var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Choose the PDFs to merge (in the order you select them)", Filter = "PDF (*.pdf)|*.pdf", Multiselect = true };
            if (dlg.ShowDialog(this) != true) return;
            _toolPdfMany.Clear();
            foreach (var f in dlg.FileNames)
            {
                var b = ReadLimited(f, PdfTools.MaxInputBytes, out var err);
                if (b == null) { ToolsReport(Path.GetFileName(f) + ": " + err, false); _toolPdfMany.Clear(); return; }
                _toolPdfMany.Add((f, b));
            }
            PostToToolsPage(new { type = "pdfmany", names = _toolPdfMany.Select(x => Path.GetFileName(x.Name)).ToList() });
        }

        private void RunPdf(string json)
        {
            try
            {
                using var d = JsonDocument.Parse(json); var r = d.RootElement;
                var op = r.GetProperty("op").GetString() ?? ""; var spec = r.TryGetProperty("spec", out var sp) ? sp.GetString() ?? "" : "";
                int deg = r.TryGetProperty("deg", out var dg) && dg.ValueKind == JsonValueKind.Number ? dg.GetInt32() : 90;
                if (op == "merge")
                {
                    if (_toolPdfMany.Count < 2) { ToolsReport("choose at least two PDFs to merge", false); return; }
                    var outBytes = PdfTools.Merge(_toolPdfMany.Select(x => x.Data));
                    SavePdfResult(outBytes, "merged.pdf", "merge", _toolPdfMany.Select(x => x.Name).ToList());
                    return;
                }
                if (_toolPdf == null) { ToolsReport("choose a PDF first", false); return; }
                var stem = Path.GetFileNameWithoutExtension(_toolPdfName);
                switch (op)
                {
                    case "extract": SavePdfResult(PdfTools.Extract(_toolPdf, spec), stem + "-pages.pdf", op, new List<string> { _toolPdfName }); break;
                    case "reorder": SavePdfResult(PdfTools.Extract(_toolPdf, spec), stem + "-reordered.pdf", op, new List<string> { _toolPdfName }); break;
                    case "delete": SavePdfResult(PdfTools.Delete(_toolPdf, spec), stem + "-trimmed.pdf", op, new List<string> { _toolPdfName }); break;
                    case "rotate": SavePdfResult(PdfTools.Rotate(_toolPdf, spec, deg), stem + "-rotated.pdf", op, new List<string> { _toolPdfName }); break;
                    case "split":
                    {
                        var parts = PdfTools.SplitEach(_toolPdf);
                        var fd = new Microsoft.Win32.OpenFolderDialog { Title = "Choose the folder for the single-page PDFs" };
                        if (fd.ShowDialog(this) != true) return;
                        for (int i = 0; i < parts.Count; i++)
                        {
                            var target = Path.Combine(fd.FolderName, stem + "-p" + (i + 1).ToString("D" + Math.Max(3, parts.Count.ToString().Length)) + ".pdf");
                            if (File.Exists(target)) { ToolsReport("stopped: " + Path.GetFileName(target) + " already exists in that folder", false); return; }
                            File.WriteAllBytes(target, parts[i]);
                        }
                        _actions?.Append("tools.pdf.split", Path.GetFileName(_toolPdfName) + ":" + parts.Count);
                        ToolsReport("wrote " + parts.Count + " single-page PDFs to " + fd.FolderName);
                        break;
                    }
                    default: ToolsReport("unknown PDF operation", false); break;
                }
            }
            catch (PdfToolException ex) { ToolsReport(ex.Message, false); }
            catch (Exception ex) { ToolsReport("PDF tool failed: " + ex.Message, false); }
        }

        private void SavePdfResult(byte[] bytes, string suggested, string op, List<string> inputs)
        {
            var dlg = new Microsoft.Win32.SaveFileDialog { Title = "Save the new PDF", FileName = SafeStem(suggested, "result") , Filter = "PDF (*.pdf)|*.pdf", DefaultExt = ".pdf" };
            if (!dlg.FileName.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase)) dlg.FileName += ".pdf";
            if (dlg.ShowDialog(this) != true) return;
            if (inputs.Any(i => string.Equals(Path.GetFullPath(i), Path.GetFullPath(dlg.FileName), StringComparison.OrdinalIgnoreCase)))
            { ToolsReport("refused: the output would overwrite the original file. Choose a new name.", false); return; }
            File.WriteAllBytes(dlg.FileName, bytes);
            _actions?.Append("tools.pdf." + op, Path.GetFileName(dlg.FileName) + ":" + Sha256Of(bytes));
            ToolsReport("saved " + Path.GetFileName(dlg.FileName) + " (" + PdfTools.PageCount(bytes) + " pages). The original was not changed.");
        }

        private void PickImage()
        {
            var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Choose an image", Filter = "Images|*.png;*.jpg;*.jpeg;*.gif;*.bmp;*.webp;*.tif;*.tiff;*.ico" };
            if (dlg.ShowDialog(this) != true) return;
            try
            {
                var fi = new FileInfo(dlg.FileName);
                if (fi.Length > 100L * 1024 * 1024) { ToolsReport("image file is larger than 100 MB", false); return; }
                using var fs = File.OpenRead(dlg.FileName);
                var dec = BitmapDecoder.Create(fs, BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.None);
                var f = dec.Frames[0];
                _toolImagePath = dlg.FileName;
                PostToToolsPage(new { type = "img", name = fi.Name, w = f.PixelWidth, h = f.PixelHeight, kb = fi.Length / 1024 });
            }
            catch (Exception ex) { _toolImagePath = null; ToolsReport("could not read that image: " + ex.Message, false); }
        }

        private void RunImage(string json)
        {
            if (_toolImagePath == null) { ToolsReport("choose an image first", false); return; }
            try
            {
                using var d = JsonDocument.Parse(json); var r = d.RootElement;
                string S(string k) => r.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
                double N(string k) => r.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : double.NaN;
                bool B(string k) => r.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.True;
                var fmt = ImageMath.FormatFor(S("format")); if (fmt == null) { ToolsReport("choose an output format", false); return; }
                int rot = ImageMath.NormalizeRotation((int)(double.IsNaN(N("rot")) ? 0 : N("rot"))); if (rot < 0) { ToolsReport("rotation must be a multiple of 90", false); return; }
                int q = ImageMath.ClampQuality((int)(double.IsNaN(N("quality")) ? 90 : N("quality")));

                BitmapSource src;
                using (var fs = File.OpenRead(_toolImagePath)) src = BitmapFrame.Create(fs, BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.OnLoad);
                if ((long)src.PixelWidth * src.PixelHeight > 400_000_000L) { ToolsReport("the source image is too large to process safely", false); return; }
                if (rot != 0 || B("flipH") || B("flipV"))
                {
                    var tg = new TransformGroup();
                    if (rot != 0) tg.Children.Add(new RotateTransform(rot));
                    if (B("flipH")) tg.Children.Add(new ScaleTransform(-1, 1));
                    if (B("flipV")) tg.Children.Add(new ScaleTransform(1, -1));
                    src = new TransformedBitmap(src, tg);
                }
                var mode = S("mode");
                int w = src.PixelWidth, h = src.PixelHeight;
                if (mode != "none")
                {
                    if (!ImageMath.TryTarget(src.PixelWidth, src.PixelHeight, mode, N("a"), double.IsNaN(N("b")) ? 0 : N("b"), out w, out h, out var err)) { ToolsReport(err ?? "invalid size", false); return; }
                }
                if (w != src.PixelWidth || h != src.PixelHeight || fmt == "jpg")
                {
                    var dv = new DrawingVisual();
                    RenderOptions.SetBitmapScalingMode(dv, BitmapScalingMode.HighQuality);
                    using (var dc = dv.RenderOpen())
                    {
                        if (fmt == "jpg" || fmt == "bmp") dc.DrawRectangle(Brushes.White, null, new Rect(0, 0, w, h));   // JPEG has no transparency
                        dc.DrawImage(src, new Rect(0, 0, w, h));
                    }
                    var rtb = new RenderTargetBitmap(w, h, 96, 96, PixelFormats.Pbgra32); rtb.Render(dv); src = rtb;
                }
                BitmapEncoder enc = fmt switch
                {
                    "png" => new PngBitmapEncoder(),
                    "jpg" => new JpegBitmapEncoder { QualityLevel = q },
                    "bmp" => new BmpBitmapEncoder(),
                    "gif" => new GifBitmapEncoder(),
                    _ => new TiffBitmapEncoder()
                };
                enc.Frames.Add(BitmapFrame.Create(src));   // new frame without metadata: camera/GPS/EXIF data is not carried over
                using var ms = new MemoryStream(); enc.Save(ms);
                var ext = "." + fmt;
                var dlg = new Microsoft.Win32.SaveFileDialog { Title = "Save the new image", FileName = SafeStem(Path.GetFileNameWithoutExtension(_toolImagePath), "image") + "-edited" + ext, Filter = fmt.ToUpperInvariant() + " (*" + ext + ")|*" + ext, DefaultExt = ext };
                if (dlg.ShowDialog(this) != true) return;
                if (string.Equals(Path.GetFullPath(dlg.FileName), Path.GetFullPath(_toolImagePath), StringComparison.OrdinalIgnoreCase)) { ToolsReport("refused: the output would overwrite the original image. Choose a new name.", false); return; }
                File.WriteAllBytes(dlg.FileName, ms.ToArray());
                _actions?.Append("tools.image", Path.GetFileName(dlg.FileName) + ":" + Sha256Of(ms.ToArray()));
                ToolsReport("saved " + Path.GetFileName(dlg.FileName) + " (" + w + "×" + h + ", " + (ms.Length / 1024) + " KB). Metadata was not copied. The original was not changed.");
            }
            catch (Exception ex) { ToolsReport("image tool failed: " + ex.Message, false); }
        }

        private string ToolsHtml()
        {
            var sb = new StringBuilder(PageHead);
            sb.Append(@"<title>Tools</title><h1>Tools</h1>
<div class='muted'>Everything here runs on this computer, only when you click, and never changes the original file: results are saved under a new name. Each saved result is receipted by name and hash.</div>
<div id='msg' class='u' style='min-height:18px;margin:8px 0'></div>

<h1 style='font-size:16px'>Current page</h1>
<div class='muted'>Acts on your most recent web tab.</div>
<div style='display:flex;gap:8px;flex-wrap:wrap;margin:6px 0 16px'>
 <a class='btn' onclick=""send('tools-page:snapshot')"">Save snapshot (.mhtml + evidence)</a>
 <a class='btn ghost' onclick=""send('tools-page:print')"">Print&hellip;</a>
 <a class='btn ghost' onclick=""send('tools-page:pdf')"">Save as PDF&hellip;</a>
 <a class='btn ghost' onclick=""send('tools-page:shot')"">Screenshot&hellip;</a>
 <a class='btn ghost' onclick=""send('tools-page:edit')"">Edit this page (on/off)</a>
 <a class='btn ghost' onclick=""send('tools-page:source')"">View source (highlighted)</a>
 <a class='btn ghost' onclick=""send('tools-page:fullpng')"">Full-page screenshot (PNG)&hellip;</a>
 <a class='btn ghost' onclick=""send('tools-page:pdffromtab')"">Use the PDF open in a tab&hellip;</a>
</div>
<div class='muted'><b>Full-page screenshot to PDF</b> captures the whole page, top to bottom, as a picture (text in it cannot be selected; use Save as PDF for selectable text). Pages up to 60,000 px tall.</div>
<div style='display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:6px 0 16px'>
 <select id='fpl' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:6px'><option value='a4'>A4 pages</option><option value='letter'>Letter pages</option><option value='single'>One long page</option></select>
 <select id='fps' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:6px'><option value='1'>normal sharpness</option><option value='2'>sharp (2x, larger file)</option></select>
 <a class='btn' onclick=""send('tools-page:fullpdf:'+$('fpl').value+':'+$('fps').value)"">Save full page as PDF&hellip;</a>
</div>

<h1 style='font-size:16px'>Open a file</h1>
<div class='muted'>PDFs and images open in the built-in viewer (search, select text, annotate, print). Source code and text open in a code viewer with syntax colours and line numbers (C#, JS/TS, Java, Kotlin, C/C++, Go, Rust, Python, PowerShell, shell, SQL, JSON, YAML, TOML, INI, CSS, HTML, XML).</div>
<div style='margin:6px 0 16px'><a class='btn' onclick=""send('tools-open')"">Choose a file&hellip;</a></div>

<h1 style='font-size:16px'>PDF page tools</h1>
<div class='muted'>Extract, delete, reorder, rotate, merge and split pages. These rearrange whole pages; they do not edit text inside a page, fill forms, OCR or sign. Password-protected PDFs are refused.</div>
<div style='margin:8px 0'><a class='btn' onclick=""send('tools-pdf-pick')"">Choose a PDF&hellip;</a> <span id='pdfname' class='u'></span></div>
<div style='display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:6px 0'>
 <input id='spec' placeholder='pages, e.g. 1-3,5,7-  (5-1 reverses)' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:8px;width:300px'>
 <a class='btn ghost' onclick=""pdf('extract')"">Extract</a><a class='btn ghost' onclick=""pdf('delete')"">Delete</a><a class='btn ghost' onclick=""pdf('reorder')"">Reorder (full order, e.g. 3,1,2)</a>
 <select id='deg' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:6px'><option value='90'>90&deg; right</option><option value='180'>180&deg;</option><option value='-90'>90&deg; left</option></select>
 <a class='btn ghost' onclick=""pdf('rotate')"">Rotate</a><a class='btn ghost' onclick=""pdf('split')"">Split into single pages&hellip;</a>
</div>
<div style='margin:6px 0 16px'><a class='btn ghost' onclick=""send('tools-pdf-many')"">Choose PDFs to merge&hellip;</a> <span id='manynames' class='u'></span> <a class='btn' onclick=""pdf('merge')"">Merge</a></div>

<h1 style='font-size:16px'>Image tools</h1>
<div class='muted'>Resize, rotate, flip and convert. Saving re-encodes the image, which also removes camera, location and other metadata.</div>
<div style='margin:8px 0'><a class='btn' onclick=""send('tools-img-pick')"">Choose an image&hellip;</a> <span id='imgname' class='u'></span></div>
<div style='display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:6px 0'>
 <select id='mode' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:6px'><option value='none'>keep size</option><option value='percent'>scale to % </option><option value='width'>width (px)</option><option value='height'>height (px)</option><option value='fit'>fit in box (px)</option><option value='exact'>exact size (px)</option></select>
 <input id='a' type='number' placeholder='value / width' style='width:110px;background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:6px'>
 <input id='b' type='number' placeholder='height' style='width:90px;background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:6px'>
 <select id='rot' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:6px'><option value='0'>no rotation</option><option value='90'>90&deg; right</option><option value='180'>180&deg;</option><option value='270'>90&deg; left</option></select>
 <label><input type='checkbox' id='fh'> flip &harr;</label><label><input type='checkbox' id='fv'> flip &updownarrow;</label>
 <select id='fmt' style='background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:6px'><option value='png'>PNG</option><option value='jpg'>JPG</option><option value='bmp'>BMP</option><option value='gif'>GIF</option><option value='tiff'>TIFF</option></select>
 <input id='q' type='number' min='1' max='100' value='90' title='JPEG quality' style='width:70px;background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:6px'>
 <a class='btn' onclick='img()'>Save as&hellip;</a>
</div>
<script>
function $(i){return document.getElementById(i)}
var enc=encodeURIComponent;
function pdf(op){send('tools-pdf-run:'+enc(JSON.stringify({op:op,spec:$('spec').value,deg:parseInt($('deg').value,10)})))}
function img(){var a=parseFloat($('a').value),b=parseFloat($('b').value);
  send('tools-img-run:'+enc(JSON.stringify({mode:$('mode').value,a:isNaN(a)?null:a,b:isNaN(b)?null:b,rot:parseInt($('rot').value,10),flipH:$('fh').checked,flipV:$('fv').checked,format:$('fmt').value,quality:parseInt($('q').value,10)||90})))}
window.chrome.webview.addEventListener('message',function(ev){var m=ev.data;if(!m)return;
  if(m.type==='pdf')$('pdfname').textContent=m.name+' ('+m.pages+' pages)';
  else if(m.type==='pdfmany')$('manynames').textContent=m.names.join(' + ');
  else if(m.type==='img')$('imgname').textContent=m.name+' ('+m.w+'×'+m.h+', '+m.kb+' KB)';
  else if(m.type==='action'){$('msg').textContent=m.text;$('msg').style.color=m.ok?'':'#e57373'}});
send('tools-state');
</script>");
            sb.Append(SendScript()).Append(PageFoot);
            return sb.ToString();
        }
    }
}
