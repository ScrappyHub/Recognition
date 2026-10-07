using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;

namespace Recognition.Browser
{
    // Full-page screenshot of the current web page, saved as a PDF (paged A4 / Letter, or one long page) or a PNG.
    // The page layout and PDF writing are in ImagePdf.cs (executed by the tests); this file captures the page through the
    // engine's own DevTools protocol, shows progress, and saves under a name the user picks. Local only, user-initiated, receipted.
    //
    // It is a picture of the page, so text in the PDF is not selectable (use "Save page as PDF" for text). Very long pages are
    // limited (60,000 px). Fixed headers appear once, at the top. Pages that load more content as you scroll are scrolled once
    // first so lazy images appear, but endless feeds are cut at the limit.
    public partial class MainWindow
    {
        private bool _fullPageBusy;

        private async void MenuFullPdfA4_Click(object sender, RoutedEventArgs e) => await FullPagePdfAsync("a4", 1);
        private async void MenuFullPdfLetter_Click(object sender, RoutedEventArgs e) => await FullPagePdfAsync("letter", 1);
        private async void MenuFullPdfSingle_Click(object sender, RoutedEventArgs e) => await FullPagePdfAsync("single", 1);
        private async void MenuFullPng_Click(object sender, RoutedEventArgs e) => await FullPagePngAsync();
        private async void MenuPdfFromTab_Click(object sender, RoutedEventArgs e) => await PdfFromCurrentTabAsync();

        private static int ReadInt(JsonElement e, string name)
            => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? (int)Math.Ceiling(v.GetDouble()) : 0;

        private async Task<(int W, int H)> MeasurePageAsync(Microsoft.Web.WebView2.Core.CoreWebView2 core)
        {
            // scroll once so lazily loaded content is present, then come back to the top
            try
            {
                var rawH = await core.ExecuteScriptAsync("Math.max(document.documentElement.scrollHeight,document.body?document.body.scrollHeight:0)");
                int h0 = int.TryParse(rawH, out var hv) ? hv : 0;
                for (int y = 0; y < Math.Min(h0, PagePlanner.MaxHeightCss); y += 700)
                {
                    await core.ExecuteScriptAsync("window.scrollTo(0," + y + ")");
                    await Task.Delay(110);
                }
                await core.ExecuteScriptAsync("window.scrollTo(0,0)");
                await Task.Delay(300);
            }
            catch { }
            var res = await core.CallDevToolsProtocolMethodAsync("Page.getLayoutMetrics", "{}");
            using var d = JsonDocument.Parse(res); var root = d.RootElement;
            var size = root.TryGetProperty("cssContentSize", out var c) ? c : root.GetProperty("contentSize");
            return (ReadInt(size, "width"), ReadInt(size, "height"));
        }

        private static async Task<byte[]> CaptureTileAsync(Microsoft.Web.WebView2.Core.CoreWebView2 core, string format, int quality, int y, int w, int h, int scale)
        {
            var args = "{\"format\":\"" + format + "\"," + (format == "jpeg" ? "\"quality\":" + quality + "," : "") +
                       "\"captureBeyondViewport\":true,\"fromSurface\":true,\"clip\":{\"x\":0,\"y\":" + y + ",\"width\":" + w + ",\"height\":" + h + ",\"scale\":" + scale + "}}";
            var res = await core.CallDevToolsProtocolMethodAsync("Page.captureScreenshot", args);
            using var d = JsonDocument.Parse(res);
            return Convert.FromBase64String(d.RootElement.GetProperty("data").GetString() ?? "");
        }

        private async Task FullPagePdfAsync(string layout, int scale)
        {
            if (_fullPageBusy) { Status("a full-page capture is already running"); return; }
            var t = TargetWebTab(); if (t == null) return;
            var dlg = new Microsoft.Win32.SaveFileDialog { Title = "Save full-page screenshot as PDF", FileName = SafeStem(t.CurrentTitle) + "-full.pdf", Filter = "PDF (*.pdf)|*.pdf", DefaultExt = ".pdf" };
            if (dlg.ShowDialog(this) != true) return;
            _fullPageBusy = true;
            try
            {
                var core = t.Web.CoreWebView2;
                Status("measuring the page…");
                var (w, h) = await MeasurePageAsync(core);
                var plan = PagePlanner.Plan(w, h, layout, Math.Max(500, 8000 / Math.Max(1, scale)));
                var tiles = new List<byte[]>();
                for (int i = 0; i < plan.Tiles.Count; i++)
                {
                    Status("capturing part " + (i + 1) + " of " + plan.Tiles.Count + "…");
                    tiles.Add(await CaptureTileAsync(core, "jpeg", 92, plan.Tiles[i].Top, plan.WidthCss, plan.Tiles[i].Height, scale));
                }
                var url = t.Private ? "" : t.CurrentUrl;
                var pdf = ImagePdf.Build(plan, tiles, t.Private ? "Page screenshot" : t.CurrentTitle, url, DateTime.UtcNow);
                File.WriteAllBytes(dlg.FileName, pdf);
                if (!t.Private) _actions?.Append("page.fullpage_pdf", PasswordRules.OriginOf(t.CurrentUrl) + ":" + Sha256Of(pdf));
                Status("saved " + Path.GetFileName(dlg.FileName) + " (" + plan.Pages.Count + " page" + (plan.Pages.Count == 1 ? "" : "s") + ", " + (pdf.Length / 1024) + " KB)" + (plan.Truncated ? ". The page was longer than the limit and was cut." : ""));
            }
            catch (ImagePdfException ex) { Status("full-page PDF failed: " + ex.Message); }
            catch (Exception ex) { Status("full-page PDF failed: " + ex.Message); }
            finally { _fullPageBusy = false; }
        }

        private async Task FullPagePngAsync()
        {
            if (_fullPageBusy) { Status("a full-page capture is already running"); return; }
            var t = TargetWebTab(); if (t == null) return;
            var dlg = new Microsoft.Win32.SaveFileDialog { Title = "Save full-page screenshot", FileName = SafeStem(t.CurrentTitle) + "-full.png", Filter = "PNG image (*.png)|*.png", DefaultExt = ".png" };
            if (dlg.ShowDialog(this) != true) return;
            _fullPageBusy = true;
            try
            {
                var core = t.Web.CoreWebView2;
                var (w, h) = await MeasurePageAsync(core);
                if (h > 16000) { Status("this page is " + h + " px tall; a single PNG is limited to 16,000 px. Use the PDF option instead."); return; }
                var png = await CaptureTileAsync(core, "png", 0, 0, Math.Min(w, PagePlanner.MaxWidthCss), h, 1);
                File.WriteAllBytes(dlg.FileName, png);
                if (!t.Private) _actions?.Append("page.fullpage_png", PasswordRules.OriginOf(t.CurrentUrl) + ":" + Sha256Of(png));
                Status("saved " + Path.GetFileName(dlg.FileName) + " (" + w + "×" + h + ")");
            }
            catch (Exception ex) { Status("full-page screenshot failed: " + ex.Message); }
            finally { _fullPageBusy = false; }
        }

        // Pull the PDF that is open in a tab into the PDF page tools (extract, delete, reorder, rotate, split, merge).
        private async Task PdfFromCurrentTabAsync()
        {
            var t = TargetWebTab(); if (t == null) return;
            try
            {
                var core = t.Web.CoreWebView2;
                var url = core.Source ?? "";
                byte[]? data = null; string name = SafeStem(Path.GetFileNameWithoutExtension(new Uri(url).AbsolutePath), "document") + ".pdf";
                if (url.StartsWith("file:", StringComparison.OrdinalIgnoreCase))
                {
                    var path = new Uri(url).LocalPath;
                    data = ReadLimited(path, PdfTools.MaxInputBytes, out var err);
                    if (data == null) { Status("could not read the PDF: " + err); return; }
                    name = Path.GetFileName(path);
                }
                else
                {
                    var ct = await core.ExecuteScriptAsync("document.contentType");
                    if (!ct.Contains("pdf", StringComparison.OrdinalIgnoreCase)) { Status("the current tab is not showing a PDF"); return; }
                    var max = 40 * 1024 * 1024;   // moves through the page as text, so kept modest; open bigger files from disk
                    var js = "(async function(){try{var r=await fetch(location.href,{credentials:'include'});var b=await r.arrayBuffer();if(b.byteLength>" + max +
                             ")return 'toolarge';var u=new Uint8Array(b),s='';for(var i=0;i<u.length;i+=32768)s+=String.fromCharCode.apply(null,u.subarray(i,i+32768));return btoa(s)}catch(e){return 'error'}})()";
                    var raw = await core.ExecuteScriptAsync(js);
                    var s = JsonSerializer.Deserialize<string>(raw) ?? "error";
                    if (s == "toolarge") { Status("the PDF is larger than the " + (max / 1024 / 1024) + " MB limit"); return; }
                    if (s == "error" || s.Length == 0) { Status("could not read the PDF from the page"); return; }
                    data = Convert.FromBase64String(s);
                }
                var pages = PdfTools.PageCount(data);
                _toolPdf = data; _toolPdfName = name;
                _actions?.Append("tools.pdf.from_tab", name + ":" + Sha256Of(data));
                var tools = _tabs.FirstOrDefault(x => x.Internal == "tools");
                if (tools == null) { tools = await NewTabCoreAsync("Tools"); if (tools == null) return; }
                Tabs.SelectedItem = tools.Item; ShowActiveWebView();
                LoadInternal(tools, "tools");
                Status("loaded " + name + " (" + pages + " pages) into the PDF page tools");
            }
            catch (PdfToolException ex) { _toolPdf = null; Status(ex.Message); }
            catch (Exception ex) { Status("could not use this PDF: " + ex.Message); }
        }
    }
}
