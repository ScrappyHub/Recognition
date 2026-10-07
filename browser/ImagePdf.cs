using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace Recognition.Browser
{
    // Full-page screenshot to PDF. Pure code (no WPF, no WebView2) so it is covered by the executed tests.
    //
    //  CapturePlan  decides how a tall web page is cut into capture tiles (the engine cannot render an arbitrarily tall image in one go)
    //               and how those tiles are laid out on PDF pages (paged A4 / Letter, or one long page).
    //  ImagePdf     writes a PDF whose pages show the captured JPEG tiles. JPEG data is embedded as-is (DCTDecode), so nothing is
    //               re-encoded here, each tile is stored once even when it appears on two pages, and the writer uses no third-party code.
    //
    // This is a picture of the page: text in the PDF is not selectable. For selectable text use "Save page as PDF" (print layout).
    internal sealed class ImagePdfException : Exception { public ImagePdfException(string m) : base(m) { } }

    internal readonly record struct JpegInfo(int Width, int Height, int Components);
    internal readonly record struct CaptureTile(int Top, int Height);   // CSS pixels

    internal sealed class PlannedPage
    {
        public double WidthPt, HeightPt;
        public int Top, Height;   // the slice of the page, in CSS pixels
    }

    internal sealed class CapturePlan
    {
        public int WidthCss, HeightCss;
        public double PtPerCss;
        public bool Truncated;
        public string Layout = "a4";
        public List<CaptureTile> Tiles = new();
        public List<PlannedPage> Pages = new();
    }

    internal static class PagePlanner
    {
        public const int MaxWidthCss = 4000, MaxHeightCss = 60000, MaxPages = 300, MaxTiles = 600;
        public const double MaxPdfPt = 14400;   // PDF viewers support at most 200 inches per side

        // layout: "a4", "letter" (paged, fitted to paper width) or "single" (one long page).
        public static CapturePlan Plan(int widthCss, int heightCss, string layout, int maxTileCssHeight)
        {
            if (widthCss < 1 || heightCss < 1) throw new ImagePdfException("the page has no size to capture");
            if (maxTileCssHeight < 100) throw new ImagePdfException("tile height too small");
            var p = new CapturePlan { Layout = layout is "a4" or "letter" or "single" ? layout : "a4" };
            p.WidthCss = Math.Min(widthCss, MaxWidthCss);
            p.HeightCss = Math.Min(heightCss, MaxHeightCss);
            p.Truncated = widthCss > MaxWidthCss || heightCss > MaxHeightCss;

            for (int y = 0; y < p.HeightCss; y += maxTileCssHeight)
                p.Tiles.Add(new CaptureTile(y, Math.Min(maxTileCssHeight, p.HeightCss - y)));
            if (p.Tiles.Count > MaxTiles) throw new ImagePdfException("the page is too large to capture");

            if (p.Layout == "single")
            {
                double k = 0.75;                                   // 96 CSS px per inch = 0.75 pt per px
                if (p.HeightCss * k > MaxPdfPt) k = MaxPdfPt / p.HeightCss;
                if (p.WidthCss * k > MaxPdfPt) k = MaxPdfPt / p.WidthCss;
                p.PtPerCss = k;
                p.Pages.Add(new PlannedPage { WidthPt = p.WidthCss * k, HeightPt = p.HeightCss * k, Top = 0, Height = p.HeightCss });
            }
            else
            {
                double pw = p.Layout == "letter" ? 612.0 : 595.28, ph = p.Layout == "letter" ? 792.0 : 841.89;
                double k = pw / p.WidthCss; p.PtPerCss = k;
                int sliceCss = Math.Max(1, (int)Math.Floor(ph / k));
                for (int y = 0; y < p.HeightCss; y += sliceCss)
                    p.Pages.Add(new PlannedPage { WidthPt = pw, HeightPt = ph, Top = y, Height = Math.Min(sliceCss, p.HeightCss - y) });
                if (p.Pages.Count > MaxPages) throw new ImagePdfException("the page would need more than " + MaxPages + " PDF pages; use the one-long-page layout");
            }
            return p;
        }

        // Tiles that must be drawn on a page, with their position from the top of the page in points.
        public static List<(int Tile, double YPt, double HPt)> Placements(CapturePlan plan, PlannedPage page)
        {
            var list = new List<(int, double, double)>();
            for (int i = 0; i < plan.Tiles.Count; i++)
            {
                var t = plan.Tiles[i];
                if (t.Top < page.Top + page.Height && t.Top + t.Height > page.Top)
                    list.Add((i, (t.Top - page.Top) * plan.PtPerCss, t.Height * plan.PtPerCss));
            }
            return list;
        }
    }

    internal static class ImagePdf
    {
        public const int MaxTileBytes = 40 * 1024 * 1024;

        // Reads width/height/components from the JPEG header. Only what PDF's DCTDecode filter can carry is accepted.
        public static JpegInfo ParseJpeg(byte[] b)
        {
            if (b == null || b.Length < 4 || b[0] != 0xFF || b[1] != 0xD8) throw new ImagePdfException("not a JPEG image");
            if (b.Length > MaxTileBytes) throw new ImagePdfException("image part is too large");
            int i = 2;
            while (i + 3 < b.Length)
            {
                if (b[i] != 0xFF) { i++; continue; }
                int m = b[i + 1];
                if (m == 0xFF) { i++; continue; }                                         // fill byte
                if (m == 0x00 || m == 0x01 || m == 0xD8 || (m >= 0xD0 && m <= 0xD7)) { i += 2; continue; }   // markers without a length
                if (m == 0xD9 || m == 0xDA) break;                                        // end of image / scan reached before any frame header
                int len = (b[i + 2] << 8) | b[i + 3];
                if (len < 2) throw new ImagePdfException("damaged JPEG");
                bool sof = m >= 0xC0 && m <= 0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC;
                if (sof)
                {
                    if (m > 0xC2) throw new ImagePdfException("unsupported JPEG variant");
                    if (len < 8 || i + 9 >= b.Length) throw new ImagePdfException("damaged JPEG header");
                    int precision = b[i + 4], h = (b[i + 5] << 8) | b[i + 6], w = (b[i + 7] << 8) | b[i + 8], comps = b[i + 9];
                    if (precision != 8) throw new ImagePdfException("only 8-bit JPEG is supported");
                    if (w < 1 || h < 1) throw new ImagePdfException("JPEG has no size");
                    if (comps != 1 && comps != 3) throw new ImagePdfException("only grey or RGB JPEG is supported");
                    return new JpegInfo(w, h, comps);
                }
                i += 2 + len;
            }
            throw new ImagePdfException("could not read the JPEG header");
        }

        private static string Num(double d) => Math.Round(d, 3).ToString("0.###", CultureInfo.InvariantCulture);
        private static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

        // PDF text string as UTF-16BE hex, so any title or address is stored safely.
        public static string HexString(string? s)
        {
            var sb = new StringBuilder("<FEFF");
            foreach (var ch in (s ?? "")) sb.Append(((int)ch).ToString("X4", CultureInfo.InvariantCulture));
            return sb.Append('>').ToString();
        }

        public static byte[] Build(CapturePlan plan, IReadOnlyList<byte[]> tileJpegs, string title, string subject, DateTime utcNow)
        {
            if (plan == null || plan.Pages.Count == 0) throw new ImagePdfException("nothing to write");
            if (tileJpegs.Count != plan.Tiles.Count) throw new ImagePdfException("image parts do not match the plan");
            var infos = tileJpegs.Select(ParseJpeg).ToList();

            int tileBase = 4;                                      // 1 catalog, 2 pages, 3 info, then one object per tile
            int firstPageObj = tileBase + infos.Count;             // then (page, content) pairs
            var bodies = new List<byte[]>();                       // bodies[n-1] is the full body of object n

            byte[] Obj(string dict) => Ascii(dict);
            byte[] Stream(string dictWithoutLength, byte[] data)
            {
                using var ms = new MemoryStream();
                var head = Ascii(dictWithoutLength.TrimEnd().TrimEnd('>').TrimEnd() + " /Length " + data.Length.ToString(CultureInfo.InvariantCulture) + " >>\nstream\n");
                ms.Write(head, 0, head.Length); ms.Write(data, 0, data.Length);
                var tail = Ascii("\nendstream"); ms.Write(tail, 0, tail.Length);
                return ms.ToArray();
            }

            var kids = new StringBuilder();
            for (int p = 0; p < plan.Pages.Count; p++) kids.Append(firstPageObj + p * 2).Append(" 0 R ");
            bodies.Add(Obj("<< /Type /Catalog /Pages 2 0 R >>"));
            bodies.Add(Obj("<< /Type /Pages /Kids [ " + kids + "] /Count " + plan.Pages.Count + " >>"));
            bodies.Add(Obj("<< /Title " + HexString(title) + " /Subject " + HexString(subject) + " /Producer " + HexString("Recognition") +
                           " /CreationDate (D:" + utcNow.ToUniversalTime().ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture) + "Z) >>"));
            for (int i = 0; i < infos.Count; i++)
                bodies.Add(Stream("<< /Type /XObject /Subtype /Image /Width " + infos[i].Width + " /Height " + infos[i].Height +
                                  " /ColorSpace " + (infos[i].Components == 1 ? "/DeviceGray" : "/DeviceRGB") + " /BitsPerComponent 8 /Filter /DCTDecode >>", tileJpegs[i]));

            for (int p = 0; p < plan.Pages.Count; p++)
            {
                var page = plan.Pages[p];
                var place = PagePlanner.Placements(plan, page);
                var res = new StringBuilder(); var content = new StringBuilder();
                content.Append("q 0 0 ").Append(Num(page.WidthPt)).Append(' ').Append(Num(page.HeightPt)).Append(" re W n\n");
                foreach (var (tile, yTop, h) in place)
                {
                    res.Append("/Im").Append(tile).Append(' ').Append(tileBase + tile).Append(" 0 R ");
                    double yBottom = page.HeightPt - (yTop + h);
                    content.Append("q ").Append(Num(page.WidthPt)).Append(" 0 0 ").Append(Num(h)).Append(" 0 ").Append(Num(yBottom)).Append(" cm /Im").Append(tile).Append(" Do Q\n");
                }
                content.Append("Q\n");
                int pageObj = firstPageObj + p * 2, contentObj = pageObj + 1;
                bodies.Add(Obj("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 " + Num(page.WidthPt) + " " + Num(page.HeightPt) + "] /Resources << /XObject << " + res + ">> >> /Contents " + contentObj + " 0 R >>"));
                bodies.Add(Stream("<< >>", Ascii(content.ToString())));
            }

            using var o = new MemoryStream();
            void W(byte[] bytes) => o.Write(bytes, 0, bytes.Length);
            W(Ascii("%PDF-1.4\n")); W(new byte[] { (byte)'%', 0xE2, 0xE3, 0xCF, 0xD3, (byte)'\n' });
            var offsets = new long[bodies.Count];
            for (int n = 0; n < bodies.Count; n++)
            {
                offsets[n] = o.Position;
                W(Ascii((n + 1).ToString(CultureInfo.InvariantCulture) + " 0 obj\n")); W(bodies[n]); W(Ascii("\nendobj\n"));
            }
            long xref = o.Position;
            var x = new StringBuilder();
            x.Append("xref\n0 ").Append(bodies.Count + 1).Append('\n').Append("0000000000 65535 f \n");
            foreach (var off in offsets) x.Append(off.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n");
            x.Append("trailer\n<< /Size ").Append(bodies.Count + 1).Append(" /Root 1 0 R /Info 3 0 R >>\nstartxref\n").Append(xref).Append("\n%%EOF\n");
            W(Ascii(x.ToString()));
            return o.ToArray();
        }
    }
}
