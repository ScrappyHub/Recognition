using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using PdfSharp.Pdf;
using PdfSharp.Pdf.IO;

namespace Recognition.Browser
{
    internal sealed class PdfToolException : Exception { public PdfToolException(string m) : base(m) { } }

    // Offline PDF page tools: extract, delete, reorder (any order, including reverse), merge, split, rotate.
    // Built on PDFsharp (MIT, pinned version). Pure byte[] in / byte[] out, no WPF/WebView2, executed by browser.tests.
    // Honest scope: these tools rearrange and rotate whole pages. They do NOT edit text/images inside a page,
    // fill forms, OCR, sign, redact or compress, and password-protected PDFs are refused (never silently bypassed).
    // Viewing, text selection and annotation use the browser's built-in PDF viewer.
    internal static class PdfTools
    {
        public const int MaxInputBytes = 200 * 1024 * 1024, MaxPages = 20000, MaxSpecEntries = 10000;

        private static PdfDocument OpenForImport(byte[] pdf)
        {
            if (pdf == null || pdf.Length < 8) throw new PdfToolException("not a PDF file");
            if (pdf.Length > MaxInputBytes) throw new PdfToolException("PDF is larger than the 200 MB limit");
            try
            {
                var d = PdfReader.Open(new MemoryStream(pdf, writable: false), PdfDocumentOpenMode.Import);
                if (d.PageCount > MaxPages) throw new PdfToolException("PDF has more than " + MaxPages + " pages");
                return d;
            }
            catch (PdfToolException) { throw; }
            catch (Exception) { throw new PdfToolException("not a valid or supported PDF (it may be password-protected, damaged, or use an unsupported feature)"); }
        }

        private static byte[] Save(PdfDocument d)
        {
            if (d.PageCount == 0) throw new PdfToolException("the result would have no pages");
            using var ms = new MemoryStream();
            d.Save(ms, false);
            return ms.ToArray();
        }

        public static int PageCount(byte[] pdf) { using var d = OpenForImport(pdf); return d.PageCount; }

        // "1-3,5,7-" (to the last page), "-2" (first two), "5-3" (descending). 1-based. Returns 0-based indexes, or null + error.
        public static List<int>? ParseRange(string? spec, int pageCount, out string? error)
        {
            error = null;
            if (string.IsNullOrWhiteSpace(spec)) { error = "enter the pages, for example 1-3,5,7-"; return null; }
            var result = new List<int>();
            var parts = spec.Split(',');
            if (parts.Length > MaxSpecEntries) { error = "too many entries"; return null; }
            foreach (var raw in parts)
            {
                var p = raw.Trim();
                if (p.Length == 0) { error = "empty entry in the page list"; return null; }
                int dash = p.IndexOf('-');
                int a, b;
                if (dash < 0) { if (!TryNum(p, pageCount, out a)) { error = Bad(p, pageCount); return null; } b = a; }
                else
                {
                    var left = p.Substring(0, dash).Trim(); var right = p.Substring(dash + 1).Trim();
                    if (right.Contains('-')) { error = Bad(p, pageCount); return null; }
                    if (left.Length == 0 && right.Length == 0) { error = Bad(p, pageCount); return null; }
                    a = 1; b = pageCount;
                    if (left.Length > 0 && !TryNum(left, pageCount, out a)) { error = Bad(p, pageCount); return null; }
                    if (right.Length > 0 && !TryNum(right, pageCount, out b)) { error = Bad(p, pageCount); return null; }
                }
                if (a <= b) for (int i = a; i <= b; i++) result.Add(i - 1); else for (int i = a; i >= b; i--) result.Add(i - 1);
                if (result.Count > MaxPages) { error = "the page list produces too many pages"; return null; }
            }
            return result;
        }
        private static bool TryNum(string s, int max, out int n) => int.TryParse(s, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out n) && n >= 1 && n <= max;
        private static string Bad(string p, int max) => "'" + p + "' is not valid (pages are 1 to " + max + ")";

        private static List<int> MustParse(string spec, int count)
        {
            var r = ParseRange(spec, count, out var err);
            if (r == null) throw new PdfToolException(err ?? "invalid page list");
            return r;
        }

        // Pages in exactly the order given (duplicates allowed): extract, reorder and reverse are the same operation.
        public static byte[] Extract(byte[] pdf, string spec)
        {
            using var src = OpenForImport(pdf);
            var idx = MustParse(spec, src.PageCount);
            var dst = new PdfDocument();
            foreach (var i in idx) dst.AddPage(src.Pages[i]);
            return Save(dst);
        }

        public static byte[] Delete(byte[] pdf, string spec)
        {
            using var src = OpenForImport(pdf);
            var del = new HashSet<int>(MustParse(spec, src.PageCount));
            if (del.Count >= src.PageCount) throw new PdfToolException("that would delete every page");
            var dst = new PdfDocument();
            for (int i = 0; i < src.PageCount; i++) if (!del.Contains(i)) dst.AddPage(src.Pages[i]);
            return Save(dst);
        }

        public static byte[] Merge(IEnumerable<byte[]> pdfs)
        {
            var dst = new PdfDocument(); int files = 0;
            foreach (var bytes in pdfs)
            {
                using var src = OpenForImport(bytes); files++;
                for (int i = 0; i < src.PageCount; i++) { dst.AddPage(src.Pages[i]); if (dst.PageCount > MaxPages) throw new PdfToolException("the merged file would exceed " + MaxPages + " pages"); }
            }
            if (files < 2) throw new PdfToolException("choose at least two PDFs to merge");
            return Save(dst);
        }

        public static List<byte[]> SplitEach(byte[] pdf)
        {
            using var src = OpenForImport(pdf);
            var outs = new List<byte[]>();
            for (int i = 0; i < src.PageCount; i++) { var d = new PdfDocument(); d.AddPage(src.Pages[i]); outs.Add(Save(d)); }
            return outs;
        }

        // Rotate the listed pages by 90, 180, 270 or -90 degrees (added to the page's existing rotation); other pages are kept as they are.
        public static byte[] Rotate(byte[] pdf, string spec, int degrees)
        {
            if (degrees % 90 != 0 || degrees == 0) throw new PdfToolException("rotation must be 90, 180, 270 or -90 degrees");
            using var src = OpenForImport(pdf);
            var which = new HashSet<int>(MustParse(spec, src.PageCount));
            var dst = new PdfDocument();
            for (int i = 0; i < src.PageCount; i++)
            {
                var p = dst.AddPage(src.Pages[i]);
                if (which.Contains(i)) p.Rotate = (((p.Rotate + degrees) % 360) + 360) % 360;
            }
            return Save(dst);
        }

        // Page list for display: "1  (A4 portrait)" is not available without rendering, so report count and rotation only.
        public static List<int> Rotations(byte[] pdf)
        {
            using var d = OpenForImport(pdf);
            return Enumerable.Range(0, d.PageCount).Select(i => d.Pages[i].Rotate).ToList();
        }
    }
}
