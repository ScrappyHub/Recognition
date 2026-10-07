using System;

namespace Recognition.Browser
{
    // Pure maths and validation for the image tools (resize / rotate / convert). The pixel work itself is done by
    // Windows Imaging (WPF) in MainWindow.Tools.cs; every number that reaches it has passed through here first.
    // Executed by browser.tests.
    internal static class ImageMath
    {
        public const int MaxDimension = 20000;
        public const long MaxPixels = 100_000_000;

        private static readonly string[] ImageExts = { ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tif", ".tiff", ".webp", ".ico" };

        public static bool IsImageFile(string? name)
        {
            var ext = System.IO.Path.GetExtension(name ?? "").ToLowerInvariant();
            return Array.IndexOf(ImageExts, ext) >= 0;
        }

        // Allowlist of output formats. Returns the canonical id or null.
        public static string? FormatFor(string? f)
        {
            switch ((f ?? "").Trim().ToLowerInvariant())
            {
                case "png": return "png";
                case "jpg": case "jpeg": return "jpg";
                case "bmp": return "bmp";
                case "gif": return "gif";
                case "tif": case "tiff": return "tiff";
                default: return null;
            }
        }

        public static int ClampQuality(int q) => q < 1 ? 1 : q > 100 ? 100 : q;

        // 0/90/180/270, or -1 when the angle is not a multiple of 90.
        public static int NormalizeRotation(int deg) => deg % 90 != 0 ? -1 : ((deg % 360) + 360) % 360;
        public static (int W, int H) AfterRotation(int w, int h, int deg) => (deg == 90 || deg == 270) ? (h, w) : (w, h);

        private static bool InRange(double v, double lo, double hi) => !double.IsNaN(v) && !double.IsInfinity(v) && v >= lo && v <= hi;

        // mode: percent (a = 1..1000) | width (a) | height (a) | fit (a x b box) | exact (a x b). Sizes are 1..MaxDimension pixels.
        public static bool TryTarget(int srcW, int srcH, string? mode, double a, double b, out int w, out int h, out string? error)
        {
            w = h = 0; error = null;
            if (srcW < 1 || srcH < 1) { error = "the image has no size"; return false; }
            double tw, th;
            switch (mode)
            {
                case "percent":
                    if (!InRange(a, 1, 1000)) { error = "percent must be between 1 and 1000"; return false; }
                    tw = srcW * a / 100.0; th = srcH * a / 100.0; break;
                case "width":
                    if (!InRange(a, 1, MaxDimension)) { error = "width must be between 1 and " + MaxDimension; return false; }
                    tw = a; th = srcH * a / srcW; break;
                case "height":
                    if (!InRange(a, 1, MaxDimension)) { error = "height must be between 1 and " + MaxDimension; return false; }
                    th = a; tw = srcW * a / srcH; break;
                case "fit":
                    if (!InRange(a, 1, MaxDimension) || !InRange(b, 1, MaxDimension)) { error = "the box must be between 1 and " + MaxDimension + " pixels"; return false; }
                    { double s = Math.Min(a / srcW, b / srcH); tw = srcW * s; th = srcH * s; }
                    break;
                case "exact":
                    if (!InRange(a, 1, MaxDimension) || !InRange(b, 1, MaxDimension)) { error = "width and height must be between 1 and " + MaxDimension; return false; }
                    tw = a; th = b; break;
                default: error = "unknown resize mode"; return false;
            }
            w = (int)Math.Max(1, Math.Round(tw, MidpointRounding.AwayFromZero)); h = (int)Math.Max(1, Math.Round(th, MidpointRounding.AwayFromZero));
            if (w > MaxDimension || h > MaxDimension || (long)w * h > MaxPixels) { w = h = 0; error = "the result would be larger than the limit (" + MaxDimension + " px per side, " + (MaxPixels / 1_000_000) + " megapixels)"; return false; }
            return true;
        }
    }
}
