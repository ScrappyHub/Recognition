using System;
using System.Text.RegularExpressions;

namespace Recognition.Browser
{
    // The start page background and the home page address. Everything that reaches the page is checked here: only a fixed preset name,
    // a #rrggbb colour or the user's own saved image can become CSS, and only http/https addresses (or the start page) can become the home page.
    internal static class StartBackground
    {
        public static readonly string[] Presets = { "default", "aurora", "dusk", "forest", "slate", "light" };
        public const string StartPage = "recognition:start";

        public static string Normalize(string? key)
        {
            var k = (key ?? "").Trim().ToLowerInvariant();
            if (k == "image" || Array.IndexOf(Presets, k) >= 0) return k;
            return Regex.IsMatch(k, "^#[0-9a-f]{6}$") ? k : "default";
        }

        private static bool HexIsLight(string hex)
        {
            int r = Convert.ToInt32(hex.Substring(1, 2), 16), g = Convert.ToInt32(hex.Substring(3, 2), 16), b = Convert.ToInt32(hex.Substring(5, 2), 16);
            return (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255.0 > 0.6;
        }

        private const string LightVars = ":root{--panel:#ffffff;--line:#d5dae2;--txt:#1b2230;--mut:#586172}.tile:hover{background:#f1f3f7!important;border-color:#b9c0cc!important}.facts{color:#6b7385!important}input::placeholder{color:#8a93a3!important}.si{filter:invert(.6)}";

        // CSS added after the page's own style. Empty for "default". An image is used only when it is a data: URL made of base64 characters.
        public static string Css(string? key, string? imageDataUrl)
        {
            var k = Normalize(key);
            switch (k)
            {
                case "default": return "";
                case "aurora": return "body{background:radial-gradient(900px 520px at 18% -10%,rgba(72,200,170,.34),transparent 70%),radial-gradient(800px 520px at 92% 110%,rgba(76,155,240,.30),transparent 70%),#0c1317}";
                case "dusk": return "body{background:radial-gradient(900px 520px at 80% -10%,rgba(240,130,90,.28),transparent 70%),radial-gradient(800px 520px at 5% 105%,rgba(140,100,240,.32),transparent 70%),#15121c}";
                case "forest": return "body{background:radial-gradient(900px 520px at 50% -15%,rgba(90,190,110,.28),transparent 70%),radial-gradient(800px 520px at 95% 105%,rgba(60,140,100,.24),transparent 70%),#0e1511}";
                case "slate": return "body{background:#1b1f27}";
                case "light": return "body{background:linear-gradient(180deg,#f6f8fb,#e8ecf3)}" + LightVars;
                case "image":
                    if (imageDataUrl != null && imageDataUrl.Length < 3_000_000 && Regex.IsMatch(imageDataUrl, "^data:image/jpeg;base64,[A-Za-z0-9+/=]+$"))
                        return "body{background:linear-gradient(rgba(10,12,16,.38),rgba(10,12,16,.58)),url(" + imageDataUrl + ") center/cover fixed no-repeat}";
                    return "";
                default:
                    return "body{background:" + k + "}" + (HexIsLight(k) ? LightVars : "");
            }
        }

        // A home page the user typed. Returns null when it is not acceptable. Accepts the start page, a full http/https address, a bare
        // site name such as example.com, or an existing local .html file (LaunchArgs rules: no user names in addresses, no control characters).
        public static string? HomeUrl(string? input, Func<string, bool>? fileExists = null)
        {
            var v = (input ?? "").Trim();
            if (v.Length == 0 || v.Length > LaunchArgs.MaxLen) return null;
            if (string.Equals(v, StartPage, StringComparison.OrdinalIgnoreCase) || string.Equals(v, "start", StringComparison.OrdinalIgnoreCase)) return StartPage;
            var direct = LaunchArgs.Parse(v, fileExists);
            if (direct != null) return direct;
            if (v.IndexOf("://", StringComparison.Ordinal) < 0 && v.IndexOf(' ') < 0 && v.IndexOf(':') < 0 && v.IndexOf('.') > 0)
                return LaunchArgs.Parse("https://" + v, fileExists);
            return null;
        }
    }
}
