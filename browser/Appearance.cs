using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Recognition.Browser
{
    // User appearance preferences: colour scheme, dark-mode style, page colours, fonts.
    // Pure logic with NO WPF/WebView2 dependency (compiled into browser.tests too). Every value that
    // ends up inside injected CSS is validated here: colours must be #rrggbb and fonts must come from
    // a fixed allowlist, so a crafted message can never smuggle CSS/JS into a page.
    internal sealed class AppearanceSettings
    {
        public static readonly string[] Themes = { "system", "light", "dark" };
        // off: leave pages alone | prefer: ask sites for their dark theme (prefers-color-scheme)
        // invert: smart-invert every page | custom: force the chosen page colours on every page
        public static readonly string[] DarkStyles = { "off", "prefer", "invert", "custom" };
        public static readonly string[] Fonts =
        {
            "default", "Segoe UI", "Arial", "Verdana", "Tahoma", "Georgia", "Times New Roman",
            "Consolas", "Cascadia Mono", "Courier New", "Comic Sans MS"
        };

        public string Theme = "system";          // browser internal pages + prefers-color-scheme
        public string DarkStyle = "off";
        public string PageBg = "#1b1d22";        // used by DarkStyle == custom
        public string PageText = "#d8dae0";
        public string LinkColor = "#7db4f0";
        public string Font = "default";
        public bool OverrideSiteFonts = false;   // apply Font to every page, not just internal pages

        private static readonly Regex Hex = new("^#[0-9a-fA-F]{6}$", RegexOptions.Compiled);

        // Returns false (and changes nothing) for an unknown key or an invalid value.
        public bool Set(string key, string value)
        {
            value = (value ?? "").Trim();
            switch (key)
            {
                case "theme": if (!Themes.Contains(value)) return false; Theme = value; return true;
                case "darkstyle": if (!DarkStyles.Contains(value)) return false; DarkStyle = value; return true;
                case "bg": if (!Hex.IsMatch(value)) return false; PageBg = value.ToLowerInvariant(); return true;
                case "text": if (!Hex.IsMatch(value)) return false; PageText = value.ToLowerInvariant(); return true;
                case "link": if (!Hex.IsMatch(value)) return false; LinkColor = value.ToLowerInvariant(); return true;
                case "font": if (!Fonts.Contains(value)) return false; Font = value; return true;
                case "overridefonts": if (value != "on" && value != "off") return false; OverrideSiteFonts = value == "on"; return true;
                default: return false;
            }
        }

        public void Reset()
        {
            Theme = "system"; DarkStyle = "off"; PageBg = "#1b1d22"; PageText = "#d8dae0"; LinkColor = "#7db4f0";
            Font = "default"; OverrideSiteFonts = false;
        }

        // 0 = Auto, 1 = Light, 2 = Dark — mirrors CoreWebView2PreferredColorScheme without referencing it.
        public int PreferredScheme()
        {
            if (DarkStyle == "prefer") return 2;
            return Theme == "dark" ? 2 : Theme == "light" ? 1 : 0;
        }

        private static string FontFamilyCss(string f) => "'" + f + "', sans-serif";   // f is allowlisted: no quotes possible

        // CSS applied to every WEB page (empty string = nothing to inject).
        public string PageCss()
        {
            var sb = new StringBuilder();
            if (DarkStyle == "invert")
            {
                sb.Append("html{filter:invert(1) hue-rotate(180deg)!important;background:#fff!important}");
                sb.Append("img,video,canvas,picture,iframe,svg image{filter:invert(1) hue-rotate(180deg)!important}");
            }
            else if (DarkStyle == "custom")
            {
                sb.Append("html,body{background:" + PageBg + "!important;color:" + PageText + "!important}");
                sb.Append("*:not(img):not(video):not(canvas):not(svg):not(iframe){background-color:transparent!important;color:" + PageText + "!important;border-color:" + PageText + "33!important}");
                sb.Append("a,a *{color:" + LinkColor + "!important}");
            }
            if (OverrideSiteFonts && Font != "default")
                sb.Append("*:not(code):not(pre):not(kbd):not(samp){font-family:" + FontFamilyCss(Font) + "!important}");
            return sb.ToString();
        }

        // Script that (re)applies PageCss to the current document. Safe to run repeatedly; an empty
        // CSS removes the style element, so the same script is used to apply, update, and clear.
        public string InjectScript()
        {
            var css = PageCss().Replace("\\", "\\\\").Replace("'", "\\'");
            return "(function(){var css='" + css + "';function ap(){var s=document.getElementById('__rec_style');" +
                   "if(!css||document.querySelector('meta[name=rec-internal]')){if(s)s.remove();return;}" +
                   "if(!s){s=document.createElement('style');s.id='__rec_style';(document.head||document.documentElement).appendChild(s);}" +
                   "s.textContent=css;}" +
                   "if(document.documentElement)ap();else new MutationObserver(function(m,o){if(document.documentElement){o.disconnect();ap();}}).observe(document,{childList:true});" +
                   "document.addEventListener('DOMContentLoaded',ap);})();";
        }

        // Extra CSS appended to the browser's own internal pages (settings, history, ...). The base
        // stylesheet is dark; "light" overrides it, and the chosen font applies to internal pages.
        public string InternalPageCss()
        {
            var sb = new StringBuilder();
            bool light = Theme == "light";
            if (light)
            {
                sb.Append("body{background:#f4f5f7!important;color:#1d2026!important}");
                sb.Append(".row{background:#fff!important;border-color:#dfe2e8!important}");
                sb.Append(".row .t{color:#1d2026!important}.row .u,.muted,.kv .k{color:#5d6470!important}.row .ts{color:#7b828e!important}");
                sb.Append(".kv{border-color:#e3e6ec!important}.kv .v{color:#1d2026!important}");
                sb.Append(".btn.ghost{color:#333a46!important;border-color:#c6cbd4!important}.big{color:#1f8a4c!important}a{color:#1a62b8!important}");
            }
            if (Font != "default") sb.Append("body{font-family:" + FontFamilyCss(Font) + "!important}");
            return sb.ToString();
        }

        // ---- persistence: flat JSON object, hand-built (no external serializer needed) ----
        public string ToJson()
        {
            string J(string s) => "\"" + (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
            return "{" + J("theme") + ":" + J(Theme) + "," + J("dark_style") + ":" + J(DarkStyle) + "," +
                   J("page_bg") + ":" + J(PageBg) + "," + J("page_text") + ":" + J(PageText) + "," +
                   J("link_color") + ":" + J(LinkColor) + "," + J("font") + ":" + J(Font) + "," +
                   J("override_site_fonts") + ":" + (OverrideSiteFonts ? "true" : "false") + "}";
        }

        // Applies every recognised, VALID field of a parsed settings object; invalid values are ignored.
        public void FromJson(System.Text.Json.JsonElement r)
        {
            string? S(string k) => r.TryGetProperty(k, out var v) && v.ValueKind == System.Text.Json.JsonValueKind.String ? v.GetString() : null;
            var m = new (string key, string? val)[]
            {
                ("theme", S("theme")), ("darkstyle", S("dark_style")), ("bg", S("page_bg")), ("text", S("page_text")),
                ("link", S("link_color")), ("font", S("font")),
            };
            foreach (var (key, val) in m) if (val != null) Set(key, val);
            if (r.TryGetProperty("override_site_fonts", out var o) && (o.ValueKind == System.Text.Json.JsonValueKind.True || o.ValueKind == System.Text.Json.JsonValueKind.False))
                OverrideSiteFonts = o.GetBoolean();
        }
    }
}
