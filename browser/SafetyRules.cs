using System;
using System.Linq;

namespace Recognition.Browser
{
    internal enum MessageVerdict { Deny, Shortcut, Command }

    // Who may talk to the browser's privileged command handlers?
    //
    // WebView2 exposes window.chrome.webview.postMessage to EVERY page, including hostile websites and cross-origin
    // iframes. The browser's own pages (settings, network, passwords, tools, ...) use the same channel to send
    // commands such as "site-perm:evil.com:Camera:allow", "cert-trust:...", "cookies-clear-all", "update-apply",
    // "net-forget:...". If the host accepted those from any page, a website could grant itself permissions, trust
    // its own bad certificate, or drive the updater. Rule: commands are accepted ONLY from a tab that is showing one
    // of the browser's own internal pages AND whose message did not originate from a web (http/https/file/ftp/ws)
    // document. Web content may only send keyboard shortcuts, which go through a separate allowlist.
    internal static class MessageGate
    {
        public static bool IsWebSource(string? source)
        {
            var s = (source ?? "").Trim();
            if (s.Length == 0) return false;   // internal pages loaded with NavigateToString may report an empty or about:/data: source
            return s.StartsWith("http:", StringComparison.OrdinalIgnoreCase) || s.StartsWith("https:", StringComparison.OrdinalIgnoreCase) ||
                   s.StartsWith("file:", StringComparison.OrdinalIgnoreCase) || s.StartsWith("ftp:", StringComparison.OrdinalIgnoreCase) ||
                   s.StartsWith("ws:", StringComparison.OrdinalIgnoreCase) || s.StartsWith("wss:", StringComparison.OrdinalIgnoreCase) ||
                   s.StartsWith("blob:", StringComparison.OrdinalIgnoreCase) || s.StartsWith("filesystem:", StringComparison.OrdinalIgnoreCase);
        }

        public static MessageVerdict Classify(bool tabIsInternal, string? source, string? message)
        {
            if (string.IsNullOrEmpty(message)) return MessageVerdict.Deny;
            if (message.StartsWith("sc:", StringComparison.Ordinal)) return MessageVerdict.Shortcut;   // allowlisted separately, callable from any page
            return tabIsInternal && !IsWebSource(source) ? MessageVerdict.Command : MessageVerdict.Deny;
        }

        // Shortcuts that create or close tabs are rate-limited when they come from web content, so a page cannot spam them.
        public static bool IsTabShortcut(string name) => name == "newtab" || name == "newprivate" || name == "closetab";
    }

    internal enum DownloadRisk { None, Executable, DeceptiveName }

    // Drive-by download protection: a download that could run code (or that disguises its real type) needs an explicit yes.
    internal static class DownloadRules
    {
        private static readonly string[] Executable =
        {
            ".exe", ".msi", ".msix", ".msixbundle", ".appx", ".appxbundle", ".bat", ".cmd", ".com", ".scr", ".pif", ".cpl", ".msc", ".msp", ".mst", ".gadget",
            ".ps1", ".psm1", ".psd1", ".ps1xml", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".jar", ".reg", ".lnk", ".url", ".dll", ".sys", ".inf", ".application", ".settingcontent-ms", ".iso", ".img", ".vhd", ".vhdx"
        };

        public static DownloadRisk Assess(string? fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName)) return DownloadRisk.None;
            // right-to-left override and similar characters are used to make "txt.exe" look like "exe.txt"
            if (fileName.Any(c => c == '‮' || c == '‭' || c == '‫' || c == '‪' || c == '⁦' || c == '⁧' || c == '⁨' || c == '‎' || c == '‏')) return DownloadRisk.DeceptiveName;
            // Windows ignores trailing dots and spaces, so "setup.exe. " is still setup.exe
            var name = fileName.TrimEnd(' ', '.', '\t');
            var ext = System.IO.Path.GetExtension(name).ToLowerInvariant();
            return Array.IndexOf(Executable, ext) >= 0 ? DownloadRisk.Executable : DownloadRisk.None;
        }
    }
}
