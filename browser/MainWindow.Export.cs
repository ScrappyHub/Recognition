using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;

namespace Recognition.Browser
{
    // "Export Session" used to end in a message box with a path. The result is now a page that says what was exported, shows the
    // packet's fingerprint as a short code and a QR (the QR carries only the fingerprint, never the session), and can copy it or open
    // the folder. The packet itself is written by the existing governed export script.
    public partial class MainWindow
    {
        private sealed class ExportSummary
        {
            public bool Ok; public string PacketDir = "", Error = ""; public DateTime Utc;
            public int Tabs, Visits, Blocked; public bool ActionsOk, CookiesOk, PolicyOk;
        }
        private ExportSummary? _lastExport;

        private async Task FinishExportAsync(string script, ExportSummary s)
        {
            string outp = "", err = "";
            try
            {
                var root = _repoRoot;
                (outp, err) = await Task.Run(() =>
                {
                    var psi = new ProcessStartInfo("powershell.exe", $"-NoProfile -ExecutionPolicy Bypass -File \"{script}\" -RepoRoot \"{root}\"")
                    { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
                    using var p = Process.Start(psi)!;
                    var o = p.StandardOutput.ReadToEndAsync(); var e2 = p.StandardError.ReadToEndAsync();
                    if (!p.WaitForExit(120000)) { try { p.Kill(true); } catch { } return ("", "the export took longer than two minutes and was stopped"); }
                    return (o.Result, e2.Result);
                });
            }
            catch (Exception ex) { err = ex.Message; }

            var m = Regex.Match(outp, @"EXPORT_OK:\s*(?<d>.+)");
            if (m.Success)
            {
                s.Ok = true; s.PacketDir = m.Groups["d"].Value.Trim();
                _actions?.Append("session.export", s.PacketDir);
                Status("Exported governed packet: " + Path.GetFileName(s.PacketDir));
            }
            else
            {
                s.Ok = false; var e = (err.Length > 0 ? err : outp).Trim();
                s.Error = e.Length > 1500 ? e.Substring(0, 1500) : e;
                Status("Export failed");
            }
            _lastExport = s;
            OpenInternalInActiveTab("export");
        }

        // The packet folder name is its SHA-256. Anything else is shown without a code or QR.
        private static string PacketId(string dir)
        {
            var n = Path.GetFileName((dir ?? "").TrimEnd('\\', '/'));
            return Regex.IsMatch(n, "^[0-9a-f]{64}$") ? n : "";
        }

        private static string ShortCode(string id) =>
            id.Length < 16 ? "" : string.Join("-", id.Substring(0, 4), id.Substring(4, 4), id.Substring(8, 4), id.Substring(12, 4)).ToUpperInvariant();

        private bool PacketDirIsOurs(string dir)
        {
            try
            {
                var packets = Path.GetFullPath(Path.Combine(_repoRoot, "packets")).TrimEnd('\\') + "\\";
                var full = Path.GetFullPath(dir);
                return full.StartsWith(packets, StringComparison.OrdinalIgnoreCase) && Directory.Exists(full);
            }
            catch { return false; }
        }

        private void HandleExportMessage(string msg)
        {
            try
            {
                var s = _lastExport; if (s == null) return;
                var id = PacketId(s.PacketDir);
                string? text = msg switch
                {
                    "exp-copy-code" => ShortCode(id),
                    "exp-copy-id" => id,
                    "exp-copy-path" => s.PacketDir,
                    _ => null
                };
                if (text != null)
                {
                    if (text.Length == 0) { Status("nothing to copy"); return; }
                    try { Clipboard.SetText(text); Status("copied"); } catch { Status("the clipboard is busy; try again"); }
                    return;
                }
                if (msg == "exp-open") { if (s.Ok && PacketDirIsOurs(s.PacketDir)) OpenFolder(s.PacketDir); else Status("the packet folder is not available"); return; }
                if (msg == "exp-again") { Export_Click(this, new RoutedEventArgs()); return; }
            }
            catch (Exception ex) { Status("export page error: " + ex.Message); }
        }

        private string ExportHtml()
        {
            var s = _lastExport;
            var sb = new StringBuilder(PageHead);
            sb.Append("<title>Session exported</title>");
            if (s == null)
            {
                sb.Append("<h1>Export session</h1><div class='muted'>Nothing has been exported in this run yet.</div><div style='margin:10px 0'><a class='btn' onclick=\"send('exp-again')\">Export this session</a></div>");
                sb.Append(SendScript()).Append(PageFoot); return sb.ToString();
            }
            if (!s.Ok)
            {
                sb.Append("<h1>Export failed</h1><div class='muted'>The session could not be written as a governed packet. Nothing was changed.</div>");
                sb.Append("<pre style='white-space:pre-wrap;color:#e0a0a0;background:#1b1416;padding:10px;border-radius:8px'>" + Esc(s.Error) + "</pre>");
                sb.Append("<div style='margin:10px 0'><a class='btn' onclick=\"send('exp-again')\">Try again</a></div>");
                sb.Append(SendScript()).Append(PageFoot); return sb.ToString();
            }

            var id = PacketId(s.PacketDir); var code = ShortCode(id);
            sb.Append("<h1>Session exported</h1><div class='muted'>A governed evidence packet was written on this computer. It lists your tabs and visits as hashes (not the addresses), the blocked counts, and the state of the browser's evidence chains. Private tabs leave no trace in it.</div>");
            if (id.Length == 64)
            {
                string qr = "";
                try
                {
                    var grid = QrCode.Encode("recognition:packet:v1:" + id, out _, out _); int n = grid.GetLength(0) + 8;
                    qr = "<svg viewBox='0 0 " + n + " " + n + "' width='200' height='200' xmlns='http://www.w3.org/2000/svg' shape-rendering='crispEdges'><rect width='" + n + "' height='" + n + "' fill='#fff'/><path d='" + QrCode.ToSvgPath(grid) + "' fill='#000'/></svg>";
                }
                catch { }
                sb.Append("<div style='display:flex;gap:26px;flex-wrap:wrap;align-items:center;margin:18px 0'>");
                if (qr.Length > 0) sb.Append("<div style='background:#fff;border-radius:12px;padding:6px'>" + qr + "</div>");
                sb.Append("<div><div class='u'>Packet code</div><div style='font:600 30px Consolas,monospace;letter-spacing:2px;margin:4px 0 10px'>" + Esc(code) + "</div>");
                sb.Append("<div class='u' style='max-width:430px'>The code is the first part of the packet's fingerprint, and the QR holds the whole fingerprint (a SHA-256). Scan or read it to check that another copy of this packet is the same one. The QR does not contain your session; the packet stays in the folder below.</div>");
                sb.Append("<div style='display:flex;gap:8px;flex-wrap:wrap;margin-top:12px'><a class='btn' onclick=\"send('exp-copy-code')\">Copy code</a><a class='btn ghost' onclick=\"send('exp-copy-id')\">Copy full fingerprint</a></div></div></div>");
                sb.Append("<div class='kv'><div class='k'>Fingerprint</div><div class='v' style='font-family:Consolas,monospace;word-break:break-all'>" + Esc(id) + "</div></div>");
            }
            sb.Append("<div class='kv'><div class='k'>Folder</div><div class='v' style='word-break:break-all'>" + Esc(s.PacketDir) + "</div></div>");
            sb.Append("<div class='kv'><div class='k'>Contents</div><div class='v'>" + s.Tabs + " tab(s), " + s.Visits + " visit(s), " + s.Blocked + " blocked this session</div></div>");
            sb.Append("<div class='kv'><div class='k'>Evidence chains</div><div class='v'>actions " + (s.ActionsOk ? "verified" : "<b style='color:#e57373'>NOT verified</b>") + " &middot; cookies " + (s.CookiesOk ? "verified" : "<b style='color:#e57373'>NOT verified</b>") + " &middot; site rules " + (s.PolicyOk ? "verified" : "<b style='color:#e57373'>NOT verified</b>") + "</div></div>");
            sb.Append("<div style='display:flex;gap:8px;flex-wrap:wrap;margin:16px 0'><a class='btn' onclick=\"send('exp-open')\">Open folder</a><a class='btn ghost' onclick=\"send('exp-copy-path')\">Copy folder path</a><a class='btn ghost' onclick=\"send('exp-again')\">Export again</a></div>");
            sb.Append(SendScript()).Append(PageFoot);
            return sb.ToString();
        }
    }
}
