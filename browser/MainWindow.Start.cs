using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Windows;
using System.Windows.Media.Imaging;

namespace Recognition.Browser
{
    // The home page, the start page background, and the "is a VPN app running" hint. The rules are in StartBackground.cs and VpnDetect.cs
    // (executed by tests). The background image is read once from a file you pick, shrunk, and kept as runtime\start_bg.jpg; the start page
    // embeds it, so it makes no web requests.
    public partial class MainWindow
    {
        private string _startBg = "default";                 // persisted as start_bg in browser_settings.json
        private string? _startImageUrl;                      // cached data: URL of runtime\start_bg.jpg
        private VpnFound? _sysVpn;
        private bool _sysVpnHooked;

        private string StartImagePath() => Path.Combine(_repoRoot, "runtime", "start_bg.jpg");

        private string? StartImageDataUrl()
        {
            if (_startImageUrl != null) return _startImageUrl;
            try
            {
                var p = StartImagePath();
                if (!File.Exists(p)) return null;
                var fi = new FileInfo(p); if (fi.Length > 2_000_000) return null;
                _startImageUrl = "data:image/jpeg;base64," + Convert.ToBase64String(File.ReadAllBytes(p));
            }
            catch { _startImageUrl = null; }
            return _startImageUrl;
        }

        private string StartBackgroundCss() => StartBackground.Css(_startBg, _startBg == "image" ? StartImageDataUrl() : null);

        // ---- VPN app hint --------------------------------------------------------------------------------------------------
        private void RefreshSysVpn()
        {
            try
            {
                _sysVpn = VpnDetect.Find(NetworkInterface.GetAllNetworkInterfaces()
                    .Select(n => new AdapterInfo(n.Name, n.Description, n.NetworkInterfaceType.ToString(), n.OperationalStatus == OperationalStatus.Up)).ToList());
            }
            catch { _sysVpn = null; }
            if (!_sysVpnHooked)
            {
                _sysVpnHooked = true;
                try { NetworkChange.NetworkAddressChanged += (_, __) => Dispatcher.BeginInvoke(new Action(() => { RefreshSysVpn(); UpdateVpn(); })); } catch { }
            }
        }

        // ---- settings rows -------------------------------------------------------------------------------------------------
        private string StartSettingsHtml()
        {
            var sb = new StringBuilder();
            sb.Append("<h1 style='font-size:16px'>Home page and start page</h1>");
            var home = _homeUrl == StartBackground.StartPage ? "the Recognition start page" : Esc(_homeUrl);
            sb.Append("<div class='row'><div><div class='t'>Home page</div><div class='u'>New tabs and the Home button open: " + home + ". Type a site such as example.com, or use the start page.</div></div>" +
                      "<div class='ts'><input id='hm' placeholder='example.com' style='width:190px;background:#0e1015;color:#e8e8e8;border:1px solid #333844;border-radius:6px;padding:6px'> " +
                      "<a class='btn' onclick=\"send('home-set:'+encodeURIComponent(document.getElementById('hm').value))\">Set</a> " +
                      "<a class='btn ghost' onclick=\"send('home-set:recognition%3Astart')\">Use start page</a></div></div>");
            var cur = _startBg == "image" ? "your picture" : (_startBg.StartsWith("#") ? "colour " + Esc(_startBg) : _startBg);
            sb.Append("<div class='row'><div><div class='t'>Start page background</div><div class='u'>Now: " + cur + ". The start page is what new tabs show when your home page is the start page. A picture is shrunk and kept on this computer only.</div></div><div class='ts'>");
            foreach (var p in StartBackground.Presets) sb.Append("<a class='btn ghost' onclick=\"send('bg-set:" + p + "')\">" + (p == "default" ? "Default" : char.ToUpperInvariant(p[0]) + p.Substring(1)) + "</a> ");
            sb.Append("<input type='color' id='bgc' value='#1b1f27' style='vertical-align:middle;height:30px;width:42px;background:none;border:0'> <a class='btn ghost' onclick=\"send('bg-set:'+document.getElementById('bgc').value)\">Use colour</a> ");
            sb.Append("<a class='btn' onclick=\"send('bg-image')\">Choose a picture...</a>");
            if (File.Exists(StartImagePath())) sb.Append(" <a class='btn ghost' onclick=\"send('bg-clear')\">Remove picture</a>");
            sb.Append("</div></div>");
            return sb.ToString();
        }

        private void ReloadStartTabs()
        {
            foreach (var t in _tabs.Where(x => x.Internal == "start" && !x.Private && x.Ready).ToList()) LoadInternal(t, "start");
        }

        private void HandleStartPageMessage(BrowserTab from, string msg)
        {
            try
            {
                if (msg.StartsWith("home-set:", StringComparison.Ordinal))
                {
                    string raw; try { raw = Uri.UnescapeDataString(msg.Substring("home-set:".Length)); } catch { raw = ""; }
                    var h = StartBackground.HomeUrl(raw, File.Exists);
                    if (h == null) { Status("that is not a web address I can use as a home page"); return; }
                    _homeUrl = h; SaveSettings(); _actions?.Append("home.set", h == StartBackground.StartPage ? "start" : "custom");
                    Status("home page: " + (h == StartBackground.StartPage ? "the start page" : h));
                }
                else if (msg.StartsWith("bg-set:", StringComparison.Ordinal))
                {
                    var k = StartBackground.Normalize(msg.Substring("bg-set:".Length));
                    if (k == "image" && StartImageDataUrl() == null) { Status("no picture is saved yet; choose one first"); return; }
                    _startBg = k; SaveSettings(); Status("start page background: " + (k == "image" ? "your picture" : k));
                }
                else if (msg == "bg-clear")
                {
                    try { File.Delete(StartImagePath()); } catch { }
                    _startImageUrl = null; if (_startBg == "image") _startBg = "default";
                    SaveSettings(); Status("picture removed");
                }
                else if (msg == "bg-image")
                {
                    var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Choose a start page picture", Filter = "Pictures (*.jpg;*.jpeg;*.png;*.bmp;*.gif;*.tif;*.tiff)|*.jpg;*.jpeg;*.png;*.bmp;*.gif;*.tif;*.tiff" };
                    if (dlg.ShowDialog(this) != true) return;
                    var err = ImportStartPicture(dlg.FileName);
                    if (err != null) { Status(err); return; }
                    _startImageUrl = null; _startBg = "image"; SaveSettings(); Status("start page picture saved");
                }
                else return;
                ReloadStartTabs();
                if (from.Internal == "settings") LoadInternal(from, "settings");
            }
            catch (Exception ex) { Status("start page setting failed: " + ex.Message); }
        }

        // Reads a picture, shrinks it to at most 1920 pixels wide, and keeps a JPEG of at most about 1.3 MB.
        private string? ImportStartPicture(string path)
        {
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists || fi.Length > 40_000_000) return "that picture is missing or larger than 40 MB";
                int origW;
                using (var s = File.OpenRead(path)) origW = BitmapFrame.Create(s, BitmapCreateOptions.DelayCreation, BitmapCacheOption.None).PixelWidth;
                byte[]? best = null;
                foreach (var (w, q) in new[] { (1920, 84), (1920, 66), (1440, 60), (1024, 55) })
                {
                    var bi = new BitmapImage();
                    bi.BeginInit(); bi.CacheOption = BitmapCacheOption.OnLoad; bi.UriSource = new Uri(path);
                    if (origW > w) bi.DecodePixelWidth = w;
                    bi.EndInit(); bi.Freeze();
                    var enc = new JpegBitmapEncoder { QualityLevel = q };
                    enc.Frames.Add(BitmapFrame.Create(bi));
                    using var ms = new MemoryStream(); enc.Save(ms);
                    best = ms.ToArray();
                    if (best.Length <= 1_300_000) break;
                }
                if (best == null || best.Length > 1_600_000) return "that picture is too detailed to keep; choose a smaller one";
                Directory.CreateDirectory(Path.GetDirectoryName(StartImagePath())!);
                File.WriteAllBytes(StartImagePath(), best);
                return null;
            }
            catch { return "could not read that picture (JPEG, PNG, BMP, GIF and TIFF work)"; }
        }
    }
}
