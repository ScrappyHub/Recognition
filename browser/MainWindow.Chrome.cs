using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace Recognition.Browser
{
    // Window frame polish. The title bar is drawn by Windows, so it ignored the browser's dark theme (a solid light bar above a dark
    // toolbar). Windows 10 (20H1+) and 11 let a program ask for a dark frame, and Windows 11 also lets it set the exact caption colour.
    // Both are best effort: an older Windows simply keeps its normal title bar. Nothing here can fail startup.
    public partial class MainWindow
    {
        private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20, DWMWA_BORDER_COLOR = 34, DWMWA_CAPTION_COLOR = 35, DWMWA_TEXT_COLOR = 36;

        [DllImport("dwmapi.dll", PreserveSig = true)]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            try
            {
                var h = new WindowInteropHelper(this).Handle;
                if (h == IntPtr.Zero) return;
                int on = 1;
                DwmSetWindowAttribute(h, DWMWA_USE_IMMERSIVE_DARK_MODE, ref on, sizeof(int));
                int caption = Colorref(0x1B, 0x1E, 0x24), text = Colorref(0xD6, 0xDA, 0xE2), border = Colorref(0x2A, 0x2E, 0x36);   // same as the toolbar
                DwmSetWindowAttribute(h, DWMWA_CAPTION_COLOR, ref caption, sizeof(int));
                DwmSetWindowAttribute(h, DWMWA_TEXT_COLOR, ref text, sizeof(int));
                DwmSetWindowAttribute(h, DWMWA_BORDER_COLOR, ref border, sizeof(int));
            }
            catch { }
        }

        private static int Colorref(int r, int g, int b) => r | (g << 8) | (b << 16);   // COLORREF is 0x00BBGGRR
    }
}
