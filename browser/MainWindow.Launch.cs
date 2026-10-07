using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;

namespace Recognition.Browser
{
    // Addresses that arrive from outside (command line, a second launch, Windows when Recognition is the default browser), and the
    // "make Recognition my default browser" shortcut. The address rules are in LaunchArgs.cs (executed by tests).
    public partial class MainWindow
    {
        private bool _startupDone;

        // Called on the UI thread with an address LaunchArgs already accepted (or "" to just bring the window forward).
        internal async void OpenFromOutside(string url)
        {
            try
            {
                if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
                Activate();
                if (url.Length == 0) return;
                if (!_startupDone) { App.PendingUrls.Enqueue(url); return; }
                if (!_preflightOk) { Status("locked: not opening an address from outside"); return; }
                var t = await NewTabCoreAsync("New tab");
                if (t == null) return;
                Tabs.SelectedItem = t.Item; ShowActiveWebView(); NavigateTab(t, url);
                _actions?.Append("launch.open", "external");   // the address itself is not recorded
            }
            catch { }
        }

        // After the first tab exists: open what the command line or an early second launch asked for. The first address replaces the
        // blank start page; later ones get their own tabs.
        private async Task DrainOutsideUrlsAsync()
        {
            bool first = true;
            while (App.PendingUrls.TryDequeue(out var url))
            {
                if (first && Active != null && Active.Internal == "start") { NavigateTab(Active, url); first = false; _actions?.Append("launch.open", "external"); continue; }
                first = false;
                var t = await NewTabCoreAsync("New tab");
                if (t == null) continue;
                Tabs.SelectedItem = t.Item; ShowActiveWebView(); NavigateTab(t, url);
                _actions?.Append("launch.open", "external");
            }
        }

        // Windows does not let a program make itself the default browser; the person chooses it in Windows settings. This opens the
        // right page (a fixed settings address, only on click).
        private void OpenDefaultAppsSettings()
        {
            try { Process.Start(new ProcessStartInfo("ms-settings:defaultapps") { UseShellExecute = true }); }
            catch (Exception ex) { Status("could not open Windows settings: " + ex.Message); }
        }

        private static string DefaultBrowserHtmlRow() =>
            "<div class='row'><div><div class='t'>Default browser</div><div class='u'>Make Recognition open web links from other programs. Windows asks you to choose it in Default apps (it cannot be set silently). Needs the installed copy.</div></div>" +
            "<div class='ts'><a class='btn' onclick=\"send('default-browser')\">Open Windows Default apps</a></div></div>";
    }
}
