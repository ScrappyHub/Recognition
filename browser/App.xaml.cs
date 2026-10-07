using System;
using System.Collections.Concurrent;
using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace Recognition.Browser
{
    // Start-up: a light splash while the engine and the locked-start checks run, one running copy per install (a second launch hands
    // its address to the first and exits), and the addresses Windows passes when Recognition is your default browser.
    public partial class App : Application
    {
        // Addresses to open once the first tab exists. Filled from the command line and from the second-launch messages.
        internal static readonly ConcurrentQueue<string> PendingUrls = new();

        private Mutex? _mutex;
        private CancellationTokenSource? _cts;
        private Window? _splash;

        protected override void OnStartup(StartupEventArgs e)
        {
            var url = LaunchArgs.FromArgs(e.Args, File.Exists);
            var id = InstanceId();
            try { _mutex = new Mutex(true, "Local\\RecognitionBrowser_" + id, out bool first); if (!first) { SendToRunning(id, url ?? ""); Shutdown(); return; } }
            catch { /* no mutex: run anyway, never block the browser from starting */ }

            if (url != null) PendingUrls.Enqueue(url);
            ShowSplash();
            base.OnStartup(e);
            _cts = new CancellationTokenSource();
            _ = Task.Run(() => PipeLoop(id, _cts.Token));
        }

        protected override void OnExit(ExitEventArgs e)
        {
            try { _cts?.Cancel(); } catch { }
            try { _mutex?.ReleaseMutex(); } catch { }
            base.OnExit(e);
        }

        // one id per install location, so a development build and the installed one do not hand addresses to each other
        private static string InstanceId()
        {
            var b = SHA256.HashData(Encoding.UTF8.GetBytes(AppContext.BaseDirectory.ToLowerInvariant()));
            return Convert.ToHexString(b, 0, 8).ToLowerInvariant();
        }

        private static void SendToRunning(string id, string text)
        {
            try
            {
                using var c = new NamedPipeClientStream(".", "RecognitionBrowser_" + id, PipeDirection.Out, PipeOptions.CurrentUserOnly);
                c.Connect(4000);
                var bytes = Encoding.UTF8.GetBytes(text.Length > LaunchArgs.MaxLen ? "" : text);
                c.Write(bytes, 0, bytes.Length);
                c.Flush();
            }
            catch { }
        }

        private async Task PipeLoop(string id, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    // only this Windows user can connect; whatever arrives is validated again by LaunchArgs.Parse
                    using var s = new NamedPipeServerStream("RecognitionBrowser_" + id, PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.CurrentUserOnly | PipeOptions.Asynchronous);
                    await s.WaitForConnectionAsync(ct);
                    using var rd = CancellationTokenSource.CreateLinkedTokenSource(ct); rd.CancelAfter(TimeSpan.FromSeconds(3));
                    var buf = new byte[LaunchArgs.MaxLen * 3 + 8]; int total = 0;
                    while (total < buf.Length) { int n = await s.ReadAsync(buf.AsMemory(total), rd.Token); if (n == 0) break; total += n; }
                    var text = total >= buf.Length ? "" : Encoding.UTF8.GetString(buf, 0, total).Trim();
                    var url = text.Length == 0 ? "" : LaunchArgs.Parse(text, File.Exists);
                    if (url != null) _ = Dispatcher.BeginInvoke(new Action(() => { FindMain()?.OpenFromOutside(url); }));
                }
                catch (OperationCanceledException) { if (ct.IsCancellationRequested) break; }
                catch { try { await Task.Delay(300, ct); } catch { break; } }
            }
        }

        // The splash is the first window created, so Application.MainWindow points at it; look the real window up instead.
        private static global::Recognition.Browser.MainWindow? FindMain()
        {
            foreach (Window w in Current.Windows) if (w is global::Recognition.Browser.MainWindow m) return m;
            return null;
        }

        // ---- splash ------------------------------------------------------------------------------------------------------------
        private void ShowSplash()
        {
            try
            {
                var title = new TextBlock { Text = "Recognition", FontSize = 30, FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush(Color.FromRgb(0xE8, 0xEA, 0xEE)), HorizontalAlignment = HorizontalAlignment.Center, FontFamily = new FontFamily("Segoe UI Variable Display, Segoe UI") };
                var sub = new TextBlock { Text = "Governed browser  ·  starting", FontSize = 12, Foreground = new SolidColorBrush(Color.FromRgb(0x7F, 0x87, 0x94)), HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 6, 0, 22), FontFamily = new FontFamily("Segoe UI") };
                var bar = new ProgressBar { IsIndeterminate = true, Height = 3, Width = 180, Background = new SolidColorBrush(Color.FromRgb(0x24, 0x28, 0x31)), Foreground = new SolidColorBrush(Color.FromRgb(0x4C, 0x9B, 0xF0)), BorderThickness = new Thickness(0) };
                var panel = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
                panel.Children.Add(title); panel.Children.Add(sub); panel.Children.Add(bar);
                _splash = new Window
                {
                    WindowStyle = WindowStyle.None, ResizeMode = ResizeMode.NoResize, ShowInTaskbar = false, Topmost = true,
                    Width = 420, Height = 220, WindowStartupLocation = WindowStartupLocation.CenterScreen,
                    Background = new SolidColorBrush(Color.FromRgb(0x11, 0x13, 0x18)),
                    BorderBrush = new SolidColorBrush(Color.FromRgb(0x2A, 0x2E, 0x36)), BorderThickness = new Thickness(1),
                    Content = panel
                };
                _splash.Show();
                var t = new DispatcherTimer { Interval = TimeSpan.FromSeconds(20) };   // never leave it up if start-up stalls
                t.Tick += (_, __) => { t.Stop(); CloseSplash(); };
                t.Start();
            }
            catch { _splash = null; }
        }

        private void CloseSplash() { try { _splash?.Close(); } catch { } _splash = null; }
        internal static void HideSplash() { try { (Current as App)?.CloseSplash(); } catch { } }
    }
}
