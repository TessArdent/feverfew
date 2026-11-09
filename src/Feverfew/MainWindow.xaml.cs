using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;

namespace Feverfew
{
    public partial class MainWindow : Window
    {
        private const int DwmUseDarkMode = 20;
        private const int DwmBackdropType = 38;
        private const int BackdropMica = 2;
        private const int FirstBuildWithBackdrop = 22621;
        private const double MaximizedInset = 8;

        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr window, int attribute, ref int value, int size);

        private readonly ScanOptions options;
        private readonly bool limited;
        private ScanResult result;
        private TaskCompletionSource<bool> question;
        private readonly System.Collections.Generic.List<System.Collections.Generic.KeyValuePair<Fix, TextBlock>> statusLines = new System.Collections.Generic.List<System.Collections.Generic.KeyValuePair<Fix, TextBlock>>();
        private bool tipsLoaded;

        public MainWindow(ScanOptions options, bool limited)
        {
            this.options = options;
            this.limited = limited;
            InitializeComponent();

            var version = Updater.CurrentVersion().ToString();
            TitleVersion.Text = version;
            VersionText.Text = "Feverfew " + version;
            Identifiers.IsChecked = options.IncludeIdentifiers;
            AccessText.Text = limited ? "Limited" : "Administrator";
            AccessText.Foreground = (Brush)FindResource(limited ? "WarningText" : "Accent");
            AccessDetail.Text = limited ? "Some checks will be skipped" : "Full scan available";
            LimitedBar.Visibility = limited ? Visibility.Visible : Visibility.Collapsed;

            foreach (var fix in Fixes.All) RepairList.Children.Add(BuildFixRow(fix, RepairStatus, "Run"));
            foreach (var fix in Fixes.Gaming) GamingList.Children.Add(BuildFixRow(fix, GamingStatus, "Apply"));
            SourceInitialized += (s, e) => ApplyBackdrop();
            StateChanged += (s, e) => Root.Margin = new Thickness(WindowState == WindowState.Maximized ? MaximizedInset : 0);
            Closed += (s, e) => Environment.Exit(0); // an abandoned scan step may still be running on a background thread
        }

        // Mica needs Windows 11 22H2 or later. Older versions keep the solid dark background.
        private void ApplyBackdrop()
        {
            var handle = new WindowInteropHelper(this).Handle;
            int on = 1;
            DwmSetWindowAttribute(handle, DwmUseDarkMode, ref on, sizeof(int));
            if (Environment.OSVersion.Version.Build < FirstBuildWithBackdrop) return;

            int mica = BackdropMica;
            if (DwmSetWindowAttribute(handle, DwmBackdropType, ref mica, sizeof(int)) != 0) return;
            Background = Brushes.Transparent;
            HwndSource.FromHwnd(handle).CompositionTarget.BackgroundColor = Colors.Transparent;
        }

        private void Nav_Checked(object sender, RoutedEventArgs e)
        {
            if (ScanPage == null) return; // fires during startup, before the pages exist
            ScanPage.Visibility = sender == NavScan ? Visibility.Visible : Visibility.Collapsed;
            RepairPage.Visibility = sender == NavRepair ? Visibility.Visible : Visibility.Collapsed;
            GamingPage.Visibility = sender == NavGaming ? Visibility.Visible : Visibility.Collapsed;
            UpdatesPage.Visibility = sender == NavUpdates ? Visibility.Visible : Visibility.Collapsed;
            if (sender == NavGaming) RefreshGamingPage();
        }

        // Re-read on every visit, so a change made in an administrator window shows when the user comes back.
        private async void RefreshGamingPage()
        {
            foreach (var pair in statusLines)
            {
                var fix = pair.Key;
                var line = pair.Value;
                line.Text = await Task.Run(() =>
                {
                    try { return fix.Status(); }
                    catch (Exception) { return "Couldn't read the current setting"; }
                });
            }

            if (tipsLoaded) return;
            tipsLoaded = true;
            try
            {
                var tips = await Task.Run(() => Collectors.GamingCollector.TipsForThisPc());
                foreach (var tip in tips)
                {
                    var text = new StackPanel();
                    text.Children.Add(new TextBlock { Text = tip.Name, Style = (Style)FindResource("CardTitle") });
                    text.Children.Add(new TextBlock { Text = tip.Text, Style = (Style)FindResource("Caption"), Margin = new Thickness(0, 2, 0, 0) });
                    GraphicsTipsList.Children.Add(new Border { Style = (Style)FindResource("Card"), Margin = new Thickness(0, 0, 0, 8), Child = text });
                }
                GraphicsTipsPanel.Visibility = tips.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            }
            catch (Exception) { /* the tips are optional, so the page works without them */ }
        }

        private void RestartElevated_Click(object sender, RoutedEventArgs e)
        {
            options.IncludeIdentifiers = Identifiers.IsChecked == true;
            if (Program.RelaunchElevated(options)) Close();
        }

        private async void Run_Click(object sender, RoutedEventArgs e)
        {
            options.IncludeIdentifiers = Identifiers.IsChecked == true;
            RunButton.IsEnabled = false;
            UpdateButton.IsEnabled = false;
            Identifiers.IsEnabled = false;
            ResultsPanel.Visibility = Visibility.Collapsed;
            ProgressPanel.Visibility = Visibility.Visible;
            Progress.Value = 0;

            Action<int, string> report = (percent, step) => Dispatcher.BeginInvoke((Action)(() =>
            {
                Progress.Value = percent;
                StatusText.Text = step + "...";
            }));

            try
            {
                ShowResult(await Task.Run(() => Scanner.Run(options, report)));
            }
            catch (Exception ex)
            {
                StatusText.Text = "The report couldn't be saved: " + ex.Message;
            }
            RunButton.Content = "Run again";
            RunButton.IsEnabled = true;
            UpdateButton.IsEnabled = true;
            Identifiers.IsEnabled = true;
        }

        public void ShowResult(ScanResult scan)
        {
            result = scan;
            var findings = scan.Report.Findings;
            Progress.Value = 100;
            ProgressPanel.Visibility = Visibility.Visible;
            StatusText.Text = "Saved to " + scan.HtmlPath;
            CriticalCount.Text = findings.Count(f => f.Severity == Severity.Critical).ToString();
            WarningCount.Text = findings.Count(f => f.Severity == Severity.Warning).ToString();
            InfoCount.Text = findings.Count(f => f.Severity == Severity.Info).ToString();
            ScanKind.Text = scan.Report.Elevated ? "Full" : "Limited";

            FindingsList.Children.Clear();
            foreach (var finding in findings) FindingsList.Children.Add(BuildFinding(finding));

            GlanceGrid.Children.Clear();
            GlanceGrid.RowDefinitions.Clear();
            foreach (var fact in scan.Report.Summary)
            {
                int row = GlanceGrid.RowDefinitions.Count;
                GlanceGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                AddToGrid(GlanceGrid, new TextBlock { Text = fact.Name, Style = (Style)FindResource("Secondary"), Margin = new Thickness(0, 2, 12, 2) }, row, 0);
                AddToGrid(GlanceGrid, new TextBlock { Text = fact.Value, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 2) }, row, 1);
            }
            ResultsPanel.Visibility = Visibility.Visible;
        }

        private static void AddToGrid(Grid grid, UIElement element, int row, int column)
        {
            Grid.SetRow(element, row);
            Grid.SetColumn(element, column);
            grid.Children.Add(element);
        }

        private Border BuildFinding(Finding finding)
        {
            string glyph, brush;
            switch (finding.Severity)
            {
                case Severity.Critical: glyph = ""; brush = "CriticalText"; break;
                case Severity.Warning: glyph = ""; brush = "WarningText"; break;
                case Severity.Good: glyph = ""; brush = "Accent"; break;
                default: glyph = ""; brush = "InfoText"; break;
            }

            var text = new StackPanel();
            text.Children.Add(new TextBlock { Text = finding.Title, Style = (Style)FindResource("CardTitle") });
            if (!string.IsNullOrEmpty(finding.Detail))
                text.Children.Add(new TextBlock { Text = finding.Detail, Style = (Style)FindResource("Secondary"), Margin = new Thickness(0, 3, 0, 0) });
            if (!string.IsNullOrEmpty(finding.Advice))
                text.Children.Add(new TextBlock { Text = "Try: " + finding.Advice, Style = (Style)FindResource("Caption"), Margin = new Thickness(0, 6, 0, 0) });

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(32) });
            grid.ColumnDefinitions.Add(new ColumnDefinition());
            AddToGrid(grid, new TextBlock { Text = glyph, Style = (Style)FindResource("Icon"), Foreground = (Brush)FindResource(brush), Margin = new Thickness(0, 2, 0, 0) }, 0, 0);
            AddToGrid(grid, text, 0, 1);
            return new Border { Style = (Style)FindResource("Card"), Margin = new Thickness(0, 0, 0, 8), Child = grid };
        }

        private Button BuildCommandButton(Fix fix, string command, string label, TextBlock status)
        {
            var button = new Button { Content = label, MinWidth = 72, Margin = new Thickness(8, 0, 0, 0) };
            button.Click += async (s, e) =>
            {
                if (fix.Caution != null && !await Ask(fix.Name, fix.Caution, label)) return;
                status.Text = Fixes.Run(command)
                    ? "Started: " + fix.Name + ". Read the result in its window, then close it."
                    : "Not started, because the Windows permission prompt was declined.";
            };
            return button;
        }

        private Border BuildFixRow(Fix fix, TextBlock status, string runLabel)
        {
            var text = new StackPanel { Margin = new Thickness(0, 0, 16, 0) };
            text.Children.Add(new TextBlock { Text = fix.Name, Style = (Style)FindResource("CardTitle") });
            text.Children.Add(new TextBlock { Text = fix.When, Style = (Style)FindResource("Caption"), Margin = new Thickness(0, 2, 0, 0) });
            if (fix.Status != null)
            {
                var line = new TextBlock { Text = "Checking...", Style = (Style)FindResource("Caption"), Foreground = (Brush)FindResource("Accent"), Margin = new Thickness(0, 4, 0, 0) };
                text.Children.Add(line);
                statusLines.Add(new System.Collections.Generic.KeyValuePair<Fix, TextBlock>(fix, line));
            }

            var buttons = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            if (fix.Undo != null) buttons.Children.Add(BuildCommandButton(fix, fix.Undo, "Undo", status));
            buttons.Children.Add(BuildCommandButton(fix, fix.Command, runLabel, status));

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition());
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            AddToGrid(grid, text, 0, 0);
            AddToGrid(grid, buttons, 0, 1);
            return new Border { Style = (Style)FindResource("Card"), Margin = new Thickness(0, 0, 0, 8), Child = grid };
        }

        private Task<bool> Ask(string title, string text, string confirm)
        {
            DialogTitle.Text = title;
            DialogText.Text = text;
            DialogYes.Content = confirm;
            DialogLayer.Visibility = Visibility.Visible;
            question = new TaskCompletionSource<bool>();
            return question.Task;
        }

        private void Answer(bool yes)
        {
            DialogLayer.Visibility = Visibility.Collapsed;
            question.TrySetResult(yes);
        }

        private void DialogYes_Click(object sender, RoutedEventArgs e) { Answer(true); }
        private void DialogNo_Click(object sender, RoutedEventArgs e) { Answer(false); }

        // Going through Explorer opens the browser as the normal user, not as administrator.
        private static void OpenUnelevated(string target) { Process.Start("explorer.exe", "\"" + target + "\""); }

        private void OpenReport_Click(object sender, RoutedEventArgs e) { OpenUnelevated(result.HtmlPath); }
        private void ShowFile_Click(object sender, RoutedEventArgs e) { Process.Start("explorer.exe", "/select,\"" + result.HtmlPath + "\""); }
        private void Repository_Click(object sender, RoutedEventArgs e) { OpenUnelevated("https://github.com/" + Updater.Repository); }

        private async void CheckUpdates_Click(object sender, RoutedEventArgs e)
        {
            RunButton.IsEnabled = false;
            UpdateButton.IsEnabled = false;
            UpdateStatus.Text = "Asking GitHub for the latest version...";
            try
            {
                var current = Updater.CurrentVersion();
                var info = await Task.Run(() => Updater.Check(current));
                if (!info.IsNewer)
                {
                    UpdateStatus.Text = "You have the latest version.";
                    return;
                }

                bool install = info.CanDownload && Updater.CanInstallInPlace();
                var message = "Feverfew " + info.Latest + " is available. You have " + current + ".";
                if (!await Ask("Update available", message, install ? "Download and install" : "Open download page"))
                {
                    UpdateStatus.Text = "Update skipped.";
                    return;
                }

                if (!install)
                {
                    OpenUnelevated(info.PageUrl);
                    UpdateStatus.Text = "The download page is open in your browser.";
                    return;
                }

                UpdateStatus.Text = "Downloading the update...";
                var setup = await Task.Run(() => Updater.Download(info));
                Process.Start(new ProcessStartInfo(setup) { UseShellExecute = true });
                Close();
            }
            catch (Exception ex)
            {
                UpdateStatus.Text = "Couldn't check for updates: " + ex.Message;
            }
            finally
            {
                RunButton.IsEnabled = true;
                UpdateButton.IsEnabled = true;
            }
        }
    }
}
