using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows;

namespace Feverfew
{
    public static class Program
    {
        [DllImport("kernel32.dll")]
        private static extern bool AttachConsole(int processId);

        private const string RelaunchedFlag = "--relaunched";

        private const string Usage = @"Feverfew: collects hardware and software diagnostics into one report.

  Feverfew.exe                     Open the window
  Feverfew.exe --cli               Scan without a window
    --out <folder>                 Where to save the report
    --include-identifiers          Keep serial numbers, names, MAC and public IP addresses
    --no-network                   Skip the ping and name lookup tests
  Feverfew.exe --check-update      Ask GitHub whether a newer version exists
  Feverfew.exe --help              Show this help

Without administrator rights the scan still runs, but skips TPM, BitLocker,
drive health counters and crash dumps.";

        public static string DefaultOutput()
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Feverfew Reports");
        }

        [STAThread]
        public static int Main(string[] args)
        {
            CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;
            Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture;

            var options = new ScanOptions
            {
                IncludeIdentifiers = args.Contains("--include-identifiers"),
                NetworkTests = !args.Contains("--no-network"),
                OutputDirectory = DefaultOutput()
            };
            var at = Array.IndexOf(args, "--out");
            if (at >= 0 && at + 1 < args.Length) options.OutputDirectory = args[at + 1];

            if (args.Contains("--check-update"))
            {
                AttachConsole(-1);
                return RunUpdateCheck();
            }

            if (args.Contains("--help") || args.Contains("-h") || args.Contains("/?") || args.Contains("--cli"))
            {
                AttachConsole(-1);
                if (!args.Contains("--cli")) { Console.WriteLine(Usage); return 0; }
                return RunCli(options);
            }

            // Ask for admin before showing anything. If it's declined, open anyway with a limited scan.
            bool elevated = Scanner.IsElevated();
            if (!elevated && !args.Contains(RelaunchedFlag) && RelaunchElevated(options)) return 0;

            new Application().Run(new MainWindow(options, !elevated));
            return 0;
        }

        private static int RunUpdateCheck()
        {
            try
            {
                var info = Updater.Check(Updater.CurrentVersion());
                Console.WriteLine(info.IsNewer ? "Feverfew " + info.Latest + " is available: " + info.PageUrl : "You have the latest version (" + info.Current + ").");
                return 0;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Couldn't check for updates: " + e.Message);
                return 1;
            }
        }

        private static int RunCli(ScanOptions options)
        {
            try
            {
                var result = Scanner.Run(options, (percent, step) => Console.WriteLine("[" + percent.ToString().PadLeft(3) + "%] " + step));
                Console.WriteLine(result.HtmlPath);
                Console.WriteLine(result.JsonPath);
                Environment.Exit(0); // an abandoned step may still be running on a background thread
                return 0;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Feverfew failed: " + e.Message);
                return 1;
            }
        }

        /// <summary>Restarts elevated. Returns false if the user declined the permission prompt.</summary>
        public static bool RelaunchElevated(ScanOptions options)
        {
            // --out keeps the report on this user's Desktop even if a different admin account approves the prompt.
            var arguments = RelaunchedFlag + " --out \"" + options.OutputDirectory.TrimEnd('\\') + "\"";
            if (options.IncludeIdentifiers) arguments += " --include-identifiers";
            if (!options.NetworkTests) arguments += " --no-network";
            try
            {
                Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, arguments) { UseShellExecute = true, Verb = "runas" });
                return true;
            }
            catch (Win32Exception e) when (e.NativeErrorCode == 1223)
            {
                return false; // ERROR_CANCELLED
            }
        }
    }
}
