using System.ComponentModel;
using System.Diagnostics;

namespace Feverfew
{
    public sealed class Fix
    {
        public string Name;
        public string When;
        public string Command;
        /// <summary>Set when the fix needs a restart or changes settings; the app asks first and shows this text.</summary>
        public string Caution;
    }

    public static class Fixes
    {
        private const string ResetWindowsUpdate =
            @"net stop bits & net stop wuauserv & net stop cryptsvc" +
            @" & rd /s /q %SystemRoot%\SoftwareDistribution.bak & ren %SystemRoot%\SoftwareDistribution SoftwareDistribution.bak" +
            @" & rd /s /q %SystemRoot%\System32\catroot2.bak & ren %SystemRoot%\System32\catroot2 catroot2.bak" +
            @" & net start cryptsvc & net start bits & net start wuauserv";

        public static readonly Fix[] All =
        {
            new Fix { Name = "Create a restore point", When = "Before trying the other fixes. Needs System Protection to be on.",
                Command = "powershell -NoProfile -Command Checkpoint-Computer -Description Feverfew -RestorePointType MODIFY_SETTINGS" },
            new Fix { Name = "Check the Windows image", When = "First step for corrupted Windows files. Takes under a minute and changes nothing.",
                Command = "DISM /Online /Cleanup-Image /CheckHealth" },
            new Fix { Name = "Repair the Windows image", When = "When the check finds damage or SFC can't finish. Downloads clean files, can take 20 minutes.",
                Command = "DISM /Online /Cleanup-Image /RestoreHealth" },
            new Fix { Name = "Repair system files (SFC)", When = "Crashes, broken Windows features. Run it after repairing the image.",
                Command = "sfc /scannow" },
            new Fix { Name = "Scan the Windows drive for errors", When = "File system errors in the report. Runs while Windows is in use.",
                Command = "chkdsk %SystemDrive% /scan" },
            new Fix { Name = "Repair the Windows drive at restart", When = "When the scan finds errors it can't fix online. Answer Y when asked.",
                Command = "chkdsk %SystemDrive% /f", Caution = "The repair runs at the next restart and can take a long time." },
            new Fix { Name = "Test the memory", When = "Random crashes and blue screens with changing stop codes.",
                Command = "mdsched.exe" },
            new Fix { Name = "Clear the DNS cache", When = "Websites fail to load while other internet apps work.",
                Command = "ipconfig /flushdns" },
            new Fix { Name = "Reset network settings", When = "Network problems that survive a router restart.",
                Command = "netsh winsock reset & netsh int ip reset", Caution = "You must restart afterwards, and any static IP address may be lost. VPN software may need reinstalling." },
            new Fix { Name = "Reset Windows Update", When = "Updates keep failing or get stuck.",
                Command = ResetWindowsUpdate, Caution = "Windows Update stops briefly, its cache is renamed, and the list of past updates may appear empty." }
        };

        public static void AddToReport(Report r)
        {
            var s = r.NewSection("Typical fixes");
            var t = s.Table("Commands to run from an administrator prompt", "Fix", "When to use it", "Command", "Caution");
            foreach (var f in All) t.Rows.Add(new[] { f.Name, f.When, f.Command, f.Caution ?? "" });
            s.Note("Feverfew doesn't run any of these during a scan. To run one, open Repair tools in Feverfew.");
        }

        public static string ConsoleArguments(string command) { return "/k \"" + command + "\""; }

        /// <summary>Opens an administrator console that runs the fix and stays open. Returns false if the user declined the prompt.</summary>
        public static bool Run(Fix fix)
        {
            try
            {
                Process.Start(new ProcessStartInfo("cmd.exe", ConsoleArguments(fix.Command)) { UseShellExecute = true, Verb = "runas" });
                return true;
            }
            catch (Win32Exception e) when (e.NativeErrorCode == 1223)
            {
                return false; // ERROR_CANCELLED
            }
        }
    }
}
