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
        /// <summary>Command that reverses this one, for fixes that offer an Undo button.</summary>
        public string Undo;
        /// <summary>Reads this PC's current state as one short line, for the Gaming page.</summary>
        public System.Func<string> Status;
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

        private const string GameBar = @"HKCU\Software\Microsoft\GameBar";
        private const string GameDvr = @"HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR";
        private const string GraphicsDrivers = @"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers";
        private const string SystemProfile = @"""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile""";
        private const string GpuRestart = "You must restart for this to take effect.";
        private const string AdapterRestart = "The network adapter restarts, so the connection drops for a few seconds.";
        private const string EnergyEfficientEthernet = "powershell -NoProfile -Command \"Get-NetAdapterAdvancedProperty -AllProperties -RegistryKeyword '*EEE' -ErrorAction SilentlyContinue | Set-NetAdapterAdvancedProperty -RegistryValue ";

        public static readonly Fix[] Gaming =
        {
            new Fix { Name = "Use the High performance power plan", When = "The CPU is slow to ramp up in games. Uses more power and makes laptops run hotter. Undo returns to Balanced.",
                Command = "powercfg /setactive SCHEME_MIN", Undo = "powercfg /setactive SCHEME_BALANCED", Status = Collectors.GamingCollector.PowerStatus },
            new Fix { Name = "Turn on Game Mode", When = "The scan reports that Game Mode is off. Undo turns it off.",
                Command = "reg add " + GameBar + " /v AutoGameModeEnabled /t REG_DWORD /d 1 /f & reg add " + GameBar + " /v AllowAutoGameMode /t REG_DWORD /d 1 /f",
                Undo = "reg add " + GameBar + " /v AutoGameModeEnabled /t REG_DWORD /d 0 /f", Status = Collectors.GamingCollector.GameModeStatus },
            new Fix { Name = "Turn off background recording", When = "You don't use Game Bar to save the last moments of play. Undo turns it back on.",
                Command = "reg add " + GameDvr + " /v HistoricalCaptureEnabled /t REG_DWORD /d 0 /f",
                Undo = "reg add " + GameDvr + " /v HistoricalCaptureEnabled /t REG_DWORD /d 1 /f", Status = Collectors.GamingCollector.RecordingStatus },
            new Fix { Name = "Turn on hardware-accelerated GPU scheduling", When = "Needed for DLSS Frame Generation and helpful on some recent cards. Needs a supported card and driver. Undo turns it off.",
                Command = "reg add " + GraphicsDrivers + " /v HwSchMode /t REG_DWORD /d 2 /f", Undo = "reg add " + GraphicsDrivers + " /v HwSchMode /t REG_DWORD /d 1 /f", Caution = GpuRestart, Status = Collectors.GamingCollector.SchedulingStatus },
            new Fix { Name = "Turn off Energy Efficient Ethernet", When = "Wired connections with small, irregular delays. Changes every adapter that supports it. Undo turns it back on.",
                Command = EnergyEfficientEthernet + "0\"", Undo = EnergyEfficientEthernet + "1\"", Caution = AdapterRestart, Status = Collectors.GamingCollector.EnergyEfficientEthernetStatus },
            new Fix { Name = "Restore default TCP settings", When = "The scan reports changed TCP settings, or a tweak tool has been used. Sets auto-tuning to normal, receive side scaling on and heuristics off.",
                Command = "netsh int tcp set global autotuninglevel=normal & netsh int tcp set global rss=enabled & netsh int tcp set heuristics disabled", Status = Collectors.GamingCollector.TcpStatus },
            new Fix { Name = "Restore default multimedia settings", When = "The scan reports changed network throttling or system responsiveness values.",
                Command = "reg add " + SystemProfile + " /v NetworkThrottlingIndex /t REG_DWORD /d 10 /f & reg add " + SystemProfile + " /v SystemResponsiveness /t REG_DWORD /d 20 /f", Status = Collectors.GamingCollector.MultimediaStatus }
        };

        public static void AddToReport(Report r)
        {
            var s = r.NewSection("Typical fixes");
            var t = s.Table("Commands to run from an administrator prompt", "Fix", "When to use it", "Command", "Caution");
            foreach (var f in All) t.Rows.Add(new[] { f.Name, f.When, f.Command, f.Caution ?? "" });
            var g = s.Table("Gaming optimisations", "Optimisation", "When to use it", "Command", "Undo command", "Caution");
            foreach (var f in Gaming) g.Rows.Add(new[] { f.Name, f.When, f.Command, f.Undo ?? "", f.Caution ?? "" });
            s.Note("Feverfew doesn't run any of these during a scan. To run one, open Repair tools or Gaming in Feverfew.");
        }

        public static string ConsoleArguments(string command) { return "/k \"" + command + "\""; }

        /// <summary>Opens an administrator console that runs the fix and stays open. Returns false if the user declined the prompt.</summary>
        public static bool Run(Fix fix) { return Run(fix.Command); }

        public static bool Run(string command)
        {
            try
            {
                Process.Start(new ProcessStartInfo("cmd.exe", ConsoleArguments(command)) { UseShellExecute = true, Verb = "runas" });
                return true;
            }
            catch (Win32Exception e) when (e.NativeErrorCode == 1223)
            {
                return false; // ERROR_CANCELLED
            }
        }
    }
}
