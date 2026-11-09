using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32;

namespace Feverfew.Collectors
{
    /// <summary>Read-only checks of what affects games. Changes are offered separately, in Fixes.Gaming.</summary>
    public static class GamingCollector
    {
        private const string VideoClass = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";
        private const string NetworkNamespace = @"root\StandardCimv2";
        private const string TcpInterfaces = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
        private const string SystemProfile = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile";
        private const int PingSamples = 20;
        private const int PingTimeoutMs = 1000;
        private const int PingGapMs = 100;
        private const int MemoryIntegrityService = 2;
        private const int DefaultNetworkThrottling = 10;
        private const int DefaultSystemResponsiveness = 20;
        private const int TcpAutoTuningNormal = 3;

        [DllImport("powrprof.dll")]
        private static extern uint PowerGetActiveScheme(IntPtr rootKey, out IntPtr scheme);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        public static void Settings(Report r)
        {
            var s = r.NewSection("Gaming: Windows settings");

            Guard.Try(s, "Power plan", () =>
            {
                var name = ActivePowerPlan();
                s.Add("Power plan", name);
                if (name == "Power saver")
                    r.Find(Severity.Info, "Gaming: Power saver plan is active", "This plan can hold back the CPU and GPU during games.", "Use the Power plan option on the Gaming page, or choose Balanced.");
            });

            Guard.Try(s, "Game Mode", () =>
            {
                // Windows leaves this value out until someone changes the setting, and the default is on.
                var v = Reg.Get(RegistryHive.CurrentUser, @"Software\Microsoft\GameBar", "AutoGameModeEnabled");
                bool on = v == null || Convert.ToInt32(v) != 0;
                s.Add("Game Mode", on ? "On" : "Off");
                if (!on) r.Find(Severity.Info, "Gaming: Game Mode is off", "Game Mode limits background work such as Windows Update during games.", "Turn it on from the Gaming page.");
            });

            Guard.Try(s, "Game recording", () =>
            {
                var v = Reg.Get(RegistryHive.CurrentUser, @"System\GameConfigStore", "GameDVR_Enabled");
                s.Add("Game Bar recording", v == null || Convert.ToInt32(v) != 0 ? "Available" : "Off");
                var history = Reg.Get(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\GameDVR", "HistoricalCaptureEnabled");
                bool background = history != null && Convert.ToInt32(history) != 0;
                s.Add("Background recording", background ? "On" : "Off");
                if (background)
                    r.Find(Severity.Info, "Gaming: Background recording is on", "Windows keeps recording the last moments of play, which uses some GPU and disk time.", "Turn it off from the Gaming page if you don't use it.");
            });

            Guard.Try(s, "Hardware-accelerated GPU scheduling", () =>
            {
                var v = Reg.Machine(@"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode");
                s.Add("Hardware-accelerated GPU scheduling", v == null ? "Driver default" : Convert.ToInt32(v) == 2 ? "On" : "Off");
            });

            Guard.Try(s, "Memory integrity", () =>
            {
                var d = Wmi.Query(@"root\Microsoft\Windows\DeviceGuard", "SELECT SecurityServicesRunning FROM Win32_DeviceGuard").FirstOrDefault();
                if (d == null) return;
                var running = d.Raw("SecurityServicesRunning") as Array;
                bool on = running != null && running.Cast<object>().Any(x => Convert.ToInt32(x) == MemoryIntegrityService);
                s.Add("Memory integrity", on ? "On" : "Off");
                if (on)
                    r.Find(Severity.Info, "Gaming: Memory integrity is on", "It protects Windows from malicious drivers and can cost a little performance in some games.", "Keep it on unless you've measured a real problem. Feverfew doesn't offer to turn it off, because it's a security feature.");
            });

            s.Note("Game Mode and recording are per-user settings. If a different account approved the Windows permission prompt, these values are that account's.");
        }

        public static void Network(Report r)
        {
            var s = r.NewSection("Gaming: network");
            var adapters = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up
                    && (n.NetworkInterfaceType == NetworkInterfaceType.Ethernet || n.NetworkInterfaceType == NetworkInterfaceType.GigabitEthernet || n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211)
                    && Gateway(n) != null)
                .OrderBy(n => n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ? 1 : 0)
                .ToList();

            Guard.Try(s, "Connection type", () =>
            {
                var main = adapters.FirstOrDefault();
                if (main == null) { s.Add("Connection used for games", "No wired or Wi-Fi connection found"); return; }
                bool wifi = main.NetworkInterfaceType == NetworkInterfaceType.Wireless80211;
                s.Add("Connection used for games", (wifi ? "Wi-Fi" : "Wired") + " (" + main.Description + ")");
                if (wifi)
                    r.Find(Severity.Info, "Gaming: Playing over Wi-Fi", "Wi-Fi is more prone to latency spikes and packet loss than a cable.", "Use Ethernet if you can, or the router's 5 GHz or 6 GHz band.");
                else if (main.Speed > 0 && main.Speed <= 100000000)
                    r.Find(Severity.Info, "Gaming: Wired link is 100 Mbps or slower", main.Description + " negotiated " + Fmt.Num(main.Speed / 1000000.0, "0") + " Mbps.", "A damaged or older cable often causes this. Try a Cat 5e or better cable.");
            });

            if (r.NetworkTests)
            {
                Guard.Try(s, "Latency test", () =>
                {
                    var t = s.Table("Latency test (" + PingSamples + " pings each)", "Target", "Average", "Worst", "Jitter", "Lost");
                    var gateway = adapters.Select(Gateway).FirstOrDefault();
                    if (gateway != null)
                    {
                        var local = Measure(gateway);
                        t.Rows.Add(local.Row("Router"));
                        if (local.LossPercent >= 5)
                            r.Find(Severity.Warning, "Gaming: Packets lost on the way to the router", local.LossPercent + "% of pings to the router got no reply.", "Check the cable, or move closer to the router on Wi-Fi.");
                        else if (local.JitterMs > 20)
                            r.Find(Severity.Warning, "Gaming: Unstable connection to the router", "Latency to the router varied by " + Fmt.Num(local.JitterMs, "0") + " ms between pings.", "This usually means Wi-Fi interference or a busy local network.");
                    }
                    var internet = Measure("1.1.1.1");
                    t.Rows.Add(internet.Row("Internet (1.1.1.1)"));
                    if (internet.LossPercent >= 10)
                        r.Find(Severity.Warning, "Gaming: Packets lost on the way to the internet", internet.LossPercent + "% of pings to 1.1.1.1 got no reply.", "If the router test was clean, ask your internet provider about it.");
                    s.Note("Run with nothing else using the connection. This doesn't measure latency under load or the route to a specific game server.");
                });
            }
            else s.Note("Latency tests were turned off for this scan.");

            Guard.Try(s, "TCP settings", () =>
            {
                var tcp = Wmi.Query(NetworkNamespace, "SELECT * FROM MSFT_NetTCPSetting").FirstOrDefault(x => x.Str("SettingName") == "Internet");
                if (tcp == null) return;
                var auto = tcp.Long("AutoTuningLevelLocal");
                s.Add("TCP receive window auto-tuning", AutoTuning(auto));
                s.Add("TCP congestion control", Congestion(tcp.Long("CongestionProvider")));
                if (auto != null && auto != TcpAutoTuningNormal)
                    r.Find(Severity.Info, "Gaming: TCP auto-tuning isn't at its default", "It's set to " + AutoTuning(auto) + ", which can limit download speed.", "Use Restore default TCP settings on the Gaming page.");
            });

            Guard.Try(s, "Receive side scaling", () =>
            {
                var g = Wmi.Query(NetworkNamespace, "SELECT ReceiveSideScaling FROM MSFT_NetOffloadGlobalSetting").FirstOrDefault();
                if (g == null) return;
                // Get-NetOffloadGlobalSetting shows "Enabled" where this raw value is 1.
                bool on = g.Long("ReceiveSideScaling") == 1;
                s.Add("Receive side scaling", on ? "On" : "Off");
                if (!on) r.Find(Severity.Info, "Gaming: Receive side scaling is off", "Network work is limited to one CPU core.", "Use Restore default TCP settings on the Gaming page.");
            });

            Guard.Try(s, "Multimedia network settings", () =>
            {
                var throttle = Reg.Machine(SystemProfile, "NetworkThrottlingIndex");
                var responsive = Reg.Machine(SystemProfile, "SystemResponsiveness");
                s.Add("Network throttling index", throttle == null ? "Not set" : Unsigned(throttle).ToString(CultureInfo.InvariantCulture));
                s.Add("System responsiveness", responsive == null ? "Not set" : Unsigned(responsive).ToString(CultureInfo.InvariantCulture));
                if ((throttle != null && Unsigned(throttle) != DefaultNetworkThrottling) || (responsive != null && Unsigned(responsive) != DefaultSystemResponsiveness))
                    r.Find(Severity.Info, "Gaming: Multimedia network settings have been changed", "These are often changed by tweak guides, with little measured benefit in games.", "Use Restore default multimedia settings on the Gaming page if you didn't mean to change them.");
            });

            Guard.Try(s, "Adapter settings", () =>
            {
                var wanted = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "*EEE", "EnableGreenEthernet", "*InterruptModeration", "*FlowControl", "*SpeedDuplex" };
                var t = s.Table("Network adapter settings", "Adapter", "Setting", "Value");
                foreach (var p in Wmi.Query(NetworkNamespace, "SELECT * FROM MSFT_NetAdapterAdvancedPropertySettingData").Where(x => wanted.Contains(x.Str("RegistryKeyword"))).OrderBy(x => x.Str("InterfaceDescription")))
                {
                    t.Rows.Add(new[] { p.Str("InterfaceDescription"), p.Str("DisplayName"), p.Str("DisplayValue") });
                    var key = p.Str("RegistryKeyword");
                    if ((key.Equals("*EEE", StringComparison.OrdinalIgnoreCase) || key.Equals("EnableGreenEthernet", StringComparison.OrdinalIgnoreCase)) && p.Str("RegistryValue") != "0")
                        r.Find(Severity.Info, "Gaming: Network power saving is on", p.Str("InterfaceDescription") + " has " + p.Str("DisplayName") + " turned on, which can add small delays.", "Turn it off in the adapter's Advanced properties in Device Manager.");
                }
            });

            Guard.Try(s, "Interface tweaks", () =>
            {
                using (var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (var key = root.OpenSubKey(TcpInterfaces))
                {
                    if (key == null) return;
                    int tweaked = 0;
                    foreach (var name in key.GetSubKeyNames())
                        using (var k = key.OpenSubKey(name))
                            if (k != null && (k.GetValue("TcpAckFrequency") != null || k.GetValue("TCPNoDelay") != null)) tweaked++;
                    s.Add("Interfaces with Nagle tweaks", tweaked);
                    if (tweaked > 0)
                        r.Find(Severity.Info, "Gaming: Nagle tweaks found", tweaked + " network interface" + (tweaked == 1 ? " has" : "s have") + " TcpAckFrequency or TCPNoDelay set.", "Most games already turn this behaviour off for their own traffic, so these rarely help.");
                }
            });

            s.Note("Feverfew doesn't offer TCP changes that promise lower ping. Windows' defaults are already suited to games, and most games use UDP, which TCP settings don't affect.");
        }

        public static void Graphics(Report r)
        {
            var s = r.NewSection("Gaming: graphics");
            var gpus = new List<Row>();

            Guard.Try(s, "Graphics adapters", () =>
            {
                gpus = Wmi.Cim("SELECT Name, CurrentRefreshRate, MaxRefreshRate, CurrentHorizontalResolution FROM Win32_VideoController");
                foreach (var g in gpus.Where(x => x.Long("CurrentHorizontalResolution") > 0))
                {
                    long current = g.Long("CurrentRefreshRate") ?? 0, max = g.Long("MaxRefreshRate") ?? 0;
                    if (current <= 1 || max <= 1) continue;
                    s.Add("Refresh rate (" + g.Str("Name") + ")", current + " Hz, up to " + max + " Hz");
                    if (max > current + 1)
                        r.Find(Severity.Info, "Gaming: Display may be below its highest refresh rate", "Running at " + current + " Hz, and the driver lists up to " + max + " Hz.", "Choose the higher rate in Settings > System > Display > Advanced display.");
                }
            });

            if (gpus.Any(g => Is(g, "NVIDIA"))) Guard.Try(s, "NVIDIA details", () => Nvidia(r, s));
            if (gpus.Any(g => Is(g, "AMD") || Is(g, "Radeon"))) Guard.Try(s, "AMD details", () => Amd(s));
            if (!gpus.Any(g => Is(g, "NVIDIA") || Is(g, "AMD") || Is(g, "Radeon")))
                s.Note("No NVIDIA or AMD graphics card was found.");

            Guard.Try(s, "Suggested graphics settings", () =>
            {
                var tips = TipsForThisPc();
                if (tips.Count == 0) return;
                var t = s.Table("Suggested settings to check in the graphics app", "Setting", "Suggestion");
                foreach (var tip in tips) t.Rows.Add(new[] { tip.Name, tip.Text });
            });
        }

        private static void Nvidia(Report r, Section s)
        {
            var tool = Path.Combine(Environment.SystemDirectory, "nvidia-smi.exe");
            if (!File.Exists(tool)) { s.Note("NVIDIA details: nvidia-smi wasn't found, so the driver may be incomplete."); return; }

            const string fields = "name,driver_version,pstate,temperature.gpu,utilization.gpu,power.draw,power.limit,pcie.link.gen.current,pcie.link.gen.max,pcie.link.width.current,pcie.link.width.max";
            var lines = Lines(RunTool(tool, "--query-gpu=" + fields + " --format=csv,noheader,nounits"));
            var bars = Bar1Sizes(RunTool(tool, "-q -d MEMORY"));

            var t = s.Table("NVIDIA graphics cards", "Card", "Driver", "State", "Temperature", "Load", "Power / limit", "PCIe now / maximum", "Resizable BAR");
            for (int i = 0; i < lines.Count; i++)
            {
                var c = lines[i].Split(',').Select(x => x.Trim()).ToArray();
                if (c.Length < 11) continue;
                var bar = i < bars.Count ? bars[i] : (long?)null;
                t.Rows.Add(new[]
                {
                    c[0], c[1], c[2], c[3] + " °C", c[4] + "%", c[5] + " W / " + c[6] + " W",
                    "Gen " + c[7] + " x" + c[9] + " / Gen " + c[8] + " x" + c[10],
                    bar == null ? "Unknown" : bar >= 1024 ? "On" : "Off"
                });

                int width, widthMax;
                if (int.TryParse(c[9], out width) && int.TryParse(c[10], out widthMax) && width < widthMax)
                    r.Find(Severity.Info, "Gaming: Graphics card is using fewer PCIe lanes than it supports", c[0] + " is running at x" + width + " of x" + widthMax + ".", "Check that it's in the top slot and fully seated. Some boards also share lanes with M.2 drives.");
                if (bar != null && bar < 1024)
                    r.Find(Severity.Info, "Gaming: Resizable BAR appears to be off", c[0] + " exposes " + bar + " MiB through its BAR.", "If the card and board support it, turn on Above 4G Decoding and Resizable BAR in BIOS setup. It requires UEFI boot.");
            }
            if (t.Rows.Count == 0) s.Tables.Remove(t);

            // Separate query: a field an older driver doesn't know would fail the whole table above.
            const string limits = "name,power.default_limit,power.limit,clocks_throttle_reasons.hw_thermal_slowdown,clocks_throttle_reasons.sw_thermal_slowdown,clocks_throttle_reasons.hw_power_brake_slowdown";
            foreach (var line in Lines(RunTool(tool, "--query-gpu=" + limits + " --format=csv,noheader,nounits")))
            {
                var c = line.Split(',').Select(x => x.Trim()).ToArray();
                if (c.Length < 6) continue;
                double standard, limit;
                if (double.TryParse(c[1], NumberStyles.Float, CultureInfo.InvariantCulture, out standard) && double.TryParse(c[2], NumberStyles.Float, CultureInfo.InvariantCulture, out limit) && limit < standard - 1)
                    r.Find(Severity.Info, "Gaming: Graphics card power limit is below its default", c[0] + " is limited to " + Fmt.Num(limit, "0") + " W, and its default is " + Fmt.Num(standard, "0") + " W.", "If you didn't lower it, check overclocking tools such as MSI Afterburner.");
                if (c[3] == "Active" || c[4] == "Active")
                    r.Find(Severity.Warning, "Gaming: Graphics card is slowing down from heat", c[0] + " was thermally throttling during the scan.", "Clean the dust out, check that its fans spin, and improve case airflow.");
                if (c[5] == "Active")
                    r.Find(Severity.Warning, "Gaming: Graphics card is slowing down from a power limit signal", c[0] + " reported a hardware power brake during the scan.", "Check that every power connector is fully seated, and that the power supply is adequate.");
            }

            s.Note("The PCIe generation drops when the card is idle, so a lower 'now' generation is normal during a scan. Per-game NVIDIA settings can't be read here.");
        }

        private static void Amd(Section s)
        {
            bool found = false;
            using (var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (var key = root.OpenSubKey(VideoClass))
            {
                if (key == null) return;
                foreach (var sub in key.GetSubKeyNames().Where(n => n.All(char.IsDigit)))
                    using (var k = key.OpenSubKey(sub))
                    {
                        var name = k == null ? null : k.GetValue("DriverDesc") as string;
                        if (name == null || (name.IndexOf("AMD", StringComparison.OrdinalIgnoreCase) < 0 && name.IndexOf("Radeon", StringComparison.OrdinalIgnoreCase) < 0)) continue;
                        found = true;
                        var software = k.GetValue("RadeonSoftwareVersion");
                        if (software != null) s.Add("AMD Software version (" + name + ")", software);
                        var ulps = k.GetValue("EnableUlps");
                        if (ulps != null) s.Add("Ultra Low Power State (" + name + ")", Convert.ToInt32(ulps) == 0 ? "Off" : "On");
                    }
            }
            s.Note(found ? "Anti-Lag, Chill and other Radeon settings are stored per game and can't be read here." : "AMD details: no driver entry was found.");
        }

        private static bool Is(Row gpu, string vendor) { return gpu.Str("Name").IndexOf(vendor, StringComparison.OrdinalIgnoreCase) >= 0; }

        private static long Unsigned(object registryValue) { return unchecked((uint)Convert.ToInt32(registryValue)); }

        private static string Gateway(NetworkInterface n)
        {
            var g = n.GetIPProperties().GatewayAddresses.Select(x => x.Address).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(System.Net.IPAddress.Any));
            return g == null ? null : g.ToString();
        }

        public sealed class GraphicsTip
        {
            public string Vendor, Name, Text;
        }

        // These live in the vendors' own apps, which offer no simple supported command to change them.
        private static readonly GraphicsTip[] Tips =
        {
            new GraphicsTip { Vendor = "NVIDIA", Name = "NVIDIA Reflex", Text = "Turn it on in games that offer it. It's the most effective way to lower input lag on NVIDIA cards." },
            new GraphicsTip { Vendor = "NVIDIA", Name = "Low Latency Mode", Text = "For games without Reflex, set it to On in NVIDIA Control Panel, under Manage 3D settings." },
            new GraphicsTip { Vendor = "NVIDIA", Name = "G-SYNC", Text = "Turn it on for a compatible display, and keep the frame rate a few frames below the refresh rate." },
            new GraphicsTip { Vendor = "NVIDIA", Name = "Power management mode", Text = "Leave it on Normal globally. Use Prefer maximum performance only for a game with unstable clocks, because it raises power use." },
            new GraphicsTip { Vendor = "AMD", Name = "Radeon Anti-Lag", Text = "Turn it on in AMD Software, under Gaming and then Graphics, to lower input lag." },
            new GraphicsTip { Vendor = "AMD", Name = "FreeSync", Text = "Turn it on in both AMD Software and the monitor's own menu." },
            new GraphicsTip { Vendor = "AMD", Name = "Smart Access Memory", Text = "Needs Resizable BAR to be on in BIOS setup, and can then be checked in AMD Software." },
            new GraphicsTip { Vendor = "AMD", Name = "Radeon Chill", Text = "Leave it off for the highest frame rates. It's meant for saving power and heat." }
        };

        public static List<GraphicsTip> TipsForThisPc()
        {
            var gpus = Wmi.Cim("SELECT Name FROM Win32_VideoController");
            return Tips.Where(t => gpus.Any(g => Is(g, t.Vendor) || (t.Vendor == "AMD" && Is(g, "Radeon")))).ToList();
        }

        // Status lines for the Gaming page. "Already set" means pressing Apply would change nothing useful.
        public static string PowerStatus()
        {
            var plan = ActivePowerPlan();
            return plan == "High performance" || plan == "Ultimate Performance" ? "Already set: " + plan : "Optional: currently " + plan;
        }

        public static string GameModeStatus()
        {
            var v = Reg.Get(RegistryHive.CurrentUser, @"Software\Microsoft\GameBar", "AutoGameModeEnabled");
            return v == null || Convert.ToInt32(v) != 0 ? "Already set: Game Mode is on" : "Worth applying: Game Mode is off";
        }

        public static string RecordingStatus()
        {
            var v = Reg.Get(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\GameDVR", "HistoricalCaptureEnabled");
            return v == null || Convert.ToInt32(v) == 0 ? "Already set: background recording is off" : "Worth applying if you don't use it: background recording is on";
        }

        public static string SchedulingStatus()
        {
            var v = Reg.Machine(@"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode");
            if (v == null) return "Optional: using the driver's default";
            return Convert.ToInt32(v) == 2 ? "Already set: on" : "Optional: currently off";
        }

        public static string TcpStatus()
        {
            var tcp = Wmi.Query(NetworkNamespace, "SELECT * FROM MSFT_NetTCPSetting").First(x => x.Str("SettingName") == "Internet");
            var offload = Wmi.Query(NetworkNamespace, "SELECT ReceiveSideScaling FROM MSFT_NetOffloadGlobalSetting").First();
            bool defaults = tcp.Long("AutoTuningLevelLocal") == TcpAutoTuningNormal && tcp.Long("ScalingHeuristics") == 0 && offload.Long("ReceiveSideScaling") == 1;
            return defaults ? "Already set: TCP settings are at their defaults" : "Worth applying: TCP settings have been changed";
        }

        public static string MultimediaStatus()
        {
            var throttle = Reg.Machine(SystemProfile, "NetworkThrottlingIndex");
            var responsive = Reg.Machine(SystemProfile, "SystemResponsiveness");
            bool defaults = (throttle == null || Unsigned(throttle) == DefaultNetworkThrottling) && (responsive == null || Unsigned(responsive) == DefaultSystemResponsiveness);
            return defaults ? "Already set: these are at their defaults" : "Worth applying: these have been changed";
        }

        public static string EnergyEfficientEthernetStatus()
        {
            var values = Wmi.Query(NetworkNamespace, "SELECT * FROM MSFT_NetAdapterAdvancedPropertySettingData")
                .Where(x => x.Str("RegistryKeyword").Equals("*EEE", StringComparison.OrdinalIgnoreCase)).ToList();
            if (values.Count == 0) return "Not available on this PC's adapters";
            return values.All(x => x.Str("RegistryValue") == "0") ? "Already set: it's off" : "Optional: it's on";
        }

        private static string ActivePowerPlan()
        {
            var scheme = ActivePowerSchemeGuid();
            if (scheme == null) return "";
            switch (scheme)
            {
                case "381b4222-f694-41f0-9685-ff5bb260df2e": return "Balanced";
                case "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c": return "High performance";
                case "e9a42b02-d5df-448d-aa00-03f14749eb61": return "Ultimate Performance";
                case "a1841308-3541-4fab-bc81-f71556f20b4a": return "Power saver";
                default: return "Custom";
            }
        }

        public static string ActivePowerSchemeGuid()
        {
            IntPtr pointer;
            if (PowerGetActiveScheme(IntPtr.Zero, out pointer) != 0) return null;
            try { return ((Guid)Marshal.PtrToStructure(pointer, typeof(Guid))).ToString(); }
            finally { LocalFree(pointer); }
        }

        private static string AutoTuning(long? level)
        {
            switch (level)
            {
                case 0: return "Disabled";
                case 1: return "Highly restricted";
                case 2: return "Restricted";
                case 3: return "Normal";
                case 4: return "Experimental";
                default: return "Unknown";
            }
        }

        private static string Congestion(long? provider)
        {
            switch (provider)
            {
                case 1: return "NewReno";
                case 5: return "CUBIC";
                default: return provider == null ? "Unknown" : "Other (" + provider + ")";
            }
        }

        private sealed class Latency
        {
            public int LossPercent; public double AverageMs, WorstMs, JitterMs; public bool AnyReply;

            public string[] Row(string target)
            {
                return AnyReply
                    ? new[] { target, Fmt.Num(AverageMs, "0") + " ms", Fmt.Num(WorstMs, "0") + " ms", Fmt.Num(JitterMs, "0.#") + " ms", LossPercent + "%" }
                    : new[] { target, "-", "-", "-", LossPercent + "%" };
            }
        }

        private static Latency Measure(string host)
        {
            var times = new List<double>();
            using (var p = new Ping())
            {
                for (int i = 0; i < PingSamples; i++)
                {
                    try
                    {
                        var reply = p.Send(host, PingTimeoutMs);
                        if (reply.Status == IPStatus.Success) times.Add(reply.RoundtripTime);
                    }
                    catch (PingException) { /* counts as a lost packet */ }
                    Thread.Sleep(PingGapMs);
                }
            }

            var result = new Latency { LossPercent = (PingSamples - times.Count) * 100 / PingSamples, AnyReply = times.Count > 0 };
            if (times.Count == 0) return result;
            result.AverageMs = times.Average();
            result.WorstMs = times.Max();
            result.JitterMs = times.Count < 2 ? 0 : times.Skip(1).Zip(times, (a, b) => Math.Abs(a - b)).Average();
            return result;
        }

        private static string RunTool(string path, string arguments)
        {
            var info = new ProcessStartInfo(path, arguments) { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true };
            using (var p = Process.Start(info))
            {
                var output = p.StandardOutput.ReadToEndAsync();
                if (!p.WaitForExit(15000))
                {
                    p.Kill();
                    throw new TimeoutException("nvidia-smi didn't respond");
                }
                return output.Result;
            }
        }

        private static List<string> Lines(string text)
        {
            return text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Where(l => l.Trim().Length > 0).ToList();
        }

        // The -q output has a "BAR1 Memory Usage" block per card, and its first line is "Total : 16384 MiB".
        private static List<long?> Bar1Sizes(string text)
        {
            var sizes = new List<long?>();
            var lines = Lines(text);
            for (int i = 0; i < lines.Count - 1; i++)
            {
                if (lines[i].IndexOf("BAR1", StringComparison.OrdinalIgnoreCase) < 0) continue;
                var parts = lines[i + 1].Split(':');
                long value;
                var number = parts.Length == 2 ? parts[1].Trim().Split(' ')[0] : "";
                sizes.Add(long.TryParse(number, NumberStyles.Integer, CultureInfo.InvariantCulture, out value) ? value : (long?)null);
            }
            return sizes;
        }
    }
}
