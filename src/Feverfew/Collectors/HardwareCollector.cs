using System;
using System.Linq;
using System.Text;
using Microsoft.Win32;

namespace Feverfew.Collectors
{
    public static class HardwareCollector
    {
        public static void Processor(Report r)
        {
            var s = r.NewSection("Processor");
            Guard.Try(s, "CPU", () =>
            {
                var cpus = Wmi.Cim("SELECT * FROM Win32_Processor");
                foreach (var c in cpus)
                {
                    s.Add("Model", c.Str("Name"));
                    s.Add("Socket", c.Str("SocketDesignation"));
                    s.Add("Cores / threads", c.Str("NumberOfCores") + " / " + c.Str("NumberOfLogicalProcessors"));
                    s.Add("Base speed", c.Str("MaxClockSpeed") + " MHz");
                    s.Add("Speed during scan", c.Str("CurrentClockSpeed") + " MHz");
                    s.Add("L2 / L3 cache", Fmt.Bytes(c.Long("L2CacheSize") * 1024) + " / " + Fmt.Bytes(c.Long("L3CacheSize") * 1024));
                    s.Add("Load during scan", c.Str("LoadPercentage") + "%");
                    s.Add("Virtualization on in firmware", Fmt.YesNo(c.Bool("VirtualizationFirmwareEnabled")));
                }
                var first = cpus.First();
                r.AddSummary("CPU", first.Str("Name"));
                r.Signals.CpuCores = (int?)cpus.Sum(c => c.Long("NumberOfCores") ?? 0);
                r.Signals.CpuMhz = (int?)first.Long("MaxClockSpeed");
            });

            Guard.Try(s, "Temperature sensors", () =>
            {
                var zones = Wmi.Query(@"root\wmi", "SELECT InstanceName, CurrentTemperature FROM MSAcpi_ThermalZoneTemperature");
                var t = s.Table("Motherboard thermal zones", "Zone", "Temperature");
                foreach (var z in zones)
                {
                    var c = (z.Long("CurrentTemperature") ?? 0) / 10.0 - 273.15;
                    if (c < 1 || c > 125) continue; // many boards report placeholder values
                    t.Rows.Add(new[] { z.Str("InstanceName"), Fmt.Num(c, "0") + " °C" });
                    if (c >= 90)
                        r.Find(Severity.Warning, "Running hot", "A thermal zone reported " + Fmt.Num(c, "0") + " °C during the scan.", "Clean the dust out and check that the fans spin.");
                }
                if (t.Rows.Count == 0) s.Tables.Remove(t);
                s.Note("Windows only exposes motherboard thermal zones, so these aren't per-core CPU temperatures.");
            });
        }

        public static void Memory(Report r)
        {
            var s = r.NewSection("Memory");
            Guard.Try(s, "Memory modules", () =>
            {
                var sticks = Wmi.Cim("SELECT * FROM Win32_PhysicalMemory");
                var t = s.Table("Installed modules", "Slot", "Size", "Rated speed", "Running at", "Maker", "Part number", "Serial");
                long total = 0;
                foreach (var m in sticks)
                {
                    total += m.Long("Capacity") ?? 0;
                    t.Rows.Add(new[]
                    {
                        m.Str("DeviceLocator"), Fmt.Bytes(m.Long("Capacity")), m.Str("Speed") + " MT/s", m.Str("ConfiguredClockSpeed") + " MT/s",
                        m.Str("Manufacturer"), m.Str("PartNumber"), r.Private(m.Str("SerialNumber"))
                    });
                }
                s.Add("Total installed", Fmt.Bytes(total));
                r.Signals.RamGb = total / 1073741824.0;
                var speed = sticks.Select(m => m.Long("ConfiguredClockSpeed")).FirstOrDefault(v => v > 0);
                r.AddSummary("Memory", Fmt.Bytes(total) + " in " + sticks.Count + " module" + (sticks.Count == 1 ? "" : "s") + (speed != null ? " at " + speed + " MT/s" : ""));

                Guard.Try(s, "Memory slots", () =>
                {
                    var a = Wmi.Cim("SELECT MemoryDevices, MaxCapacityEx FROM Win32_PhysicalMemoryArray").FirstOrDefault();
                    if (a != null) s.Add("Slots used", sticks.Count + " of " + a.Str("MemoryDevices"));
                });

                if (sticks.Select(m => m.Long("Capacity")).Distinct().Count() > 1 || sticks.Select(m => m.Str("PartNumber")).Distinct().Count() > 1)
                    r.Find(Severity.Info, "Mixed memory modules", "The installed RAM sticks aren't an identical set.",
                        "Mixed kits usually work, but they're a common cause of random crashes when memory runs at higher speeds.");

                var slow = sticks.Where(m => m.Long("Speed") > 0 && m.Long("ConfiguredClockSpeed") > 0 && m.Long("ConfiguredClockSpeed") < m.Long("Speed") * 0.9).ToList();
                if (slow.Count > 0)
                    r.Find(Severity.Info, "Memory is running below its rated speed",
                        "Rated " + slow[0].Str("Speed") + " MT/s, running at " + slow[0].Str("ConfiguredClockSpeed") + " MT/s.",
                        "This is normal unless XMP/EXPO is meant to be on in BIOS setup. If the PC crashes with XMP on, leave it off.");
            });
        }

        public static void Graphics(Report r)
        {
            var s = r.NewSection("Graphics and displays");
            Guard.Try(s, "Graphics adapters", () =>
            {
                var gpus = Wmi.Cim("SELECT * FROM Win32_VideoController");
                var t = s.Table("Graphics adapters", "Name", "Memory", "Driver version", "Driver date", "Current mode", "Status");
                foreach (var g in gpus)
                {
                    var date = g.Date("DriverDate");
                    var mode = g.Long("CurrentHorizontalResolution") > 0
                        ? g.Str("CurrentHorizontalResolution") + " x " + g.Str("CurrentVerticalResolution") + " at " + g.Str("CurrentRefreshRate") + " Hz" : "Inactive";
                    t.Rows.Add(new[] { g.Str("Name"), Fmt.Bytes(VideoMemory(g.Str("Name")) ?? g.Long("AdapterRAM")), g.Str("DriverVersion"), Fmt.Date(date), mode, g.Str("Status") });

                    if (g.Str("Name").IndexOf("Basic Display", StringComparison.OrdinalIgnoreCase) >= 0)
                        r.Find(Severity.Warning, "No proper graphics driver", "Windows is using the Microsoft Basic Display Adapter.", "Install the driver from NVIDIA, AMD, Intel, or the PC maker.");
                    else if (date != null && (DateTime.Now - date.Value).TotalDays > 365 * 2)
                        r.Find(Severity.Info, "Old graphics driver", g.Str("Name") + " has a driver dated " + Fmt.Date(date) + ".", "Update it from the graphics card maker's site if games or video misbehave.");
                }
                r.AddSummary("Graphics", string.Join(", ", gpus.Select(g => g.Str("Name"))));
            });

            Guard.Try(s, "Monitors", () =>
            {
                var t = s.Table("Connected monitors", "Maker code", "Model");
                foreach (var m in Wmi.Query(@"root\wmi", "SELECT ManufacturerName, UserFriendlyName FROM WmiMonitorID"))
                    t.Rows.Add(new[] { Decode(m.Raw("ManufacturerName")), Decode(m.Raw("UserFriendlyName")) });
            });

            Guard.Try(s, "Sound devices", () =>
            {
                var t = s.Table("Sound devices", "Name", "Status");
                foreach (var d in Wmi.Cim("SELECT Name, Status FROM Win32_SoundDevice"))
                    t.Rows.Add(new[] { d.Str("Name"), d.Str("Status") });
            });
        }

        // Win32_VideoController.AdapterRAM stops at 4 GB; the driver's registry entry has the true size.
        private static long? VideoMemory(string name)
        {
            const string cls = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";
            try
            {
                using (var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (var key = root.OpenSubKey(cls))
                {
                    foreach (var sub in key.GetSubKeyNames().Where(n => n.All(char.IsDigit)))
                        using (var k = key.OpenSubKey(sub))
                        {
                            if (!string.Equals(k.GetValue("DriverDesc") as string, name, StringComparison.OrdinalIgnoreCase)) continue;
                            var v = k.GetValue("HardwareInformation.qwMemorySize");
                            if (v != null) return Convert.ToInt64(v);
                        }
                }
            }
            catch (Exception) { /* fall back to AdapterRAM */ }
            return null;
        }

        private static string Decode(object raw)
        {
            var codes = raw as ushort[];
            if (codes == null) return "";
            var b = new StringBuilder();
            foreach (var c in codes) if (c != 0) b.Append((char)c);
            return b.ToString();
        }

        public static void Devices(Report r)
        {
            var s = r.NewSection("Devices and drivers");
            Guard.Try(s, "Problem devices", () =>
            {
                var bad = Wmi.Cim("SELECT Name, PNPDeviceID, ConfigManagerErrorCode, Status FROM Win32_PnPEntity WHERE ConfigManagerErrorCode <> 0");
                var t = s.Table("Devices with problems", "Device", "Hardware ID", "Problem");
                foreach (var d in bad)
                    t.Rows.Add(new[] { d.Str("Name"), ShortId(d.Str("PNPDeviceID")), ProblemText(d.Long("ConfigManagerErrorCode")) });
                // Code 22 means someone disabled the device on purpose, and 45 means it's unplugged.
                var real = bad.Where(d => d.Long("ConfigManagerErrorCode") != 22 && d.Long("ConfigManagerErrorCode") != 45).ToList();
                if (real.Count > 0)
                    r.Find(Severity.Warning, real.Count + " device" + (real.Count == 1 ? " has" : "s have") + " a driver or hardware problem",
                        string.Join("; ", real.Take(6).Select(d => (d.Str("Name").Length > 0 ? d.Str("Name") : ShortId(d.Str("PNPDeviceID"))) + " (code " + d.Str("ConfigManagerErrorCode") + ")")) + (real.Count > 6 ? "; and more" : ""),
                        "Open the 'Devices with problems' table. The hardware ID identifies the right driver to look for.");
            });

            Guard.Try(s, "USB devices", () =>
            {
                var t = s.Table("USB devices", "Name", "Status");
                foreach (var d in Wmi.Cim("SELECT Name, Status FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB\\\\VID%'").OrderBy(d => d.Str("Name")))
                    t.Rows.Add(new[] { d.Str("Name"), d.Str("Status") });
            });
        }

        public static void Drivers(Report r)
        {
            var s = r.NewSection("Third-party drivers");
            Guard.Try(s, "Drivers", () =>
            {
                var t = s.Table("Non-Microsoft drivers", "Device", "Provider", "Version", "Date", "Signed");
                var rows = Wmi.Cim("SELECT DeviceName, DriverProviderName, DriverVersion, DriverDate, IsSigned FROM Win32_PnPSignedDriver")
                    .Where(d => d.Str("DriverProviderName").Length > 0 && d.Str("DriverProviderName").IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) < 0)
                    .OrderBy(d => d.Str("DriverProviderName")).ThenBy(d => d.Str("DeviceName"))
                    .ToList();
                foreach (var d in rows)
                    t.Rows.Add(new[] { d.Str("DeviceName"), d.Str("DriverProviderName"), d.Str("DriverVersion"), Fmt.Date(d.Date("DriverDate")), Fmt.YesNo(d.Bool("IsSigned")) });
                var unsigned = rows.Where(d => d.Bool("IsSigned") == false).ToList();
                if (unsigned.Count > 0)
                    r.Find(Severity.Warning, "Unsigned drivers installed", string.Join(", ", unsigned.Take(5).Select(d => d.Str("DeviceName"))), "Replace them with signed drivers from the device maker.");
            });
        }

        // Keeps bus\vendor&product and drops the instance part, which can contain a device serial.
        private static string ShortId(string id)
        {
            var parts = id.Split('\\');
            return parts.Length >= 2 ? parts[0] + "\\" + parts[1] : id;
        }

        private static string ProblemText(long? code)
        {
            switch (code)
            {
                case 1: return "Not configured correctly (code 1)";
                case 3: return "Driver may be corrupted (code 3)";
                case 10: return "Device can't start (code 10)";
                case 12: return "Not enough free resources (code 12)";
                case 18: return "Drivers need reinstalling (code 18)";
                case 19: return "Registry entry is corrupted (code 19)";
                case 21: return "Being removed (code 21)";
                case 22: return "Disabled (code 22)";
                case 24: return "Not present or not working (code 24)";
                case 28: return "No driver installed (code 28)";
                case 31: return "Driver failed to load (code 31)";
                case 32: return "Driver is disabled (code 32)";
                case 37: return "Driver failed to initialize (code 37)";
                case 39: return "Driver is corrupted or missing (code 39)";
                case 43: return "Device reported a failure (code 43)";
                case 45: return "Not connected (code 45)";
                case 48: return "Driver blocked as incompatible (code 48)";
                case 52: return "Driver signature can't be verified (code 52)";
                default: return "Error code " + code;
            }
        }

        public static void Battery(Report r)
        {
            var batteries = Wmi.Cim("SELECT Name, EstimatedChargeRemaining, BatteryStatus FROM Win32_Battery");
            if (batteries.Count == 0) return;
            var s = r.NewSection("Battery");
            foreach (var b in batteries)
            {
                s.Add("Battery", b.Str("Name"));
                s.Add("Charge", b.Str("EstimatedChargeRemaining") + "%");
            }
            Guard.Try(s, "Battery wear", () =>
            {
                var design = Wmi.Query(@"root\wmi", "SELECT DesignedCapacity FROM BatteryStaticData").FirstOrDefault();
                var full = Wmi.Query(@"root\wmi", "SELECT FullChargedCapacity FROM BatteryFullChargedCapacity").FirstOrDefault();
                if (design == null || full == null || !(design.Long("DesignedCapacity") > 0)) return;
                var health = 100.0 * full.Long("FullChargedCapacity").Value / design.Long("DesignedCapacity").Value;
                s.Add("Capacity remaining", Fmt.Num(health, "0") + "% of original");
                if (health < 60)
                    r.Find(Severity.Warning, "Battery is badly worn", "It now holds " + Fmt.Num(health, "0") + "% of its original charge.", "Consider replacing it, and check it isn't swollen.");
            });
            Guard.Try(s, "Battery cycles", () =>
            {
                var c = Wmi.Query(@"root\wmi", "SELECT CycleCount FROM BatteryCycleCount").FirstOrDefault();
                if (c != null && c.Long("CycleCount") > 0) s.Add("Charge cycles", c.Str("CycleCount"));
            });
        }
    }
}
