using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;

namespace Feverfew.Collectors
{
    public static class EventCollector
    {
        private const int Days = 30;
        private const int MaxEvents = 30000;

        private sealed class Group
        {
            public string Provider; public int Id; public int Count; public DateTime? Last; public byte Level; public string Message;
        }

        private static string Query(string levels)
        {
            long ms = Days * 86400000L;
            return "*[System[(" + levels + ") and TimeCreated[timediff(@SystemTime) <= " + ms + "]]]";
        }

        private static string Describe(EventRecord e)
        {
            try { return Fmt.Clip(e.FormatDescription(), 260); }
            catch (Exception) { return ""; }
        }

        private static List<Group> Scan(string log, Action<EventRecord> visit = null)
        {
            var groups = new Dictionary<string, Group>();
            var q = new EventLogQuery(log, PathType.LogName, Query("Level=1 or Level=2 or Level=3")) { ReverseDirection = true };
            using (var reader = new EventLogReader(q))
            {
                EventRecord e; int n = 0;
                while (n++ < MaxEvents && (e = reader.ReadEvent()) != null)
                {
                    using (e)
                    {
                        if (visit != null) visit(e);
                        var key = e.ProviderName + "|" + e.Id;
                        Group g;
                        if (!groups.TryGetValue(key, out g))
                        {
                            g = new Group { Provider = e.ProviderName, Id = e.Id, Level = e.Level ?? 0, Last = e.TimeCreated, Message = Describe(e) };
                            groups[key] = g;
                        }
                        g.Count++;
                    }
                }
            }
            return groups.Values.ToList();
        }

        public static void Collect(Report r)
        {
            var s = r.NewSection("Crashes and event logs (last " + Days + " days)");

            Guard.Try(s, "System log", () =>
            {
                var sys = Scan("System");
                Fill(s.Table("Most frequent System errors", "Count", "Last seen", "Source", "ID", "Message"), sys);
                Analyze(r, s, sys);
            });

            Guard.Try(s, "Application log", () =>
            {
                var crashes = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
                var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                var app = Scan("Application", e =>
                {
                    if (e.ProviderName != "Application Error" || e.Id != 1000 || e.Properties.Count < 7) return;
                    var name = Convert.ToString(e.Properties[0].Value);
                    int c; counts.TryGetValue(name, out c); counts[name] = c + 1;
                    if (c == 0)
                        crashes[name] = new[] { name, Convert.ToString(e.Properties[3].Value), FormatCode(e.Properties[6].Value), Fmt.Time(e.TimeCreated) };
                });
                Fill(s.Table("Most frequent Application errors", "Count", "Last seen", "Source", "ID", "Message"), app);
                var t = s.Table("Program crashes", "Count", "Program", "Faulting module", "Exception", "Last crash");
                foreach (var kv in counts.OrderByDescending(k => k.Value).Take(20))
                    t.Rows.Add(new[] { kv.Value.ToString() }.Concat(crashes[kv.Key]).ToArray());
                var worst = counts.OrderByDescending(k => k.Value).FirstOrDefault();
                if (worst.Value >= 5)
                    r.Find(Severity.Warning, "A program keeps crashing: " + worst.Key, worst.Value + " crashes in the last " + Days + " days.", "Update or reinstall it. The 'Program crashes' table names the faulting module.");
            });

            Guard.Try(s, "Crash dumps", () => Dumps(r, s));
        }

        private static string FormatCode(object v)
        {
            try { return "0x" + Convert.ToUInt32(v).ToString("x8"); }
            catch (Exception) { return Convert.ToString(v); }
        }

        private static void Fill(Table t, List<Group> groups)
        {
            foreach (var g in groups.Where(g => g.Level <= 2).OrderByDescending(g => g.Count).Take(25))
                t.Rows.Add(new[] { g.Count.ToString(), Fmt.Time(g.Last), g.Provider, g.Id.ToString(), g.Message });
        }

        private static void Analyze(Report r, Section s, List<Group> sys)
        {
            Func<string, int[], int> count = (provider, ids) =>
                sys.Where(g => string.Equals(g.Provider, provider, StringComparison.OrdinalIgnoreCase) && (ids == null || ids.Contains(g.Id))).Sum(g => g.Count);

            int kernelPower = count("Microsoft-Windows-Kernel-Power", new[] { 41 });
            int dirty = count("EventLog", new[] { 6008 });
            int bugcheck = count("Microsoft-Windows-WER-SystemErrorReporting", new[] { 1001 }) + count("BugCheck", new[] { 1001 });
            int wheaError = sys.Where(g => g.Provider == "Microsoft-Windows-WHEA-Logger" && g.Level <= 2).Sum(g => g.Count);
            int wheaWarn = sys.Where(g => g.Provider == "Microsoft-Windows-WHEA-Logger" && g.Level == 3).Sum(g => g.Count);
            int badBlock = count("disk", new[] { 7 });
            int diskErr = count("disk", new[] { 11, 51, 52, 153, 154 }) + count("stornvme", new[] { 11, 129 }) + count("storahci", new[] { 11, 129 });
            int ntfs = count("Microsoft-Windows-Ntfs", new[] { 55, 98, 130, 137 });
            int gpu = count("Display", new[] { 4101 });
            int throttle = count("Microsoft-Windows-Kernel-Processor-Power", new[] { 37 });

            s.Add("Unexpected restarts (Kernel-Power 41)", kernelPower);
            s.Add("Improper shutdowns (EventLog 6008)", dirty);
            s.Add("Blue screens (BugCheck 1001)", bugcheck);
            s.Add("Hardware errors (WHEA)", wheaError + " fatal, " + wheaWarn + " corrected");
            s.Add("Disk errors", badBlock + " bad block, " + diskErr + " I/O or timeout");
            s.Add("File system errors (NTFS)", ntfs);
            s.Add("Graphics driver resets (Display 4101)", gpu);
            s.Add("CPU speed limited by firmware (Processor-Power 37)", throttle);

            if (bugcheck > 0)
                r.Find(bugcheck >= 3 ? Severity.Critical : Severity.Warning, bugcheck + " blue screen" + (bugcheck == 1 ? "" : "s") + " in " + Days + " days", "Windows recorded stop errors.", "Check 'Recent crash dumps' for the stop codes. Repeated different codes usually point to RAM, power or overclocking; a repeated single code usually points to a driver.");
            if (kernelPower > bugcheck)
                r.Find(kernelPower >= 3 ? Severity.Critical : Severity.Warning, kernelPower + " unexpected restart" + (kernelPower == 1 ? "" : "s"), "The PC stopped without shutting down cleanly, and some of those restarts had no blue screen.", "Suspect the power supply, overheating, unstable overclocks, or someone holding the power button.");
            if (wheaError > 0)
                r.Find(Severity.Critical, "Fatal hardware errors logged", wheaError + " WHEA errors. The CPU, RAM, motherboard or a PCIe device reported a failure.", "Remove any overclock, test the RAM with MemTest86, and read the WHEA message in the System errors table.");
            if (wheaWarn >= 10)
                r.Find(Severity.Warning, "Repeated corrected hardware errors", wheaWarn + " corrected WHEA events. Often a PCIe link or an unstable overclock.", "Reseat the graphics card and NVMe drive, then update the BIOS.");
            if (badBlock > 0)
                r.Find(Severity.Critical, "Bad blocks reported on a disk", badBlock + " bad block events.", "Back up now, then test the drive with its maker's tool.");
            if (diskErr >= 5)
                r.Find(Severity.Warning, "Disk I/O errors or timeouts", diskErr + " events.", "Check or replace the SATA cable, reseat the drive, and update the storage driver or firmware.");
            if (ntfs > 0)
                r.Find(Severity.Warning, "File system errors", ntfs + " NTFS events.", "Run chkdsk /scan and check the drive's health.");
            if (gpu >= 3)
                r.Find(Severity.Warning, "Graphics driver keeps resetting", gpu + " resets logged.", "Do a clean driver install, remove GPU overclocks, and check temperature and power cables.");
            if (throttle >= 10)
                r.Find(Severity.Warning, "CPU speed is being limited by firmware", throttle + " throttling events. Usually heat or a weak power adapter.", "Clean the cooler and check the charger or power supply.");
        }

        private static void Dumps(Report r, Section s)
        {
            // Without admin rights the folder just looks absent, which would read as "no crashes".
            if (!Scanner.IsElevated()) throw new UnauthorizedAccessException();
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Minidump");
            var t = s.Table("Recent crash dumps", "Date", "File", "Size", "Stop code", "Meaning");
            if (Directory.Exists(dir))
            {
                foreach (var f in new DirectoryInfo(dir).GetFiles("*.dmp").OrderByDescending(f => f.LastWriteTime).Take(15))
                {
                    var code = ReadBugCheck(f.FullName);
                    t.Rows.Add(new[] { Fmt.Time(f.LastWriteTime), f.Name, Fmt.Bytes(f.Length), code == null ? "Unreadable" : "0x" + code.Value.ToString("X8"), code == null ? "" : BugCheckName(code.Value) });
                }
            }
            var full = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "MEMORY.DMP");
            if (File.Exists(full))
            {
                var info = new FileInfo(full);
                s.Add("Full memory dump", Fmt.Time(info.LastWriteTime) + ", " + Fmt.Bytes(info.Length));
            }
        }

        // Reads the stop code from the fixed header of a kernel dump. The dump's contents stay on the PC.
        private static uint? ReadBugCheck(string path)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var br = new BinaryReader(fs))
                {
                    var sig = new string(br.ReadChars(8));
                    if (sig == "PAGEDU64") { fs.Position = 0x38; return br.ReadUInt32(); }
                    if (sig == "PAGEDUMP") { fs.Position = 0x28; return br.ReadUInt32(); }
                }
            }
            catch (Exception) { }
            return null;
        }

        private static string BugCheckName(uint code)
        {
            var names = new Dictionary<uint, string>
            {
                { 0x0A, "IRQL_NOT_LESS_OR_EQUAL" }, { 0x1A, "MEMORY_MANAGEMENT" }, { 0x1E, "KMODE_EXCEPTION_NOT_HANDLED" },
                { 0x3B, "SYSTEM_SERVICE_EXCEPTION" }, { 0x50, "PAGE_FAULT_IN_NONPAGED_AREA" }, { 0x7A, "KERNEL_DATA_INPAGE_ERROR" },
                { 0x7B, "INACCESSIBLE_BOOT_DEVICE" }, { 0x7E, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED" }, { 0x7F, "UNEXPECTED_KERNEL_MODE_TRAP" },
                { 0x9F, "DRIVER_POWER_STATE_FAILURE" }, { 0xA0, "INTERNAL_POWER_ERROR" }, { 0xBE, "ATTEMPTED_WRITE_TO_READONLY_MEMORY" },
                { 0xC2, "BAD_POOL_CALLER" }, { 0xC4, "DRIVER_VERIFIER_DETECTED_VIOLATION" }, { 0xC5, "DRIVER_CORRUPTED_EXPOOL" },
                { 0xD1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL" }, { 0xEA, "THREAD_STUCK_IN_DEVICE_DRIVER" }, { 0xEF, "CRITICAL_PROCESS_DIED" },
                { 0xF4, "CRITICAL_OBJECT_TERMINATION" }, { 0xFC, "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY" }, { 0x101, "CLOCK_WATCHDOG_TIMEOUT" },
                { 0x109, "CRITICAL_STRUCTURE_CORRUPTION" }, { 0x116, "VIDEO_TDR_FAILURE" }, { 0x117, "VIDEO_TDR_TIMEOUT_DETECTED" },
                { 0x119, "VIDEO_SCHEDULER_INTERNAL_ERROR" }, { 0x124, "WHEA_UNCORRECTABLE_ERROR" }, { 0x133, "DPC_WATCHDOG_VIOLATION" },
                { 0x139, "KERNEL_SECURITY_CHECK_FAILURE" }, { 0x13A, "KERNEL_MODE_HEAP_CORRUPTION" }, { 0x154, "UNEXPECTED_STORE_EXCEPTION" },
                { 0x18B, "SECURE_KERNEL_ERROR" }, { 0x1000007E, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M" }, { 0x1000008E, "KERNEL_MODE_EXCEPTION_NOT_HANDLED_M" },
                { 0x100000D1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL_M" }
            };
            string name;
            return names.TryGetValue(code, out name) ? name : "Look up code 0x" + code.ToString("X", CultureInfo.InvariantCulture);
        }
    }
}
