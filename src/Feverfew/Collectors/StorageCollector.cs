using System;
using System.IO;
using System.Linq;

namespace Feverfew.Collectors
{
    public static class StorageCollector
    {
        private const string StorageNs = @"root\Microsoft\Windows\Storage";

        public static void Collect(Report r)
        {
            var s = r.NewSection("Storage");

            Guard.Try(s, "Drive health", () =>
            {
                var t = s.Table("Physical drives", "Drive", "Type", "Bus", "Size", "Health", "Temp", "Wear", "Read errors", "Power-on hours", "Firmware", "Serial");
                foreach (var pair in Wmi.QueryRelated(StorageNs, "SELECT * FROM MSFT_PhysicalDisk", "MSFT_StorageReliabilityCounter"))
                {
                    var d = pair.Key; var c = pair.Value;
                    var health = d.Long("HealthStatus");
                    var name = d.Str("FriendlyName");
                    t.Rows.Add(new[]
                    {
                        name, MediaType(d.Long("MediaType")), BusType(d.Long("BusType")), Fmt.Bytes(d.Long("Size")),
                        health == 0 ? "Healthy" : health == 1 ? "Warning" : health == 2 ? "Unhealthy" : "Unknown",
                        c != null && c.Long("Temperature") > 0 ? c.Str("Temperature") + " °C" : "-",
                        c != null && c.Long("Wear") != null ? c.Str("Wear") + "%" : "-",
                        c != null && c.Long("ReadErrorsUncorrected") != null ? c.Str("ReadErrorsUncorrected") : "-",
                        c != null && c.Long("PowerOnHours") > 0 ? c.Str("PowerOnHours") : "-",
                        d.Str("FirmwareVersion"), r.Private(d.Str("SerialNumber"))
                    });

                    if (health == 2)
                        r.Find(Severity.Critical, "Drive reports it is failing: " + name, "Windows marks this drive Unhealthy.", "Back up now and replace the drive.");
                    else if (health == 1)
                        r.Find(Severity.Warning, "Drive health warning: " + name, "Windows marks this drive with a health warning.", "Back up soon and check the drive with its maker's tool.");
                    if (c != null && c.Long("Wear") >= 90)
                        r.Find(Severity.Warning, "SSD is near the end of its rated life: " + name, "Wear level is " + c.Str("Wear") + "%.", "Plan a replacement and keep backups current.");
                    if (c != null && c.Long("Temperature") >= 70)
                        r.Find(Severity.Warning, "Drive is hot: " + name, c.Str("Temperature") + " °C during the scan.", "Improve airflow around the drive.");
                    if (c != null && c.Long("ReadErrorsUncorrected") > 0)
                        r.Find(Severity.Critical, "Uncorrected read errors on " + name, c.Str("ReadErrorsUncorrected") + " errors reported by the drive.", "Back up now and test the drive.");
                }
            });

            Guard.Try(s, "SMART failure prediction", () =>
            {
                foreach (var p in Wmi.Query(@"root\wmi", "SELECT PredictFailure, InstanceName FROM MSStorageDriver_FailurePredictStatus"))
                    if (p.Bool("PredictFailure") == true)
                        r.Find(Severity.Critical, "SMART predicts a drive failure", "A drive's own monitoring predicts it will fail soon.", "Back up immediately and replace the drive.");
            });

            string systemDrive = Path.GetPathRoot(Environment.SystemDirectory).TrimEnd('\\');
            Guard.Try(s, "Disks and partitions", () => Layout(r, s, systemDrive[0]));

            Guard.Try(s, "Volumes", () =>
            {
                var t = s.Table("Volumes", "Drive", "Kind", "Label", "File system", "Size", "Free", "Free %", "Needs repair");
                foreach (var v in Wmi.Cim("SELECT DeviceID, DriveType, VolumeName, FileSystem, Size, FreeSpace, VolumeDirty FROM Win32_LogicalDisk WHERE DriveType=2 OR DriveType=3"))
                {
                    long? size = v.Long("Size"), free = v.Long("FreeSpace");
                    bool removable = v.Long("DriveType") == 2;
                    if (removable && size == null) continue; // an empty card reader slot
                    double pct = size > 0 && free != null ? 100.0 * free.Value / size.Value : 100;
                    t.Rows.Add(new[] { v.Str("DeviceID"), removable ? "Removable" : "Fixed", r.Label(v.Str("VolumeName")), v.Str("FileSystem"), Fmt.Bytes(size), Fmt.Bytes(free), Fmt.Num(pct, "0") + "%", Fmt.YesNo(v.Bool("VolumeDirty")) });

                    bool isSystem = string.Equals(v.Str("DeviceID"), systemDrive, StringComparison.OrdinalIgnoreCase);
                    if (isSystem && (pct < 5 || free < 10L * 1073741824))
                        r.Find(Severity.Critical, "System drive is nearly full", v.Str("DeviceID") + " has " + Fmt.Bytes(free) + " free. Windows slows down and updates fail when it runs out.", "Free some space: Settings > System > Storage.");
                    else if (pct < 10 && !removable)
                        r.Find(Severity.Warning, "Low disk space on " + v.Str("DeviceID"), Fmt.Bytes(free) + " free (" + Fmt.Num(pct, "0") + "%).", "Free some space or move files elsewhere.");
                    if (v.Bool("VolumeDirty") == true)
                        r.Find(Severity.Warning, "File system on " + v.Str("DeviceID") + " needs repair", "Windows has marked this volume dirty.", "Run: chkdsk " + v.Str("DeviceID") + " /f");
                }
                var total = Wmi.Cim("SELECT Size, FreeSpace, DeviceID FROM Win32_LogicalDisk WHERE DeviceID='" + systemDrive + "'").FirstOrDefault();
                if (total != null) r.AddSummary("System drive", systemDrive + " " + Fmt.Bytes(total.Long("FreeSpace")) + " free of " + Fmt.Bytes(total.Long("Size")));
            });
        }

        private static void Layout(Report r, Section s, char systemLetter)
        {
            var volumes = Wmi.Query(StorageNs, "SELECT Path, FileSystem, FileSystemLabel FROM MSFT_Volume")
                .GroupBy(v => v.Str("Path"), StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
            var partitions = Wmi.Query(StorageNs, "SELECT * FROM MSFT_Partition").OrderBy(p => p.Long("DiskNumber")).ThenBy(p => p.Long("Offset")).ToList();
            var disks = Wmi.Query(StorageNs, "SELECT * FROM MSFT_Disk").OrderBy(d => d.Long("Number")).ToList();

            var diskTable = s.Table("Disks", "Disk", "Name", "Layout", "Size", "Partitions", "Unallocated", "Holds Windows", "Online");
            foreach (var d in disks)
            {
                long? size = d.Long("Size"), allocated = d.Long("AllocatedSize");
                long free = size != null && allocated != null ? size.Value - allocated.Value : 0;
                var mine = partitions.Where(p => p.Long("DiskNumber") == d.Long("Number")).ToList();
                bool offline = d.Bool("IsOffline") == true;
                diskTable.Rows.Add(new[]
                {
                    d.Str("Number"), d.Str("FriendlyName"), Style(d.Long("PartitionStyle")), Fmt.Bytes(size), mine.Count.ToString(),
                    free >= 1048576 ? Fmt.Bytes(free) : "None", Fmt.YesNo(d.Bool("IsBoot")), offline ? "No" : "Yes"
                });
                if (offline)
                    r.Find(Severity.Warning, "Disk " + d.Str("Number") + " is offline: " + d.Str("FriendlyName"), "Windows sees this disk but isn't using it, so its files are unavailable.", "Check the reason in Disk Management before bringing it online.");

                bool holdsSystem = mine.Any(p => Letter(p) == char.ToUpperInvariant(systemLetter));
                if (!holdsSystem) continue;
                r.Signals.SystemDiskGpt = d.Long("PartitionStyle") == 2;
                r.Signals.SystemDiskGb = (size ?? 0) / 1073741824.0;
                s.Add("System disk layout", Style(d.Long("PartitionStyle")));
            }

            bool anyEfi = partitions.Any(p => PartitionKind(p) == "EFI system");
            if (r.Signals.Uefi == true && r.Signals.SystemDiskGpt == true && !anyEfi)
                r.Find(Severity.Warning, "No EFI system partition found", "This PC boots in UEFI mode, but no disk reports an EFI partition. Windows needs one to start.", "Don't restart until this is understood. Check the layout in the Partitions table.");

            var t = s.Table("Partitions", "Disk", "No.", "Kind", "Drive", "File system", "Label", "Size", "Starts at", "Flags");
            foreach (var p in partitions)
            {
                var kind = PartitionKind(p);
                var letter = Letter(p);
                Row volume = null;
                var paths = p.Raw("AccessPaths") as string[];
                if (paths != null)
                    foreach (var path in paths)
                        if (volumes.TryGetValue(path, out volume)) break;

                var fileSystem = volume == null ? "" : volume.Str("FileSystem");
                t.Rows.Add(new[]
                {
                    p.Str("DiskNumber"), p.Str("PartitionNumber"), kind, letter == '\0' ? "-" : letter + ":",
                    fileSystem.Length > 0 ? fileSystem : "-", volume == null ? "" : r.Label(volume.Str("FileSystemLabel")),
                    Fmt.Bytes(p.Long("Size")), Fmt.Bytes(p.Long("Offset")), Flags(p)
                });

                if (kind == "Basic data" && fileSystem.Length == 0 && p.Long("Size") > 1073741824L)
                    r.Find(Severity.Warning, "Partition without a readable file system", "Disk " + p.Str("DiskNumber") + " partition " + p.Str("PartitionNumber") + " (" + Fmt.Bytes(p.Long("Size")) + ") has no file system Windows can read. It may be encrypted, formatted for another operating system, unformatted, or damaged.", "If it should hold files, don't format it. Back up what you can and investigate first.");
            }
        }

        private static char Letter(Row p)
        {
            var raw = p.Raw("DriveLetter");
            return raw == null ? '\0' : char.ToUpperInvariant(Convert.ToChar(raw));
        }

        private static string Style(long? v) { return v == 2 ? "GPT" : v == 1 ? "MBR" : "Not initialized"; }

        private static string Flags(Row p)
        {
            var flags = new[] { "IsBoot:Windows", "IsSystem:Boot files", "IsActive:Active", "IsHidden:Hidden", "IsReadOnly:Read-only", "IsOffline:Offline" }
                .Where(f => p.Bool(f.Split(':')[0]) == true).Select(f => f.Split(':')[1]);
            return string.Join(", ", flags);
        }

        private static string PartitionKind(Row p)
        {
            var gpt = p.Str("GptType").Trim('{', '}').ToLowerInvariant();
            switch (gpt)
            {
                case "": break;
                case "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": return "EFI system";
                case "e3c9e316-0b5c-4db8-817d-f92df00215ae": return "Microsoft reserved";
                case "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": return "Basic data";
                case "de94bba4-06d1-4d40-a16a-bfd50179d6ac": return "Recovery";
                case "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3": return "Dynamic disk metadata";
                case "af9b60a0-1431-4f62-bc68-3311714a69ad": return "Dynamic disk data";
                case "e75caf8f-f680-4cee-afa3-b001e56efc2d": return "Storage Spaces";
                case "0fc63daf-8483-4772-8e79-3d69d8477de4": return "Linux";
                default: return "Other (" + gpt + ")";
            }
            var mbr = p.Long("MbrType");
            switch (mbr)
            {
                case null: return "Unknown";
                case 5:
                case 15: return "Extended";
                case 6:
                case 7:
                case 11:
                case 12:
                case 14: return "Basic data";
                case 39: return "Recovery";
                case 66: return "Dynamic disk";
                case 131: return "Linux";
                default: return "MBR type " + mbr;
            }
        }

        private static string MediaType(long? v) { return v == 3 ? "HDD" : v == 4 ? "SSD" : v == 5 ? "SCM" : "Unknown"; }

        private static string BusType(long? v)
        {
            switch (v)
            {
                case 3: return "ATA";
                case 7: return "USB";
                case 8: return "RAID";
                case 10: return "SAS";
                case 11: return "SATA";
                case 12: return "SD";
                case 17: return "NVMe";
                default: return v == null ? "Unknown" : "Type " + v;
            }
        }
    }
}
