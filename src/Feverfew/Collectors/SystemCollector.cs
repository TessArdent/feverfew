using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Feverfew.Collectors
{
    public static class SystemCollector
    {
        [DllImport("kernel32.dll")]
        private static extern bool GetFirmwareType(out int firmwareType);

        public static void Identity(Report r)
        {
            r.Private(Environment.MachineName);
            r.Private(Environment.UserName);
            r.Private(Environment.UserDomainName);
            try
            {
                var profiles = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory), "Users");
                foreach (var dir in Directory.GetDirectories(profiles))
                {
                    var name = Path.GetFileName(dir);
                    if (!new[] { "Public", "Default", "Default User", "All Users" }.Contains(name, StringComparer.OrdinalIgnoreCase))
                        r.Private(name);
                }
            }
            catch (Exception) { /* the profile regex in Redactor still covers paths */ }
        }

        public static void Windows(Report r)
        {
            var s = r.NewSection("Windows");
            Guard.Try(s, "Operating system", () =>
            {
                var os = Wmi.Cim("SELECT * FROM Win32_OperatingSystem").First();
                const string cv = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
                var build = os.Str("BuildNumber");
                int buildNo; int.TryParse(build, out buildNo);
                r.Signals.WindowsBuild = buildNo;
                var ubr = Reg.Machine(cv, "UBR");
                var display = Reg.Machine(cv, "DisplayVersion");
                s.Add("Edition", os.Str("Caption"));
                s.Add("Version", display);
                s.Add("Build", build + (ubr != null ? "." + ubr : ""));
                s.Add("Architecture", os.Str("OSArchitecture"));
                s.Add("Installed", Fmt.Date(os.Date("InstallDate")));
                var boot = os.Date("LastBootUpTime");
                s.Add("Last boot", Fmt.Time(boot));
                r.AddSummary("Windows", os.Str("Caption") + " " + display + " (build " + build + ")");

                if (boot != null)
                {
                    var up = DateTime.Now - boot.Value;
                    s.Add("Uptime", Fmt.Duration(up));
                    if (up.TotalDays > 30)
                        r.Find(Severity.Info, "Long time since last restart", "This PC has been up for " + Fmt.Duration(up) + ".",
                            "Restart it (use Restart, not Shut down, because Fast Startup can keep the old session).");
                }

                long? total = os.Long("TotalVisibleMemorySize"), free = os.Long("FreePhysicalMemory");
                if (total > 0 && free != null)
                {
                    var used = 100.0 * (total.Value - free.Value) / total.Value;
                    s.Add("Memory in use", Fmt.Num(used, "0") + "% of " + Fmt.Bytes(total * 1024));
                    if (used >= 90)
                        r.Find(Severity.Warning, "Memory nearly full", Fmt.Num(used, "0") + "% of RAM was in use during the scan.",
                            "See the 'Top memory use' table under Software.");
                }

                if (buildNo > 0 && buildNo < 22000)
                    r.Find(Severity.Warning, "Windows 10 is out of support",
                        "Windows 10 reached end of support on 14 October 2025, so it only gets security updates through paid or extended programmes.",
                        "Check the Windows 11 readiness section, or confirm this PC is enrolled in Extended Security Updates.");
            });

            Guard.Try(s, "Computer details", () =>
            {
                var cs = Wmi.Cim("SELECT * FROM Win32_ComputerSystem").First();
                s.Add("Computer name", r.Private(cs.Str("Name")));
                s.Add("Signed-in user", r.Private(cs.Str("UserName")));
                var user = cs.Str("UserName");
                if (user.Contains("\\")) { r.Private(user.Split('\\')[0]); r.Private(user.Split('\\')[1]); }
                s.Add("Domain or workgroup", cs.Bool("PartOfDomain") == true ? r.Private(cs.Str("Domain")) : cs.Str("Domain"));
                s.Add("Maker", cs.Str("Manufacturer"));
                s.Add("Model", cs.Str("Model"));
                s.Add("Hypervisor active (Hyper-V, memory integrity or a virtual machine)", Fmt.YesNo(cs.Bool("HypervisorPresent")));
                r.AddSummary("PC", cs.Str("Manufacturer") + " " + cs.Str("Model"));
            });

            Guard.Try(s, "Activation", () =>
            {
                var lic = Wmi.Cim("SELECT Name, LicenseStatus FROM SoftwareLicensingProduct WHERE ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL");
                var active = lic.Any(l => l.Long("LicenseStatus") == 1);
                s.Add("Activated", Fmt.YesNo(active));
                if (!active)
                    r.Find(Severity.Warning, "Windows is not activated", "No activated Windows licence was found.", "Open Settings > System > Activation.");
            });

            Guard.Try(s, "Restart status", () =>
            {
                var pending = Reg.MachineKeyExists(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")
                    || Reg.MachineKeyExists(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired");
                s.Add("Restart pending", Fmt.YesNo(pending));
                if (pending)
                    r.Find(Severity.Info, "A restart is pending", "Windows is waiting for a restart to finish installing updates.", "Restart before troubleshooting further.");
            });
        }

        public static void Firmware(Report r)
        {
            var s = r.NewSection("Motherboard and BIOS");
            Guard.Try(s, "Motherboard", () =>
            {
                var b = Wmi.Cim("SELECT * FROM Win32_BaseBoard").First();
                s.Add("Motherboard maker", b.Str("Manufacturer"));
                s.Add("Motherboard model", b.Str("Product"));
                s.Add("Motherboard revision", b.Str("Version"));
                s.Add("Motherboard serial", r.Private(b.Str("SerialNumber")));
                r.AddSummary("Motherboard", b.Str("Manufacturer") + " " + b.Str("Product"));
            });

            Guard.Try(s, "BIOS", () =>
            {
                var b = Wmi.Cim("SELECT * FROM Win32_BIOS").First();
                var date = b.Date("ReleaseDate");
                s.Add("BIOS maker", b.Str("Manufacturer"));
                s.Add("BIOS version", b.Str("SMBIOSBIOSVersion"));
                s.Add("BIOS date", Fmt.Date(date));
                s.Add("SMBIOS version", b.Str("SMBIOSMajorVersion") + "." + b.Str("SMBIOSMinorVersion"));
                s.Add("System serial", r.Private(b.Str("SerialNumber")));
                r.AddSummary("BIOS", b.Str("SMBIOSBIOSVersion") + " (" + Fmt.Date(date) + ")");
                if (date != null && (DateTime.Now - date.Value).TotalDays > 365 * 4)
                    r.Find(Severity.Info, "BIOS is over four years old", "The installed BIOS dates from " + Fmt.Date(date) + ".",
                        "Check the maker's support page. Only update the BIOS if a newer version fixes a problem you have, and keep the PC on stable power while you do.");
            });

            Guard.Try(s, "Product ID", () =>
            {
                var p = Wmi.Cim("SELECT UUID, IdentifyingNumber FROM Win32_ComputerSystemProduct").First();
                s.Add("System UUID", r.Private(p.Str("UUID")));
                r.Private(p.Str("IdentifyingNumber"));
            });

            Guard.Try(s, "Boot mode", () =>
            {
                int type;
                if (GetFirmwareType(out type))
                {
                    r.Signals.Uefi = type == 2;
                    s.Add("Boot mode", type == 2 ? "UEFI" : type == 1 ? "Legacy BIOS" : "Unknown");
                }
                var state = Reg.Machine(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled");
                if (state != null) r.Signals.SecureBoot = Convert.ToInt32(state) == 1;
                else if (r.Signals.Uefi == false) r.Signals.SecureBoot = false;
                s.Add("Secure Boot", r.Signals.SecureBoot == null ? "Unknown" : r.Signals.SecureBoot.Value ? "On" : "Off");
                if (r.Signals.SecureBoot == false)
                    r.Find(Severity.Warning, "Secure Boot is off", "Secure Boot protects Windows from tampering before it starts.",
                        "Turn it on in BIOS setup if the PC boots in UEFI mode. Converting from Legacy mode needs extra steps, so don't just flip the setting.");
            });
        }

        public static void Tpm(Report r)
        {
            var s = r.NewSection("TPM and device security");
            Guard.Try(s, "TPM", () =>
            {
                var rows = Wmi.Query(@"root\cimv2\Security\MicrosoftTpm", "SELECT * FROM Win32_Tpm");
                if (rows.Count == 0)
                {
                    r.Signals.TpmPresent = false;
                    s.Add("TPM present", "No");
                    r.Find(Severity.Warning, "No TPM detected", "Windows can't see a TPM. Windows 11 and BitLocker depend on one.",
                        "Most PCs from about 2016 onward have firmware TPM. Look for 'PTT', 'fTPM' or 'TPM' in BIOS setup and turn it on.");
                    return;
                }
                var t = rows[0];
                r.Signals.TpmPresent = true;
                r.Signals.TpmSpec = t.Str("SpecVersion");
                s.Add("TPM present", "Yes");
                s.Add("TPM version", t.Str("SpecVersion").Split(',')[0]);
                s.Add("TPM maker", TpmVendor(t.Long("ManufacturerId")));
                s.Add("TPM firmware", t.Str("ManufacturerVersion"));
                s.Add("TPM enabled", Fmt.YesNo(t.Bool("IsEnabled_InitialValue")));
                s.Add("TPM activated", Fmt.YesNo(t.Bool("IsActivated_InitialValue")));
                s.Add("TPM owned", Fmt.YesNo(t.Bool("IsOwned_InitialValue")));
                r.AddSummary("TPM", t.Str("SpecVersion").Split(',')[0] + (t.Bool("IsEnabled_InitialValue") == true ? " (enabled)" : " (disabled)"));
                if (t.Bool("IsEnabled_InitialValue") == false || t.Bool("IsActivated_InitialValue") == false)
                    r.Find(Severity.Warning, "TPM is present but not ready", "The TPM is disabled or not activated.", "Turn it on in BIOS setup.");
            });

            Guard.Try(s, "BitLocker", () =>
            {
                var t = s.Table("Drive encryption", "Drive", "BitLocker protection");
                foreach (var v in Wmi.Query(@"root\cimv2\Security\MicrosoftVolumeEncryption", "SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume"))
                {
                    if (v.Str("DriveLetter").Length == 0) continue;
                    var p = v.Long("ProtectionStatus");
                    t.Rows.Add(new[] { v.Str("DriveLetter"), p == 1 ? "On" : p == 0 ? "Off" : "Unknown (the drive may be locked)" });
                    if (p == 1)
                        r.Find(Severity.Info, "BitLocker is on for " + v.Str("DriveLetter"),
                            "Motherboard, BIOS or TPM changes can trigger a request for the recovery key.",
                            "Make sure the owner can find the key (usually at account.microsoft.com/devices/recoverykey) before changing hardware or firmware.");
                }
            });

            Guard.Try(s, "Virtualization-based security", () =>
            {
                var d = Wmi.Query(@"root\Microsoft\Windows\DeviceGuard", "SELECT * FROM Win32_DeviceGuard").FirstOrDefault();
                if (d == null) return;
                var status = d.Long("VirtualizationBasedSecurityStatus");
                s.Add("Virtualization-based security", status == 2 ? "Running" : status == 1 ? "Enabled but not running" : "Off");
            });
        }

        private static string TpmVendor(long? id)
        {
            if (id == null) return "Unknown";
            var v = id.Value;
            var chars = new[] { (char)((v >> 24) & 255), (char)((v >> 16) & 255), (char)((v >> 8) & 255), (char)(v & 255) };
            return new string(chars).Replace("\0", "").Trim();
        }

        public static void Windows11Readiness(Report r)
        {
            var s = r.NewSection("Windows 11 readiness");
            var g = r.Signals;
            var t = s.Table("Requirements", "Requirement", "This PC", "Result");
            Action<string, string, bool?> row = (name, value, pass) =>
                t.Rows.Add(new[] { name, value, pass == null ? "Could not check" : pass.Value ? "Pass" : "Fail" });

            bool? tpm2 = g.TpmPresent == false ? false : g.TpmSpec == null ? (bool?)null : g.TpmSpec.TrimStart().StartsWith("2.");
            row("UEFI boot", g.Uefi == null ? "Unknown" : g.Uefi.Value ? "UEFI" : "Legacy BIOS", g.Uefi);
            row("Secure Boot on", Fmt.YesNo(g.SecureBoot), g.SecureBoot);
            row("TPM 2.0", g.TpmPresent == false ? "None" : g.TpmSpec == null ? "Unknown" : g.TpmSpec.Split(',')[0], tpm2);
            row("GPT system disk", g.SystemDiskGpt == null ? "Unknown" : g.SystemDiskGpt.Value ? "GPT" : "MBR", g.SystemDiskGpt);
            row("4 GB RAM or more", g.RamGb == null ? "Unknown" : Fmt.Num(g.RamGb.Value) + " GB", g.RamGb == null ? (bool?)null : g.RamGb >= 3.5);
            row("64 GB system disk or more", g.SystemDiskGb == null ? "Unknown" : Fmt.Num(g.SystemDiskGb.Value, "0") + " GB", g.SystemDiskGb == null ? (bool?)null : g.SystemDiskGb >= 60);
            row("2 CPU cores or more", g.CpuCores == null ? "Unknown" : g.CpuCores.ToString(), g.CpuCores == null ? (bool?)null : g.CpuCores >= 2);
            row("1 GHz CPU or faster", g.CpuMhz == null ? "Unknown" : g.CpuMhz + " MHz", g.CpuMhz == null ? (bool?)null : g.CpuMhz >= 1000);
            s.Note("Microsoft also keeps a list of supported CPU models. Feverfew doesn't check that list.");
        }
    }
}
