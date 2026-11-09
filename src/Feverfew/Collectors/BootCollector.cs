using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Feverfew.Collectors
{
    /// <summary>Reads Secure Boot keys, firmware boot entries and EFI boot loaders. Read-only.</summary>
    public static class BootCollector
    {
        private const string GlobalGuid = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";
        private const string SecurityGuid = "{D719B2CB-3D3A-4596-A3BC-DAD00E67656F}";
        private const string EfiPartitionType = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
        private const string WindowsLoader = @"\EFI\MICROSOFT\BOOT\BOOTMGFW.EFI";
        private static readonly Guid X509Type = new Guid("a5c059a1-94e4-4aa7-87b5-ab155c2bf072");
        private const int MaxLoaders = 40;
        private const int MaxUpdateEvents = 2000;
        private const string SecureBootKey = @"SYSTEM\CurrentControlSet\Control\Secureboot";
        private const string Windows2023 = "Windows UEFI CA 2023";
        private const string Kek2023 = "KEK 2K CA 2023";
        private const string UpdateEventProvider = "Microsoft-Windows-TPM-WMI";

        private static readonly Dictionary<int, string> UpdateEvents = new Dictionary<int, string>
        {
            { 1032, "Stopped before writing to firmware, because BitLocker would have asked for its recovery key" },
            { 1036, "Added a Windows certificate to db" }, { 1043, "Updated KEK" },
            { 1044, "Added Microsoft Option ROM UEFI CA 2023 to db" }, { 1045, "Added Microsoft UEFI CA 2023 to db" },
            { 1795, "The firmware returned an error during a write" }, { 1796, "The update hit an error and will retry" },
            { 1797, "The new boot manager couldn't be installed" }, { 1799, "Installed the boot manager signed by Windows UEFI CA 2023" },
            { 1800, "A restart is needed before the next step" }, { 1801, "Certificates are not yet applied to firmware" },
            { 1802, "The update was deliberately blocked on this PC" }, { 1803, "The PC maker hasn't provided a signed KEK for this PC" },
            { 1808, "The Secure Boot certificate update is complete" }
        };

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFirmwareEnvironmentVariableW(string name, string guid, byte[] buffer, uint size);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool LookupPrivilegeValueW(string system, string name, out long luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivilege state, int length, IntPtr previous, IntPtr returned);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct TokenPrivilege { public uint Count; public long Luid; public uint Attributes; }

        /// <summary>What the separate boot checks learn, so the final advice can use all of it.</summary>
        private sealed class BootState
        {
            public bool SecureBootOn;
            public bool KeysUsable;
            public bool Has2023;
            public SignatureSet Db;
            public SignatureSet DefaultDb;
            public string WindowsLoaderIssuer;
        }

        private sealed class SignatureSet
        {
            public readonly List<X509Certificate2> Certificates = new List<X509Certificate2>();
            public int Hashes;
            public int Total { get { return Certificates.Count + Hashes; } }
        }

        public static void Collect(Report r)
        {
            var s = r.NewSection("Boot and Secure Boot");
            if (r.Signals.Uefi == false)
            {
                s.Note("This PC started in Legacy mode, so Windows can't read Secure Boot keys, firmware boot entries or EFI boot loaders.");
                r.Find(Severity.Info, "PC is booting in Legacy mode", "Secure Boot can't work until Windows boots in UEFI mode.", "If the system disk is MBR, convert it with mbr2gpt first, then disable CSM in BIOS setup.");
                return;
            }

            var state = new BootState();
            Guard.Try(s, "Secure Boot keys", () => { EnablePrivilege(); Keys(r, s, state); });
            Guard.Try(s, "Firmware boot entries", () => { EnablePrivilege(); Entries(r, s); });
            Guard.Try(s, "EFI boot loaders", () => Loaders(r, s, state));
            CheckWindowsLoaderTrust(r, state);
            Guard.Try(s, "Secure Boot certificate update", () => CertificateUpdate(r, s, state));
        }

        private static void EnablePrivilege()
        {
            const uint adjustAndQuery = 0x20 | 0x8;
            const uint enabled = 2;
            IntPtr token;
            if (!OpenProcessToken(GetCurrentProcess(), adjustAndQuery, out token)) throw new Win32Exception();
            try
            {
                var state = new TokenPrivilege { Count = 1, Attributes = enabled };
                if (!LookupPrivilegeValueW(null, "SeSystemEnvironmentPrivilege", out state.Luid)) throw new Win32Exception();
                bool ok = AdjustTokenPrivileges(token, false, ref state, 0, IntPtr.Zero, IntPtr.Zero);
                if (!ok || Marshal.GetLastWin32Error() != 0) throw new UnauthorizedAccessException();
            }
            finally { CloseHandle(token); }
        }

        /// <summary>Returns a firmware variable's bytes, or null if the variable doesn't exist.</summary>
        private static byte[] Variable(string name, string guid)
        {
            var buffer = new byte[1 << 20];
            var size = GetFirmwareEnvironmentVariableW(name, guid, buffer, (uint)buffer.Length);
            if (size == 0)
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 203) return null; // ERROR_ENVVAR_NOT_FOUND
                if (error == 5 || error == 1314) throw new UnauthorizedAccessException();
                throw new Win32Exception(error);
            }
            var result = new byte[size];
            Array.Copy(buffer, result, size);
            return result;
        }

        private static SignatureSet ParseSignatures(byte[] data)
        {
            var set = new SignatureSet();
            if (data == null) return set;
            const int listHeader = 28, ownerSize = 16;
            int offset = 0;
            while (offset + listHeader <= data.Length)
            {
                var guidBytes = new byte[16];
                Array.Copy(data, offset, guidBytes, 0, 16);
                var type = new Guid(guidBytes);
                int listSize = BitConverter.ToInt32(data, offset + 16);
                int headerSize = BitConverter.ToInt32(data, offset + 20);
                int entrySize = BitConverter.ToInt32(data, offset + 24);
                if (listSize < listHeader || entrySize <= ownerSize || headerSize < 0 || offset + listSize > data.Length) break;

                int end = offset + listSize;
                for (int p = offset + listHeader + headerSize; p + entrySize <= end; p += entrySize)
                {
                    if (type != X509Type) { set.Hashes++; continue; }
                    var der = new byte[entrySize - ownerSize];
                    Array.Copy(data, p + ownerSize, der, 0, der.Length);
                    try { set.Certificates.Add(new X509Certificate2(der)); }
                    catch (CryptographicException) { set.Hashes++; }
                }
                offset += listSize;
            }
            return set;
        }

        private static string CommonName(X509Certificate2 c) { return c.GetNameInfo(X509NameType.SimpleName, false); }

        private static bool Contains(SignatureSet set, string name)
        {
            return set != null && set.Certificates.Any(c => CommonName(c).IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        /// <summary>Reads one of the BIOS's built-in key lists. Null means this firmware doesn't expose it.</summary>
        private static SignatureSet DefaultKeys(string name)
        {
            try
            {
                var data = Variable(name, GlobalGuid);
                return data == null ? null : ParseSignatures(data);
            }
            catch (Win32Exception) { return null; }
        }

        private static string DefaultsState(SignatureSet set, string name)
        {
            return set == null ? "Couldn't be read" : Contains(set, name) ? "Yes" : "No";
        }

        private static void Keys(Report r, Section s, BootState state)
        {
            var setup = Variable("SetupMode", GlobalGuid);
            bool setupMode = setup != null && setup.Length > 0 && setup[0] == 1;
            var pk = ParseSignatures(Variable("PK", GlobalGuid));
            var kek = ParseSignatures(Variable("KEK", GlobalGuid));
            var db = ParseSignatures(Variable("db", SecurityGuid));
            var dbx = ParseSignatures(Variable("dbx", SecurityGuid));
            var enforced = Variable("SecureBoot", GlobalGuid);
            var defaultKek = DefaultKeys("KEKDefault");
            state.SecureBootOn = enforced != null && enforced.Length > 0 && enforced[0] == 1;
            state.Db = db;
            state.DefaultDb = DefaultKeys("dbDefault");

            s.Add("Setup Mode", setupMode ? "Yes (keys can be changed; Secure Boot isn't enforced)" : "No");
            s.Add("Platform key (PK)", pk.Total > 0 ? "Installed" : "Missing");
            s.Add("Key exchange keys (KEK)", kek.Total);
            s.Add("Allowed signatures (db)", db.Total);
            s.Add("Revoked signatures (dbx)", dbx.Total);
            s.Add("BIOS default db has " + Windows2023, DefaultsState(state.DefaultDb, Windows2023));
            s.Add("BIOS default KEK has a 2023 Microsoft key", DefaultsState(defaultKek, Kek2023));

            var t = s.Table("Trusted Secure Boot certificates", "Store", "Certificate", "Expires");
            foreach (var pair in new[] { Tuple.Create("PK", pk), Tuple.Create("KEK", kek), Tuple.Create("db", db), Tuple.Create("KEK (BIOS default)", defaultKek ?? new SignatureSet()), Tuple.Create("db (BIOS default)", state.DefaultDb ?? new SignatureSet()) })
                foreach (var c in pair.Item2.Certificates)
                    t.Rows.Add(new[] { pair.Item1, CommonName(c), Fmt.Date(c.NotAfter) });

            bool has2011 = Contains(db, "Windows Production PCA 2011");
            bool has2023 = Contains(db, Windows2023);
            state.Has2023 = has2023;

            if (setupMode || pk.Total == 0 || db.Total == 0)
                r.Find(Severity.Warning, "Secure Boot keys are missing", "The firmware has no complete set of keys, which is common after a BIOS update. Secure Boot can't verify Windows like this.",
                    "In BIOS setup, open Boot > Secure Boot > Key Management and install the default keys. Then set the OS Type to Windows UEFI mode.");
            else if (!has2011 && !has2023)
                r.Find(Severity.Warning, "Firmware doesn't trust Windows boot files", "The allowed list (db) has neither Microsoft Windows boot certificate, so Secure Boot would reject Windows.",
                    "In BIOS setup, reinstall the default Secure Boot keys. If they're still absent, update the BIOS.");
            else
                state.KeysUsable = true;
        }

        private static void CheckWindowsLoaderTrust(Report r, BootState state)
        {
            if (!state.KeysUsable) return;
            var issuer = state.WindowsLoaderIssuer;
            if (!state.SecureBootOn && !string.IsNullOrEmpty(issuer) && !Contains(state.Db, issuer))
            {
                bool? inDefaults = state.DefaultDb == null ? (bool?)null : Contains(state.DefaultDb, issuer);
                r.Find(Severity.Warning, "Secure Boot would reject Windows' boot file",
                    "bootmgfw.efi is signed by " + issuer + ", which isn't in the firmware's allowed list (db). Turning Secure Boot on would fail with an 'Invalid signature' error, and Windows can't add the certificate itself while Secure Boot is off.",
                    RejectionAdvice(issuer, inDefaults));
            }
            else if (!state.Has2023)
                r.Find(Severity.Info, "Newer Microsoft boot certificate isn't installed", "The firmware doesn't list Windows UEFI CA 2023, which Microsoft is moving Windows boot files to.",
                    "Install all Windows updates and the latest BIOS.");
        }

        private static string RejectionAdvice(string issuer, bool? inDefaults)
        {
            const string recovery = "boot Microsoft's SecureBootRecovery.efi from a FAT32 USB drive, as described in Microsoft's Secure Boot troubleshooting guide. It adds Windows UEFI CA 2023 to db.";
            if (inDefaults == true)
                return "The BIOS's default keys include " + issuer + ". In BIOS setup, open Boot > Secure Boot > Key Management, install the default keys, then set OS Type to Windows UEFI mode. Don't only clear the keys.";
            if (inDefaults == false)
                return "Installing the default keys won't help, because they don't include " + issuer + ". Update the BIOS if a newer version exists. Otherwise, " + recovery;
            return "Feverfew couldn't read the BIOS's default keys, so it can't tell whether installing them would help. Update the BIOS if a newer version exists. Otherwise, " + recovery;
        }

        private static void CertificateUpdate(Report r, Section s, BootState state)
        {
            var pending = Reg.Machine(SecureBootKey, "AvailableUpdates");
            var status = Reg.Machine(SecureBootKey + @"\Servicing", "UEFICA2023Status");
            var error = Reg.Machine(SecureBootKey + @"\Servicing", "UEFICA2023Error");
            var errorEvent = Reg.Machine(SecureBootKey + @"\Servicing", "UEFICA2023ErrorEvent");

            if (pending != null) s.Add("Certificate update queue (AvailableUpdates)", "0x" + unchecked((uint)Convert.ToInt32(pending)).ToString("X", CultureInfo.InvariantCulture));
            if (status != null) s.Add("Certificate update status", status);
            if (error != null) s.Add("Certificate update error", "0x" + unchecked((uint)Convert.ToInt32(error)).ToString("X", CultureInfo.InvariantCulture));
            if (!state.SecureBootOn && state.Db != null) s.Note("Secure Boot is off, so Windows won't apply its Secure Boot certificate update.");

            if (error != null && Convert.ToInt32(error) != 0)
                r.Find(Severity.Warning, "Secure Boot certificate update reported an error",
                    "Error 0x" + unchecked((uint)Convert.ToInt32(error)).ToString("X", CultureInfo.InvariantCulture) + (errorEvent != null ? ", event " + errorEvent : "") + ".",
                    "Check 'Secure Boot certificate update events', and install the latest BIOS if the firmware refused a write.");

            var filter = string.Join(" or ", UpdateEvents.Keys.Select(id => "EventID=" + id));
            var query = new EventLogQuery("System", PathType.LogName, "*[System[Provider[@Name='" + UpdateEventProvider + "'] and (" + filter + ")]]") { ReverseDirection = true };
            // The same event repeats at every startup, so a failure has to survive a long run of them.
            var newest = new Dictionary<int, DateTime?>();
            var counts = new Dictionary<int, int>();
            using (var reader = new EventLogReader(query))
            {
                EventRecord e;
                for (int n = 0; n < MaxUpdateEvents && (e = reader.ReadEvent()) != null; n++)
                    using (e)
                    {
                        if (!newest.ContainsKey(e.Id)) { newest[e.Id] = e.TimeCreated; counts[e.Id] = 0; }
                        counts[e.Id]++;
                    }
            }
            if (newest.Count == 0) return;
            var t = s.Table("Secure Boot certificate update events", "Last seen", "Count", "ID", "Meaning");
            foreach (var kv in newest.OrderByDescending(x => x.Value))
                t.Rows.Add(new[] { Fmt.Seconds(kv.Value), counts[kv.Key].ToString(CultureInfo.InvariantCulture), kv.Key.ToString(CultureInfo.InvariantCulture), UpdateEvents[kv.Key] });
        }

        private static string ReadUtf16(byte[] d, ref int p, int end)
        {
            int start = p;
            while (p + 1 < end && (d[p] != 0 || d[p + 1] != 0)) p += 2;
            var text = Encoding.Unicode.GetString(d, start, p - start);
            p += 2;
            return text;
        }

        private static string FilePath(byte[] d, int p, int end)
        {
            while (p + 4 <= end)
            {
                int type = d[p], sub = d[p + 1], length = BitConverter.ToUInt16(d, p + 2);
                if (type == 0x7F || length < 4 || p + length > end) break;
                if (type == 4 && sub == 4) return Encoding.Unicode.GetString(d, p + 4, length - 4).TrimEnd('\0');
                p += length;
            }
            return "";
        }

        private static void Entries(Report r, Section s)
        {
            var order = Variable("BootOrder", GlobalGuid);
            var t = s.Table("Firmware boot entries", "Order", "Entry", "File", "Enabled");
            bool hasWindows = false;
            string first = null;
            for (int i = 0; order != null && i + 1 < order.Length; i += 2)
            {
                var id = BitConverter.ToUInt16(order, i);
                var d = Variable("Boot" + id.ToString("X4"), GlobalGuid);
                if (d == null || d.Length < 8) continue;
                int p = 6;
                var name = ReadUtf16(d, ref p, d.Length);
                var file = FilePath(d, p, Math.Min(d.Length, p + BitConverter.ToUInt16(d, 4)));
                t.Rows.Add(new[] { (i / 2 + 1).ToString(), name, file.Length > 0 ? file : "Firmware device", (BitConverter.ToUInt32(d, 0) & 1) == 1 ? "Yes" : "No" });
                if (string.Equals(file, WindowsLoader, StringComparison.OrdinalIgnoreCase)) hasWindows = true;
                if (first == null) first = name;
            }
            if (order != null && !hasWindows)
                r.Find(Severity.Warning, "No Windows Boot Manager entry in firmware", "The firmware's boot list has no entry for Windows.", "From an administrator prompt, run: mountvol S: /s, then bcdboot C:\\Windows /s S: /f UEFI");
            if (first != null) s.Add("First boot entry", first);
        }

        private static void Loaders(Report r, Section s, BootState state)
        {
            if (!Scanner.IsElevated()) throw new UnauthorizedAccessException();
            var partitions = Wmi.Query(@"root\Microsoft\Windows\Storage", "SELECT DiskNumber, GptType, AccessPaths, IsSystem FROM MSFT_Partition")
                .Where(p => p.Str("GptType").Trim('{', '}').Equals(EfiPartitionType, StringComparison.OrdinalIgnoreCase)).ToList();

            var t = s.Table("EFI boot loaders", "Disk", "File", "Size", "Date", "Signed by", "Certificate issuer");
            bool windowsFound = false;
            foreach (var p in partitions)
            {
                var paths = p.Raw("AccessPaths") as string[];
                var root = paths == null ? null : paths.FirstOrDefault(a => a.StartsWith(@"\\?\Volume", StringComparison.OrdinalIgnoreCase));
                if (root == null) continue;
                var efi = root + "EFI";
                if (!Directory.Exists(efi)) continue;
                foreach (var file in Directory.GetFiles(efi, "*.efi", SearchOption.AllDirectories).OrderBy(f => f, StringComparer.OrdinalIgnoreCase).Take(MaxLoaders))
                {
                    var relative = "\\" + file.Substring(root.Length);
                    var info = new FileInfo(file);
                    string subject = "Not signed", issuer = "";
                    try
                    {
                        using (var c = new X509Certificate2(X509Certificate.CreateFromSignedFile(file)))
                        {
                            subject = c.GetNameInfo(X509NameType.SimpleName, false);
                            issuer = c.GetNameInfo(X509NameType.SimpleName, true);
                        }
                    }
                    catch (CryptographicException) { }
                    t.Rows.Add(new[] { p.Str("DiskNumber"), relative, Fmt.Bytes(info.Length), Fmt.Date(info.LastWriteTime), subject, issuer });
                    if (relative.Equals(WindowsLoader, StringComparison.OrdinalIgnoreCase))
                    {
                        // Another disk can hold an old copy, so the partition Windows started from wins.
                        if (!windowsFound || p.Bool("IsSystem") == true) state.WindowsLoaderIssuer = issuer;
                        windowsFound = true;
                    }
                }
            }
            if (!windowsFound)
                r.Find(Severity.Warning, "Windows boot file not found on an EFI partition", "No EFI partition contains bootmgfw.efi.", "From an administrator prompt, run: mountvol S: /s, then bcdboot C:\\Windows /s S: /f UEFI");
            s.Note("Feverfew lists who signed each boot loader, but doesn't test whether the revocation list (dbx) blocks it.");
        }
    }
}
