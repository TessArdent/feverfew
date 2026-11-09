using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Management;
using Microsoft.Win32;

namespace Feverfew
{
    /// <summary>One WMI object, copied so it can outlive the query.</summary>
    public sealed class Row
    {
        private readonly Dictionary<string, object> values = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

        public Row(ManagementBaseObject source)
        {
            foreach (var p in source.Properties) values[p.Name] = p.Value;
        }

        public object Raw(string name)
        {
            object v;
            return values.TryGetValue(name, out v) ? v : null;
        }

        public string Str(string name)
        {
            var v = Raw(name);
            if (v == null) return "";
            var strings = v as string[];
            if (strings != null) return string.Join(", ", strings).Trim();
            return Convert.ToString(v, CultureInfo.InvariantCulture).Trim();
        }

        public long? Long(string name)
        {
            var v = Raw(name);
            if (v == null) return null;
            try { return Convert.ToInt64(v, CultureInfo.InvariantCulture); }
            catch (Exception) { return null; }
        }

        public bool? Bool(string name)
        {
            var v = Raw(name);
            if (v == null) return null;
            try { return Convert.ToBoolean(v, CultureInfo.InvariantCulture); }
            catch (Exception) { return null; }
        }

        public DateTime? Date(string name)
        {
            var s = Str(name);
            if (s.Length == 0) return null;
            try { return ManagementDateTimeConverter.ToDateTime(s); }
            catch (Exception) { return null; }
        }
    }

    public static class Wmi
    {
        private static ManagementObjectSearcher Searcher(string ns, string wql)
        {
            var options = new EnumerationOptions { Timeout = TimeSpan.FromSeconds(60), ReturnImmediately = true, Rewindable = false };
            return new ManagementObjectSearcher(new ManagementScope(ns), new ObjectQuery(wql), options);
        }

        public static List<Row> Query(string ns, string wql)
        {
            var rows = new List<Row>();
            using (var searcher = Searcher(ns, wql))
            using (var results = searcher.Get())
            {
                foreach (ManagementBaseObject o in results)
                    using (o) rows.Add(new Row(o));
            }
            return rows;
        }

        public static List<Row> Cim(string wql) { return Query(@"root\cimv2", wql); }

        /// <summary>Runs a query and pairs each result with the first related object of the given class.</summary>
        public static List<KeyValuePair<Row, Row>> QueryRelated(string ns, string wql, string relatedClass)
        {
            var pairs = new List<KeyValuePair<Row, Row>>();
            using (var searcher = Searcher(ns, wql))
            using (var results = searcher.Get())
            {
                foreach (ManagementObject o in results)
                {
                    using (o)
                    {
                        Row related = null;
                        try
                        {
                            foreach (ManagementObject r in o.GetRelated(relatedClass))
                                using (r) { if (related == null) related = new Row(r); }
                        }
                        catch (ManagementException) { /* needs admin or unsupported by this drive */ }
                        pairs.Add(new KeyValuePair<Row, Row>(new Row(o), related));
                    }
                }
            }
            return pairs;
        }
    }

    public static class Reg
    {
        public static object Get(RegistryHive hive, string key, string value, RegistryView view = RegistryView.Registry64)
        {
            using (var root = RegistryKey.OpenBaseKey(hive, view))
            using (var k = root.OpenSubKey(key))
                return k == null ? null : k.GetValue(value);
        }

        public static object Machine(string key, string value) { return Get(RegistryHive.LocalMachine, key, value); }

        public static bool MachineKeyExists(string key)
        {
            using (var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (var k = root.OpenSubKey(key))
                return k != null;
        }
    }

    public static class Fmt
    {
        public static string Bytes(long? bytes)
        {
            if (bytes == null || bytes < 0) return "Unknown";
            string[] units = { "B", "KB", "MB", "GB", "TB", "PB" };
            double v = bytes.Value;
            int i = 0;
            while (v >= 1024 && i < units.Length - 1) { v /= 1024; i++; }
            return v.ToString(i == 0 ? "0" : "0.#", CultureInfo.InvariantCulture) + " " + units[i];
        }

        public static string Date(DateTime? d) { return d == null ? "Unknown" : d.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture); }
        public static string Time(DateTime? d) { return d == null ? "Unknown" : d.Value.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture); }
        public static string Seconds(DateTime? d) { return d == null ? "Unknown" : d.Value.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture); }
        public static string YesNo(bool? b) { return b == null ? "Unknown" : b.Value ? "Yes" : "No"; }
        public static string Num(double v, string format = "0.#") { return v.ToString(format, CultureInfo.InvariantCulture); }

        public static string Clip(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return "";
            s = string.Join(" ", s.Split((char[])null, StringSplitOptions.RemoveEmptyEntries));
            return s.Length <= max ? s : s.Substring(0, max) + "…";
        }

        public static string Duration(TimeSpan t)
        {
            if (t.TotalDays >= 1) return (int)t.TotalDays + " d " + t.Hours + " h";
            if (t.TotalHours >= 1) return (int)t.TotalHours + " h " + t.Minutes + " min";
            return (int)t.TotalMinutes + " min";
        }
    }

    public static class Guard
    {
        /// <summary>Runs one part of a collector; a failure becomes a note instead of ending the scan.</summary>
        public static void Try(Section section, string what, Action action)
        {
            int tablesBefore = section.Tables.Count;
            try { action(); }
            catch (Exception e)
            {
                // An empty table left by a failed read would look like "checked, found nothing".
                for (int i = section.Tables.Count - 1; i >= tablesBefore; i--)
                    if (section.Tables[i].Rows.Count == 0) section.Tables.RemoveAt(i);
                section.Note(what + ": not available (" + Explain(e) + ").");
            }
        }

        public static string Explain(Exception e)
        {
            if (e is UnauthorizedAccessException) return "needs administrator rights";
            var m = e as ManagementException;
            if (m != null)
            {
                if (m.ErrorCode == ManagementStatus.AccessDenied) return "needs administrator rights";
                if (m.ErrorCode == ManagementStatus.InvalidNamespace || m.ErrorCode == ManagementStatus.InvalidClass
                    || m.ErrorCode == ManagementStatus.NotSupported)
                    return "not supported on this PC";
            }
            var ua = e.InnerException as UnauthorizedAccessException;
            if (ua != null) return "needs administrator rights";
            var text = Fmt.Clip(e.Message, 160);
            return text.Length > 0 ? text : "Windows returned no details";
        }
    }
}
