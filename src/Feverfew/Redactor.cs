using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Feverfew
{
    /// <summary>Hides names, serial numbers, MAC addresses and public IPs everywhere in a finished report.</summary>
    public static class Redactor
    {
        public const string Hidden = "[hidden]";

        // Placeholders that boards report instead of a real value. They identify nobody and are useful to see.
        private static readonly HashSet<string> Junk = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "To be filled by O.E.M.", "To Be Filled By O.E.M.", "Default string", "System Serial Number", "Not Specified", "Not Applicable",
            "None", "N/A", "NA", "Unknown", "0", "00000000", "0000000000", "123456789", "1234567890", "SerialNumber", "Base Board Serial Number",
            "Chassis Serial Number", "O.E.M.", "WORKGROUP", "OEM", "Administrator", "SYSTEM", "Local", "Windows", "Data", "New Volume", "03000200-0400-0500-0006-000700080009",
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", "00000000-0000-0000-0000-000000000000"
        };

        private static readonly Regex UserPath = new Regex(@"([A-Za-z]:\\Users\\)[^\\""'<>|:*?\r\n]+", RegexOptions.Compiled);
        private static readonly Regex Email = new Regex(@"[\w.+-]+@[\w-]+(\.[\w-]+)+", RegexOptions.Compiled);

        public static void Apply(Report report)
        {
            var values = report.PrivateValues.Select(v => v.Trim()).Where(v => v.Length > 0 && !Junk.Contains(v)).ToList();
            var exact = new HashSet<string>(values, StringComparer.OrdinalIgnoreCase);
            var inText = values.Where(v => v.Length >= 4).OrderByDescending(v => v.Length).Select(Regex.Escape).ToList();
            var pattern = inText.Count == 0 ? null
                : new Regex(@"(?<![\p{L}\p{N}_])(?:" + string.Join("|", inText) + @")(?![\p{L}\p{N}_])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

            Func<string, string> clean = text =>
            {
                if (string.IsNullOrEmpty(text)) return text;
                if (exact.Contains(text.Trim())) return Hidden;
                text = UserPath.Replace(text, "$1" + Hidden);
                text = Email.Replace(text, Hidden);
                return pattern == null ? text : pattern.Replace(text, Hidden);
            };

            foreach (var f in report.Summary) f.Value = clean(f.Value);
            foreach (var f in report.Findings) { f.Title = clean(f.Title); f.Detail = clean(f.Detail); f.Advice = clean(f.Advice); }
            foreach (var s in report.Sections)
            {
                foreach (var f in s.Facts) f.Value = clean(f.Value);
                for (int i = 0; i < s.Notes.Count; i++) s.Notes[i] = clean(s.Notes[i]);
                foreach (var t in s.Tables)
                    foreach (var row in t.Rows)
                        for (int i = 0; i < row.Length; i++) row[i] = clean(row[i]);
            }
        }
    }
}
