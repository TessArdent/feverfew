using System;
using System.Collections.Generic;

namespace Feverfew
{
    public enum Severity { Critical, Warning, Info, Good }

    public sealed class Finding
    {
        public Severity Severity;
        public string Title;
        public string Detail;
        public string Advice;
    }

    public sealed class Fact
    {
        public string Name;
        public string Value;
    }

    public sealed class Table
    {
        public string Title;
        public string[] Columns;
        public List<string[]> Rows = new List<string[]>();
    }

    public sealed class Section
    {
        public string Title;
        public List<Fact> Facts = new List<Fact>();
        public List<Table> Tables = new List<Table>();
        public List<string> Notes = new List<string>();

        public Section(string title) { Title = title; }

        public void Add(string name, object value)
        {
            var text = value == null ? "" : value.ToString().Trim();
            Facts.Add(new Fact { Name = name, Value = text.Length == 0 ? "Unknown" : text });
        }

        public Table Table(string title, params string[] columns)
        {
            var t = new Table { Title = title, Columns = columns };
            Tables.Add(t);
            return t;
        }

        public void Note(string text) { Notes.Add(text); }
    }

    /// <summary>Facts one collector needs from another (used by the Windows 11 check and the summary).</summary>
    public sealed class Signals
    {
        public bool? Uefi;
        public bool? SecureBoot;
        public bool? TpmPresent;
        public string TpmSpec;
        public double? RamGb;
        public double? SystemDiskGb;
        public bool? SystemDiskGpt;
        public int? CpuCores;
        public int? CpuMhz;
        public int? WindowsBuild;
    }

    public sealed class Report
    {
        public DateTime Created = DateTime.Now;
        public string Version;
        public bool Elevated;
        public bool IdentifiersIncluded;
        public bool NetworkTests = true;
        public Signals Signals = new Signals();
        public List<Section> Sections = new List<Section>();
        public List<Finding> Findings = new List<Finding>();
        public List<Fact> Summary = new List<Fact>();
        public HashSet<string> PrivateValues = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public Section NewSection(string title)
        {
            var s = new Section(title);
            Sections.Add(s);
            return s;
        }

        public void Find(Severity severity, string title, string detail, string advice = null)
        {
            Findings.Add(new Finding { Severity = severity, Title = title, Detail = detail, Advice = advice });
        }

        public void AddSummary(string name, string value)
        {
            Summary.Add(new Fact { Name = name, Value = string.IsNullOrWhiteSpace(value) ? "Unknown" : value.Trim() });
        }

        /// <summary>Registers an identifying value so it is hidden wherever it appears, and returns it.</summary>
        public string Private(string value)
        {
            if (!string.IsNullOrWhiteSpace(value)) PrivateValues.Add(value.Trim());
            return value;
        }

        /// <summary>Hides a free-text label in its own cell. Labels are often ordinary words, so they aren't hidden everywhere.</summary>
        public string Label(string value)
        {
            return IdentifiersIncluded || string.IsNullOrWhiteSpace(value) ? value : Redactor.Hidden;
        }

        public void Merge(Report other)
        {
            Sections.AddRange(other.Sections);
            Findings.AddRange(other.Findings);
            Summary.AddRange(other.Summary);
            PrivateValues.UnionWith(other.PrivateValues);
        }
    }
}
