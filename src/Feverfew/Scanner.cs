using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Threading.Tasks;
using Feverfew.Collectors;

namespace Feverfew
{
    public sealed class ScanOptions
    {
        public string OutputDirectory;
        public bool IncludeIdentifiers;
        public bool NetworkTests = true;
    }

    public sealed class ScanResult
    {
        public string HtmlPath;
        public string JsonPath;
        public Report Report;
    }

    public static class Scanner
    {
        private sealed class Step
        {
            public readonly string Name; public readonly Action<Report> Run; public readonly int TimeoutSeconds;
            public Step(string name, Action<Report> run, int timeoutSeconds = 60) { Name = name; Run = run; TimeoutSeconds = timeoutSeconds; }
        }

        public static bool IsElevated()
        {
            using (var id = WindowsIdentity.GetCurrent())
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static ScanResult Run(ScanOptions options, Action<int, string> progress)
        {
            var report = new Report
            {
                Version = Assembly.GetExecutingAssembly().GetName().Version.ToString(3),
                Elevated = IsElevated(),
                IdentifiersIncluded = options.IncludeIdentifiers,
                NetworkTests = options.NetworkTests
            };

            var steps = new[]
            {
                new Step("Identifying this PC", SystemCollector.Identity),
                new Step("Reading Windows details", SystemCollector.Windows, 90),
                new Step("Reading motherboard and BIOS", SystemCollector.Firmware),
                new Step("Checking TPM and device security", SystemCollector.Tpm),
                new Step("Reading boot entries and Secure Boot keys", BootCollector.Collect),
                new Step("Checking the processor", HardwareCollector.Processor),
                new Step("Checking memory", HardwareCollector.Memory),
                new Step("Checking graphics and displays", HardwareCollector.Graphics),
                new Step("Checking drives", StorageCollector.Collect, 90),
                new Step("Checking the battery", HardwareCollector.Battery),
                new Step("Checking devices", HardwareCollector.Devices),
                new Step("Listing third-party drivers", HardwareCollector.Drivers, 120),
                new Step("Testing the network", NetworkCollector.Collect),
                new Step("Checking settings that affect games", GamingCollector.Settings),
                new Step("Measuring connection quality for games", GamingCollector.Network, 90),
                new Step("Checking graphics for games", GamingCollector.Graphics),
                new Step("Checking protection and updates", SoftwareCollector.Security, 90),
                new Step("Listing software", SoftwareCollector.Programs, 90),
                new Step("Reading crash history and event logs", EventCollector.Collect, 180),
                new Step("Checking Windows 11 readiness", SystemCollector.Windows11Readiness),
                new Step("Adding typical fixes", Fixes.AddToReport)
            };

            var problems = report.NewSection("Scan notes");
            for (int i = 0; i < steps.Length; i++)
            {
                var step = steps[i];
                progress(i * 100 / steps.Length, step.Name);

                // Each step fills its own report, so one that hangs can't change the result after it's abandoned.
                var part = new Report { Signals = report.Signals, NetworkTests = report.NetworkTests, IdentifiersIncluded = report.IdentifiersIncluded };
                var task = Task.Run(() => step.Run(part));
                try
                {
                    if (task.Wait(TimeSpan.FromSeconds(step.TimeoutSeconds))) report.Merge(part);
                    else problems.Note(step.Name + " timed out after " + step.TimeoutSeconds + " seconds and was skipped.");
                }
                catch (AggregateException e)
                {
                    problems.Note(step.Name + " failed: " + Guard.Explain(e.InnerException ?? e));
                }
            }

            if (!report.Elevated)
                report.Find(Severity.Info, "Scan ran without administrator rights", "TPM, BitLocker, drive health counters and crash dumps can't be read without them.", "Run Feverfew again and accept the Windows permission prompt.");
            if (problems.Notes.Count == 0) report.Sections.Remove(problems);
            else { report.Sections.Remove(problems); report.Sections.Add(problems); }

            report.Findings = report.Findings.OrderBy(f => f.Severity).ToList();
            if (!report.Findings.Any(f => f.Severity == Severity.Critical || f.Severity == Severity.Warning))
                report.Find(Severity.Good, "No serious problems found", "None of Feverfew's automatic checks raised a warning.");

            progress(97, "Writing the report");
            if (!options.IncludeIdentifiers) Redactor.Apply(report);

            Directory.CreateDirectory(options.OutputDirectory);
            var stamp = report.Created.ToString("yyyy-MM-dd-HHmmss");
            var result = new ScanResult
            {
                Report = report,
                HtmlPath = Path.Combine(options.OutputDirectory, "Feverfew-report-" + stamp + ".html"),
                JsonPath = Path.Combine(options.OutputDirectory, "Feverfew-report-" + stamp + ".json")
            };
            File.WriteAllText(result.HtmlPath, HtmlReport.Render(report), new System.Text.UTF8Encoding(false));
            File.WriteAllText(result.JsonPath, JsonReport.Render(report), new System.Text.UTF8Encoding(false));
            progress(100, "Done");
            return result;
        }
    }
}
