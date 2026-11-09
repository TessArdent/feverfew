using System.Linq;
using System.Net;
using System.Text;
using System.Web.Script.Serialization;

namespace Feverfew
{
    public static class HtmlReport
    {
        private const int CollapseAbove = 25;

        private const string Css = @"
:root{color-scheme:light dark;--bg:#f7f6f1;--card:#fff;--text:#22261f;--muted:#646b5f;--line:#deddd3;--accent:#4e7a35;
--crit:#b3261e;--critbg:#fbe9e7;--warn:#8a5a00;--warnbg:#fdf3dc;--info:#2a5f8f;--infobg:#e7f0f8;--good:#2e6b2e;--goodbg:#e6f3e2}
@media(prefers-color-scheme:dark){:root{--bg:#171a15;--card:#21251e;--text:#e8eae3;--muted:#a3aa9c;--line:#383e33;--accent:#9ccc7a;
--crit:#ffb4ab;--critbg:#47201c;--warn:#f2c464;--warnbg:#40310f;--info:#a3cdf2;--infobg:#1c3347;--good:#a5d99b;--goodbg:#21391f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 'Segoe UI',system-ui,sans-serif}
main{max-width:1080px;margin:0 auto;padding:28px 16px 60px}
h1{font-size:28px;margin:0;color:var(--accent)}h2{font-size:19px;margin:0 0 12px}h3{font-size:14px;margin:18px 0 6px;color:var(--muted)}
.sub{color:var(--muted);font-size:13px;margin:2px 0 20px}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:18px;margin:14px 0}
dl{display:grid;grid-template-columns:minmax(150px,280px) 1fr;gap:3px 16px;margin:0}dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}
.f{border-radius:6px;padding:10px 12px;margin:8px 0}.f b{display:block}.f p{margin:2px 0 0;font-size:14px}.f .a{font-style:normal;opacity:.85}
.Critical{background:var(--critbg);color:var(--crit)}.Warning{background:var(--warnbg);color:var(--warn)}.Info{background:var(--infobg);color:var(--info)}.Good{background:var(--goodbg);color:var(--good)}
.f p{color:var(--text)}.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:4px 10px 4px 0;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;white-space:nowrap}.note{color:var(--muted);font-size:13px;margin:8px 0 0}
summary{cursor:pointer;color:var(--accent);font-size:13px;margin:6px 0}nav{display:flex;flex-wrap:wrap;gap:2px 14px;font-size:13px;line-height:2}nav a{color:var(--accent);white-space:nowrap}
@media(max-width:600px){dl{grid-template-columns:1fr}dd{margin-bottom:6px}}";

        private static string E(string s) { return WebUtility.HtmlEncode(s ?? ""); }

        public static string Render(Report r)
        {
            var b = new StringBuilder();
            b.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Feverfew report</title><style>")
             .Append(Css).Append("</style></head><body><main><h1>Feverfew report</h1><p class=\"sub\">")
             .Append(E(Fmt.Time(r.Created))).Append(" &middot; Feverfew ").Append(E(r.Version))
             .Append(" &middot; ").Append(r.Elevated ? "Full scan (administrator)" : "Limited scan (no administrator rights)")
             .Append(" &middot; ").Append(r.IdentifiersIncluded ? "Serial numbers and names included" : "Serial numbers and names hidden")
             .Append("</p>");

            b.Append("<section class=\"card\"><h2>At a glance</h2><dl>");
            foreach (var key in new[] { "PC", "Motherboard", "BIOS", "TPM", "CPU", "Memory", "Graphics", "System drive", "Windows" })
            {
                var f = r.Summary.FirstOrDefault(x => x.Name == key);
                if (f != null) b.Append("<dt>").Append(E(f.Name)).Append("</dt><dd>").Append(E(f.Value)).Append("</dd>");
            }
            b.Append("</dl></section>");

            b.Append("<section class=\"card\"><h2>Findings</h2>");
            foreach (var f in r.Findings)
            {
                b.Append("<div class=\"f ").Append(f.Severity).Append("\"><b>").Append(E(f.Severity.ToString())).Append(": ").Append(E(f.Title)).Append("</b>");
                if (!string.IsNullOrEmpty(f.Detail)) b.Append("<p>").Append(E(f.Detail)).Append("</p>");
                if (!string.IsNullOrEmpty(f.Advice)) b.Append("<p class=\"a\">Try: ").Append(E(f.Advice)).Append("</p>");
                b.Append("</div>");
            }
            b.Append("</section><nav>");
            for (int i = 0; i < r.Sections.Count; i++)
                b.Append("<a href=\"#s").Append(i).Append("\">").Append(E(r.Sections[i].Title)).Append("</a>");
            b.Append("</nav>");

            for (int i = 0; i < r.Sections.Count; i++)
            {
                var s = r.Sections[i];
                b.Append("<section class=\"card\" id=\"s").Append(i).Append("\"><h2>").Append(E(s.Title)).Append("</h2>");
                if (s.Facts.Count > 0)
                {
                    b.Append("<dl>");
                    foreach (var f in s.Facts) b.Append("<dt>").Append(E(f.Name)).Append("</dt><dd>").Append(E(f.Value)).Append("</dd>");
                    b.Append("</dl>");
                }
                foreach (var t in s.Tables) AppendTable(b, t);
                foreach (var n in s.Notes) b.Append("<p class=\"note\">").Append(E(n)).Append("</p>");
                b.Append("</section>");
            }
            b.Append("</main></body></html>");
            return b.ToString();
        }

        private static void AppendTable(StringBuilder b, Table t)
        {
            b.Append("<h3>").Append(E(t.Title)).Append("</h3>");
            if (t.Rows.Count == 0) { b.Append("<p class=\"note\">None.</p>"); return; }
            bool collapse = t.Rows.Count > CollapseAbove;
            if (collapse) b.Append("<details><summary>Show all ").Append(t.Rows.Count).Append(" rows</summary>");
            b.Append("<div class=\"scroll\"><table><thead><tr>");
            foreach (var c in t.Columns) b.Append("<th>").Append(E(c)).Append("</th>");
            b.Append("</tr></thead><tbody>");
            foreach (var row in t.Rows)
            {
                b.Append("<tr>");
                foreach (var cell in row) b.Append("<td>").Append(E(cell)).Append("</td>");
                b.Append("</tr>");
            }
            b.Append("</tbody></table></div>");
            if (collapse) b.Append("</details>");
        }
    }

    public static class JsonReport
    {
        public static string Render(Report r)
        {
            var json = new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 16 };
            return json.Serialize(new
            {
                tool = "Feverfew",
                version = r.Version,
                created = r.Created.ToString("o"),
                elevated = r.Elevated,
                identifiersIncluded = r.IdentifiersIncluded,
                summary = r.Summary.ToDictionary(f => f.Name, f => f.Value),
                findings = r.Findings.Select(f => new { severity = f.Severity.ToString(), title = f.Title, detail = f.Detail, advice = f.Advice }),
                sections = r.Sections.Select(s => new
                {
                    title = s.Title,
                    facts = s.Facts.Select(f => new { name = f.Name, value = f.Value }),
                    tables = s.Tables.Select(t => new { title = t.Title, columns = t.Columns, rows = t.Rows }),
                    notes = s.Notes
                })
            });
        }
    }
}
