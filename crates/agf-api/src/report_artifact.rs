//! Deterministic report exports. PDF embeds a licensed font subset and Unicode character maps.
use agf_core::{
    error::DomainResult,
    report::{Report, ReportFormat},
};

pub fn mime(format: ReportFormat) -> &'static str {
    match format {
        ReportFormat::Pdf => "application/pdf",
        ReportFormat::Markdown => "text/markdown; charset=utf-8",
        ReportFormat::Html => "text/html; charset=utf-8",
        ReportFormat::Csv => "text/csv; charset=utf-8",
        ReportFormat::Json => "application/json",
    }
}

pub fn encode(report: &Report) -> DomainResult<(Vec<u8>, &'static str)> {
    let source = report.body.as_deref().unwrap_or_default();
    Ok(match report.format {
        ReportFormat::Markdown => (source.as_bytes().to_vec(), "text/markdown; charset=utf-8"),
        ReportFormat::Pdf => (crate::report_pdf::render(source)?, "application/pdf"),
        ReportFormat::Html => (html(source, &report.title).into_bytes(), "text/html; charset=utf-8"),
        ReportFormat::Json => (
            serde_json::to_vec_pretty(
                &serde_json::json!({"id":report.id,"title":report.title,"kind":report.kind,"range":report.range,"created_at":report.created_at,"markdown":source}),
            )?,
            "application/json",
        ),
        ReportFormat::Csv => {
            let mut csv = String::from("\u{feff}line,text\r\n");
            for (index, line) in source.lines().enumerate() {
                // Prevent spreadsheet formula execution when a title or source contains a formula.
                let prefix = if line.starts_with(['=', '+', '-', '@', '\t', '\r']) { "'" } else { "" };
                csv.push_str(&format!("{},\"{}{}\"\r\n", index + 1, prefix, line.replace('"', "\"\"")));
            }
            (csv.into_bytes(), "text/csv; charset=utf-8")
        }
    })
}

fn escape_html(source: &str) -> String {
    source.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn html(source: &str, title: &str) -> String {
    let mut output = format!(
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><title>{}</title><style>body{{max-width:960px;margin:40px auto;padding:0 24px;font:15px/1.6 sans-serif;color:#293445}}h1,h2,h3{{color:#203f68}}table{{width:100%;border-collapse:collapse;margin:16px 0;table-layout:fixed}}td,th{{border:1px solid #ccd5df;padding:8px;text-align:left;overflow-wrap:anywhere}}th{{background:#edf3fa}}p{{overflow-wrap:anywhere}}@media print{{tr{{break-inside:avoid}}thead{{display:table-header-group}}}}</style></head><body>",
        escape_html(title)
    );
    let mut table = false;
    for line in source.lines().map(str::trim) {
        if line.starts_with('|') {
            if line.chars().all(|c| c.is_whitespace() || "|:-".contains(c)) {
                continue;
            }
            let tag = if table {
                "td"
            } else {
                output.push_str("<table><thead>");
                "th"
            };
            output.push_str("<tr>");
            for cell in line.trim_matches('|').split('|') {
                output.push_str(&format!("<{tag}>{}</{tag}>", escape_html(cell.trim()).replace("&amp;#124;", "|")));
            }
            output.push_str("</tr>");
            if !table {
                output.push_str("</thead><tbody>");
            }
            table = true;
        } else {
            if table {
                output.push_str("</tbody></table>");
                table = false;
            }
            if line.is_empty() {
                continue;
            }
            let level = line.chars().take_while(|c| *c == '#').count();
            if (1..=6).contains(&level) {
                output.push_str(&format!("<h{level}>{}</h{level}>", escape_html(line.trim_start_matches('#').trim())));
            } else {
                output.push_str(&format!("<p>{}</p>", escape_html(line)));
            }
        }
    }
    if table {
        output.push_str("</tbody></table>");
    }
    output.push_str("</body></html>");
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn html_renders_tables_without_executing_report_content() {
        let value = html("# 标题\n|名称|内容|\n|---|---|\n|<script>|& test|\n\n普通正文", "<title>");
        assert!(value.contains("<h1>标题</h1>"));
        assert!(value.contains("<td>&lt;script&gt;</td>"));
        assert!(!value.contains("<script>"));
        assert!(value.contains("</tbody></table><p>普通正文</p>"));
    }
}
