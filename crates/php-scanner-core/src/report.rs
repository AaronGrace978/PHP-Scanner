use crate::advisory::RuntimeStatus;
use crate::finding::{Finding, Severity};
use crate::rules;
use crate::scanner::{AdvisoryVerdict, ScanReport, TOOL_NAME, TOOL_VERSION};
use html_escape::encode_text as esc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Json,
    Sarif,
    Html,
    Csv,
}

impl Format {
    pub fn extension(self) -> &'static str {
        match self {
            Format::Json => "json",
            Format::Sarif => "sarif",
            Format::Html => "html",
            Format::Csv => "csv",
        }
    }
}

impl FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "json" => Ok(Format::Json),
            "sarif" => Ok(Format::Sarif),
            "html" => Ok(Format::Html),
            "csv" => Ok(Format::Csv),
            o => Err(format!("unknown report format '{o}' (expected json, sarif, html, csv)")),
        }
    }
}

pub fn render(report: &ScanReport, format: Format) -> String {
    match format {
        Format::Json => serde_json::to_string_pretty(report).unwrap_or_default(),
        Format::Sarif => sarif(report),
        Format::Html => html(report),
        Format::Csv => csv(report),
    }
}

fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

pub fn sarif(report: &ScanReport) -> String {
    let used: BTreeSet<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    let rule_list: Vec<&rules::Rule> = rules::all().iter().filter(|r| used.contains(r.id)).collect();
    let rule_index = |id: &str| rule_list.iter().position(|r| r.id == id).unwrap_or(0);
    let sarif_rules: Vec<_> = rule_list
        .iter()
        .map(|r| {
            let mut tags = vec!["security".to_string(), r.category.label().to_string()];
            if let Some(c) = r.cwe {
                tags.push(format!("external/cwe/cwe-{c}"));
            }
            json!({
                "id": r.id,
                "name": r.id.split('-').map(|w| { let mut c = w.chars(); c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default() }).collect::<String>(),
                "shortDescription": { "text": r.title },
                "fullDescription": { "text": r.description },
                "help": { "text": r.remediation, "markdown": format!("**{}**\n\n{}\n\n**Remediation:** {}", r.title, r.description, r.remediation) },
                "defaultConfiguration": { "level": sarif_level(r.severity) },
                "properties": {
                    "security-severity": format!("{:.1}", r.severity.score()),
                    "precision": "high",
                    "tags": tags,
                }
            })
        })
        .collect();
    let results: Vec<_> = report
        .findings
        .iter()
        .map(|f| {
            let mut v = json!({
                "ruleId": f.rule_id,
                "ruleIndex": rule_index(&f.rule_id),
                "level": sarif_level(f.severity),
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file, "uriBaseId": "%SRCROOT%" },
                        "region": {
                            "startLine": f.line,
                            "startColumn": f.column,
                            "endLine": f.end_line.max(f.line),
                            "endColumn": if f.end_line > f.line || f.end_column > f.column { f.end_column } else { f.column + 1 },
                            "snippet": { "text": f.snippet },
                        }
                    }
                }],
                "partialFingerprints": { "phpScanner/v1": f.fingerprint },
                "properties": { "confidence": f.confidence.as_str(), "severity": f.severity.as_str() },
            });
            if f.flow.len() > 1 {
                let locs: Vec<_> = f
                    .flow
                    .iter()
                    .map(|s| json!({
                        "location": {
                            "physicalLocation": {
                                "artifactLocation": { "uri": f.file, "uriBaseId": "%SRCROOT%" },
                                "region": { "startLine": s.line }
                            },
                            "message": { "text": s.description }
                        }
                    }))
                    .collect();
                v["codeFlows"] = json!([{ "threadFlows": [{ "locations": locs }] }]);
            }
            v
        })
        .collect();
    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "semanticVersion": TOOL_VERSION,
                    "informationUri": "https://github.com/php-scanner/php-scanner",
                    "rules": sarif_rules,
                }
            },
            "invocations": [{ "executionSuccessful": !report.cancelled, "startTimeUtc": report.started_at }],
            "results": results,
        }]
    });
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

fn csv_field(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@']) { format!("'{s}") } else { s.to_string() };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

pub fn csv(report: &ScanReport) -> String {
    let mut out = String::from("severity,confidence,rule_id,title,cwe,file,line,column,message,snippet,fingerprint\n");
    for f in &report.findings {
        let row = [
            f.severity.as_str().to_string(),
            f.confidence.as_str().to_string(),
            f.rule_id.clone(),
            f.title.clone(),
            f.cwe.map(|c| format!("CWE-{c}")).unwrap_or_default(),
            f.file.clone(),
            f.line.to_string(),
            f.column.to_string(),
            f.message.clone(),
            f.snippet.clone(),
            f.fingerprint.clone(),
        ];
        out.push_str(&row.iter().map(|c| csv_field(c)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

fn sev_color(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "#b91c1c",
        Severity::High => "#ea580c",
        Severity::Medium => "#ca8a04",
        Severity::Low => "#2563eb",
        Severity::Info => "#6b7280",
    }
}

fn status_label(s: RuntimeStatus) -> (&'static str, &'static str) {
    match s {
        RuntimeStatus::Vulnerable => ("Vulnerable", "#b91c1c"),
        RuntimeStatus::Unsupported => ("Unsupported", "#7f1d1d"),
        RuntimeStatus::Unverified => ("Verify", "#ca8a04"),
        RuntimeStatus::Patched => ("Patched", "#15803d"),
    }
}

fn finding_html(f: &Finding) -> String {
    let ctx: String = f
        .context
        .iter()
        .map(|c| {
            let cls = if c.line == f.line { " class=\"hit\"" } else { "" };
            format!("<div{cls}><span class=\"ln\">{}</span>{}</div>", c.line, esc(&c.text))
        })
        .collect();
    let flow = if f.flow.is_empty() {
        String::new()
    } else {
        let steps: String = f.flow.iter().map(|s| format!("<li>Line {}: {}</li>", s.line, esc(&s.description))).collect();
        format!("<h4>Data flow</h4><ol class=\"flow\">{steps}</ol>")
    };
    let cwe = f.cwe.map(|c| format!(" · <a href=\"https://cwe.mitre.org/data/definitions/{c}.html\">CWE-{c}</a>")).unwrap_or_default();
    let owasp = f.owasp.as_deref().map(|o| format!(" · {}", esc(o))).unwrap_or_default();
    format!(
        r#"<details class="finding" data-sev="{sev}"><summary><span class="sev" style="background:{color}">{sev}</span><strong>{title}</strong><span class="loc">{file}:{line}</span></summary>
<div class="body"><p>{msg}</p><p class="meta">Rule <code>{rule}</code> · confidence {conf}{cwe}{owasp}</p><pre class="code">{ctx}</pre>{flow}<p class="fix"><strong>Fix:</strong> {fix}</p></div></details>"#,
        sev = f.severity,
        color = sev_color(f.severity),
        title = esc(&f.title),
        file = esc(&f.file),
        line = f.line,
        msg = esc(&f.message),
        rule = esc(&f.rule_id),
        conf = f.confidence,
        fix = esc(&f.remediation),
    )
}

pub fn html(report: &ScanReport) -> String {
    let cards: String = Severity::ALL
        .iter()
        .map(|s| {
            let n = report.summary.by_severity.get(s.as_str()).copied().unwrap_or(0);
            format!("<div class=\"card\" style=\"border-top:4px solid {}\"><div class=\"n\">{n}</div><div>{}</div></div>", sev_color(*s), s)
        })
        .collect();

    let advisories: String = report
        .advisories
        .iter()
        .map(|a| {
            let (verdict, color) = match a.verdict {
                AdvisoryVerdict::ActionRequired => ("ACTION REQUIRED", "#b91c1c"),
                AdvisoryVerdict::Verify => ("VERIFY PRODUCTION RUNTIMES", "#ca8a04"),
                AdvisoryVerdict::PatchedInSource => ("PATCHED IN SOURCE", "#15803d"),
            };
            let rows: String = a
                .runtimes
                .iter()
                .map(|r| {
                    let (l, c) = status_label(r.status);
                    format!("<tr><td><span class=\"pill\" style=\"background:{c}\">{l}</span></td><td>{}</td><td><code>{}</code></td><td>{}:{}</td></tr>",
                        esc(&r.kind), esc(&r.reference), esc(&r.location), r.line)
                })
                .chain(a.local_runtimes.iter().map(|r| {
                    let (l, c) = status_label(r.status);
                    format!("<tr><td><span class=\"pill\" style=\"background:{c}\">{l}</span></td><td>Installed on this machine ({})</td><td><code>{}</code></td><td>{}</td></tr>",
                        esc(r.sapi.as_deref().unwrap_or("php")), esc(r.version.as_deref().unwrap_or("unknown")), esc(&r.binary))
                }))
                .collect();
            let table = if rows.is_empty() {
                "<p>No PHP runtime references (Composer platform, Dockerfiles, compose files, OS packages, version files) were found in the scanned source. Verify the runtimes on your servers directly.</p>".to_string()
            } else {
                format!("<table><thead><tr><th>Status</th><th>Source</th><th>Runtime</th><th>Location</th></tr></thead><tbody>{rows}</tbody></table>")
            };
            let actions: String = a.advisory.actions.iter().map(|x| format!("<li>{}</li>", esc(x))).collect();
            let sources: String = a.advisory.sources.iter().map(|s| format!("<li><a href=\"{}\">{}</a></li>", esc(&s.url), esc(&s.name))).collect();
            format!(
                r#"<section class="advisory"><h2>{title}</h2><p><span class="pill" style="background:{color}">{verdict}</span> {cves} · published {published} · fixed in {fixed}</p><p>{summary}</p>
<div class="stats"><span>{related} configuration findings</span><span>{comp} compromise indicators</span><span>{secrets} secrets to rotate</span></div>{table}
<h3>Required actions</h3><ol>{actions}</ol><h3>Sources</h3><ul>{sources}</ul></section>"#,
                title = esc(&a.advisory.title),
                cves = esc(&a.advisory.cves.join(", ")),
                published = esc(&a.advisory.published),
                fixed = esc(&a.advisory.fixed_list()),
                summary = esc(&a.advisory.summary),
                related = a.related_findings,
                comp = a.compromise_indicators,
                secrets = a.secrets_to_rotate,
            )
        })
        .collect();

    let findings: String = report.findings.iter().map(finding_html).collect();
    let empty = if report.findings.is_empty() { "<p>No findings.</p>" } else { "" };
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{tool} report – {root}</title>
<style>
body{{font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f8fafc;color:#0f172a}}
header{{background:#0f172a;color:#fff;padding:24px 32px}}header h1{{margin:0 0 4px;font-size:22px}}header p{{margin:0;color:#cbd5e1}}
main{{padding:24px 32px;max-width:1200px}}.cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}}
.card{{background:#fff;border-radius:8px;padding:12px 20px;min-width:110px;box-shadow:0 1px 2px #0001;text-transform:capitalize}}.card .n{{font-size:26px;font-weight:700}}
.advisory{{background:#fff;border:1px solid #fecaca;border-radius:8px;padding:16px 20px;margin-bottom:24px}}.advisory h2{{margin-top:0}}
.stats{{display:flex;gap:16px;color:#475569;margin:8px 0}}
table{{border-collapse:collapse;width:100%;margin:8px 0}}td,th{{border-bottom:1px solid #e2e8f0;padding:6px 8px;text-align:left;vertical-align:top}}
.pill,.sev{{display:inline-block;color:#fff;border-radius:999px;padding:1px 10px;font-size:12px;font-weight:600;text-transform:uppercase}}
.finding{{background:#fff;border-radius:8px;margin-bottom:8px;box-shadow:0 1px 2px #0001}}.finding summary{{cursor:pointer;padding:10px 14px;display:flex;gap:12px;align-items:center}}
.finding .loc{{margin-left:auto;color:#64748b;font-family:ui-monospace,monospace;font-size:12px}}.finding .body{{padding:0 16px 12px}}
.meta{{color:#64748b}}pre.code{{background:#0f172a;color:#e2e8f0;padding:10px;border-radius:6px;overflow:auto;font-size:12px}}
pre.code .ln{{display:inline-block;width:44px;color:#64748b;user-select:none}}pre.code .hit{{background:#7f1d1d}}
.fix{{background:#f0fdf4;border-left:3px solid #16a34a;padding:8px 12px}}code{{font-family:ui-monospace,monospace}}
</style></head><body>
<header><h1>{tool} security report</h1><p>{root} · {files} files · {lines} lines · {ms} ms · {started} · advisory DB {db}</p></header>
<main><div class="cards">{cards}</div>{advisories}<h2>Findings ({total})</h2>{empty}{findings}</main></body></html>"#,
        tool = TOOL_NAME,
        root = esc(&report.root),
        files = report.files_scanned,
        lines = report.lines_scanned,
        ms = report.duration_ms,
        started = esc(&report.started_at),
        db = esc(&report.advisory_db_version),
        total = report.findings.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_escaping_and_formula_guard() {
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("=cmd()"), "'=cmd()");
        assert_eq!(csv_field("plain"), "plain");
    }
}
