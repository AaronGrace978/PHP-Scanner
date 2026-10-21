use crate::advisory::{self, Advisory, AdvisoryDb, LocalRuntime, RuntimeDetection, RuntimeStatus};
use crate::analyzer::{self, RawFinding};
use crate::config::ScanConfig;
use crate::discovery::{self, DiscoveredFile, FileKind};
use crate::finding::{Category, ContextLine, Finding, Severity};
use crate::patterns;
use crate::rules;
use crate::suppress::Suppressions;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub const TOOL_NAME: &str = "PHP Scanner";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    pub files_total: usize,
    pub files_done: usize,
    pub findings: usize,
    pub current_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Baseline {
    pub fingerprints: HashSet<String>,
}

impl Baseline {
    pub fn from_report(r: &ScanReport) -> Self {
        Baseline { fingerprints: r.findings.iter().map(|f| f.fingerprint.clone()).collect() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdvisoryVerdict {
    /// Vulnerable or unsupported runtimes referenced, or mitigations broken.
    ActionRequired,
    /// Runtimes could not be verified from source; check production.
    Verify,
    /// Every referenced runtime is at or above the fixed release.
    PatchedInSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvisoryReport {
    pub advisory: Advisory,
    pub verdict: AdvisoryVerdict,
    pub runtimes: Vec<RuntimeDetection>,
    pub local_runtimes: Vec<LocalRuntime>,
    pub related_findings: usize,
    pub compromise_indicators: usize,
    pub secrets_to_rotate: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub by_severity: BTreeMap<String, usize>,
    pub by_rule: BTreeMap<String, usize>,
    pub by_category: BTreeMap<String, usize>,
    pub total: usize,
    pub suppressed: usize,
    pub baselined: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport {
    pub tool: String,
    pub version: String,
    pub advisory_db_version: String,
    pub root: String,
    pub started_at: String,
    pub duration_ms: u128,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub lines_scanned: usize,
    pub parse_errors: usize,
    pub cancelled: bool,
    pub findings: Vec<Finding>,
    pub summary: Summary,
    pub advisories: Vec<AdvisoryReport>,
    pub errors: Vec<String>,
    pub config: ScanConfig,
}

impl ScanReport {
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    pub fn count_at_least(&self, s: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity >= s).count()
    }
}

pub struct Scanner {
    pub config: ScanConfig,
    pub advisories: AdvisoryDb,
    pub baseline: Option<Baseline>,
    /// Probe PHP binaries installed on this machine for the advisory report.
    pub probe_local_runtimes: bool,
    cancel: Arc<AtomicBool>,
}

struct FileResult {
    findings: Vec<Finding>,
    runtimes: Vec<RuntimeDetection>,
    lines: usize,
    parse_error: bool,
    suppressed: usize,
    skipped: bool,
    error: Option<String>,
}

const UPLOAD_DIRS: &[&str] = &["uploads", "upload", "user_uploads", "useruploads", "attachments", "user-uploads"];

impl Scanner {
    pub fn new(config: ScanConfig) -> Self {
        Scanner {
            config,
            advisories: AdvisoryDb::builtin(),
            baseline: None,
            probe_local_runtimes: false,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel_token(&self) -> Arc<AtomicBool> {
        self.cancel.clone()
    }

    pub fn scan(&self, root: &Path) -> Result<ScanReport, String> {
        self.scan_with_progress(root, &|_| {})
    }

    pub fn scan_with_progress(&self, root: &Path, progress: &(dyn Fn(ScanProgress) + Sync)) -> Result<ScanReport, String> {
        let started = Instant::now();
        let started_at = chrono::Utc::now().to_rfc3339();
        let root = root.canonicalize().map_err(|e| format!("{}: {e}", root.display()))?;
        let files = discovery::walk(&root, &self.config)?;
        let total = files.len();
        let done = AtomicUsize::new(0);
        let found = AtomicUsize::new(0);
        let last_emit = Mutex::new(Instant::now() - std::time::Duration::from_secs(1));

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.config.threads)
            .build()
            .map_err(|e| e.to_string())?;

        progress(ScanProgress { files_total: total, files_done: 0, findings: 0, current_file: String::new() });

        let results: Vec<FileResult> = pool.install(|| {
            files
                .par_iter()
                .filter_map(|f| {
                    if self.cancel.load(Ordering::Relaxed) {
                        return None;
                    }
                    let r = self.scan_file(f);
                    let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                    let n = found.fetch_add(r.findings.len(), Ordering::Relaxed) + r.findings.len();
                    let mut last = last_emit.lock().unwrap();
                    if last.elapsed().as_millis() >= 50 || d == total {
                        *last = Instant::now();
                        drop(last);
                        progress(ScanProgress { files_total: total, files_done: d, findings: n, current_file: f.rel.clone() });
                    }
                    Some(r)
                })
                .collect()
        });

        let cancelled = self.cancel.load(Ordering::Relaxed);
        let mut findings = Vec::new();
        let mut runtimes = Vec::new();
        let mut summary = Summary::default();
        let mut errors = Vec::new();
        let (mut lines, mut parse_errors, mut scanned, mut skipped) = (0, 0, 0, 0);
        for r in results {
            lines += r.lines;
            parse_errors += r.parse_error as usize;
            summary.suppressed += r.suppressed;
            if r.skipped {
                skipped += 1;
            } else {
                scanned += 1;
            }
            if let Some(e) = r.error {
                errors.push(e);
            }
            findings.extend(r.findings);
            runtimes.extend(r.runtimes);
        }

        if let Some(b) = &self.baseline {
            let before = findings.len();
            findings.retain(|f| !b.fingerprints.contains(&f.fingerprint));
            summary.baselined = before - findings.len();
        }

        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.file.cmp(&b.file))
                .then_with(|| a.line.cmp(&b.line))
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        });
        for f in &findings {
            *summary.by_severity.entry(f.severity.to_string()).or_default() += 1;
            *summary.by_rule.entry(f.rule_id.clone()).or_default() += 1;
            *summary.by_category.entry(f.category.label().to_string()).or_default() += 1;
        }
        summary.total = findings.len();

        let advisories = self.advisories.advisories.iter().map(|a| self.advisory_report(a, &runtimes, &findings)).collect();

        Ok(ScanReport {
            tool: TOOL_NAME.into(),
            version: TOOL_VERSION.into(),
            advisory_db_version: self.advisories.version.clone(),
            root: root.display().to_string(),
            started_at,
            duration_ms: started.elapsed().as_millis(),
            files_scanned: scanned,
            files_skipped: skipped,
            lines_scanned: lines,
            parse_errors,
            cancelled,
            findings,
            summary,
            advisories,
            errors,
            config: self.config.clone(),
        })
    }

    fn advisory_report(&self, adv: &Advisory, runtimes: &[RuntimeDetection], findings: &[Finding]) -> AdvisoryReport {
        let runtimes: Vec<RuntimeDetection> = runtimes.iter().filter(|r| r.advisory_id == adv.id).cloned().collect();
        let local_runtimes = if self.probe_local_runtimes { advisory::probe_local_runtimes(adv) } else { Vec::new() };
        let related = findings.iter().filter(|f| f.rule_id.starts_with("php2shell-")).count();
        let compromise = findings.iter().filter(|f| f.category == Category::Malware).count();
        let secrets = findings.iter().filter(|f| f.category == Category::Secrets).count();
        let bad = |s: RuntimeStatus| matches!(s, RuntimeStatus::Vulnerable | RuntimeStatus::Unsupported);
        let action = runtimes.iter().any(|r| bad(r.status))
            || local_runtimes.iter().any(|r| bad(r.status))
            || findings.iter().any(|f| f.rule_id.starts_with("php2shell-") && f.severity >= Severity::High)
            || compromise > 0;
        let all_patched = !runtimes.is_empty() && runtimes.iter().all(|r| r.status == RuntimeStatus::Patched)
            && local_runtimes.iter().all(|r| r.status == RuntimeStatus::Patched);
        let verdict = if action {
            AdvisoryVerdict::ActionRequired
        } else if all_patched {
            AdvisoryVerdict::PatchedInSource
        } else {
            AdvisoryVerdict::Verify
        };
        AdvisoryReport {
            advisory: adv.clone(),
            verdict,
            runtimes,
            local_runtimes,
            related_findings: related,
            compromise_indicators: compromise,
            secrets_to_rotate: secrets,
        }
    }

    fn scan_file(&self, f: &DiscoveredFile) -> FileResult {
        let mut res = FileResult { findings: vec![], runtimes: vec![], lines: 0, parse_error: false, suppressed: 0, skipped: false, error: None };
        if f.size > self.config.max_file_size {
            res.skipped = true;
            return res;
        }
        let bytes = match std::fs::read(&f.path) {
            Ok(b) => b,
            Err(e) => {
                res.skipped = true;
                res.error = Some(format!("{}: {e}", f.rel));
                return res;
            }
        };
        if bytes.iter().take(8192).any(|b| *b == 0) {
            res.skipped = true;
            return res;
        }
        let src = String::from_utf8_lossy(&bytes);
        let src = src.as_ref();
        let starts = patterns::line_starts(src);
        res.lines = starts.len();

        let mut raw: Vec<RawFinding> = Vec::new();
        let mut secret_spans = Vec::new();

        match f.kind {
            FileKind::Php => {
                if let Some(tree) = analyzer::parse(src) {
                    res.parse_error = tree.root_node().has_error();
                    raw.extend(analyzer::analyze(src, &tree));
                } else {
                    res.error = Some(format!("{}: failed to parse", f.rel));
                }
                let p = patterns::scan_text(src, &starts, &f.rel);
                raw.extend(p.findings);
                secret_spans.extend(p.secret_spans);
                self.upload_dir_check(f, src, &mut raw);
            }
            FileKind::Config(kind) => {
                for adv in &self.advisories.advisories {
                    let r = advisory::check_config(adv, kind, &f.rel, src, &starts);
                    raw.extend(r.findings);
                    res.runtimes.extend(r.runtimes);
                }
                let p = patterns::scan_text(src, &starts, &f.rel);
                raw.extend(p.findings.into_iter().filter(|x| x.rule_id == "leaked-secret"));
                secret_spans.extend(p.secret_spans);
            }
            FileKind::Env => {
                let p = patterns::scan_text(src, &starts, &f.rel);
                raw.extend(p.findings.into_iter().filter(|x| x.rule_id == "leaked-secret"));
                secret_spans.extend(p.secret_spans);
            }
            FileKind::Other => {}
        }

        let supp = Suppressions::parse(src);
        let lines: Vec<&str> = src.lines().collect();
        let mut occurrences: HashMap<(String, String), usize> = HashMap::new();
        let mut seen = HashSet::new();
        for r in raw {
            let Some(rule) = rules::get(r.rule_id) else { continue };
            if !self.config.rule_enabled(rule.id) || rule.severity < self.config.min_severity || r.confidence < self.config.min_confidence {
                continue;
            }
            if !seen.insert((r.rule_id, r.start.0, r.start.1)) {
                continue;
            }
            if supp.is_suppressed(rule.id, r.start.0) {
                res.suppressed += 1;
                continue;
            }
            let row = r.start.0.min(lines.len().saturating_sub(1));
            let line_text = lines.get(row).copied().unwrap_or("");
            let snippet = clip(&redact_line(line_text, starts.get(row).copied().unwrap_or(0), &secret_spans), 300);
            let ctx_from = row.saturating_sub(self.config.context_lines);
            let ctx_to = (row + self.config.context_lines).min(lines.len().saturating_sub(1));
            let context = (ctx_from..=ctx_to)
                .filter_map(|i| {
                    lines.get(i).map(|t| ContextLine {
                        line: i + 1,
                        text: clip(&redact_line(t, starts[i], &secret_spans), 300),
                    })
                })
                .collect();
            let norm: String = line_text.split_whitespace().collect::<Vec<_>>().join(" ");
            let occ = occurrences.entry((rule.id.to_string(), norm.clone())).or_insert(0);
            *occ += 1;
            let fingerprint = fingerprint(rule.id, &f.rel, &norm, *occ);
            res.findings.push(Finding {
                fingerprint,
                rule_id: rule.id.to_string(),
                title: rule.title.to_string(),
                message: r.message,
                severity: rule.severity,
                confidence: r.confidence,
                category: rule.category,
                cwe: rule.cwe,
                owasp: rule.owasp.map(|s| s.to_string()),
                file: f.rel.clone(),
                line: r.start.0 + 1,
                column: r.start.1 + 1,
                end_line: r.end.0 + 1,
                end_column: r.end.1 + 1,
                snippet: snippet.trim().to_string(),
                context,
                flow: r.flow,
                remediation: rule.remediation.to_string(),
            });
        }
        res
    }

    fn upload_dir_check(&self, f: &DiscoveredFile, src: &str, raw: &mut Vec<RawFinding>) {
        let lower = f.rel.to_ascii_lowercase();
        let segments: Vec<&str> = lower.split('/').collect();
        let in_upload = segments[..segments.len().saturating_sub(1)].iter().any(|s| UPLOAD_DIRS.contains(s));
        if !in_upload {
            return;
        }
        let stripped: String = src
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with("//") && !l.starts_with('#') && !l.starts_with("/*") && !l.starts_with('*'))
            .collect();
        let trivial = matches!(stripped.as_str(), "<?php" | "<?php?>" | "<?php // Silence is golden." | "<?phpexit;" | "<?phpdie();" | "<?phpexit();");
        if trivial {
            return;
        }
        raw.push(RawFinding {
            rule_id: "php-in-upload-dir",
            message: format!("Executable PHP file '{}' found inside an upload directory.", f.rel),
            confidence: crate::finding::Confidence::Medium,
            start: (0, 0),
            end: (0, 0),
            flow: vec![],
        });
    }
}

fn fingerprint(rule: &str, file: &str, norm_line: &str, occurrence: usize) -> String {
    let mut h = Sha256::new();
    h.update(rule.as_bytes());
    h.update([0]);
    h.update(file.as_bytes());
    h.update([0]);
    h.update(norm_line.as_bytes());
    h.update([0]);
    h.update(occurrence.to_le_bytes());
    let d = h.finalize();
    d.iter().take(10).map(|b| format!("{b:02x}")).collect()
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

/// Masks secret byte ranges that fall on a line starting at `line_start`.
fn redact_line(line: &str, line_start: usize, spans: &[(usize, usize)]) -> String {
    let line_end = line_start + line.len();
    let mut out = line.to_string();
    let mut relevant: Vec<(usize, usize)> = spans
        .iter()
        .filter(|(s, e)| *s < line_end && *e > line_start)
        .map(|(s, e)| (s.saturating_sub(line_start), (*e).min(line_end) - line_start))
        .collect();
    relevant.sort_by_key(|r| std::cmp::Reverse(r.0));
    for (s, e) in relevant {
        if !out.is_char_boundary(s) || !out.is_char_boundary(e) || s >= e {
            continue;
        }
        let secret = &out[s..e];
        let masked = analyzer::redact(secret);
        out.replace_range(s..e, &masked);
    }
    out
}
