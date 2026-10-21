use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use php_scanner_core::advisory::{self, AdvisoryDb, RuntimeStatus};
use php_scanner_core::integrity;
use php_scanner_core::report::{self, Format};
use php_scanner_core::scanner::AdvisoryVerdict;
use php_scanner_core::{rules, Baseline, Confidence, ScanConfig, ScanReport, Scanner, Severity};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "php-scanner", version, about = "Static security scanner for PHP applications", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Disable coloured output (also honours NO_COLOR).
    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a directory or file for vulnerabilities, malware, secrets and runtime advisories.
    Scan(ScanArgs),
    /// Focused check for the php2shell advisory (CVE-2026-109618 / CVE-2026-109619).
    Php2shell(Php2shellArgs),
    /// Inspect PHP runtimes installed on this machine against current advisories.
    Runtime {
        #[arg(long)]
        json: bool,
        #[arg(long, value_name = "FILE")]
        advisory_db: Option<PathBuf>,
    },
    /// Known-good file comparison for web shell detection (NSA guidance).
    Integrity {
        #[command(subcommand)]
        action: IntegrityAction,
    },
    /// List all detection rules.
    Rules {
        #[arg(long)]
        json: bool,
    },
    /// Show the bundled runtime advisory database.
    Advisories {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum IntegrityAction {
    /// Record SHA-256 hashes of a verified, known-good deployment.
    Snapshot {
        path: PathBuf,
        #[arg(short, long, default_value = "php-scanner-manifest.json")]
        output: PathBuf,
    },
    /// Compare a deployment against a manifest and report added/modified/removed files.
    Verify {
        path: PathBuf,
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum OutFormat {
    Text,
    Json,
    Sarif,
    Html,
    Csv,
}

#[derive(Args, Clone)]
struct CommonScan {
    /// Glob patterns to exclude (repeatable), e.g. --exclude 'tests/**'.
    #[arg(short = 'x', long = "exclude", value_name = "GLOB")]
    exclude: Vec<String>,
    /// Also scan vendor/ and node_modules/.
    #[arg(long)]
    include_vendor: bool,
    /// Do not honour .gitignore files.
    #[arg(long)]
    no_gitignore: bool,
    /// Worker threads (0 = all CPUs).
    #[arg(short = 'j', long, default_value_t = 0)]
    threads: usize,
    /// Load a newer advisory database (JSON) instead of the bundled one.
    #[arg(long, value_name = "FILE", env = "PHP_SCANNER_ADVISORY_DB")]
    advisory_db: Option<PathBuf>,
}

#[derive(Args)]
struct ScanArgs {
    #[arg(default_value = ".")]
    path: PathBuf,
    #[arg(short, long, value_enum, default_value = "text")]
    format: OutFormat,
    /// Write the report to a file instead of stdout.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Exit with status 1 when a finding at or above this severity exists ("none" to never fail).
    #[arg(long, default_value = "high", value_name = "SEVERITY")]
    fail_on: String,
    #[arg(long, default_value = "info", value_parser = parse_severity)]
    min_severity: Severity,
    #[arg(long, default_value = "low", value_parser = parse_confidence)]
    min_confidence: Confidence,
    /// Run only these rules (repeatable).
    #[arg(long = "rule", value_name = "ID")]
    rules: Vec<String>,
    /// Disable these rules (repeatable).
    #[arg(long = "disable-rule", value_name = "ID")]
    disabled: Vec<String>,
    /// Ignore findings recorded in this baseline file.
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,
    /// Write all current findings to a baseline file.
    #[arg(long, value_name = "FILE")]
    write_baseline: Option<PathBuf>,
    /// Also probe PHP binaries installed on this machine.
    #[arg(long)]
    check_local_runtime: bool,
    /// Only print the summary in text mode.
    #[arg(short, long)]
    quiet: bool,
    #[command(flatten)]
    common: CommonScan,
}

#[derive(Args)]
struct Php2shellArgs {
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Skip probing PHP binaries on this machine.
    #[arg(long)]
    no_local_runtime: bool,
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    common: CommonScan,
}

fn parse_severity(s: &str) -> Result<Severity, String> {
    s.parse()
}

fn parse_severity_or_none(s: &str) -> Result<Option<Severity>, String> {
    if s.eq_ignore_ascii_case("none") || s.eq_ignore_ascii_case("never") {
        Ok(None)
    } else {
        s.parse().map(Some)
    }
}

fn parse_confidence(s: &str) -> Result<Confidence, String> {
    match s.to_ascii_lowercase().as_str() {
        "low" => Ok(Confidence::Low),
        "medium" => Ok(Confidence::Medium),
        "high" => Ok(Confidence::High),
        o => Err(format!("unknown confidence '{o}'")),
    }
}

struct Style {
    color: bool,
}

impl Style {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn sev(&self, s: Severity) -> String {
        let code = match s {
            Severity::Critical => "1;97;41",
            Severity::High => "1;31",
            Severity::Medium => "1;33",
            Severity::Low => "1;34",
            Severity::Info => "2",
        };
        self.paint(code, &format!("{:<8}", s.as_str().to_uppercase()))
    }
    fn status(&self, s: RuntimeStatus) -> String {
        match s {
            RuntimeStatus::Vulnerable => self.paint("1;31", "VULNERABLE "),
            RuntimeStatus::Unsupported => self.paint("1;97;41", "UNSUPPORTED"),
            RuntimeStatus::Unverified => self.paint("1;33", "VERIFY     "),
            RuntimeStatus::Patched => self.paint("1;32", "PATCHED    "),
        }
    }
    fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
}

fn load_db(path: &Option<PathBuf>) -> Result<AdvisoryDb> {
    match path {
        Some(p) => AdvisoryDb::from_file(p).map_err(anyhow::Error::msg),
        None => Ok(AdvisoryDb::builtin()),
    }
}

fn base_config(c: &CommonScan) -> ScanConfig {
    ScanConfig {
        exclude: c.exclude.clone(),
        scan_dependencies: c.include_vendor,
        respect_gitignore: !c.no_gitignore,
        threads: c.threads,
        ..Default::default()
    }
}

fn run_scan(scanner: &Scanner, path: &Path, show_progress: bool) -> Result<ScanReport> {
    let tty = show_progress && std::io::stderr().is_terminal();
    let report = scanner
        .scan_with_progress(path, &|p| {
            if tty && p.files_total > 0 {
                eprint!(
                    "\r\x1b[2KScanning {}/{} files · {} findings",
                    p.files_done, p.files_total, p.findings
                );
            }
        })
        .map_err(anyhow::Error::msg)?;
    if tty {
        eprint!("\r\x1b[2K");
    }
    Ok(report)
}

fn print_advisories(report: &ScanReport, st: &Style, out: &mut impl Write) -> Result<()> {
    for a in &report.advisories {
        let verdict = match a.verdict {
            AdvisoryVerdict::ActionRequired => st.paint("1;97;41", " ACTION REQUIRED "),
            AdvisoryVerdict::Verify => st.paint("1;30;43", " VERIFY PRODUCTION RUNTIMES "),
            AdvisoryVerdict::PatchedInSource => st.paint("1;97;42", " PATCHED IN SOURCE "),
        };
        writeln!(out, "\n{} {}", verdict, st.bold(&a.advisory.title))?;
        writeln!(
            out,
            "  {} · fixed in {}",
            a.advisory.cves.join(", "),
            a.advisory.fixed_list()
        )?;
        if a.runtimes.is_empty() && a.local_runtimes.is_empty() {
            writeln!(out, "  No PHP runtime references found in source. Verify server runtimes directly (php -v, php-fpm -v).")?;
        }
        for r in &a.runtimes {
            writeln!(
                out,
                "  {} {:<26} {}  {}",
                st.status(r.status),
                r.kind,
                r.reference,
                st.dim(&format!("{}:{}", r.location, r.line))
            )?;
        }
        for r in &a.local_runtimes {
            writeln!(
                out,
                "  {} {:<26} {}  {}",
                st.status(r.status),
                "Installed on this machine",
                r.version.as_deref().unwrap_or("unknown"),
                st.dim(&r.binary)
            )?;
            for i in &r.issues {
                writeln!(out, "      - {i}")?;
            }
        }
        writeln!(
            out,
            "  {} compromise indicators · {} secrets to rotate · {} configuration findings",
            a.compromise_indicators, a.secrets_to_rotate, a.related_findings
        )?;
        if a.verdict != AdvisoryVerdict::PatchedInSource {
            writeln!(out, "  Next steps:")?;
            for (i, act) in a.advisory.actions.iter().enumerate() {
                writeln!(out, "    {}. {act}", i + 1)?;
            }
        }
    }
    Ok(())
}

fn print_text(report: &ScanReport, st: &Style, quiet: bool, out: &mut impl Write) -> Result<()> {
    if !quiet {
        for f in &report.findings {
            writeln!(
                out,
                "{} {}  {}",
                st.sev(f.severity),
                st.bold(&f.title),
                st.dim(&format!("[{}]", f.rule_id))
            )?;
            writeln!(out, "         {}:{}:{}", f.file, f.line, f.column)?;
            writeln!(out, "         {}", f.message)?;
            if !f.snippet.is_empty() {
                writeln!(out, "         {} {}", st.dim("│"), f.snippet)?;
            }
            if f.flow.len() > 1 {
                let path: Vec<String> = f.flow.iter().map(|s| format!("L{}", s.line)).collect();
                writeln!(out, "         {} {}", st.dim("flow:"), path.join(" → "))?;
            }
            writeln!(out)?;
        }
    }
    print_advisories(report, st, out)?;
    let counts: Vec<String> = Severity::ALL
        .iter()
        .map(|s| {
            format!(
                "{} {}",
                report
                    .summary
                    .by_severity
                    .get(s.as_str())
                    .copied()
                    .unwrap_or(0),
                s
            )
        })
        .collect();
    writeln!(
        out,
        "\n{} {} findings ({}) in {} files, {} lines, {} ms",
        st.bold("Summary:"),
        report.findings.len(),
        counts.join(", "),
        report.files_scanned,
        report.lines_scanned,
        report.duration_ms
    )?;
    if report.summary.suppressed + report.summary.baselined > 0 {
        writeln!(
            out,
            "         {} suppressed inline, {} in baseline",
            report.summary.suppressed, report.summary.baselined
        )?;
    }
    if report.parse_errors > 0 {
        writeln!(
            out,
            "         {} files had syntax errors and were analysed partially",
            report.parse_errors
        )?;
    }
    for e in &report.errors {
        writeln!(out, "         warning: {e}")?;
    }
    Ok(())
}

fn cmd_scan(a: ScanArgs, st: &Style) -> Result<ExitCode> {
    let fail_on = parse_severity_or_none(&a.fail_on).map_err(anyhow::Error::msg)?;
    let mut cfg = base_config(&a.common);
    cfg.min_severity = a.min_severity;
    cfg.min_confidence = a.min_confidence;
    cfg.enabled_rules = a.rules.clone();
    cfg.disabled_rules = a.disabled.clone();
    for r in cfg.enabled_rules.iter().chain(cfg.disabled_rules.iter()) {
        if rules::get(r).is_none() {
            bail!("unknown rule '{r}' (see `php-scanner rules`)");
        }
    }
    let mut scanner = Scanner::new(cfg);
    scanner.advisories = load_db(&a.common.advisory_db)?;
    scanner.probe_local_runtimes = a.check_local_runtime;
    if let Some(b) = &a.baseline {
        let text = std::fs::read_to_string(b)
            .with_context(|| format!("reading baseline {}", b.display()))?;
        scanner.baseline =
            Some(serde_json::from_str::<Baseline>(&text).context("invalid baseline file")?);
    }
    let report = run_scan(&scanner, &a.path, true)?;

    if let Some(path) = &a.write_baseline {
        let b = Baseline::from_report(&report);
        std::fs::write(path, serde_json::to_string_pretty(&b)?)?;
        eprintln!(
            "Baseline with {} findings written to {}",
            b.fingerprints.len(),
            path.display()
        );
    }

    let rendered = match a.format {
        OutFormat::Text => None,
        OutFormat::Json => Some(report::render(&report, Format::Json)),
        OutFormat::Sarif => Some(report::render(&report, Format::Sarif)),
        OutFormat::Html => Some(report::render(&report, Format::Html)),
        OutFormat::Csv => Some(report::render(&report, Format::Csv)),
    };
    match (&a.output, rendered) {
        (Some(path), Some(text)) => {
            std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
            eprintln!("Report written to {}", path.display());
            let plain = Style {
                color: st.color && std::io::stderr().is_terminal(),
            };
            print_text(&report, &plain, true, &mut std::io::stderr())?;
        }
        (Some(path), None) => {
            let mut buf = Vec::new();
            print_text(&report, &Style { color: false }, a.quiet, &mut buf)?;
            std::fs::write(path, buf)?;
        }
        (None, Some(text)) => println!("{text}"),
        (None, None) => print_text(&report, st, a.quiet, &mut std::io::stdout().lock())?,
    }

    let failed = fail_on
        .map(|s| report.count_at_least(s) > 0)
        .unwrap_or(false);
    Ok(if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn cmd_php2shell(a: Php2shellArgs, st: &Style) -> Result<ExitCode> {
    let mut cfg = base_config(&a.common);
    cfg.enabled_rules = rules::all()
        .iter()
        .filter(|r| {
            r.id.starts_with("php2shell-")
                || r.category == php_scanner_core::Category::Malware
                || r.category == php_scanner_core::Category::Secrets
        })
        .map(|r| r.id.to_string())
        .collect();
    let mut scanner = Scanner::new(cfg);
    scanner.advisories = load_db(&a.common.advisory_db)?;
    scanner.probe_local_runtimes = !a.no_local_runtime;
    let report = run_scan(&scanner, &a.path, !a.json)?;
    if a.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "advisories": report.advisories,
                "findings": report.findings,
            }))?
        );
    } else {
        let mut out = std::io::stdout().lock();
        for f in &report.findings {
            writeln!(
                out,
                "{} {}:{}  {}",
                st.sev(f.severity),
                f.file,
                f.line,
                f.message
            )?;
        }
        print_advisories(&report, st, &mut out)?;
    }
    let action = report
        .advisories
        .iter()
        .any(|a| a.verdict == AdvisoryVerdict::ActionRequired);
    Ok(if action {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn cmd_runtime(json: bool, db: &Option<PathBuf>, st: &Style) -> Result<ExitCode> {
    let db = load_db(db)?;
    let mut bad = false;
    let mut all = Vec::new();
    for adv in &db.advisories {
        let rts = advisory::probe_local_runtimes(adv);
        bad |= rts.iter().any(|r| {
            matches!(
                r.status,
                RuntimeStatus::Vulnerable | RuntimeStatus::Unsupported
            )
        });
        if !json {
            println!("{} ({})", st.bold(&adv.title), adv.cves.join(", "));
            if rts.is_empty() {
                println!("  No PHP binaries found on PATH or in common install locations.");
            }
            for r in &rts {
                println!(
                    "  {} {:<10} {:<12} {}",
                    st.status(r.status),
                    r.version.as_deref().unwrap_or("unknown"),
                    r.sapi.as_deref().unwrap_or("-"),
                    r.binary
                );
                for i in &r.issues {
                    println!("      - {i}");
                }
            }
        }
        all.push(serde_json::json!({ "advisory": adv.id, "runtimes": rts }));
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&all)?);
    }
    Ok(if bad {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn cmd_integrity(action: IntegrityAction, st: &Style) -> Result<ExitCode> {
    let cfg = ScanConfig {
        respect_gitignore: false,
        include_hidden: true,
        scan_dependencies: true,
        ..Default::default()
    };
    match action {
        IntegrityAction::Snapshot { path, output } => {
            let m = integrity::create_manifest(&path, &cfg).map_err(anyhow::Error::msg)?;
            std::fs::write(&output, serde_json::to_string_pretty(&m)?)?;
            println!("Recorded {} files in {}", m.files.len(), output.display());
            Ok(ExitCode::SUCCESS)
        }
        IntegrityAction::Verify {
            path,
            manifest,
            json,
        } => {
            let text = std::fs::read_to_string(&manifest)
                .with_context(|| format!("reading {}", manifest.display()))?;
            let m: integrity::Manifest = serde_json::from_str(&text).context("invalid manifest")?;
            let r = integrity::verify(&path, &cfg, &m).map_err(anyhow::Error::msg)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                println!(
                    "Compared {} files against manifest from {}",
                    r.files_checked, r.manifest_created_at
                );
                for c in r.added.iter().chain(&r.modified).chain(&r.removed) {
                    let tag = if c.executable {
                        st.paint("1;31", "EXECUTABLE")
                    } else {
                        "          ".into()
                    };
                    println!("  {:<9} {} {}", c.change.to_uppercase(), tag, c.path);
                }
                if r.is_clean() {
                    println!(
                        "{}",
                        st.paint("1;32", "No differences from the known-good manifest.")
                    );
                } else {
                    println!(
                        "{} added, {} modified, {} removed. Review executable changes first.",
                        r.added.len(),
                        r.modified.len(),
                        r.removed.len()
                    );
                }
            }
            Ok(if r.is_clean() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let color =
        !cli.no_color && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal();
    let st = Style { color };
    let result = match cli.command {
        Command::Scan(a) => cmd_scan(a, &st),
        Command::Php2shell(a) => cmd_php2shell(a, &st),
        Command::Runtime { json, advisory_db } => cmd_runtime(json, &advisory_db, &st),
        Command::Integrity { action } => cmd_integrity(action, &st),
        Command::Rules { json } => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(rules::all()).unwrap_or_default()
                );
            } else {
                for r in rules::all() {
                    let cwe = r.cwe.map(|c| format!("CWE-{c}")).unwrap_or_default();
                    println!("{} {:<34} {:<9} {}", st.sev(r.severity), r.id, cwe, r.title);
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Advisories { json } => {
            let db = AdvisoryDb::builtin();
            if json {
                println!("{}", serde_json::to_string_pretty(&db).unwrap_or_default());
            } else {
                println!("Advisory database {}", db.version);
                for a in &db.advisories {
                    println!(
                        "\n{} [{}] {}\n  {}\n  Fixed: {}",
                        st.bold(&a.id),
                        a.cves.join(", "),
                        a.title,
                        a.summary,
                        a.fixed_list()
                    );
                    for s in &a.sources {
                        println!("  - {}: {}", s.name, s.url);
                    }
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}
