//! Runtime advisories (e.g. php2shell, CVE-2026-109618 / CVE-2026-109619).
//!
//! Interpreter vulnerabilities cannot be found in application source, so this
//! module inventories PHP runtimes referenced by the project (Composer
//! platform pins, container images, OS packages, version files), the local
//! machine's PHP installs, and checks configuration-level mitigations.

use crate::analyzer::RawFinding;
use crate::finding::Confidence;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const BUILTIN_DB: &str = include_str!("../advisories/advisories.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvisoryDb {
    pub version: String,
    pub advisories: Vec<Advisory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Advisory {
    pub id: String,
    pub title: String,
    pub cves: Vec<String>,
    pub published: String,
    pub severity: String,
    pub summary: String,
    pub fixed: Vec<FixedRelease>,
    pub minimum_supported_branch: String,
    #[serde(default)]
    pub ini_mitigations: Vec<IniMitigation>,
    pub actions: Vec<String>,
    pub sources: Vec<Source>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixedRelease {
    pub branch: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IniMitigation {
    pub directive: String,
    pub safe_values: Vec<String>,
    pub default: String,
    pub cve: String,
    /// Branches the directive applies to; empty = all.
    #[serde(default)]
    pub branches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    pub name: String,
    pub url: String,
}

impl AdvisoryDb {
    pub fn builtin() -> Self {
        serde_json::from_str(BUILTIN_DB).expect("embedded advisory database is valid JSON")
    }

    pub fn from_file(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        serde_json::from_str(&text)
            .map_err(|e| format!("{}: invalid advisory database: {e}", path.display()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PhpVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: Option<u32>,
}

impl PhpVersion {
    pub fn parse(s: &str) -> Option<Self> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\d+)\.(\d+)(?:\.(\d+))?").unwrap());
        let c = RE.captures(s)?;
        Some(PhpVersion {
            major: c[1].parse().ok()?,
            minor: c[2].parse().ok()?,
            patch: c.get(3).and_then(|m| m.as_str().parse().ok()),
        })
    }

    pub fn branch(&self) -> (u32, u32) {
        (self.major, self.minor)
    }
}

impl std::fmt::Display for PhpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.patch {
            Some(p) => write!(f, "{}.{}.{}", self.major, self.minor, p),
            None => write!(f, "{}.{}", self.major, self.minor),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeStatus {
    Patched,
    Vulnerable,
    Unsupported,
    Unverified,
}

impl Advisory {
    fn branch_of(s: &str) -> Option<(u32, u32)> {
        PhpVersion::parse(s).map(|v| v.branch())
    }

    pub fn fixed_for(&self, branch: (u32, u32)) -> Option<PhpVersion> {
        self.fixed
            .iter()
            .find(|f| Self::branch_of(&f.branch) == Some(branch))
            .and_then(|f| PhpVersion::parse(&f.version))
    }

    pub fn fixed_list(&self) -> String {
        self.fixed
            .iter()
            .map(|f| f.version.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn evaluate(&self, v: &PhpVersion) -> RuntimeStatus {
        let min = Self::branch_of(&self.minimum_supported_branch).unwrap_or((0, 0));
        if v.branch() < min {
            return RuntimeStatus::Unsupported;
        }
        match self.fixed_for(v.branch()) {
            Some(fixed) => match v.patch {
                Some(p) if p >= fixed.patch.unwrap_or(0) => RuntimeStatus::Patched,
                Some(_) => RuntimeStatus::Vulnerable,
                None => RuntimeStatus::Unverified,
            },
            None => {
                let newest = self
                    .fixed
                    .iter()
                    .filter_map(|f| Self::branch_of(&f.branch))
                    .max()
                    .unwrap_or((0, 0));
                if v.branch() > newest {
                    RuntimeStatus::Patched
                } else {
                    RuntimeStatus::Unverified
                }
            }
        }
    }

    fn mitigation_applies(&self, m: &IniMitigation, branch: Option<(u32, u32)>) -> bool {
        m.branches.is_empty()
            || match branch {
                Some(b) => m.branches.iter().any(|x| Self::branch_of(x) == Some(b)),
                None => true,
            }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeDetection {
    pub advisory_id: String,
    /// Relative file path, or a binary path for local runtimes.
    pub location: String,
    pub line: usize,
    pub kind: String,
    pub reference: String,
    pub version: Option<String>,
    pub status: RuntimeStatus,
    pub note: String,
}

#[derive(Debug, Default)]
pub struct ConfigResult {
    pub findings: Vec<RawFinding>,
    pub runtimes: Vec<RuntimeDetection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigKind {
    ComposerJson,
    Dockerfile,
    Yaml,
    VersionFile,
    ToolVersions,
    PhpIni,
    FpmPool,
    PerDirIni,
    Htaccess,
    SystemdUnit,
    Shell,
    ServerConf,
}

/// Classifies non-PHP files that matter for runtime advisories.
pub fn classify(rel_path: &str) -> Option<ConfigKind> {
    let lower = rel_path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    let in_dir = |d: &str| lower.split('/').any(|seg| seg == d);
    Some(match name {
        "composer.json" => ConfigKind::ComposerJson,
        "dockerfile" | "containerfile" => ConfigKind::Dockerfile,
        n if n.starts_with("dockerfile.")
            || n.ends_with(".dockerfile")
            || n.ends_with(".containerfile") =>
        {
            ConfigKind::Dockerfile
        }
        ".php-version" => ConfigKind::VersionFile,
        ".tool-versions" => ConfigKind::ToolVersions,
        ".user.ini" => ConfigKind::PerDirIni,
        ".htaccess" => ConfigKind::Htaccess,
        "php.ini" | "php.ini-production" | "php.ini-development" | "php-fpm.conf" => {
            ConfigKind::PhpIni
        }
        n if n.ends_with(".ini")
            && (n.contains("php") || lower.contains("php") || in_dir("conf.d")) =>
        {
            ConfigKind::PhpIni
        }
        n if n.ends_with(".conf")
            && (in_dir("php-fpm.d") || in_dir("pool.d") || n == "www.conf") =>
        {
            ConfigKind::FpmPool
        }
        n if n.ends_with(".conf")
            && (lower.contains("apache")
                || lower.contains("httpd")
                || lower.contains("nginx")
                || n.contains("php")) =>
        {
            ConfigKind::ServerConf
        }
        n if n.ends_with(".service") => ConfigKind::SystemdUnit,
        n if n.ends_with(".sh")
            || n.starts_with("entrypoint")
            || n.starts_with("docker-entrypoint") =>
        {
            ConfigKind::Shell
        }
        n if n.ends_with(".yml") || n.ends_with(".yaml") => ConfigKind::Yaml,
        _ => return None,
    })
}

static IMAGE_LINE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?im)^\s*(?:from\s+(?:--platform=\S+\s+)?|-?\s*image:\s*|type:\s*)['"]?([a-z0-9][a-z0-9._/:@${}\-]*)"#).unwrap()
});
static TAG_PHP: Lazy<Regex> = Lazy::new(|| Regex::new(r"php-?(\d+\.\d+(?:\.\d+)?)").unwrap());
static ARG_LINE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?im)^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)=([^\s]+)").unwrap());
static PKG_LINE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(apt-get|apt|apk|yum|dnf|zypper|microdnf)\b[^\n]*\binstall|apk\s+add").unwrap()
});
static PKG_NAME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bphp(\d)\.?(\d)(?:-[a-z0-9]+)?\b").unwrap());
static GAE_RUNTIME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?im)^\s*runtime:\s*['\x22]?php(\d)(\d)\b").unwrap());
static RLIMIT_UNIT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?im)^\s*Limit(AS|DATA)\s*=\s*(\S+)").unwrap());
static RLIMIT_ULIMIT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bulimit\s+(?:-[A-Za-z]*\s+)*-([A-Za-z]*[vd][A-Za-z]*)\s+(\d+)").unwrap()
});

const PHP_BUNDLING_IMAGES: &[&str] = &[
    "wordpress",
    "drupal",
    "joomla",
    "nextcloud",
    "matomo",
    "phpmyadmin",
    "mediawiki",
    "magento",
    "prestashop",
    "moodle",
    "owncloud",
    "roundcube",
    "mautic",
    "kanboard",
    "bookstack",
    "grav",
    "craftcms",
    "statamic",
    "sylius",
    "shopware",
    "typo3",
    "concrete5",
    "opencart",
    "phpbb",
    "frankenphp",
    "laravelsail",
    "sail-8.0",
    "sail-8.1",
    "sail-8.2",
    "sail-8.3",
    "sail-8.4",
];

fn line_at(starts: &[usize], offset: usize) -> usize {
    match starts.binary_search(&offset) {
        Ok(r) => r,
        Err(r) => r - 1,
    }
}

struct Ctx<'a> {
    adv: &'a Advisory,
    rel: &'a str,
    starts: &'a [usize],
    out: ConfigResult,
}

impl<'a> Ctx<'a> {
    fn finding(&mut self, rule: &'static str, conf: Confidence, row: usize, msg: String) {
        self.out.findings.push(RawFinding {
            rule_id: rule,
            message: msg,
            confidence: conf,
            start: (row, 0),
            end: (row, 0),
            flow: Vec::new(),
        });
    }

    fn runtime(
        &mut self,
        row: usize,
        kind: &str,
        reference: &str,
        version: Option<PhpVersion>,
        forced: Option<RuntimeStatus>,
        note: String,
    ) {
        let status = forced.unwrap_or_else(|| {
            version
                .map(|v| self.adv.evaluate(&v))
                .unwrap_or(RuntimeStatus::Unverified)
        });
        let adv = self.adv;
        let fixed = adv.fixed_list();
        let vtext = version.map(|v| v.to_string());
        let (rule, conf, msg) = match status {
            RuntimeStatus::Vulnerable => (
                Some("php2shell-vulnerable-runtime"),
                Confidence::High,
                format!("{kind} '{reference}' uses PHP {} which is affected by {} ({}). Fixed releases: {fixed}.", vtext.clone().unwrap_or_default(), adv.cves.join(" / "), adv.id),
            ),
            RuntimeStatus::Unsupported => (
                Some("php2shell-unsupported-runtime"),
                Confidence::High,
                format!("{kind} '{reference}' uses end-of-life PHP {} with no official fix for {}. Upgrade or take offline.", vtext.clone().unwrap_or_default(), adv.cves.join(" / ")),
            ),
            RuntimeStatus::Unverified => (
                Some("php2shell-unpinned-runtime"),
                Confidence::Medium,
                format!("{kind} '{reference}' does not pin a PHP patch level; ensure it resolves to {fixed} or later and restart PHP. {note}"),
            ),
            RuntimeStatus::Patched => (None, Confidence::High, String::new()),
        };
        if let Some(rule) = rule {
            self.finding(rule, conf, row, msg.trim().to_string());
        }
        self.out.runtimes.push(RuntimeDetection {
            advisory_id: adv.id.clone(),
            location: self.rel.to_string(),
            line: row + 1,
            kind: kind.to_string(),
            reference: reference.to_string(),
            version: vtext,
            status,
            note,
        });
    }
}

/// Analyses a non-PHP configuration file against an advisory.
pub fn check_config(
    adv: &Advisory,
    kind: ConfigKind,
    rel: &str,
    src: &str,
    starts: &[usize],
) -> ConfigResult {
    let mut cx = Ctx {
        adv,
        rel,
        starts,
        out: ConfigResult::default(),
    };
    match kind {
        ConfigKind::ComposerJson => composer(&mut cx, src),
        ConfigKind::Dockerfile => {
            images(&mut cx, src, true);
            packages(&mut cx, src);
            rlimits(&mut cx, src);
        }
        ConfigKind::Yaml => {
            images(&mut cx, src, false);
            if let Some(m) = GAE_RUNTIME.captures(src) {
                let v = PhpVersion::parse(&format!("{}.{}", &m[1], &m[2]));
                let row = line_at(starts, m.get(0).unwrap().start());
                cx.runtime(row, "Platform runtime", m.get(0).unwrap().as_str().trim(), v, None,
                    "Managed runtimes are patched by the provider; redeploy to pick up the fixed build.".into());
            }
        }
        ConfigKind::VersionFile => {
            if let Some(v) = PhpVersion::parse(src.trim()) {
                cx.runtime(0, "Version file", src.trim(), Some(v), None, String::new());
            }
        }
        ConfigKind::ToolVersions => {
            for (i, l) in src.lines().enumerate() {
                let mut parts = l.split_whitespace();
                if parts.next() == Some("php") {
                    if let Some(ver) = parts.next() {
                        cx.runtime(
                            i,
                            "asdf/mise .tool-versions",
                            l.trim(),
                            PhpVersion::parse(ver),
                            None,
                            String::new(),
                        );
                    }
                }
            }
        }
        ConfigKind::PhpIni | ConfigKind::FpmPool | ConfigKind::ServerConf => {
            ini(&mut cx, src, kind)
        }
        ConfigKind::PerDirIni | ConfigKind::Htaccess => per_dir(&mut cx, src, kind),
        ConfigKind::SystemdUnit | ConfigKind::Shell => rlimits(&mut cx, src),
    }
    cx.out
}

fn find_row(src: &str, starts: &[usize], needle: &Regex) -> usize {
    needle
        .find(src)
        .map(|m| line_at(starts, m.start()))
        .unwrap_or(0)
}

fn composer(cx: &mut Ctx, src: &str) {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(src) else {
        return;
    };
    static PHP_KEY: Lazy<Regex> = Lazy::new(|| Regex::new(r#""php"\s*:"#).unwrap());
    if let Some(pin) = json
        .pointer("/config/platform/php")
        .and_then(|v| v.as_str())
    {
        let row = src
            .find("\"platform\"")
            .and_then(|p| PHP_KEY.find_at(src, p))
            .map(|m| line_at(cx.starts, m.start()))
            .unwrap_or(0);
        cx.runtime(
            row,
            "Composer platform pin",
            pin,
            PhpVersion::parse(pin),
            None,
            String::new(),
        );
    }
    if let Some(req) = json.pointer("/require/php").and_then(|v| v.as_str()) {
        let row = find_row(src, cx.starts, &PHP_KEY);
        let vulnerable_floor = req
            .split("||")
            .flat_map(|alt| alt.split('|'))
            .filter_map(|alt| {
                let alt = alt.trim();
                if alt.starts_with('<') {
                    return None;
                }
                let lower = alt.split_whitespace().next().unwrap_or(alt);
                PhpVersion::parse(lower).map(|mut v| {
                    v.patch = Some(v.patch.unwrap_or(0));
                    v
                })
            })
            .find(|v| {
                matches!(
                    cx.adv.evaluate(v),
                    RuntimeStatus::Vulnerable | RuntimeStatus::Unsupported
                )
            });
        if let Some(v) = vulnerable_floor {
            cx.finding("php2shell-composer-constraint", Confidence::High, row,
                format!("\"php\": \"{req}\" accepts PHP {v}, which is affected by {}. Require {} or later.", cx.adv.cves.join(" / "), cx.adv.fixed_list()));
        }
    }
}

fn images(cx: &mut Ctx, src: &str, dockerfile: bool) {
    let mut args: HashMap<String, String> = HashMap::new();
    if dockerfile {
        for c in ARG_LINE.captures_iter(src) {
            args.insert(c[1].to_string(), c[2].trim_matches('"').to_string());
        }
    }
    for c in IMAGE_LINE.captures_iter(src) {
        let mut image = c[1].to_string();
        for (k, v) in &args {
            image = image
                .replace(&format!("${{{k}}}"), v)
                .replace(&format!("${k}"), v);
        }
        let row = line_at(cx.starts, c.get(0).unwrap().start());
        let image = image.split('@').next().unwrap_or(&image).to_string();
        let (repo, tag) = match image.rsplit_once(':') {
            Some((r, t)) if !t.contains('/') => (r.to_string(), t.to_string()),
            _ => (image.clone(), "latest".to_string()),
        };
        let base = repo
            .rsplit('/')
            .next()
            .unwrap_or(&repo)
            .to_ascii_lowercase();
        let tag_l = tag.to_ascii_lowercase();
        if base == "php"
            || base.starts_with("php-")
            || base.starts_with("php8")
            || base.starts_with("php7")
            || base.ends_with("-php")
            || base == "frankenphp" && tag_l.contains("php")
        {
            let version = if base.starts_with("php8") || base.starts_with("php7") {
                PhpVersion::parse(&format!("{}.{}", &base[3..4], &base[4..5]))
                    .filter(|_| base.len() >= 5)
            } else {
                PhpVersion::parse(&tag_l)
            };
            let note = if version.is_none() {
                "Floating tag; pull and rebuild to get a patched runtime, then pin the exact version.".to_string()
            } else {
                String::new()
            };
            cx.runtime(row, "Container image", &image, version, None, note);
        } else if let Some(m) = TAG_PHP.captures(&tag_l) {
            cx.runtime(
                row,
                "Container image",
                &image,
                PhpVersion::parse(&m[1]),
                None,
                "Bundled PHP inside an application image; rebuild from the vendor's patched image."
                    .into(),
            );
        } else if PHP_BUNDLING_IMAGES
            .iter()
            .any(|b| base == *b || base.starts_with(&format!("{b}-")))
        {
            cx.runtime(
                row,
                "Container image",
                &image,
                None,
                Some(RuntimeStatus::Unverified),
                "This image bundles a PHP runtime; pull the vendor's rebuilt image and restart."
                    .into(),
            );
        }
    }
}

fn packages(cx: &mut Ctx, src: &str) {
    for (i, line) in src.lines().enumerate() {
        if !PKG_LINE.is_match(line) && !line.contains("ppa:ondrej/php") {
            continue;
        }
        if let Some(c) = PKG_NAME.captures(line) {
            let v = PhpVersion::parse(&format!("{}.{}", &c[1], &c[2]));
            cx.runtime(i, "OS package", c.get(0).unwrap().as_str(), v, None,
                "Distribution packages may carry backported fixes; confirm with your vendor's security tracker and restart PHP after updating.".into());
        }
    }
}

fn rlimits(cx: &mut Ctx, src: &str) {
    for c in RLIMIT_UNIT.captures_iter(src) {
        let val = c[2].to_ascii_lowercase();
        if val != "infinity" && val != "unlimited" {
            let row = line_at(cx.starts, c.get(0).unwrap().start());
            cx.finding("php2shell-rlimit-misuse", Confidence::High, row,
                format!("Limit{}={} sets RLIMIT_{}, which PHP warns can trigger the CVE-2026-109618 allocation-failure path.", &c[1], &c[2], &c[1]));
        }
    }
    for c in RLIMIT_ULIMIT.captures_iter(src) {
        let row = line_at(cx.starts, c.get(0).unwrap().start());
        let which = if c[1].contains('v') {
            "RLIMIT_AS"
        } else {
            "RLIMIT_DATA"
        };
        cx.finding("php2shell-rlimit-misuse", Confidence::Medium, row,
            format!("'{}' sets {which}; PHP warns this can trigger the CVE-2026-109618 vulnerable allocation failure.", c.get(0).unwrap().as_str()));
    }
}

/// Parses `directive = value`, `php_admin_value[directive] = value` and
/// `php_admin_flag directive value` forms. Returns (row, directive, value).
fn ini_directives(src: &str) -> Vec<(usize, String, String)> {
    static POOL: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)^\s*php(?:_admin)?_(?:value|flag)\[([a-z0-9_.]+)\]\s*=\s*(.*?)\s*$")
            .unwrap()
    });
    static APACHE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)^\s*php(?:_admin)?_(?:value|flag)\s+([a-z0-9_.]+)\s+(.*?)\s*$").unwrap()
    });
    static INI: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?i)^\s*([a-z0-9_.]+)\s*=\s*(.*?)\s*$").unwrap());
    let mut out = Vec::new();
    for (i, line) in src.lines().enumerate() {
        let t = line.trim_start();
        if t.starts_with(';') || t.starts_with('#') {
            continue;
        }
        let caps = POOL
            .captures(line)
            .or_else(|| APACHE.captures(line))
            .or_else(|| INI.captures(line));
        if let Some(c) = caps {
            let v = c[2]
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_ascii_lowercase();
            out.push((i, c[1].to_ascii_lowercase(), v));
        }
    }
    out
}

fn ini(cx: &mut Ctx, src: &str, kind: ConfigKind) {
    let directives = ini_directives(src);
    let is_main = cx.rel.to_ascii_lowercase().ends_with("php.ini")
        || cx.rel.to_ascii_lowercase().ends_with("php.ini-production");
    let mut missing = Vec::new();
    for m in cx.adv.ini_mitigations.clone() {
        if !cx.adv.mitigation_applies(&m, None) {
            continue;
        }
        let set = directives.iter().rev().find(|(_, d, _)| *d == m.directive);
        match set {
            Some((row, _, val)) if !m.safe_values.contains(val) => {
                let scope = if m.branches.is_empty() {
                    String::new()
                } else {
                    format!(" (PHP {})", m.branches.join(", "))
                };
                cx.finding("php2shell-mitigation-missing", Confidence::High, *row,
                    format!("{} is enabled ('{val}'){scope}; this keeps the {} exploitation path open until PHP is patched.", m.directive, m.cve));
            }
            None if is_main && kind == ConfigKind::PhpIni => missing.push(m.directive.clone()),
            _ => {}
        }
    }
    if !missing.is_empty() {
        cx.finding(
            "php2shell-mitigation-missing",
            Confidence::Medium,
            0,
            format!(
                "{} not disabled here (PHP default is on). Set {} until every runtime is patched.",
                missing.join(" / "),
                missing
                    .iter()
                    .map(|d| format!("{d}=0"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
}

fn per_dir(cx: &mut Ctx, src: &str, kind: ConfigKind) {
    let label = if kind == ConfigKind::Htaccess {
        ".htaccess"
    } else {
        ".user.ini"
    };
    for (row, d, _) in ini_directives(src) {
        if cx.adv.ini_mitigations.iter().any(|m| m.directive == d) {
            cx.finding("php2shell-ineffective-mitigation", Confidence::High, row,
                format!("{d} is set in {label}; PHP's advisory requires php.ini, an FPM pool or server config for this mitigation."));
        }
    }
}

// ---------------------------------------------------------------------------------------
// Local runtime probe
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalRuntime {
    pub binary: String,
    pub version: Option<String>,
    pub sapi: Option<String>,
    pub ini: HashMap<String, String>,
    pub status: RuntimeStatus,
    pub issues: Vec<String>,
}

fn run_with_timeout(bin: &str, args: &[&str], timeout: Duration) -> Option<String> {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return None,
        }
    }
    let out = child.wait_with_output().ok()?;
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(s)
}

fn candidate_binaries() -> Vec<String> {
    let mut names: Vec<String> = vec![
        "php".into(),
        "php-fpm".into(),
        "php-cgi".into(),
        "frankenphp".into(),
    ];
    for minor in [
        "5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1", "8.2", "8.3", "8.4", "8.5",
    ] {
        names.push(format!("php{minor}"));
        names.push(format!("php-fpm{minor}"));
        names.push(format!("php{}", minor.replace('.', "")));
    }
    let mut found = Vec::new();
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut dirs: Vec<std::path::PathBuf> = std::env::split_paths(&path).collect();
    for extra in [
        "/usr/sbin",
        "/usr/local/sbin",
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "C:\\php",
        "C:\\xampp\\php",
        "C:\\wamp64\\bin\\php",
    ] {
        dirs.push(extra.into());
    }
    for d in dirs {
        for n in &names {
            for candidate in [d.join(n), d.join(format!("{n}.exe"))] {
                if candidate.is_file() {
                    let canon = std::fs::canonicalize(&candidate).unwrap_or(candidate.clone());
                    let s = canon.to_string_lossy().to_string();
                    if !found.contains(&s) {
                        found.push(s);
                    }
                }
            }
        }
    }
    found
}

/// Probes PHP binaries installed on this machine (PATH and common locations).
pub fn probe_local_runtimes(adv: &Advisory) -> Vec<LocalRuntime> {
    const PROBE: &str = "echo PHP_VERSION,'|',PHP_SAPI,'|',ini_get('session.upload_progress.enabled'),'|',ini_get('fatal_error_backtraces'),'|',ini_get('memory_limit'),'|',ini_get('post_max_size');";
    let mut out = Vec::new();
    for bin in candidate_binaries() {
        let is_fpm = bin.contains("fpm");
        let (version, sapi, ini) = if is_fpm || bin.contains("frankenphp") {
            let v = run_with_timeout(&bin, &["-v"], Duration::from_secs(5))
                .and_then(|s| PhpVersion::parse(&s));
            (
                v,
                Some(if is_fpm {
                    "fpm-fcgi".to_string()
                } else {
                    "frankenphp".to_string()
                }),
                HashMap::new(),
            )
        } else {
            let raw = run_with_timeout(&bin, &["-r", PROBE], Duration::from_secs(5));
            match raw {
                Some(s) if s.contains('|') => {
                    let parts: Vec<&str> = s.trim().split('|').collect();
                    let mut ini = HashMap::new();
                    for (k, i) in [
                        ("session.upload_progress.enabled", 2),
                        ("fatal_error_backtraces", 3),
                        ("memory_limit", 4),
                        ("post_max_size", 5),
                    ] {
                        if let Some(v) = parts.get(i) {
                            ini.insert(k.to_string(), v.to_string());
                        }
                    }
                    (
                        PhpVersion::parse(parts[0]),
                        parts.get(1).map(|s| s.to_string()),
                        ini,
                    )
                }
                Some(s) => (PhpVersion::parse(&s), None, HashMap::new()),
                None => (None, None, HashMap::new()),
            }
        };
        let status = version
            .map(|v| adv.evaluate(&v))
            .unwrap_or(RuntimeStatus::Unverified);
        let mut issues = Vec::new();
        match status {
            RuntimeStatus::Vulnerable => issues.push(format!(
                "Affected by {}; upgrade to {} and restart.",
                adv.cves.join(" / "),
                adv.fixed_list()
            )),
            RuntimeStatus::Unsupported => issues.push(
                "End-of-life branch with no official fix; upgrade or use an LTS vendor build."
                    .into(),
            ),
            RuntimeStatus::Unverified => issues.push("Version could not be determined.".into()),
            RuntimeStatus::Patched => {}
        }
        if status != RuntimeStatus::Patched {
            for m in &adv.ini_mitigations {
                if !adv.mitigation_applies(m, version.map(|v| v.branch())) {
                    continue;
                }
                if let Some(v) = ini.get(&m.directive) {
                    if !m.safe_values.contains(&v.to_ascii_lowercase()) {
                        issues.push(format!(
                            "{} = {v} (temporary mitigation: set to 0 in php.ini / FPM pool).",
                            m.directive
                        ));
                    }
                }
            }
        }
        out.push(LocalRuntime {
            binary: bin,
            version: version.map(|v| v.to_string()),
            sapi,
            ini,
            status,
            issues,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::line_starts;

    fn adv() -> Advisory {
        AdvisoryDb::builtin().advisories.remove(0)
    }

    fn v(s: &str) -> PhpVersion {
        PhpVersion::parse(s).unwrap()
    }

    #[test]
    fn evaluates_versions_against_fixed_releases() {
        let a = adv();
        assert_eq!(a.evaluate(&v("8.3.35")), RuntimeStatus::Vulnerable);
        assert_eq!(a.evaluate(&v("8.3.36")), RuntimeStatus::Patched);
        assert_eq!(a.evaluate(&v("8.5.11")), RuntimeStatus::Vulnerable);
        assert_eq!(a.evaluate(&v("8.5.12")), RuntimeStatus::Patched);
        assert_eq!(a.evaluate(&v("8.2.34")), RuntimeStatus::Vulnerable);
        assert_eq!(a.evaluate(&v("8.4.27")), RuntimeStatus::Patched);
        assert_eq!(a.evaluate(&v("8.1.30")), RuntimeStatus::Unsupported);
        assert_eq!(a.evaluate(&v("7.4.33")), RuntimeStatus::Unsupported);
        assert_eq!(a.evaluate(&v("8.3")), RuntimeStatus::Unverified);
        assert_eq!(a.evaluate(&v("8.6.0")), RuntimeStatus::Patched);
    }

    fn run(kind: ConfigKind, rel: &str, src: &str) -> ConfigResult {
        check_config(&adv(), kind, rel, src, &line_starts(src))
    }

    fn rules(r: &ConfigResult) -> Vec<&str> {
        r.findings.iter().map(|f| f.rule_id).collect()
    }

    #[test]
    fn dockerfile_images_and_args() {
        let src = "ARG PHP_VERSION=8.3.10\nFROM php:${PHP_VERSION}-fpm AS base\nFROM php:8.4-apache\nFROM php:8.4.27-cli\nFROM wordpress:6.6-php8.1-apache\nRUN apt-get install -y php8.2-fpm\n";
        let r = run(ConfigKind::Dockerfile, "Dockerfile", src);
        assert_eq!(
            rules(&r),
            vec![
                "php2shell-vulnerable-runtime",
                "php2shell-unpinned-runtime",
                "php2shell-unsupported-runtime",
                "php2shell-unpinned-runtime"
            ]
        );
        assert_eq!(r.findings[0].start.0, 1);
        assert_eq!(r.runtimes.len(), 5);
        assert_eq!(r.runtimes[2].status, RuntimeStatus::Patched);
    }

    #[test]
    fn compose_and_bundling_images() {
        let src = "services:\n  app:\n    image: wordpress:latest\n  db:\n    image: mysql:8\n  php:\n    image: \"php:7.4-fpm\"\n";
        let r = run(ConfigKind::Yaml, "docker-compose.yml", src);
        assert_eq!(
            rules(&r),
            vec![
                "php2shell-unpinned-runtime",
                "php2shell-unsupported-runtime"
            ]
        );
    }

    #[test]
    fn composer_platform_and_constraint() {
        let src = r#"{
  "require": { "php": "^8.1 || ^8.2" },
  "config": { "platform": { "php": "8.2.20" } }
}"#;
        let r = run(ConfigKind::ComposerJson, "composer.json", src);
        assert_eq!(
            rules(&r),
            vec![
                "php2shell-vulnerable-runtime",
                "php2shell-composer-constraint"
            ]
        );
        assert_eq!(r.findings[0].start.0, 2);
        assert_eq!(r.findings[1].start.0, 1);

        let ok = run(
            ConfigKind::ComposerJson,
            "composer.json",
            r#"{"require":{"php":"~8.3.36 || ^8.5.12"}}"#,
        );
        assert!(ok.findings.is_empty());
    }

    #[test]
    fn ini_mitigations() {
        let r = run(
            ConfigKind::PhpIni,
            "docker/php.ini",
            "memory_limit = 256M\nsession.upload_progress.enabled = On\n",
        );
        assert_eq!(
            rules(&r),
            vec![
                "php2shell-mitigation-missing",
                "php2shell-mitigation-missing"
            ]
        );
        assert_eq!(r.findings[0].start.0, 1);
        assert!(r.findings[1].message.starts_with("fatal_error_backtraces"));

        let missing = run(ConfigKind::PhpIni, "php.ini", "memory_limit = -1\n");
        assert_eq!(rules(&missing), vec!["php2shell-mitigation-missing"]);

        let ok = run(
            ConfigKind::PhpIni,
            "php.ini",
            "session.upload_progress.enabled = 0\nfatal_error_backtraces = Off\n",
        );
        assert!(ok.findings.is_empty());

        let pool = run(
            ConfigKind::FpmPool,
            "php-fpm.d/www.conf",
            "php_admin_value[session.upload_progress.enabled] = 1\n",
        );
        assert_eq!(rules(&pool), vec!["php2shell-mitigation-missing"]);

        let pool_ok = run(
            ConfigKind::FpmPool,
            "php-fpm.d/www.conf",
            "php_admin_flag[session.upload_progress.enabled] = off\n",
        );
        assert!(pool_ok.findings.is_empty());
    }

    #[test]
    fn per_dir_mitigation_is_ineffective() {
        let r = run(
            ConfigKind::PerDirIni,
            "public/.user.ini",
            "session.upload_progress.enabled=0\n",
        );
        assert_eq!(rules(&r), vec!["php2shell-ineffective-mitigation"]);
        let h = run(
            ConfigKind::Htaccess,
            "public/.htaccess",
            "php_flag session.upload_progress.enabled off\n",
        );
        assert_eq!(rules(&h), vec!["php2shell-ineffective-mitigation"]);
    }

    #[test]
    fn rlimit_detection() {
        let r = run(
            ConfigKind::SystemdUnit,
            "deploy/php-fpm.service",
            "[Service]\nLimitAS=4G\nLimitNOFILE=65535\nLimitDATA=infinity\n",
        );
        assert_eq!(rules(&r), vec!["php2shell-rlimit-misuse"]);
        let s = run(
            ConfigKind::Shell,
            "docker-entrypoint.sh",
            "#!/bin/sh\nulimit -v 2000000\nexec php-fpm\n",
        );
        assert_eq!(rules(&s), vec!["php2shell-rlimit-misuse"]);
    }

    #[test]
    fn version_files() {
        assert_eq!(
            rules(&run(ConfigKind::VersionFile, ".php-version", "8.3.12\n")),
            vec!["php2shell-vulnerable-runtime"]
        );
        assert_eq!(
            rules(&run(
                ConfigKind::ToolVersions,
                ".tool-versions",
                "nodejs 22.1.0\nphp 8.4.27\n"
            )),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn classification() {
        assert_eq!(classify("composer.json"), Some(ConfigKind::ComposerJson));
        assert_eq!(
            classify("docker/app/Dockerfile"),
            Some(ConfigKind::Dockerfile)
        );
        assert_eq!(
            classify("docker/php/conf.d/custom.ini"),
            Some(ConfigKind::PhpIni)
        );
        assert_eq!(
            classify("etc/php-fpm.d/www.conf"),
            Some(ConfigKind::FpmPool)
        );
        assert_eq!(classify("public/.user.ini"), Some(ConfigKind::PerDirIni));
        assert_eq!(classify("src/index.php"), None);
    }
}
