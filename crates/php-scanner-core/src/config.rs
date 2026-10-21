use crate::finding::{Confidence, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ScanConfig {
    /// File extensions (without dot) treated as PHP source.
    pub extensions: Vec<String>,
    /// Glob patterns (relative to the scan root) to exclude.
    pub exclude: Vec<String>,
    /// Respect .gitignore / .ignore files.
    pub respect_gitignore: bool,
    pub include_hidden: bool,
    pub follow_symlinks: bool,
    /// Files larger than this are skipped (bytes).
    pub max_file_size: u64,
    /// When non-empty, only these rules run.
    pub enabled_rules: Vec<String>,
    pub disabled_rules: Vec<String>,
    pub min_severity: Severity,
    pub min_confidence: Confidence,
    /// Worker threads; 0 = number of CPUs.
    pub threads: usize,
    /// Lines of source context captured before/after each finding.
    pub context_lines: usize,
    /// Scan vendor/ and node_modules/ directories.
    pub scan_dependencies: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            extensions: [
                "php", "phtml", "php3", "php4", "php5", "php7", "php8", "phps", "inc", "module",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            exclude: Vec::new(),
            respect_gitignore: true,
            include_hidden: false,
            follow_symlinks: false,
            max_file_size: 8 * 1024 * 1024,
            enabled_rules: Vec::new(),
            disabled_rules: Vec::new(),
            min_severity: Severity::Info,
            min_confidence: Confidence::Low,
            threads: 0,
            context_lines: 3,
            scan_dependencies: false,
        }
    }
}

impl ScanConfig {
    pub fn rule_enabled(&self, id: &str) -> bool {
        if self.disabled_rules.iter().any(|r| r == id) {
            return false;
        }
        self.enabled_rules.is_empty() || self.enabled_rules.iter().any(|r| r == id)
    }
}
