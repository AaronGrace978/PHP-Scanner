use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// CVSS-like score used for SARIF `security-severity`.
    pub fn score(self) -> f32 {
        match self {
            Severity::Info => 0.0,
            Severity::Low => 3.0,
            Severity::Medium => 5.5,
            Severity::High => 8.0,
            Severity::Critical => 9.5,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" | "informational" | "note" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" | "moderate" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            other => Err(format!("unknown severity '{other}'")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Injection,
    CrossSiteScripting,
    CodeExecution,
    FileAccess,
    Deserialization,
    Cryptography,
    Secrets,
    Malware,
    Configuration,
    InformationDisclosure,
    Authentication,
    CodeQuality,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Injection => "Injection",
            Category::CrossSiteScripting => "Cross-Site Scripting",
            Category::CodeExecution => "Code Execution",
            Category::FileAccess => "File Access",
            Category::Deserialization => "Deserialization",
            Category::Cryptography => "Cryptography",
            Category::Secrets => "Secrets",
            Category::Malware => "Malware / Backdoor",
            Category::Configuration => "Configuration",
            Category::InformationDisclosure => "Information Disclosure",
            Category::Authentication => "Authentication",
            Category::CodeQuality => "Code Quality",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextLine {
    pub line: usize,
    pub text: String,
}

/// A step in a taint flow, from user-controlled source to dangerous sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowStep {
    pub line: usize,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Stable fingerprint used for baselines and de-duplication.
    pub fingerprint: String,
    pub rule_id: String,
    pub title: String,
    pub message: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub category: Category,
    pub cwe: Option<u32>,
    pub owasp: Option<String>,
    /// Path relative to the scan root, using forward slashes.
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub snippet: String,
    pub context: Vec<ContextLine>,
    pub flow: Vec<FlowStep>,
    pub remediation: String,
}

impl Finding {
    pub fn location(&self) -> String {
        format!("{}:{}:{}", self.file, self.line, self.column)
    }
}
