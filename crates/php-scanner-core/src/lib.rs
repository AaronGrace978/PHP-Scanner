//! PHP Scanner core engine.
//!
//! - [`analyzer`]: tree-sitter based taint tracking and dangerous-API checks
//! - [`patterns`]: secrets, web shell signatures and encoded payloads
//! - [`advisory`]: PHP runtime advisories (php2shell CVE-2026-109618 / CVE-2026-109619)
//! - [`integrity`]: known-good file manifests for web shell detection
//! - [`report`]: JSON, SARIF 2.1.0, HTML and CSV output

pub mod advisory;
pub mod analyzer;
pub mod config;
pub mod discovery;
pub mod finding;
pub mod integrity;
pub mod patterns;
pub mod report;
pub mod rules;
pub mod scanner;
pub mod suppress;

pub use config::ScanConfig;
pub use finding::{Category, Confidence, Finding, Severity};
pub use scanner::{Baseline, ScanProgress, ScanReport, Scanner};
