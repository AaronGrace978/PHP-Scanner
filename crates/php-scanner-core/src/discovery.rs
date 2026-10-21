use crate::advisory::{classify, ConfigKind};
use crate::config::ScanConfig;
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Php,
    Config(ConfigKind),
    /// Dotenv-style files: scanned for secrets only.
    Env,
    Other,
}

#[derive(Debug, Clone)]
pub struct DiscoveredFile {
    pub path: PathBuf,
    /// Relative to the scan root, forward slashes.
    pub rel: String,
    pub kind: FileKind,
    pub size: u64,
}

const DEPENDENCY_DIRS: &[&str] = &["vendor", "node_modules", "bower_components"];
const ALWAYS_SKIP_DIRS: &[&str] = &[".git", ".hg", ".svn", ".idea", ".vscode", ".cache"];
const ALLOWED_HIDDEN_DIRS: &[&str] = &[".github", ".docker", ".platform", ".ddev", ".lando"];

fn build_globs(patterns: &[String]) -> Result<GlobSet, String> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        b.add(Glob::new(p).map_err(|e| format!("invalid exclude pattern '{p}': {e}"))?);
        if !p.contains('/') && !p.starts_with("**") {
            b.add(Glob::new(&format!("**/{p}")).map_err(|e| e.to_string())?);
        }
        if !p.ends_with("/**") {
            b.add(Glob::new(&format!("{}/**", p.trim_end_matches('/'))).map_err(|e| e.to_string())?);
        }
    }
    b.build().map_err(|e| e.to_string())
}

pub fn classify_file(rel: &str, cfg: &ScanConfig) -> FileKind {
    let lower = rel.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    if let Some((_, ext)) = name.rsplit_once('.') {
        if cfg.extensions.iter().any(|e| e.eq_ignore_ascii_case(ext)) && name != ".user.ini" {
            return FileKind::Php;
        }
    }
    if let Some(k) = classify(rel) {
        return FileKind::Config(k);
    }
    if name == ".env" || name.starts_with(".env.") || name.ends_with(".env") {
        return FileKind::Env;
    }
    FileKind::Other
}

fn walker(root: &Path, cfg: &ScanConfig) -> WalkBuilder {
    let mut b = WalkBuilder::new(root);
    let include_hidden = cfg.include_hidden;
    let scan_deps = cfg.scan_dependencies;
    b.hidden(false)
        .git_ignore(cfg.respect_gitignore)
        .git_global(false)
        .git_exclude(cfg.respect_gitignore)
        .ignore(cfg.respect_gitignore)
        .parents(cfg.respect_gitignore)
        .require_git(false)
        .follow_links(cfg.follow_symlinks)
        .filter_entry(move |e| {
            if e.depth() == 0 || !e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                return true;
            }
            let name = e.file_name().to_string_lossy();
            if ALWAYS_SKIP_DIRS.contains(&name.as_ref()) {
                return false;
            }
            if !scan_deps && DEPENDENCY_DIRS.contains(&name.as_ref()) {
                return false;
            }
            if name.starts_with('.') && !include_hidden && !ALLOWED_HIDDEN_DIRS.contains(&name.as_ref()) {
                return false;
            }
            true
        });
    if cfg.threads > 0 {
        b.threads(cfg.threads);
    }
    b
}

fn rel_path(root: &Path, p: &Path) -> String {
    let rel = p.strip_prefix(root).unwrap_or(p);
    let s = rel.to_string_lossy().replace('\\', "/");
    if s.is_empty() {
        p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()
    } else {
        s
    }
}

fn collect(root: &Path, cfg: &ScanConfig, keep_other: bool) -> Result<Vec<DiscoveredFile>, String> {
    if !root.exists() {
        return Err(format!("path does not exist: {}", root.display()));
    }
    let excludes = build_globs(&cfg.exclude)?;
    if root.is_file() {
        let rel = root.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let kind = classify_file(&rel, cfg);
        let size = std::fs::metadata(root).map(|m| m.len()).unwrap_or(0);
        let kind = if kind == FileKind::Other && !keep_other { FileKind::Php } else { kind };
        return Ok(vec![DiscoveredFile { path: root.to_path_buf(), rel, kind, size }]);
    }
    let mut out = Vec::new();
    for entry in walker(root, cfg).build() {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let rel = rel_path(root, entry.path());
        if excludes.is_match(&rel) {
            continue;
        }
        let kind = classify_file(&rel, cfg);
        if kind == FileKind::Other && !keep_other {
            continue;
        }
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        out.push(DiscoveredFile { path: entry.into_path(), rel, kind, size });
    }
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(out)
}

/// Files relevant to the scanner (PHP sources, runtime config, dotenv files).
pub fn walk(root: &Path, cfg: &ScanConfig) -> Result<Vec<DiscoveredFile>, String> {
    collect(root, cfg, false)
}

/// Every file under root (used for integrity manifests).
pub fn walk_all(root: &Path, cfg: &ScanConfig) -> Result<Vec<DiscoveredFile>, String> {
    collect(root, cfg, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_vendor_and_respects_excludes() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path();
        std::fs::create_dir_all(p.join("src")).unwrap();
        std::fs::create_dir_all(p.join("vendor/pkg")).unwrap();
        std::fs::create_dir_all(p.join("tests")).unwrap();
        std::fs::create_dir_all(p.join(".git")).unwrap();
        std::fs::write(p.join("src/a.php"), "<?php").unwrap();
        std::fs::write(p.join("vendor/pkg/b.php"), "<?php").unwrap();
        std::fs::write(p.join("tests/c.php"), "<?php").unwrap();
        std::fs::write(p.join(".git/d.php"), "<?php").unwrap();
        std::fs::write(p.join("Dockerfile"), "FROM php:8.3").unwrap();
        std::fs::write(p.join(".env"), "X=1").unwrap();
        std::fs::write(p.join("readme.md"), "x").unwrap();
        let cfg = ScanConfig { exclude: vec!["tests".into()], ..Default::default() };
        let files: Vec<String> = walk(p, &cfg).unwrap().into_iter().map(|f| f.rel).collect();
        assert_eq!(files, vec![".env", "Dockerfile", "src/a.php"]);
    }
}
