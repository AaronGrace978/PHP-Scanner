//! Known-good comparison (NSA "Detect and Prevent Web Shell Malware", section
//! "Known-Good Comparison"): snapshot file hashes of a verified deployment and
//! later report files that were added, modified or removed.

use crate::discovery::{walk_all, DiscoveredFile};
use crate::config::ScanConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub format: u32,
    pub created_at: String,
    pub root: String,
    pub files: BTreeMap<String, FileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntegrityChange {
    pub path: String,
    pub change: String,
    /// True when the file can be executed by PHP (by extension or content).
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntegrityReport {
    pub manifest_created_at: String,
    pub files_checked: usize,
    pub added: Vec<IntegrityChange>,
    pub modified: Vec<IntegrityChange>,
    pub removed: Vec<IntegrityChange>,
}

impl IntegrityReport {
    pub fn is_clean(&self) -> bool {
        self.added.is_empty() && self.modified.is_empty() && self.removed.is_empty()
    }
}

fn hash_file(path: &Path) -> std::io::Result<(String, u64, bool)> {
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    let mut php_tag = false;
    let mut first = true;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if first {
            php_tag = buf[..n].windows(5).any(|w| w.eq_ignore_ascii_case(b"<?php")) || buf[..n].windows(3).any(|w| w == b"<?=");
            first = false;
        }
        size += n as u64;
        hasher.update(&buf[..n]);
    }
    Ok((format!("{:x}", hasher.finalize()), size, php_tag))
}

fn is_executable(f: &DiscoveredFile, cfg: &ScanConfig, php_tag: bool) -> bool {
    let ext = f.rel.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    php_tag || cfg.extensions.contains(&ext)
}

pub fn create_manifest(root: &Path, cfg: &ScanConfig) -> Result<Manifest, String> {
    let mut files = BTreeMap::new();
    for f in walk_all(root, cfg)? {
        if let Ok((sha256, size, _)) = hash_file(&f.path) {
            files.insert(f.rel.clone(), FileEntry { sha256, size });
        }
    }
    Ok(Manifest {
        format: 1,
        created_at: chrono::Utc::now().to_rfc3339(),
        root: root.display().to_string(),
        files,
    })
}

pub fn verify(root: &Path, cfg: &ScanConfig, manifest: &Manifest) -> Result<IntegrityReport, String> {
    let mut report = IntegrityReport {
        manifest_created_at: manifest.created_at.clone(),
        files_checked: 0,
        added: Vec::new(),
        modified: Vec::new(),
        removed: Vec::new(),
    };
    let mut seen = std::collections::HashSet::new();
    for f in walk_all(root, cfg)? {
        let Ok((sha, _, php_tag)) = hash_file(&f.path) else { continue };
        report.files_checked += 1;
        seen.insert(f.rel.clone());
        let exec = is_executable(&f, cfg, php_tag);
        match manifest.files.get(&f.rel) {
            None => report.added.push(IntegrityChange { path: f.rel.clone(), change: "added".into(), executable: exec }),
            Some(e) if e.sha256 != sha => report.modified.push(IntegrityChange { path: f.rel.clone(), change: "modified".into(), executable: exec }),
            _ => {}
        }
    }
    for path in manifest.files.keys() {
        if !seen.contains(path) {
            report.removed.push(IntegrityChange { path: path.clone(), change: "removed".into(), executable: false });
        }
    }
    for list in [&mut report.added, &mut report.modified] {
        list.sort_by(|a, b| b.executable.cmp(&a.executable).then(a.path.cmp(&b.path)));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_added_modified_removed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        std::fs::write(p.join("index.php"), "<?php echo 1;").unwrap();
        std::fs::write(p.join("style.css"), "a{}").unwrap();
        std::fs::write(p.join("old.txt"), "x").unwrap();
        let cfg = ScanConfig::default();
        let m = create_manifest(p, &cfg).unwrap();
        assert_eq!(m.files.len(), 3);

        std::fs::write(p.join("index.php"), "<?php echo 2;").unwrap();
        std::fs::write(p.join("logo.jpg"), "GIF89a<?php system($_GET['c']);").unwrap();
        std::fs::remove_file(p.join("old.txt")).unwrap();

        let r = verify(p, &cfg, &m).unwrap();
        assert_eq!(r.added.len(), 1);
        assert!(r.added[0].executable, "php hidden in an image must be flagged executable");
        assert_eq!(r.modified.len(), 1);
        assert_eq!(r.removed.len(), 1);
        assert!(!r.is_clean());
    }
}
