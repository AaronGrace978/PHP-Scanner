//! Inline suppressions:
//!
//! ```php
//! $x = eval($code); // php-scanner-ignore
//! // php-scanner-ignore: sql-injection, xss
//! $db->query($sql);
//! // php-scanner-ignore-file: hardcoded-credential
//! ```

const LINE_MARKER: &str = "php-scanner-ignore";
const FILE_MARKER: &str = "php-scanner-ignore-file";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Scope {
    All,
    Rules(Vec<String>),
}

impl Scope {
    fn covers(&self, rule: &str) -> bool {
        match self {
            Scope::All => true,
            Scope::Rules(r) => r.iter().any(|x| x == rule),
        }
    }
}

#[derive(Debug, Default)]
pub struct Suppressions {
    file: Vec<Scope>,
    /// (0-based line, applies to the following line, scope)
    lines: Vec<(usize, bool, Scope)>,
}

fn is_comment_only(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//")
        || t.starts_with('#')
        || t.starts_with("/*")
        || t.starts_with('*')
        || t.starts_with("<?php //")
}

fn parse_scope(rest: &str) -> Scope {
    let rest = rest.trim_start();
    let Some(list) = rest.strip_prefix(':').or_else(|| rest.strip_prefix('=')) else {
        return Scope::All;
    };
    let rules: Vec<String> = list
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(|s| s.trim().trim_end_matches("*/").trim())
        .take_while(|s| !s.starts_with("--"))
        .filter(|s| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
        .map(|s| s.to_string())
        .collect();
    if rules.is_empty() {
        Scope::All
    } else {
        Scope::Rules(rules)
    }
}

impl Suppressions {
    pub fn parse(src: &str) -> Self {
        let mut s = Suppressions::default();
        if !src.contains(LINE_MARKER) {
            return s;
        }
        for (i, line) in src.lines().enumerate() {
            if let Some(pos) = line.find(FILE_MARKER) {
                s.file.push(parse_scope(&line[pos + FILE_MARKER.len()..]));
            } else if let Some(pos) = line.find(LINE_MARKER) {
                s.lines.push((
                    i,
                    is_comment_only(line),
                    parse_scope(&line[pos + LINE_MARKER.len()..]),
                ));
            }
        }
        s
    }

    /// A finding on `line` (0-based) is suppressed by a trailing marker on the same
    /// line, or by a comment-only marker line directly above it.
    pub fn is_suppressed(&self, rule: &str, line: usize) -> bool {
        if self.file.iter().any(|sc| sc.covers(rule)) {
            return true;
        }
        self.lines
            .iter()
            .any(|(l, next, sc)| (*l == line || (*next && *l + 1 == line)) && sc.covers(rule))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_and_previous_line() {
        let s =
            Suppressions::parse("a\n// php-scanner-ignore\nb\nc // php-scanner-ignore: xss\nd\n");
        assert!(s.is_suppressed("sql-injection", 1));
        assert!(s.is_suppressed("sql-injection", 2));
        assert!(!s.is_suppressed("sql-injection", 3));
        assert!(s.is_suppressed("xss", 3));
        assert!(
            !s.is_suppressed("xss", 4),
            "trailing marker must not leak to the next line"
        );
        assert!(!s.is_suppressed("xss", 0));
    }

    #[test]
    fn file_level() {
        let s = Suppressions::parse("<?php /* php-scanner-ignore-file: hardcoded-credential */");
        assert!(s.is_suppressed("hardcoded-credential", 100));
        assert!(!s.is_suppressed("xss", 100));
    }
}
