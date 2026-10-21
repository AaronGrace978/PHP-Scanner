//! Text-level detectors that do not need a syntax tree: leaked secrets,
//! web shell signatures and encoded payloads.

use crate::analyzer::RawFinding;
use crate::finding::Confidence;
use once_cell::sync::Lazy;
use regex::Regex;

struct SecretPattern {
    name: &'static str,
    re: Regex,
}

static SECRETS: Lazy<Vec<SecretPattern>> = Lazy::new(|| {
    let p = |name, re: &str| SecretPattern {
        name,
        re: Regex::new(re).unwrap(),
    };
    vec![
        p(
            "AWS access key ID",
            r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
        ),
        p(
            "private key",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
        ),
        p(
            "GitHub token",
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b",
        ),
        p("Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,72}\b"),
        p(
            "Slack webhook URL",
            r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]{16,}",
        ),
        p(
            "Stripe live secret key",
            r"\b[sr]k_live_[0-9a-zA-Z]{20,99}\b",
        ),
        p("Google API key", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        p(
            "SendGrid API key",
            r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
        ),
        p(
            "OpenAI API key",
            r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b",
        ),
        p(
            "Anthropic API key",
            r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b",
        ),
        p("Twilio API key", r"\bSK[0-9a-f]{32}\b"),
        p("Mailchimp API key", r"\b[0-9a-f]{32}-us\d{1,2}\b"),
        p("Square access token", r"\bsq0atp-[0-9A-Za-z\-_]{22}\b"),
        p(
            "PayPal Braintree token",
            r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b",
        ),
        p(
            "database URL with password",
            r"\b(?:mysql|mysqli|pgsql|postgres|postgresql|mongodb(?:\+srv)?|redis|amqp|mssql|sqlsrv)://[^\s:/'\x22@]+:[^\s@'\x22$]{3,}@[^\s'\x22]+",
        ),
    ]
});

static WEBSHELL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b(c99shell|c99_buff_prepare|c100\s*shell|r57shell|r57_pwd_hash|filesman|b374k|indoxploit|anonymousfox|wso_version|wso\s*shell|alfa_data|alfashell|marijuana\s*shell|p0wny@shell|weevely|phpspy|safe0ver|madspot|syrian\s*shell|bypass\s*shell|uploader\s+by\s+|leaf\s*mailer|kacak\s*fsoe)\b",
    )
    .unwrap()
});

static LONG_BASE64: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"['"]([A-Za-z0-9+/]{600,}={0,2})['"]"#).unwrap());
static HEX_ESCAPES: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?:\\x[0-9a-fA-F]{2}){40,}").unwrap());
static CHR_CHAIN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:chr\(\s*\d+\s*\)\s*\.\s*){15,}").unwrap());
static BLADE_RAW: Lazy<Regex> = Lazy::new(|| Regex::new(r"\{!!\s*(.+?)\s*!!\}").unwrap());

pub struct PatternResult {
    pub findings: Vec<RawFinding>,
    /// Byte ranges that must be masked in any snippet shown to users.
    pub secret_spans: Vec<(usize, usize)>,
}

fn pos(line_starts: &[usize], offset: usize) -> (usize, usize) {
    let row = match line_starts.binary_search(&offset) {
        Ok(r) => r,
        Err(r) => r - 1,
    };
    (row, offset - line_starts[row])
}

pub fn line_starts(src: &str) -> Vec<usize> {
    let mut v = vec![0];
    v.extend(src.match_indices('\n').map(|(i, _)| i + 1));
    v
}

fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub fn scan_text(src: &str, starts: &[usize], path: &str) -> PatternResult {
    let mut findings = Vec::new();
    let mut secret_spans = Vec::new();
    let mut push = |rule: &'static str, conf: Confidence, s: usize, e: usize, msg: String| {
        findings.push(RawFinding {
            rule_id: rule,
            message: msg,
            confidence: conf,
            start: pos(starts, s),
            end: pos(starts, e),
            flow: Vec::new(),
        });
    };

    for sp in SECRETS.iter() {
        for m in sp.re.find_iter(src) {
            let text = m.as_str();
            if sp.name == "database URL with password" {
                let lower = text.to_ascii_lowercase();
                if lower.contains(":password@")
                    || lower.contains(":secret@")
                    || lower.contains(":pass@")
                    || lower.contains("${")
                {
                    continue;
                }
            }
            secret_spans.push((m.start(), m.end()));
            push(
                "leaked-secret",
                Confidence::High,
                m.start(),
                m.end(),
                format!("{} found in source code.", sp.name),
            );
        }
    }

    if let Some(m) = WEBSHELL.find(src) {
        push(
            "webshell-signature",
            Confidence::Medium,
            m.start(),
            m.end(),
            format!("Matches known web shell signature '{}'.", m.as_str()),
        );
    }

    for c in LONG_BASE64.captures_iter(src) {
        let m = c.get(1).unwrap();
        let entropy = shannon_entropy(m.as_str());
        if entropy > 5.0 {
            push(
                "encoded-payload",
                Confidence::Medium,
                m.start(),
                m.start() + 1,
                format!(
                    "{}-character base64 blob with entropy {:.2} bits/char.",
                    m.as_str().len(),
                    entropy
                ),
            );
        }
    }
    for m in HEX_ESCAPES.find_iter(src) {
        push(
            "encoded-payload",
            Confidence::Medium,
            m.start(),
            m.start() + 1,
            format!(
                "Hex-escaped string of {} bytes, typical of obfuscated code.",
                m.as_str().len() / 4
            ),
        );
    }
    for m in CHR_CHAIN.find_iter(src) {
        push(
            "encoded-payload",
            Confidence::Medium,
            m.start(),
            m.start() + 1,
            "Long chr() concatenation chain, typical of obfuscated code.".into(),
        );
    }

    if path.ends_with(".blade.php") {
        for c in BLADE_RAW.captures_iter(src) {
            let expr = c.get(1).unwrap().as_str();
            let l = expr.to_ascii_lowercase();
            if l.contains("request")
                || l.contains("$_")
                || l.contains("input(")
                || l.contains("old(")
            {
                let m = c.get(0).unwrap();
                push(
                    "xss",
                    Confidence::Medium,
                    m.start(),
                    m.end(),
                    format!("Unescaped Blade output of request data: {{!! {expr} !!}}"),
                );
            }
        }
    }

    PatternResult {
        findings,
        secret_spans,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_aws_key_and_masks_span() {
        let src = "<?php\n$k = 'AKIAIOSFODNN7EXAMPLE';\n";
        let r = scan_text(src, &line_starts(src), "a.php");
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].start.0, 1);
        assert_eq!(r.secret_spans.len(), 1);
    }

    #[test]
    fn ignores_placeholder_db_url() {
        let src = "mysql://user:password@localhost/db";
        let r = scan_text(src, &line_starts(src), "a.php");
        assert!(r.findings.is_empty());
    }

    #[test]
    fn entropy_of_uniform_is_high() {
        assert!(
            shannon_entropy("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/")
                > 5.9
        );
        assert!(shannon_entropy("aaaaaaaa") < 0.1);
    }
}
