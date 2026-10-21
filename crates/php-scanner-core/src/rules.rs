use crate::finding::{Category, Severity};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub category: Category,
    pub cwe: Option<u32>,
    pub owasp: Option<&'static str>,
    pub description: &'static str,
    pub remediation: &'static str,
}

macro_rules! rule {
    ($id:expr, $title:expr, $sev:ident, $cat:ident, $cwe:expr, $owasp:expr, $desc:expr, $fix:expr) => {
        Rule {
            id: $id,
            title: $title,
            severity: Severity::$sev,
            category: Category::$cat,
            cwe: $cwe,
            owasp: $owasp,
            description: $desc,
            remediation: $fix,
        }
    };
}

const A01: Option<&str> = Some("A01:2021 Broken Access Control");
const A02: Option<&str> = Some("A02:2021 Cryptographic Failures");
const A03: Option<&str> = Some("A03:2021 Injection");
const A05: Option<&str> = Some("A05:2021 Security Misconfiguration");
const A06: Option<&str> = Some("A06:2021 Vulnerable and Outdated Components");
const A07: Option<&str> = Some("A07:2021 Identification and Authentication Failures");
const A08: Option<&str> = Some("A08:2021 Software and Data Integrity Failures");
const A10: Option<&str> = Some("A10:2021 Server-Side Request Forgery");

pub static RULES: &[Rule] = &[
    // ---- Taint-tracked vulnerabilities -------------------------------------------------
    rule!("sql-injection", "SQL injection", Critical, Injection, Some(89), A03,
        "User-controlled data is concatenated or interpolated into a SQL query.",
        "Use prepared statements with bound parameters (PDO::prepare + execute, mysqli_stmt_bind_param). Never build SQL strings from request data."),
    rule!("command-injection", "OS command injection", Critical, Injection, Some(78), A03,
        "User-controlled data reaches a function that executes shell commands.",
        "Avoid shell execution. If unavoidable, pass every argument through escapeshellarg() and use an allow-list of permitted values."),
    rule!("code-injection", "Code injection", Critical, CodeExecution, Some(94), A03,
        "User-controlled data is evaluated as PHP code or used as a callable.",
        "Never pass request data to eval(), assert(), create_function() or dynamic callables. Map user input to an allow-list of known functions."),
    rule!("file-inclusion", "Local/remote file inclusion", Critical, FileAccess, Some(98), A03,
        "User-controlled data determines which file is included or required, allowing arbitrary code execution.",
        "Never include files based on request data. Use a fixed map of allowed templates/modules and disable allow_url_include."),
    rule!("path-traversal", "Path traversal", High, FileAccess, Some(22), A01,
        "User-controlled data is used as a filesystem path, allowing access outside the intended directory.",
        "Normalise with basename() or realpath() and verify the resolved path is inside an allowed base directory."),
    rule!("xss", "Cross-site scripting (XSS)", High, CrossSiteScripting, Some(79), A03,
        "User-controlled data is written to the HTTP response without output encoding.",
        "Encode on output with htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') or use an auto-escaping template engine (Twig, Blade)."),
    rule!("ssrf", "Server-side request forgery (SSRF)", High, Injection, Some(918), A10,
        "User-controlled data determines the URL of an outbound server-side request.",
        "Validate URLs against an allow-list of hosts and schemes, and block internal/link-local address ranges."),
    rule!("open-redirect", "Open redirect", Medium, Injection, Some(601), A01,
        "User-controlled data is used as a redirect target in a Location header.",
        "Redirect only to relative paths or to an allow-list of trusted destinations."),
    rule!("header-injection", "HTTP header injection", Medium, Injection, Some(113), A03,
        "User-controlled data is written into an HTTP response header.",
        "Strip CR/LF characters and validate header values against an expected format."),
    rule!("insecure-deserialization", "Insecure deserialization of user input", Critical, Deserialization, Some(502), A08,
        "User-controlled data is passed to unserialize(), enabling PHP object injection.",
        "Use json_decode() for untrusted data. If unserialize() is required, pass ['allowed_classes' => false]."),
    rule!("ldap-injection", "LDAP injection", High, Injection, Some(90), A03,
        "User-controlled data is used in an LDAP search filter or DN.",
        "Escape values with ldap_escape() using LDAP_ESCAPE_FILTER or LDAP_ESCAPE_DN."),
    rule!("xpath-injection", "XPath injection", High, Injection, Some(643), A03,
        "User-controlled data is used in an XPath expression.",
        "Validate input against a strict allow-list or use parameterised XPath via DOMXPath::registerPhpFunctions with care."),
    rule!("unrestricted-file-upload", "Unrestricted file upload", High, FileAccess, Some(434), A01,
        "An uploaded file is stored using a client-supplied name or destination.",
        "Generate the stored filename server-side, validate the extension and MIME type against an allow-list, and store uploads outside the web root."),
    rule!("variable-overwrite", "Variable overwrite from user input", High, Injection, Some(621), A03,
        "extract() or single-argument parse_str() imports request data into the local symbol table.",
        "Read the specific keys you need from the request array instead of importing it wholesale."),
    rule!("regex-injection", "Regular expression injection", Medium, Injection, Some(625), A03,
        "User-controlled data is used as a regular expression pattern (ReDoS / pattern manipulation).",
        "Escape user input with preg_quote() before embedding it in a pattern."),
    rule!("session-fixation", "Session fixation", Medium, Authentication, Some(384), A07,
        "The session identifier is set from user-controlled data.",
        "Never accept session IDs from request parameters. Call session_regenerate_id(true) after login."),
    // ---- Dangerous API usage --------------------------------------------------------------
    rule!("dangerous-eval", "Dynamic code evaluation", High, CodeExecution, Some(95), A03,
        "eval(), assert() with a string, or create_function() evaluates a dynamically built string as code.",
        "Remove dynamic evaluation. Use closures, strategy objects, or a lookup table of allowed operations."),
    rule!("dangerous-exec", "Shell command execution with dynamic arguments", Medium, Injection, Some(78), A03,
        "A shell execution function is called with a non-constant argument.",
        "Ensure every dynamic component is validated and escaped with escapeshellarg(), or replace the shell call with a native PHP API."),
    rule!("dynamic-include", "Dynamic file inclusion", Low, FileAccess, Some(98), A03,
        "A file is included using a computed path. Verify that no part of it is attacker-controlled.",
        "Prefer constant include paths anchored at __DIR__, or validate against a fixed list."),
    rule!("unsafe-unserialize", "unserialize() without allowed_classes", Medium, Deserialization, Some(502), A08,
        "unserialize() is called without restricting allowed classes, which enables object injection if the data is ever attacker-influenced.",
        "Pass ['allowed_classes' => false] (or an explicit list), or switch to json_decode()."),
    rule!("preg-replace-eval", "preg_replace() with /e modifier", High, CodeExecution, Some(94), A03,
        "The /e modifier evaluates the replacement as PHP code (removed in PHP 7, but still a strong backdoor indicator).",
        "Use preg_replace_callback() instead."),
    rule!("weak-password-hash", "Weak password hashing", High, Cryptography, Some(916), A02,
        "A password appears to be hashed with a fast, unsalted digest (md5/sha1/crc32).",
        "Use password_hash() with PASSWORD_DEFAULT or PASSWORD_ARGON2ID and verify with password_verify()."),
    rule!("insecure-random", "Insecure randomness for security value", Medium, Cryptography, Some(338), A02,
        "A non-cryptographic random generator is used to create a token, password, key or salt.",
        "Use random_bytes() or random_int(), e.g. bin2hex(random_bytes(32))."),
    rule!("weak-cipher", "Weak or deprecated cryptography", Medium, Cryptography, Some(327), A02,
        "A broken cipher, ECB mode, or the removed mcrypt extension is used.",
        "Use sodium_crypto_secretbox() or openssl_encrypt() with AES-256-GCM and a random IV."),
    rule!("tls-verification-disabled", "TLS certificate verification disabled", High, Cryptography, Some(295), A02,
        "Certificate or hostname verification is disabled for an outbound TLS connection.",
        "Keep CURLOPT_SSL_VERIFYPEER = true and CURLOPT_SSL_VERIFYHOST = 2 (and verify_peer => true in stream contexts)."),
    rule!("loose-comparison", "Loose comparison of security-sensitive value", Medium, Authentication, Some(697), A07,
        "A password, hash, token or signature is compared with == / != which is vulnerable to type juggling.",
        "Use hash_equals() for secrets and === for strict comparisons."),
    rule!("hardcoded-credential", "Hard-coded credential", High, Secrets, Some(798), A07,
        "A password, API key or secret is assigned a literal value in source code.",
        "Load secrets from environment variables or a secrets manager; rotate the exposed credential."),
    rule!("leaked-secret", "Secret token in source", High, Secrets, Some(798), A07,
        "A string matching a known API key / private key format was found in source code.",
        "Revoke and rotate the credential immediately, then load it from the environment or a vault."),
    rule!("phpinfo-exposure", "phpinfo() call", Low, InformationDisclosure, Some(200), A05,
        "phpinfo() discloses server configuration, paths and environment variables.",
        "Remove phpinfo() from deployed code."),
    rule!("display-errors-enabled", "Error display enabled", Low, Configuration, Some(209), A05,
        "display_errors is enabled at runtime, leaking stack traces and paths to users.",
        "Disable display_errors in production and log errors instead."),
    rule!("xxe", "XML external entity (XXE) processing enabled", High, Injection, Some(611), A05,
        "XML is parsed with entity substitution (LIBXML_NOENT/LIBXML_DTDLOAD) or the entity loader is re-enabled.",
        "Do not pass LIBXML_NOENT or LIBXML_DTDLOAD when parsing untrusted XML."),
    rule!("insecure-file-permissions", "Overly permissive file permissions", Medium, Configuration, Some(732), A05,
        "A file or directory is made world-writable.",
        "Use the least permissive mode needed, e.g. 0644 for files and 0755 for directories."),
    rule!("deprecated-mysql", "Removed mysql_* extension", Low, CodeQuality, Some(477), A06,
        "The mysql_* extension was removed in PHP 7 and lacks prepared statements.",
        "Migrate to PDO or mysqli with prepared statements."),
    // ---- Malware / backdoor indicators -------------------------------------------------------
    rule!("obfuscated-execution", "Obfuscated code execution", Critical, Malware, Some(506), A08,
        "Encoded or compressed data is decoded and executed - a hallmark of injected malware.",
        "Treat the host as compromised: remove the code, audit for other backdoors, and rotate credentials."),
    rule!("webshell-backdoor", "Web shell / backdoor", Critical, Malware, Some(506), A08,
        "Request data is used directly as a function name or code, giving an attacker remote code execution.",
        "Treat the host as compromised: remove the file, audit access logs, and rotate credentials."),
    rule!("webshell-signature", "Known web shell signature", Critical, Malware, Some(506), A08,
        "The file contains strings characteristic of a known PHP web shell.",
        "Quarantine the file, review how it was planted, and perform incident response."),
    rule!("encoded-payload", "Large encoded payload", Medium, Malware, Some(506), A08,
        "A long, high-entropy encoded string literal was found. Malware commonly hides payloads this way.",
        "Verify the origin of the data. Legitimate assets should live in separate files, not embedded blobs."),
    rule!("php-in-upload-dir", "PHP file in an upload directory", High, Malware, Some(434), A01,
        "Executable PHP code is stored in a user-upload directory, a common web shell location (NSA web shell guidance).",
        "Verify the file against a known-good copy, remove it if unexpected, and block PHP execution in upload directories."),
    // ---- Runtime advisories (php2shell, CVE-2026-109618 / CVE-2026-109619) -----------------
    rule!("php2shell-vulnerable-runtime", "PHP runtime affected by php2shell (CVE-2026-109618 / CVE-2026-109619)", Critical, Configuration, Some(416), A06,
        "The project pins or installs a PHP runtime older than the fixed releases. The flaws allow unauthenticated remote code execution and memory disclosure before any application code runs (NSA / CISA / NCSC advisories, 21 Oct 2026).",
        "Upgrade to PHP 8.5.12, 8.4.27, 8.3.36 or 8.2.35 (or a vendor-patched build) and restart Apache / PHP-FPM / all PHP workers. If you cannot patch immediately, take the system offline."),
    rule!("php2shell-unsupported-runtime", "Unsupported PHP runtime with no official php2shell fix", Critical, Configuration, Some(1104), A06,
        "PHP 8.1 and older are end-of-life and receive no official fix for CVE-2026-109618 / CVE-2026-109619. CISA advises taking such systems offline until upgraded.",
        "Upgrade to a supported branch (8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+) or obtain a backported build from your LTS vendor; take the system offline until then."),
    rule!("php2shell-unpinned-runtime", "PHP runtime version cannot be verified as patched", Medium, Configuration, Some(1104), A06,
        "A floating image tag, distribution package or bundled runtime is used, so the PHP patch level cannot be determined from source.",
        "Rebuild and redeploy from an image or package that provides PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or later, pin the exact version, then restart all PHP processes."),
    rule!("php2shell-composer-constraint", "Composer allows PHP versions affected by php2shell", Low, Configuration, Some(1104), A06,
        "The composer.json PHP requirement accepts runtimes vulnerable to CVE-2026-109618 / CVE-2026-109619.",
        "Raise the requirement to the fixed releases, e.g. \"php\": \"~8.2.35 || ~8.3.36 || ~8.4.27 || ^8.5.12\", so deployments on vulnerable runtimes fail fast."),
    rule!("php2shell-mitigation-missing", "php2shell temporary mitigation not applied", High, Configuration, Some(1188), A05,
        "PHP configuration leaves session upload progress (or fatal_error_backtraces on PHP 8.5) enabled, which keeps the confirmed CVE-2026-109619 exploitation path open on unpatched runtimes.",
        "Patch PHP. Until then set session.upload_progress.enabled=0 (and fatal_error_backtraces=0 on 8.5) in php.ini, the FPM pool or server config, then restart every worker. This reduces exposure but is not a fix."),
    rule!("php2shell-ineffective-mitigation", "php2shell mitigation applied in a way PHP says is ineffective", Medium, Configuration, Some(1188), A05,
        "The mitigation directive is set via ini_set(), .user.ini or a per-directory file. PHP's advisory states it must be set in php.ini, an FPM pool or server configuration to take effect before the vulnerable code runs.",
        "Move the directive to php.ini / the FPM pool (php_admin_value) / server config and restart all workers."),
    rule!("php2shell-rlimit-misuse", "Address-space / data rlimit used as a memory guard", High, Configuration, Some(770), A05,
        "RLIMIT_AS / RLIMIT_DATA (LimitAS=, LimitDATA=, ulimit -v / -d) can trigger the allocation failure that CVE-2026-109618 exploits. PHP explicitly warns not to use them as a substitute for memory_limit.",
        "Remove the address-space/data limit; use memory_limit (set so applications cannot override it), post_max_size and proxy request-size limits instead, and patch PHP."),
];

pub fn all() -> &'static [Rule] {
    RULES
}

pub fn get(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn rule_ids_are_unique() {
        let mut seen = HashSet::new();
        for r in RULES {
            assert!(seen.insert(r.id), "duplicate rule id {}", r.id);
        }
    }
}
