use php_scanner_core::{ScanConfig, Scanner, Severity};
use std::path::Path;

fn scan_src(name: &str, src: &str) -> Vec<(String, usize)> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, src).unwrap();
    let report = Scanner::new(ScanConfig::default()).scan(dir.path()).unwrap();
    let mut v: Vec<(String, usize)> = report.findings.iter().map(|f| (f.rule_id.clone(), f.line)).collect();
    v.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
    v
}

fn scan(src: &str) -> Vec<(String, usize)> {
    scan_src("app.php", src)
}

fn has(findings: &[(String, usize)], rule: &str, line: usize) -> bool {
    findings.iter().any(|(r, l)| r == rule && *l == line)
}

#[track_caller]
fn assert_has(findings: &[(String, usize)], rule: &str, line: usize) {
    assert!(has(findings, rule, line), "expected {rule} at line {line}, got {findings:?}");
}

#[test]
fn sql_injection_through_variables_and_concat() {
    let f = scan(r#"<?php
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = " . $id;
mysqli_query($conn, $sql);
$pdo->query("DELETE FROM t WHERE name = '{$_POST['name']}'");
$safe = (int) $_GET['n'];
mysqli_query($conn, "SELECT * FROM t WHERE n = $safe");
$esc = mysqli_real_escape_string($conn, $_GET['q']);
mysqli_query($conn, "SELECT '$esc'");
"#);
    assert_has(&f, "sql-injection", 4);
    assert_has(&f, "sql-injection", 5);
    assert!(!has(&f, "sql-injection", 7), "int cast must sanitise: {f:?}");
    assert!(!has(&f, "sql-injection", 9), "escape must sanitise: {f:?}");
}

#[test]
fn xss_variants() {
    let f = scan(r#"<?php
$name = $_GET['name'];
echo "Hello " . $name;
echo htmlspecialchars($name, ENT_QUOTES);
print $_REQUEST['x'];
?>
<p><?= $_GET['q'] ?></p>
<?php echo $_SERVER['PHP_SELF']; echo $_SERVER['DOCUMENT_ROOT'];
"#);
    assert_has(&f, "xss", 3);
    assert!(!has(&f, "xss", 4));
    assert_has(&f, "xss", 5);
    assert_has(&f, "xss", 7);
    assert_has(&f, "xss", 8);
    assert_eq!(f.iter().filter(|(r, l)| r == "xss" && *l == 8).count(), 1);
}

#[test]
fn command_code_and_inclusion() {
    let f = scan(r#"<?php
system("ping " . $_GET['host']);
exec("ls " . escapeshellarg($_GET['d']));
$out = `cat {$_POST['f']}`;
include $_GET['page'] . '.php';
require_once __DIR__ . '/config.php';
eval($_POST['code']);
$fn = $_GET['cb']; $fn();
eval(gzinflate(base64_decode('S0lNzs9JUShILMpMSQQA')));
"#);
    assert_has(&f, "command-injection", 2);
    assert!(!has(&f, "command-injection", 3));
    assert_has(&f, "command-injection", 4);
    assert_has(&f, "file-inclusion", 5);
    assert!(!f.iter().any(|(_, l)| *l == 6), "anchored include is fine: {f:?}");
    assert_has(&f, "webshell-backdoor", 7);
    assert_has(&f, "code-injection", 8);
    assert_has(&f, "obfuscated-execution", 9);
}

#[test]
fn interprocedural_helper_flows() {
    let f = scan(r#"<?php
function getParam($k) { return $_GET[$k]; }
function runQuery($db, $sql) { return mysqli_query($db, $sql); }
function clean($v) { return htmlspecialchars($v); }
$v = getParam('id');
runQuery($conn, "SELECT * FROM t WHERE id=" . $v);
echo clean($_GET['x']);
echo trim($_GET['y']);
"#);
    assert_has(&f, "sql-injection", 6);
    assert!(!has(&f, "xss", 7), "summary must keep sanitiser: {f:?}");
    assert_has(&f, "xss", 8);
}

#[test]
fn framework_sources() {
    let f = scan(r#"<?php
class C {
  public function show(Request $request) {
    $id = $request->input('id');
    DB::select("select * from u where id = " . $id);
    DB::raw($request->get('order'));
    return redirect($request->query('next'));
  }
}
"#);
    assert_has(&f, "sql-injection", 6);
    assert_has(&f, "open-redirect", 7);
}

#[test]
fn file_and_network_sinks() {
    let f = scan(r#"<?php
readfile('/var/data/' . $_GET['file']);
readfile('/var/data/' . basename($_GET['file']));
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $_POST['url']);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
header("Location: " . $_GET['next']);
move_uploaded_file($_FILES['f']['tmp_name'], 'uploads/' . $_FILES['f']['name']);
$obj = unserialize($_COOKIE['state']);
$cfg = unserialize($cached);
extract($_POST);
"#);
    assert_has(&f, "path-traversal", 2);
    assert!(!has(&f, "path-traversal", 3));
    assert_has(&f, "ssrf", 5);
    assert_has(&f, "tls-verification-disabled", 6);
    assert_has(&f, "open-redirect", 7);
    assert_has(&f, "unrestricted-file-upload", 8);
    assert_has(&f, "insecure-deserialization", 9);
    assert_has(&f, "unsafe-unserialize", 10);
    assert_has(&f, "variable-overwrite", 11);
}

#[test]
fn crypto_secrets_and_config() {
    let f = scan(r#"<?php
$hash = md5($password);
$token = md5(uniqid(rand(), true));
$db_password = 'Sup3rS3cret!';
$label_password = 'Enter password';
if ($_POST['token'] == $storedToken) {}
phpinfo();
ini_set('display_errors', '1');
$aws = 'AKIAIOSFODNN7EXAMPLE';
$enc = openssl_encrypt($d, 'aes-128-ecb', $k);
chmod('/tmp/x', 0777);
ini_set('session.upload_progress.enabled', '0');
"#);
    assert_has(&f, "weak-password-hash", 2);
    assert_has(&f, "insecure-random", 3);
    assert_has(&f, "hardcoded-credential", 4);
    assert!(!has(&f, "hardcoded-credential", 5));
    assert_has(&f, "loose-comparison", 6);
    assert_has(&f, "phpinfo-exposure", 7);
    assert_has(&f, "display-errors-enabled", 8);
    assert_has(&f, "leaked-secret", 9);
    assert_has(&f, "weak-cipher", 10);
    assert_has(&f, "insecure-file-permissions", 11);
    assert_has(&f, "php2shell-ineffective-mitigation", 12);
}

#[test]
fn safe_code_has_no_findings() {
    let f = scan(r#"<?php
declare(strict_types=1);
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$id]);
$name = htmlspecialchars($_GET['name'] ?? '', ENT_QUOTES, 'UTF-8');
echo "<p>Hello {$name}</p>";
$count = count($_POST);
echo $count;
$token = bin2hex(random_bytes(32));
if (hash_equals($expected, $_POST['token'] ?? '')) { echo 'ok'; }
$hash = password_hash($password, PASSWORD_DEFAULT);
require __DIR__ . '/vendor/autoload.php';
echo json_encode(['q' => $_GET['q'] ?? null]);
$page = in_array($_GET['p'], ['home', 'about'], true) ? $_GET['p'] : 'home';
$n = intval($_GET['n']) + 1;
echo $n;
"#);
    assert!(f.is_empty(), "expected no findings, got {f:?}");
}

#[test]
fn reassignment_clears_taint_but_branches_do_not() {
    let f = scan(r#"<?php
$q = $_GET['q'];
$q = 'constant';
echo $q;
$r = 'x';
if ($cond) { $r = $_GET['r']; }
echo $r;
"#);
    assert!(!has(&f, "xss", 4));
    assert_has(&f, "xss", 7);
}

#[test]
fn suppression_comments() {
    let f = scan(r#"<?php
// php-scanner-ignore: xss
echo $_GET['a'];
echo $_GET['b']; // php-scanner-ignore
echo $_GET['c'];
"#);
    assert_eq!(f, vec![("xss".to_string(), 5)]);
}

#[test]
fn webshell_upload_dir_and_signatures() {
    let f = scan_src("wp-content/uploads/2026/10/x.php", "<?php /* FilesMan */ @$_POST['p']($_POST['c']);\n");
    assert!(f.iter().any(|(r, _)| r == "php-in-upload-dir"), "{f:?}");
    assert!(f.iter().any(|(r, _)| r == "webshell-signature"), "{f:?}");
    assert!(f.iter().any(|(r, _)| r == "webshell-backdoor"), "{f:?}");
}

#[test]
fn php2shell_project_inventory_and_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    std::fs::write(p.join("composer.json"), r#"{"require":{"php":"^8.2"},"config":{"platform":{"php":"8.3.12"}}}"#).unwrap();
    std::fs::write(p.join("Dockerfile"), "FROM php:8.4.20-fpm-alpine\nRUN echo hi\n").unwrap();
    std::fs::write(p.join("index.php"), "<?php echo 'hi';").unwrap();
    let report = Scanner::new(ScanConfig::default()).scan(p).unwrap();
    let adv = &report.advisories[0];
    assert_eq!(adv.advisory.cves, vec!["CVE-2026-109618", "CVE-2026-109619"]);
    assert_eq!(adv.runtimes.len(), 2);
    assert_eq!(format!("{:?}", adv.verdict), "ActionRequired");
    let crit = report.findings.iter().filter(|f| f.rule_id == "php2shell-vulnerable-runtime" && f.severity == Severity::Critical).count();
    assert_eq!(crit, 2);
    for fmt in ["json", "sarif", "html", "csv"] {
        let out = php_scanner_core::report::render(&report, fmt.parse().unwrap());
        assert!(out.contains("php2shell") || fmt == "csv" && out.contains("php2shell-vulnerable-runtime"), "{fmt}");
    }
    let sarif: serde_json::Value = serde_json::from_str(&php_scanner_core::report::sarif(&report)).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert!(!sarif["runs"][0]["results"].as_array().unwrap().is_empty());
}

#[test]
fn patched_project_verdict() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Dockerfile"), "FROM php:8.4.27-fpm\n").unwrap();
    std::fs::write(dir.path().join("php.ini"), "session.upload_progress.enabled=0\nfatal_error_backtraces=0\n").unwrap();
    let report = Scanner::new(ScanConfig::default()).scan(dir.path()).unwrap();
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(format!("{:?}", report.advisories[0].verdict), "PatchedInSource");
}

#[test]
fn secrets_are_redacted_in_snippets() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.php"), "<?php\n$k = 'AKIAIOSFODNN7EXAMPLE';\n").unwrap();
    let report = Scanner::new(ScanConfig::default()).scan(dir.path()).unwrap();
    let f = report.findings.iter().find(|f| f.rule_id == "leaked-secret").unwrap();
    assert!(!f.snippet.contains("AKIAIOSFODNN7EXAMPLE"), "{}", f.snippet);
    assert!(f.context.iter().all(|c| !c.text.contains("AKIAIOSFODNN7EXAMPLE")));
}

#[test]
fn baseline_filters_known_findings() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.php"), "<?php echo $_GET['x'];\n").unwrap();
    let s = Scanner::new(ScanConfig::default());
    let first = s.scan(dir.path()).unwrap();
    assert_eq!(first.findings.len(), 1);
    let mut s2 = Scanner::new(ScanConfig::default());
    s2.baseline = Some(php_scanner_core::Baseline::from_report(&first));
    let second = s2.scan(dir.path()).unwrap();
    assert!(second.findings.is_empty());
    assert_eq!(second.summary.baselined, 1);
}

#[test]
fn malformed_and_binary_files_do_not_crash() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("broken.php"), "<?php function ( { echo $_GET['x'] ").unwrap();
    std::fs::write(dir.path().join("bin.php"), [0u8, 1, 2, 3, 0, 255]).unwrap();
    std::fs::write(dir.path().join("utf.php"), "<?php echo \"héllo ✓ \" . $_GET['ü'];").unwrap();
    let report = Scanner::new(ScanConfig::default()).scan(Path::new(dir.path())).unwrap();
    assert_eq!(report.files_skipped, 1);
    assert!(report.parse_errors >= 1);
}
