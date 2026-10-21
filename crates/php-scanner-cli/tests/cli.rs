use assert_cmd::Command;

fn bin() -> Command {
    Command::cargo_bin("php-scanner").unwrap()
}

#[test]
fn exit_codes_follow_fail_on() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.php"), "<?php echo $_GET['x'];").unwrap();
    bin()
        .args(["scan", "--no-color"])
        .arg(dir.path())
        .assert()
        .code(1);
    bin()
        .args(["scan", "--fail-on", "critical"])
        .arg(dir.path())
        .assert()
        .code(0);
    bin()
        .args(["scan", "--fail-on", "none"])
        .arg(dir.path())
        .assert()
        .code(0);
}

#[test]
fn writes_sarif_report() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.php"), "<?php system($_GET['c']);").unwrap();
    let out = dir.path().join("r.sarif");
    bin()
        .args(["scan", "--format", "sarif", "--fail-on", "none", "-o"])
        .arg(&out)
        .arg(dir.path())
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out).unwrap()).unwrap();
    assert_eq!(v["runs"][0]["results"][0]["ruleId"], "command-injection");
}

#[test]
fn php2shell_command_flags_vulnerable_runtime() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Dockerfile"), "FROM php:8.3.30-apache\n").unwrap();
    let assert = bin()
        .args(["php2shell", "--no-local-runtime", "--no-color"])
        .arg(dir.path())
        .assert()
        .code(1);
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(out.contains("CVE-2026-109618"), "{out}");
    assert!(out.contains("VULNERABLE"), "{out}");
}

#[test]
fn unknown_rule_is_an_error() {
    bin()
        .args(["scan", "--rule", "does-not-exist", "."])
        .assert()
        .code(2);
}

#[test]
fn integrity_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let site = dir.path().join("site");
    std::fs::create_dir(&site).unwrap();
    std::fs::write(site.join("index.php"), "<?php echo 1;").unwrap();
    let manifest = dir.path().join("m.json");
    bin()
        .args(["integrity", "snapshot"])
        .arg(&site)
        .arg("-o")
        .arg(&manifest)
        .assert()
        .success();
    bin()
        .args(["integrity", "verify"])
        .arg(&site)
        .arg(&manifest)
        .assert()
        .success();
    std::fs::write(site.join("shell.php"), "<?php eval($_POST[1]);").unwrap();
    bin()
        .args(["integrity", "verify"])
        .arg(&site)
        .arg(&manifest)
        .assert()
        .code(1);
}
