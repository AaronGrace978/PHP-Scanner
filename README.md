# PHP Scanner

A fast, offline static security scanner for PHP applications, shipped as a **desktop app** (Tauri 2 + React) and a **CLI** for CI pipelines. Both share one Rust engine.

- **Taint analysis**: tracks user input (superglobals, `php://input`, `$_SERVER['HTTP_*']`, Laravel/Symfony request objects) into SQL, shell, `eval`, include, file, SSRF, redirect, header, LDAP, XPath, regex, deserialization and XSS sinks. It understands sanitizers, escaping in quoted SQL, and branches/loops, and builds per-file function summaries.
- **Dangerous APIs and configuration**: weak hashing and crypto, insecure randomness, disabled TLS verification, loose comparisons on tokens, XXE, `display_errors`, `phpinfo()`, permissive `chmod`, `mysql_*`.
- **Secrets**: AWS, GitHub, Slack, Stripe, Google, OpenAI, Anthropic, Twilio, private keys, DB URLs and hard-coded credentials. Values are masked in every report.
- **Malware and web shells**: known shell signatures, `eval($_POST…)` backdoors, obfuscated execution, encoded payloads, and PHP files in upload directories.
- **php2shell response** (NSA / CISA / NCSC advisory, 21 Oct 2026). See below.
- **Integrity manifests**: SHA-256 known-good snapshots, which are verified later to find added or modified files.
- **Reports**: HTML, SARIF 2.1.0 (GitHub code scanning), JSON and CSV. Supports baselines and inline suppressions.

Scanning WordPress core (about 2,000 files and 700k lines) takes about 1.6 s on 4 cores.

## php2shell (CVE-2026-109618 / CVE-2026-109619)

php2shell is an unauthenticated remote code execution flaw (plus a worker-memory disclosure) **in the PHP interpreter itself**. No application-code change fixes it. The fix is upgrading PHP to **8.5.12, 8.4.27, 8.3.36 or 8.2.35** (or a vendor backport) and **restarting** Apache, PHP-FPM and long-running workers. PHP 8.1 and older receive no official fix.

What the scanner does about it:

| Check | Rule |
|---|---|
| PHP versions declared in `composer.json` (`config.platform.php`), Dockerfiles (`FROM php:…`, `ARG`), compose/K8s/CI `image:`, OS packages, `.php-version`, `.tool-versions` and `app.yaml` | `php2shell-vulnerable-runtime`, `php2shell-unsupported-runtime`, `php2shell-unpinned-runtime` |
| Composer `require.php` constraints that still allow vulnerable versions | `php2shell-composer-constraint` |
| `session.upload_progress.enabled` / `fatal_error_backtraces` (8.5) not disabled in php.ini, FPM pools, Apache/nginx config | `php2shell-mitigation-missing` |
| Mitigations set via `ini_set()`, `.user.ini` or `.htaccess`, which PHP says are ineffective | `php2shell-ineffective-mitigation` |
| `RLIMIT_AS` / `RLIMIT_DATA` (systemd `LimitAS=`/`LimitDATA=`, `ulimit -v/-d`), which PHP warns against | `php2shell-rlimit-misuse` |
| PHP binaries on the scanning machine (`php`, `php8.x`, `php-fpm…`): version and effective ini | `--check-local-runtime`, `php-scanner runtime` |
| Compromise hunting: web shells, backdoors, PHP in upload directories, and integrity verification against a known-good manifest | malware rules, `php-scanner integrity` |
| Secrets that must be rotated because the memory leak can expose them | secret rules |

Each scan ends with a verdict: **Action required**, **Verify production runtimes** (nothing pinned, so a server must be checked by hand), or **Patched in source**. It also prints the advisory's response checklist.

The scanner reads source and configuration. It cannot see the PHP build that is actually running on a server you didn't scan, so always confirm with `php -v` / `php-fpm -v` on each host.

The advisory data lives in [`crates/php-scanner-core/advisories/advisories.json`](crates/php-scanner-core/advisories/advisories.json). To use updated data without rebuilding, pass `--advisory-db file.json` or set `PHP_SCANNER_ADVISORY_DB`.

## Desktop app

```bash
npm ci
npm run app:dev      # development, hot reload
npm run app:build    # installers in target/release/bundle (deb/rpm/AppImage, dmg, msi/nsis)
```

Linux needs `libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf`. See the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/).

The app has these screens:

- **Scan**: pick a folder and optional baseline, with live progress and cancel.
- **Overview**: severity and category breakdown, the php2shell verdict, exports, and baseline writing.
- **Findings**: filterable list with code context, the full file, data flow and fixes.
- **php2shell**: runtime inventory, probing local PHP, mitigations, the checklist and sources.
- **Integrity**: create and verify snapshots.
- **Rules**: enable or disable rules.
- **Settings**.

## CLI

```bash
cargo build --release -p php-scanner-cli   # target/release/php-scanner

php-scanner scan ./my-app                          # coloured text report, exit 1 on high+
php-scanner scan . -f sarif -o php-scanner.sarif   # GitHub code scanning
php-scanner scan . -f html -o report.html --fail-on critical
php-scanner scan . --baseline .php-scanner-baseline.json
php-scanner scan . --write-baseline .php-scanner-baseline.json --fail-on none
php-scanner php2shell /var/www                     # focused advisory check + local PHP probe
php-scanner runtime                                # PHP binaries on this host
php-scanner integrity snapshot /var/www -o known-good.json
php-scanner integrity verify /var/www known-good.json
php-scanner rules                                  # every rule with severity and CWE
php-scanner advisories                             # bundled advisory database
```

Exit codes: `0` clean, `1` findings at or above `--fail-on` (or php2shell action required), `2` error.

Try it on the bundled demo with `php-scanner scan examples/vulnerable-app`.

### GitHub Actions

```yaml
- run: php-scanner scan . --format sarif --output php-scanner.sarif --fail-on none
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: php-scanner.sarif, category: php-scanner }
- run: php-scanner php2shell . --no-local-runtime
```

## Suppressions and baselines

```php
$rows = $db->query($sql); // php-scanner-ignore: sql-injection
// php-scanner-ignore            (on its own line: suppresses the next line, all rules)
// php-scanner-ignore-file       (anywhere in the file)
```

A baseline stores finding fingerprints, which stay stable across line shifts, so CI only fails on **new** issues.

## Architecture

```
crates/php-scanner-core   engine: tree-sitter-php parser, taint analyzer, pattern detectors,
                          advisory checks, integrity, discovery, reports (lib)
crates/php-scanner-cli    `php-scanner` binary (clap)
src-tauri                 desktop shell: Tauri commands around the core
src                       React UI
```

Files are scanned in parallel (rayon). `vendor/` and `node_modules/` are skipped by default, and `.gitignore` is honoured.

## Limitations

- Taint tracking stays within one file. Data passed through other files, sessions or databases isn't followed, and `$_SESSION` isn't treated as a source.
- Like any static analyzer, it reports what it can prove from source. Review findings before acting on them, and don't treat a clean report as proof of security.

## Development

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run build
```

License: MIT
