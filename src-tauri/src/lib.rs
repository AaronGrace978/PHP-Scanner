use php_scanner_core::advisory::{self, AdvisoryDb, LocalRuntime};
use php_scanner_core::integrity::{self, IntegrityReport, Manifest};
use php_scanner_core::report::{self, Format};
use php_scanner_core::{rules, Baseline, ScanConfig, ScanProgress, ScanReport, Scanner};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, State};

#[derive(Default)]
struct AppState {
    cancel: Mutex<Option<Arc<AtomicBool>>>,
    last_report: Mutex<Option<ScanReport>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    version: String,
    advisory_db_version: String,
    rule_count: usize,
}

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

#[tauri::command]
fn app_info() -> AppInfo {
    AppInfo {
        version: php_scanner_core::scanner::TOOL_VERSION.to_string(),
        advisory_db_version: AdvisoryDb::builtin().version,
        rule_count: rules::all().len(),
    }
}

#[tauri::command]
fn list_rules() -> Vec<rules::Rule> {
    rules::all().to_vec()
}

#[tauri::command]
fn get_advisories() -> AdvisoryDb {
    AdvisoryDb::builtin()
}

#[tauri::command]
async fn scan(
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
    config: ScanConfig,
    check_local_runtime: bool,
    baseline_path: Option<String>,
) -> Result<ScanReport, String> {
    let mut scanner = Scanner::new(config);
    scanner.probe_local_runtimes = check_local_runtime;
    if let Some(b) = baseline_path.filter(|b| !b.is_empty()) {
        let text = std::fs::read_to_string(&b).map_err(|e| format!("baseline {b}: {e}"))?;
        scanner.baseline = Some(serde_json::from_str::<Baseline>(&text).map_err(|e| format!("invalid baseline: {e}"))?);
    }
    *state.cancel.lock().unwrap() = Some(scanner.cancel_token());

    let report = tauri::async_runtime::spawn_blocking(move || {
        scanner.scan_with_progress(Path::new(&path), &|p: ScanProgress| {
            let _ = app.emit("scan-progress", p);
        })
    })
    .await
    .map_err(err)??;

    *state.cancel.lock().unwrap() = None;
    *state.last_report.lock().unwrap() = Some(report.clone());
    Ok(report)
}

#[tauri::command]
fn cancel_scan(state: State<'_, AppState>) {
    if let Some(c) = state.cancel.lock().unwrap().as_ref() {
        c.store(true, Ordering::Relaxed);
    }
}

#[tauri::command]
fn export_report(state: State<'_, AppState>, path: String, format: String) -> Result<(), String> {
    let guard = state.last_report.lock().unwrap();
    let report = guard.as_ref().ok_or("no scan has been run yet")?;
    let format: Format = format.parse()?;
    std::fs::write(&path, report::render(report, format)).map_err(err)
}

#[tauri::command]
fn write_baseline(state: State<'_, AppState>, path: String) -> Result<usize, String> {
    let guard = state.last_report.lock().unwrap();
    let report = guard.as_ref().ok_or("no scan has been run yet")?;
    let b = Baseline::from_report(report);
    std::fs::write(&path, serde_json::to_string_pretty(&b).map_err(err)?).map_err(err)?;
    Ok(b.fingerprints.len())
}

/// Reads a scanned file for the code viewer. The path must resolve inside the scan root.
#[tauri::command]
fn read_source(root: String, file: String) -> Result<String, String> {
    let root = PathBuf::from(root).canonicalize().map_err(err)?;
    let base = if root.is_file() { root.parent().map(Path::to_path_buf).unwrap_or(root.clone()) } else { root.clone() };
    let target = if root.is_file() { root.clone() } else { base.join(&file) };
    let target = target.canonicalize().map_err(err)?;
    if !target.starts_with(&base) {
        return Err("file is outside the scanned directory".into());
    }
    let meta = std::fs::metadata(&target).map_err(err)?;
    if meta.len() > 16 * 1024 * 1024 {
        return Err("file too large to display".into());
    }
    let bytes = std::fs::read(&target).map_err(err)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[tauri::command]
async fn probe_runtimes() -> Result<Vec<LocalRuntime>, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let db = AdvisoryDb::builtin();
        db.advisories.iter().flat_map(advisory::probe_local_runtimes).collect()
    })
    .await
    .map_err(err)
}

fn integrity_config() -> ScanConfig {
    ScanConfig { respect_gitignore: false, include_hidden: true, scan_dependencies: true, ..Default::default() }
}

#[tauri::command]
async fn integrity_snapshot(path: String, output: String) -> Result<usize, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let m = integrity::create_manifest(Path::new(&path), &integrity_config())?;
        std::fs::write(&output, serde_json::to_string_pretty(&m).map_err(err)?).map_err(err)?;
        Ok(m.files.len())
    })
    .await
    .map_err(err)?
}

#[tauri::command]
async fn integrity_verify(path: String, manifest: String) -> Result<IntegrityReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let text = std::fs::read_to_string(&manifest).map_err(err)?;
        let m: Manifest = serde_json::from_str(&text).map_err(|e| format!("invalid manifest: {e}"))?;
        integrity::verify(Path::new(&path), &integrity_config(), &m)
    })
    .await
    .map_err(err)?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            app_info,
            list_rules,
            get_advisories,
            scan,
            cancel_scan,
            export_report,
            write_baseline,
            read_source,
            probe_runtimes,
            integrity_snapshot,
            integrity_verify
        ])
        .run(tauri::generate_context!())
        .expect("error while running PHP Scanner");
}
