import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AdvisoryDb,
  AppInfo,
  IntegrityReport,
  LocalRuntime,
  Rule,
  ScanConfig,
  ScanProgress,
  ScanReport,
} from "./types";

export const isTauri = () => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export const api = {
  appInfo: () => invoke<AppInfo>("app_info"),
  listRules: () => invoke<Rule[]>("list_rules"),
  advisories: () => invoke<AdvisoryDb>("get_advisories"),
  scan: (path: string, config: ScanConfig, checkLocalRuntime: boolean, baselinePath?: string) =>
    invoke<ScanReport>("scan", { path, config, checkLocalRuntime, baselinePath: baselinePath || null }),
  cancelScan: () => invoke<void>("cancel_scan"),
  exportReport: (path: string, format: string) => invoke<void>("export_report", { path, format }),
  writeBaseline: (path: string) => invoke<number>("write_baseline", { path }),
  readSource: (root: string, file: string) => invoke<string>("read_source", { root, file }),
  probeRuntimes: () => invoke<LocalRuntime[]>("probe_runtimes"),
  integritySnapshot: (path: string, output: string) => invoke<number>("integrity_snapshot", { path, output }),
  integrityVerify: (path: string, manifest: string) => invoke<IntegrityReport>("integrity_verify", { path, manifest }),
  onProgress: (cb: (p: ScanProgress) => void): Promise<UnlistenFn> =>
    listen<ScanProgress>("scan-progress", (e) => cb(e.payload)),
};

export function errorMessage(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return JSON.stringify(e);
}
