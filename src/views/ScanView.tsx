import { useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { Card, Icon, formatDuration, formatNumber } from "../components/ui";
import type { ScanConfig, ScanProgress, ScanReport } from "../types";

interface Props {
  recent: string[];
  onRemoveRecent: (path: string) => void;
  scanning: boolean;
  progress: ScanProgress | null;
  onScan: (path: string, checkLocalRuntime: boolean, baselinePath?: string) => void;
  onCancel: () => void;
  lastReport: ScanReport | null;
  config: ScanConfig;
}

export function ScanView({ recent, onRemoveRecent, scanning, progress, onScan, onCancel, lastReport, config }: Props) {
  const [path, setPath] = useState(recent[0] ?? "");
  const [checkLocal, setCheckLocal] = useState(true);
  const [baseline, setBaseline] = useState("");

  const pickFolder = async () => {
    const dir = await open({ directory: true, multiple: false, title: "Select a PHP project" });
    if (typeof dir === "string") setPath(dir);
  };

  const pickBaseline = async () => {
    const f = await open({ multiple: false, title: "Select a baseline file", filters: [{ name: "Baseline", extensions: ["json"] }] });
    if (typeof f === "string") setBaseline(f);
  };

  const start = () => path.trim() && onScan(path.trim(), checkLocal, baseline || undefined);
  const pct = progress && progress.filesTotal > 0 ? Math.min(100, (progress.filesDone / progress.filesTotal) * 100) : 0;

  return (
    <div className="view">
      <header className="view-header">
        <div>
          <h1>Scan a PHP project</h1>
          <p className="muted">
            Taint analysis, dangerous APIs, secrets, web shells, and php2shell (CVE-2026-109618 / CVE-2026-109619) runtime exposure checks.
          </p>
        </div>
      </header>

      <Card>
        <label className="field-label" htmlFor="scan-path">
          Project folder
        </label>
        <div className="row">
          <input
            id="scan-path"
            className="input grow mono"
            placeholder="/var/www/my-app"
            value={path}
            disabled={scanning}
            onChange={(e) => setPath(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && start()}
          />
          <button className="btn" onClick={pickFolder} disabled={scanning}>
            <Icon name="folder" /> Browse
          </button>
        </div>

        <div className="options">
          <label className="check">
            <input type="checkbox" checked={checkLocal} disabled={scanning} onChange={(e) => setCheckLocal(e.target.checked)} />
            <span>
              Probe PHP binaries on this machine for php2shell
              <span className="muted small"> (runs <code>php -r</code> on php, php8.x, php-fpm found in PATH)</span>
            </span>
          </label>
          <div className="row">
            <input
              className="input grow mono"
              placeholder="Baseline file (optional) — previously accepted findings are hidden"
              value={baseline}
              disabled={scanning}
              onChange={(e) => setBaseline(e.target.value)}
            />
            <button className="btn" onClick={pickBaseline} disabled={scanning}>
              <Icon name="file" /> Choose
            </button>
            {baseline && (
              <button className="icon-btn" onClick={() => setBaseline("")} aria-label="Clear baseline">
                <Icon name="close" size={16} />
              </button>
            )}
          </div>
          <div className="muted small">
            Minimum severity <b>{config.minSeverity}</b> · confidence <b>{config.minConfidence}</b> ·{" "}
            {config.scanDependencies ? "including vendor/" : "skipping vendor/ and node_modules/"} ·{" "}
            {config.disabledRules.length} rule(s) disabled
          </div>
        </div>

        <div className="row end">
          {scanning ? (
            <button className="btn danger" onClick={onCancel}>
              Cancel scan
            </button>
          ) : (
            <button className="btn primary" onClick={start} disabled={!path.trim()}>
              <Icon name="scan" /> Start scan
            </button>
          )}
        </div>

        {scanning && (
          <div className="progress-wrap" aria-live="polite">
            <div className="progress">
              <div className={`progress-bar ${progress ? "" : "indeterminate"}`} style={progress ? { width: `${pct}%` } : undefined} />
            </div>
            <div className="row between small muted">
              <span className="ellipsis mono">{progress?.currentFile || "Discovering files…"}</span>
              <span>
                {progress ? `${formatNumber(progress.filesDone)} / ${formatNumber(progress.filesTotal)} files · ${formatNumber(progress.findings)} findings` : ""}
              </span>
            </div>
          </div>
        )}
      </Card>

      {lastReport && !scanning && (
        <Card title="Last scan">
          <div className="muted small mono">{lastReport.root}</div>
          <div className="row gap-lg">
            <span>{formatNumber(lastReport.filesScanned)} files</span>
            <span>{formatNumber(lastReport.linesScanned)} lines</span>
            <span>{formatNumber(lastReport.findings.length)} findings</span>
            <span>{formatDuration(lastReport.durationMs)}</span>
            {lastReport.cancelled && <span className="pill status-unverified">Cancelled — partial results</span>}
          </div>
        </Card>
      )}

      {recent.length > 0 && (
        <Card title="Recent projects">
          <ul className="recent">
            {recent.map((r) => (
              <li key={r}>
                <button className="link mono" disabled={scanning} onClick={() => setPath(r)} onDoubleClick={() => onScan(r, checkLocal, baseline || undefined)}>
                  <Icon name="folder" size={16} /> {r}
                </button>
                <button className="icon-btn" onClick={() => onRemoveRecent(r)} aria-label={`Remove ${r}`}>
                  <Icon name="close" size={14} />
                </button>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}
