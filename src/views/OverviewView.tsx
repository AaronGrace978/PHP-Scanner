import { save } from "@tauri-apps/plugin-dialog";
import { useState } from "react";
import { api, errorMessage } from "../api";
import { Card, Icon, SeverityBadge, VerdictPill, formatDuration, formatNumber } from "../components/ui";
import { SEVERITIES, type ScanReport, type Severity } from "../types";
import type { FindingFilter } from "./FindingsView";

interface Props {
  report: ScanReport;
  onOpenFindings: (f: FindingFilter) => void;
  onOpenAdvisory: () => void;
  onError: (msg: string) => void;
}

const EXPORTS = [
  { format: "html", label: "HTML report", ext: "html" },
  { format: "sarif", label: "SARIF 2.1.0", ext: "sarif" },
  { format: "json", label: "JSON", ext: "json" },
  { format: "csv", label: "CSV", ext: "csv" },
];

export function OverviewView({ report, onOpenFindings, onOpenAdvisory, onError }: Props) {
  const [notice, setNotice] = useState<string | null>(null);
  const s = report.summary;
  const maxSev = Math.max(1, ...SEVERITIES.map((sev) => s.bySeverity[sev] ?? 0));
  const topRules = Object.entries(s.byRule)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);
  const categories = Object.entries(s.byCategory).sort((a, b) => b[1] - a[1]);
  const titles = new Map(report.findings.map((f) => [f.ruleId, f.title]));

  const exportAs = async (format: string, ext: string) => {
    const path = await save({ title: "Export report", defaultPath: `php-scanner-report.${ext}`, filters: [{ name: format.toUpperCase(), extensions: [ext] }] });
    if (!path) return;
    try {
      await api.exportReport(path, format);
      setNotice(`Saved ${path}`);
    } catch (e) {
      onError(errorMessage(e));
    }
  };

  const baseline = async () => {
    const path = await save({ title: "Write baseline", defaultPath: "php-scanner-baseline.json", filters: [{ name: "JSON", extensions: ["json"] }] });
    if (!path) return;
    try {
      const n = await api.writeBaseline(path);
      setNotice(`Baseline with ${formatNumber(n)} fingerprints saved to ${path}`);
    } catch (e) {
      onError(errorMessage(e));
    }
  };

  return (
    <div className="view">
      <header className="view-header">
        <div>
          <h1>Overview</h1>
          <p className="muted mono small">{report.root}</p>
        </div>
        <div className="row">
          {EXPORTS.map((e) => (
            <button key={e.format} className="btn" onClick={() => exportAs(e.format, e.ext)}>
              <Icon name="download" /> {e.label}
            </button>
          ))}
          <button className="btn" onClick={baseline} title="Accept the current findings so future scans only report new ones">
            Write baseline
          </button>
        </div>
      </header>

      {notice && (
        <div className="alert info">
          <span>{notice}</span>
          <button className="icon-btn" onClick={() => setNotice(null)} aria-label="Dismiss">
            <Icon name="close" size={16} />
          </button>
        </div>
      )}
      {report.cancelled && <div className="alert warn">The scan was cancelled. Results are incomplete.</div>}

      {report.advisories.map((a) => (
        <button key={a.advisory.id} className={`advisory-banner verdict-${a.verdict}`} onClick={onOpenAdvisory}>
          <Icon name="shield" size={22} />
          <div className="grow">
            <div className="row">
              <b>{a.advisory.title}</b>
              <VerdictPill verdict={a.verdict} />
            </div>
            <div className="small">
              {a.runtimes.length} runtime reference(s) found · {a.relatedFindings} related finding(s) · {a.compromiseIndicators} compromise indicator(s) ·{" "}
              {a.secretsToRotate} secret(s) to rotate
            </div>
          </div>
          <span className="muted small">Details →</span>
        </button>
      ))}

      <div className="stats">
        <Stat label="Findings" value={formatNumber(s.total)} />
        <Stat label="Files scanned" value={formatNumber(report.filesScanned)} />
        <Stat label="Lines" value={formatNumber(report.linesScanned)} />
        <Stat label="Duration" value={formatDuration(report.durationMs)} />
        <Stat label="Suppressed" value={formatNumber(s.suppressed)} hint="inline php-scanner-ignore" />
        <Stat label="Baselined" value={formatNumber(s.baselined)} />
      </div>

      <div className="grid-2">
        <Card title="By severity">
          <div className="bars">
            {SEVERITIES.map((sev: Severity) => {
              const n = s.bySeverity[sev] ?? 0;
              return (
                <button key={sev} className="bar-row" onClick={() => onOpenFindings({ severity: sev })} disabled={n === 0}>
                  <SeverityBadge severity={sev} />
                  <div className="bar-track">
                    <div className={`bar-fill sev-${sev}`} style={{ width: `${(n / maxSev) * 100}%` }} />
                  </div>
                  <span className="bar-num">{formatNumber(n)}</span>
                </button>
              );
            })}
          </div>
        </Card>
        <Card title="By category">
          {categories.length === 0 ? (
            <p className="muted">No findings.</p>
          ) : (
            <ul className="kv">
              {categories.map(([c, n]) => (
                <li key={c}>
                  <button className="link" onClick={() => onOpenFindings({ category: c })}>
                    {c.replace(/-/g, " ")}
                  </button>
                  <span>{formatNumber(n)}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card title="Top rules">
        {topRules.length === 0 ? (
          <p className="muted">No findings — nothing matched the enabled rules.</p>
        ) : (
          <ul className="kv">
            {topRules.map(([r, n]) => (
              <li key={r}>
                <button className="link" onClick={() => onOpenFindings({ ruleId: r })}>
                  {titles.get(r) ?? r} <span className="muted mono small">{r}</span>
                </button>
                <span>{formatNumber(n)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>

      {(report.errors.length > 0 || report.parseErrors > 0) && (
        <Card title={`Warnings (${report.errors.length})`}>
          {report.parseErrors > 0 && <p className="muted">{report.parseErrors} file(s) had syntax errors; analysis continued on the recoverable parts.</p>}
          <ul className="mono small errors">
            {report.errors.slice(0, 200).map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="stat" title={hint}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
