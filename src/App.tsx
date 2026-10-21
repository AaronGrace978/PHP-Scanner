import { useCallback, useEffect, useMemo, useState } from "react";
import { api, errorMessage, isTauri } from "./api";
import { Icon } from "./components/ui";
import { useRecentProjects, useScanConfig } from "./settings";
import type { AdvisoryDb, AppInfo, Rule, ScanProgress, ScanReport } from "./types";
import { ScanView } from "./views/ScanView";
import { OverviewView } from "./views/OverviewView";
import { FindingsView, type FindingFilter } from "./views/FindingsView";
import { AdvisoryView } from "./views/AdvisoryView";
import { IntegrityView } from "./views/IntegrityView";
import { RulesView } from "./views/RulesView";
import { SettingsView } from "./views/SettingsView";

export type ViewId = "scan" | "overview" | "findings" | "advisory" | "integrity" | "rules" | "settings";

const NAV: { id: ViewId; label: string; icon: string; needsReport?: boolean }[] = [
  { id: "scan", label: "Scan", icon: "scan" },
  { id: "overview", label: "Overview", icon: "overview", needsReport: true },
  { id: "findings", label: "Findings", icon: "findings", needsReport: true },
  { id: "advisory", label: "php2shell", icon: "shield" },
  { id: "integrity", label: "Integrity", icon: "integrity" },
  { id: "rules", label: "Rules", icon: "rules" },
  { id: "settings", label: "Settings", icon: "settings" },
];

export default function App() {
  const [view, setView] = useState<ViewId>("scan");
  const [config, setConfig] = useScanConfig();
  const [recent, addRecent, removeRecent] = useRecentProjects();
  const [report, setReport] = useState<ScanReport | null>(null);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rules, setRules] = useState<Rule[]>([]);
  const [advisoryDb, setAdvisoryDb] = useState<AdvisoryDb | null>(null);
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [filter, setFilter] = useState<FindingFilter>({});

  useEffect(() => {
    if (!isTauri()) {
      setError("PHP Scanner must run inside the desktop application (npm run app:dev).");
      return;
    }
    api.listRules().then(setRules).catch((e) => setError(errorMessage(e)));
    api.advisories().then(setAdvisoryDb).catch(() => undefined);
    api.appInfo().then(setInfo).catch(() => undefined);
    const un = api.onProgress(setProgress);
    return () => {
      un.then((f) => f());
    };
  }, []);

  const runScan = useCallback(
    async (path: string, checkLocalRuntime: boolean, baselinePath?: string) => {
      setError(null);
      setScanning(true);
      setProgress(null);
      try {
        const r = await api.scan(path, config, checkLocalRuntime, baselinePath);
        setReport(r);
        addRecent(path);
        setFilter({});
        setView("overview");
      } catch (e) {
        setError(errorMessage(e));
      } finally {
        setScanning(false);
      }
    },
    [config, addRecent],
  );

  const openFindings = (f: FindingFilter) => {
    setFilter(f);
    setView("findings");
  };

  const ruleMap = useMemo(() => new Map(rules.map((r) => [r.id, r])), [rules]);
  const critical = report ? (report.summary.bySeverity["critical"] ?? 0) : 0;
  const advisoryAction = report?.advisories.some((a) => a.verdict === "action-required");

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="logo">php</div>
          <div>
            <div className="brand-name">PHP Scanner</div>
            <div className="brand-sub">v{info?.version ?? "1.0.0"}</div>
          </div>
        </div>
        <nav>
          {NAV.map((n) => {
            const disabled = n.needsReport && !report;
            return (
              <button
                key={n.id}
                className={`nav-item ${view === n.id ? "active" : ""}`}
                disabled={disabled}
                onClick={() => setView(n.id)}
                title={disabled ? "Run a scan first" : n.label}
              >
                <Icon name={n.icon} />
                <span>{n.label}</span>
                {n.id === "findings" && report && <span className="count">{report.findings.length}</span>}
                {n.id === "overview" && critical > 0 && <span className="count crit">{critical}</span>}
                {n.id === "advisory" && advisoryAction && <span className="dot" title="Action required" />}
              </button>
            );
          })}
        </nav>
        <div className="sidebar-foot muted">
          {info ? `${info.ruleCount} rules · advisories ${info.advisoryDbVersion}` : ""}
        </div>
      </aside>
      <main className="content">
        {error && (
          <div className="alert error" role="alert">
            <span>{error}</span>
            <button className="icon-btn" onClick={() => setError(null)} aria-label="Dismiss">
              <Icon name="close" size={16} />
            </button>
          </div>
        )}
        {view === "scan" && (
          <ScanView
            recent={recent}
            onRemoveRecent={removeRecent}
            scanning={scanning}
            progress={progress}
            onScan={runScan}
            onCancel={() => api.cancelScan()}
            lastReport={report}
            config={config}
          />
        )}
        {view === "overview" && report && (
          <OverviewView report={report} onOpenFindings={openFindings} onOpenAdvisory={() => setView("advisory")} onError={setError} />
        )}
        {view === "findings" && report && <FindingsView report={report} filter={filter} onFilter={setFilter} rules={ruleMap} />}
        {view === "advisory" && <AdvisoryView db={advisoryDb} report={report} onOpenFindings={openFindings} onError={setError} />}
        {view === "integrity" && <IntegrityView onError={setError} />}
        {view === "rules" && <RulesView rules={rules} config={config} onConfig={setConfig} />}
        {view === "settings" && <SettingsView config={config} onConfig={setConfig} />}
      </main>
    </div>
  );
}
