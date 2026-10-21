import { useEffect, useMemo, useRef, useState } from "react";
import { api, errorMessage } from "../api";
import { Card, Empty, SeverityBadge, formatNumber } from "../components/ui";
import { SEVERITIES, type Confidence, type Finding, type Rule, type ScanReport, type Severity } from "../types";

export interface FindingFilter {
  php2shell?: boolean;
  severity?: Severity;
  category?: string;
  ruleId?: string;
  confidence?: Confidence;
  search?: string;
}

interface Props {
  report: ScanReport;
  filter: FindingFilter;
  onFilter: (f: FindingFilter) => void;
  rules: Map<string, Rule>;
}

const PAGE = 300;

function matches(f: Finding, flt: FindingFilter, q: string) {
  if (flt.php2shell && !f.ruleId.startsWith("php2shell-")) return false;
  if (flt.severity && f.severity !== flt.severity) return false;
  if (flt.category && f.category !== flt.category) return false;
  if (flt.ruleId && f.ruleId !== flt.ruleId) return false;
  if (flt.confidence && f.confidence !== flt.confidence) return false;
  if (q) {
    const hay = `${f.file} ${f.ruleId} ${f.title} ${f.message} ${f.snippet}`.toLowerCase();
    if (!hay.includes(q)) return false;
  }
  return true;
}

export function FindingsView({ report, filter, onFilter, rules }: Props) {
  const [limit, setLimit] = useState(PAGE);
  const [selected, setSelected] = useState<string | null>(null);
  const q = (filter.search ?? "").trim().toLowerCase();

  const filtered = useMemo(() => report.findings.filter((f) => matches(f, filter, q)), [report, filter, q]);
  const ruleIds = useMemo(() => Array.from(new Set(report.findings.map((f) => f.ruleId))).sort(), [report]);
  const categories = useMemo(() => Array.from(new Set(report.findings.map((f) => f.category))).sort(), [report]);

  useEffect(() => setLimit(PAGE), [filter]);
  useEffect(() => {
    if (!filtered.some((f) => f.fingerprint === selected)) setSelected(filtered[0]?.fingerprint ?? null);
  }, [filtered, selected]);

  const current = filtered.find((f) => f.fingerprint === selected) ?? null;
  const set = (patch: Partial<FindingFilter>) => onFilter({ ...filter, ...patch });
  const active = Object.entries(filter).some(([, v]) => v !== undefined && v !== "" && v !== false);

  const move = (delta: number) => {
    const i = filtered.findIndex((f) => f.fingerprint === selected);
    const next = filtered[Math.max(0, Math.min(filtered.length - 1, i + delta))];
    if (next) setSelected(next.fingerprint);
  };

  return (
    <div className="view findings-view">
      <div className="filters">
        <input
          className="input grow"
          placeholder="Search file, rule, message, code…"
          value={filter.search ?? ""}
          onChange={(e) => set({ search: e.target.value || undefined })}
        />
        <select className="input" value={filter.severity ?? ""} onChange={(e) => set({ severity: (e.target.value || undefined) as Severity | undefined })}>
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select className="input" value={filter.confidence ?? ""} onChange={(e) => set({ confidence: (e.target.value || undefined) as Confidence | undefined })}>
          <option value="">Any confidence</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
        </select>
        <select className="input" value={filter.category ?? ""} onChange={(e) => set({ category: e.target.value || undefined })}>
          <option value="">All categories</option>
          {categories.map((c) => (
            <option key={c} value={c}>
              {c.replace(/-/g, " ")}
            </option>
          ))}
        </select>
        <select className="input" value={filter.ruleId ?? ""} onChange={(e) => set({ ruleId: e.target.value || undefined })}>
          <option value="">All rules</option>
          {ruleIds.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        <label className="check compact">
          <input type="checkbox" checked={!!filter.php2shell} onChange={(e) => set({ php2shell: e.target.checked || undefined })} />
          php2shell only
        </label>
        {active && (
          <button className="btn ghost" onClick={() => onFilter({})}>
            Clear
          </button>
        )}
      </div>

      <div className="split">
        <div
          className="finding-list"
          tabIndex={0}
          onKeyDown={(e) => {
            const delta = e.key === "ArrowDown" || e.key === "j" ? 1 : e.key === "ArrowUp" || e.key === "k" ? -1 : 0;
            if (delta) {
              e.preventDefault();
              move(delta);
            }
          }}
        >
          <div className="list-head muted small">
            {formatNumber(filtered.length)} of {formatNumber(report.findings.length)} findings
          </div>
          {filtered.length === 0 && <Empty title="No findings match">Adjust or clear the filters.</Empty>}
          {filtered.slice(0, limit).map((f) => (
            <button key={f.fingerprint} className={`finding-row ${f.fingerprint === selected ? "selected" : ""}`} onClick={() => setSelected(f.fingerprint)}>
              <SeverityBadge severity={f.severity} />
              <div className="finding-row-body">
                <div className="finding-title">{f.title}</div>
                <div className="muted small mono ellipsis">
                  {f.file}:{f.line}
                </div>
              </div>
            </button>
          ))}
          {filtered.length > limit && (
            <button className="btn ghost full" onClick={() => setLimit((l) => l + PAGE)}>
              Show {formatNumber(Math.min(PAGE, filtered.length - limit))} more
            </button>
          )}
        </div>
        <div className="finding-detail">{current ? <Detail finding={current} rule={rules.get(current.ruleId)} root={report.root} /> : <Empty title="Select a finding" />}</div>
      </div>
    </div>
  );
}

function Detail({ finding: f, rule, root }: { finding: Finding; rule?: Rule; root: string }) {
  const [source, setSource] = useState<string | null>(null);
  const [srcError, setSrcError] = useState<string | null>(null);
  const hit = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setSource(null);
    setSrcError(null);
  }, [f.fingerprint]);
  useEffect(() => hit.current?.scrollIntoView({ block: "center" }), [source]);

  const loadSource = () =>
    api
      .readSource(root, f.file)
      .then(setSource)
      .catch((e) => setSrcError(errorMessage(e)));

  const lines = source !== null ? source.split("\n").map((text, i) => ({ line: i + 1, text })) : f.context;

  return (
    <div className="detail">
      <div className="row">
        <SeverityBadge severity={f.severity} />
        <span className="pill">confidence: {f.confidence}</span>
        {f.cwe && <span className="pill">CWE-{f.cwe}</span>}
        {f.owasp && <span className="pill">{f.owasp}</span>}
      </div>
      <h2>{f.title}</h2>
      <div className="mono small muted">
        {f.file}:{f.line}:{f.column} · {f.ruleId} · {f.fingerprint}
      </div>
      <p>{f.message}</p>

      <Card
        title="Code"
        actions={
          source === null ? (
            <button className="btn small" onClick={loadSource}>
              Show full file
            </button>
          ) : (
            <button className="btn small" onClick={() => setSource(null)}>
              Show context only
            </button>
          )
        }
      >
        {srcError && <div className="alert error">{srcError}</div>}
        <div className={`code ${source !== null ? "tall" : ""}`}>
          {lines.map((l) => {
            const isHit = l.line >= f.line && l.line <= Math.max(f.line, f.endLine);
            return (
              <div key={l.line} ref={l.line === f.line ? hit : undefined} className={`code-line ${isHit ? "hit" : ""}`}>
                <span className="ln">{l.line}</span>
                <span className="tx">{l.text || " "}</span>
              </div>
            );
          })}
        </div>
      </Card>

      {f.flow.length > 0 && (
        <Card title="Data flow">
          <ol className="flow">
            {f.flow.map((s, i) => (
              <li key={i}>
                <span className="mono muted">line {s.line}</span> {s.description}
              </li>
            ))}
          </ol>
        </Card>
      )}

      <Card title="How to fix">
        <p>{f.remediation}</p>
        {rule && rule.description && <p className="muted small">{rule.description}</p>}
        <p className="muted small">
          To accept this finding, add <code>// php-scanner-ignore: {f.ruleId}</code> on the line above, or write a baseline from the Overview.
        </p>
      </Card>
    </div>
  );
}
