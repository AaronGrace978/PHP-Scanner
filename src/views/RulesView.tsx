import { useMemo, useState } from "react";
import { Card, SeverityBadge } from "../components/ui";
import type { Rule, ScanConfig } from "../types";

interface Props {
  rules: Rule[];
  config: ScanConfig;
  onConfig: (c: ScanConfig) => void;
}

export function RulesView({ rules, config, onConfig }: Props) {
  const [q, setQ] = useState("");
  const disabled = useMemo(() => new Set(config.disabledRules), [config.disabledRules]);
  const shown = rules.filter((r) => `${r.id} ${r.title} ${r.category} ${r.description}`.toLowerCase().includes(q.toLowerCase()));

  const toggle = (id: string, on: boolean) => {
    const next = new Set(disabled);
    if (on) next.delete(id);
    else next.add(id);
    onConfig({ ...config, disabledRules: Array.from(next).sort() });
  };

  return (
    <div className="view">
      <header className="view-header">
        <div>
          <h1>Rules</h1>
          <p className="muted">
            {rules.length} rules · {rules.length - disabled.size} enabled. Disabled rules are skipped in the next scan.
          </p>
        </div>
        <div className="row">
          <button className="btn" onClick={() => onConfig({ ...config, disabledRules: [] })} disabled={disabled.size === 0}>
            Enable all
          </button>
        </div>
      </header>
      <input className="input full" placeholder="Filter rules…" value={q} onChange={(e) => setQ(e.target.value)} />
      <Card>
        <table className="table">
          <thead>
            <tr>
              <th />
              <th>Rule</th>
              <th>Severity</th>
              <th>Category</th>
              <th>CWE</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((r) => (
              <tr key={r.id} className={disabled.has(r.id) ? "row-off" : ""}>
                <td>
                  <input type="checkbox" aria-label={`Enable ${r.id}`} checked={!disabled.has(r.id)} onChange={(e) => toggle(r.id, e.target.checked)} />
                </td>
                <td>
                  <div>{r.title}</div>
                  <div className="mono small muted">{r.id}</div>
                  <div className="small muted">{r.description}</div>
                </td>
                <td>
                  <SeverityBadge severity={r.severity} />
                </td>
                <td className="small">{r.category.replace(/-/g, " ")}</td>
                <td className="mono small">{r.cwe ? `CWE-${r.cwe}` : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
