import { openUrl } from "@tauri-apps/plugin-opener";
import { useState } from "react";
import { api, errorMessage } from "../api";
import { Card, Empty, Icon, StatusPill, VerdictPill } from "../components/ui";
import type { Advisory, AdvisoryDb, LocalRuntime, ScanReport } from "../types";
import type { FindingFilter } from "./FindingsView";

interface Props {
  db: AdvisoryDb | null;
  report: ScanReport | null;
  onOpenFindings: (f: FindingFilter) => void;
  onError: (msg: string) => void;
}

export function AdvisoryView({ db, report, onOpenFindings, onError }: Props) {
  const [probed, setProbed] = useState<LocalRuntime[] | null>(null);
  const [probing, setProbing] = useState(false);

  if (!db) return <Empty title="Advisory database unavailable" />;

  const probe = async () => {
    setProbing(true);
    try {
      setProbed(await api.probeRuntimes());
    } catch (e) {
      onError(errorMessage(e));
    } finally {
      setProbing(false);
    }
  };

  return (
    <div className="view">
      {db.advisories.map((adv) => {
        const ar = report?.advisories.find((a) => a.advisory.id === adv.id);
        const local = probed ?? ar?.localRuntimes ?? [];
        return (
          <div key={adv.id} className="stack">
            <header className="view-header">
              <div>
                <h1>{adv.title}</h1>
                <p className="muted">
                  {adv.cves.join(" · ")} · published {adv.published} · severity {adv.severity} · advisory DB {db.version}
                </p>
              </div>
              {ar && <VerdictPill verdict={ar.verdict} />}
            </header>

            <div className="alert warn">
              <span>
                php2shell is a flaw in the PHP interpreter itself, not in your application code. The only complete fix is upgrading every PHP runtime to a
                fixed release and restarting it. This scanner finds where vulnerable runtimes are declared, checks interim mitigations, and hunts for signs of
                compromise — it cannot patch a server.
              </span>
            </div>

            <div className="grid-2">
              <Card title="Summary">
                <p>{adv.summary}</p>
                <FixedTable adv={adv} />
              </Card>
              <Card title="Interim mitigations (until patched)">
                <ul className="plain">
                  {adv.iniMitigations.map((m) => (
                    <li key={m.directive}>
                      <code>
                        {m.directive} = {m.safeValues[0]}
                      </code>{" "}
                      <span className="muted small">
                        {m.cve}
                        {m.branches.length > 0 ? ` · PHP ${m.branches.join(", ")} only` : ""} · default {m.default}
                      </span>
                    </li>
                  ))}
                </ul>
                <p className="muted small">
                  Set these in <code>php.ini</code>, the PHP-FPM pool (<code>php_admin_value</code>) or the web server config. <code>ini_set()</code>,{" "}
                  <code>.user.ini</code> and <code>.htaccess</code> are not effective. The advisory also lists <code>memory_limit = -1</code> (set where
                  applications cannot override it) with low <code>post_max_size</code> and proxy request-size limits. Never cap PHP with{" "}
                  <code>RLIMIT_AS</code>/<code>RLIMIT_DATA</code> (systemd <code>LimitAS</code>/<code>LimitDATA</code>, <code>ulimit -v/-d</code>).
                </p>
              </Card>
            </div>

            {ar ? (
              <>
                <div className="stats">
                  <button className="stat clickable" onClick={() => onOpenFindings({ php2shell: true })}>
                    <div className="stat-value">{ar.relatedFindings}</div>
                    <div className="stat-label">php2shell findings</div>
                  </button>
                  <button className={`stat clickable ${ar.compromiseIndicators > 0 ? "bad" : ""}`} onClick={() => onOpenFindings({ category: "malware" })}>
                    <div className="stat-value">{ar.compromiseIndicators}</div>
                    <div className="stat-label">Compromise indicators</div>
                  </button>
                  <button className={`stat clickable ${ar.secretsToRotate > 0 ? "warn" : ""}`} onClick={() => onOpenFindings({ category: "secrets" })}>
                    <div className="stat-value">{ar.secretsToRotate}</div>
                    <div className="stat-label">Secrets to rotate</div>
                  </button>
                  <div className="stat">
                    <div className="stat-value">{ar.runtimes.length}</div>
                    <div className="stat-label">Runtime references</div>
                  </div>
                </div>

                <Card title="PHP runtimes declared in the project">
                  {ar.runtimes.length === 0 ? (
                    <p className="muted">
                      No PHP version is pinned anywhere in this project (composer.json, Dockerfile, compose, CI, .php-version…). Verify production servers
                      manually with <code>php -v</code> and <code>php-fpm -v</code>.
                    </p>
                  ) : (
                    <table className="table">
                      <thead>
                        <tr>
                          <th>Status</th>
                          <th>Version</th>
                          <th>Source</th>
                          <th>Reference</th>
                          <th>Note</th>
                        </tr>
                      </thead>
                      <tbody>
                        {ar.runtimes.map((r, i) => (
                          <tr key={i}>
                            <td>
                              <StatusPill status={r.status} />
                            </td>
                            <td className="mono">{r.version ?? "—"}</td>
                            <td className="mono small">
                              {r.location}
                              {r.line ? `:${r.line}` : ""}
                              <div className="muted">{r.kind}</div>
                            </td>
                            <td className="mono small">{r.reference}</td>
                            <td className="small">{r.note}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </Card>
              </>
            ) : (
              <Card>
                <p className="muted">Run a scan to inventory the PHP runtimes, mitigations and compromise indicators in a project.</p>
              </Card>
            )}

            <Card
              title="PHP on this machine"
              actions={
                <button className="btn small" onClick={probe} disabled={probing}>
                  {probing ? "Probing…" : "Probe now"}
                </button>
              }
            >
              {local.length === 0 ? (
                <p className="muted">
                  {probed || ar ? "No PHP binaries found in PATH (or probing was disabled for the scan)." : "Not probed yet."}
                </p>
              ) : (
                <table className="table">
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>Binary</th>
                      <th>Version</th>
                      <th>Issues</th>
                    </tr>
                  </thead>
                  <tbody>
                    {local.map((r) => (
                      <tr key={r.binary}>
                        <td>
                          <StatusPill status={r.status} />
                        </td>
                        <td className="mono small">
                          {r.binary}
                          {r.sapi && <div className="muted">{r.sapi}</div>}
                        </td>
                        <td className="mono">{r.version ?? "—"}</td>
                        <td className="small">{r.issues.length ? r.issues.join("; ") : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              <p className="muted small">CLI settings may differ from PHP-FPM / Apache. Confirm the web SAPI with a phpinfo() page on a non-public host.</p>
            </Card>

            <Card title="Response checklist">
              <ol className="checklist">
                {adv.actions.map((a, i) => (
                  <li key={i}>{a}</li>
                ))}
              </ol>
            </Card>

            <Card title="Sources">
              <ul className="plain">
                {adv.sources.map((s) => (
                  <li key={s.url}>
                    <button className="link" onClick={() => openUrl(s.url).catch((e) => onError(errorMessage(e)))}>
                      {s.name} <Icon name="external" size={14} />
                    </button>
                  </li>
                ))}
              </ul>
            </Card>
          </div>
        );
      })}
    </div>
  );
}

function FixedTable({ adv }: { adv: Advisory }) {
  return (
    <table className="table compact">
      <thead>
        <tr>
          <th>Branch</th>
          <th>Fixed in</th>
        </tr>
      </thead>
      <tbody>
        {adv.fixed.map((f) => (
          <tr key={f.branch}>
            <td className="mono">PHP {f.branch}</td>
            <td className="mono">≥ {f.version}</td>
          </tr>
        ))}
        <tr>
          <td className="mono">&lt; {adv.minimumSupportedBranch}</td>
          <td>No official fix — upgrade to a supported branch</td>
        </tr>
      </tbody>
    </table>
  );
}
