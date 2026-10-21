import { open, save } from "@tauri-apps/plugin-dialog";
import { useState } from "react";
import { api, errorMessage } from "../api";
import { Card, Icon, formatNumber } from "../components/ui";
import type { IntegrityChange, IntegrityReport } from "../types";

export function IntegrityView({ onError }: { onError: (msg: string) => void }) {
  const [path, setPath] = useState("");
  const [manifest, setManifest] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [result, setResult] = useState<IntegrityReport | null>(null);

  const pickFolder = async () => {
    const d = await open({ directory: true, title: "Select the deployed web root" });
    if (typeof d === "string") setPath(d);
  };
  const pickManifest = async () => {
    const f = await open({ title: "Select a known-good manifest", filters: [{ name: "Manifest", extensions: ["json"] }] });
    if (typeof f === "string") setManifest(f);
  };

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setNotice(null);
    try {
      await fn();
    } catch (e) {
      onError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const snapshot = () =>
    run(async () => {
      const out = await save({ title: "Save manifest", defaultPath: "php-scanner-manifest.json", filters: [{ name: "JSON", extensions: ["json"] }] });
      if (!out) return;
      const n = await api.integritySnapshot(path, out);
      setManifest(out);
      setNotice(`Recorded SHA-256 hashes of ${formatNumber(n)} files in ${out}. Store it off the server.`);
    });

  const verify = () =>
    run(async () => {
      setResult(await api.integrityVerify(path, manifest));
    });

  const changes = result ? [...result.added, ...result.modified, ...result.removed] : [];
  const execChanges = changes.filter((c) => c.executable && c.change !== "removed").length;

  return (
    <div className="view">
      <header className="view-header">
        <div>
          <h1>File integrity</h1>
          <p className="muted">
            NSA web-shell guidance recommends comparing production against a known-good copy. Snapshot a clean release, then verify the live server to
            find added or modified PHP files — the most reliable way to spot php2shell persistence.
          </p>
        </div>
      </header>

      <Card>
        <label className="field-label">Directory</label>
        <div className="row">
          <input className="input grow mono" placeholder="/var/www/html" value={path} onChange={(e) => setPath(e.target.value)} />
          <button className="btn" onClick={pickFolder}>
            <Icon name="folder" /> Browse
          </button>
        </div>
        <label className="field-label">Manifest</label>
        <div className="row">
          <input className="input grow mono" placeholder="php-scanner-manifest.json" value={manifest} onChange={(e) => setManifest(e.target.value)} />
          <button className="btn" onClick={pickManifest}>
            <Icon name="file" /> Choose
          </button>
        </div>
        <div className="row end">
          <button className="btn" disabled={!path || busy} onClick={snapshot}>
            Create known-good snapshot
          </button>
          <button className="btn primary" disabled={!path || !manifest || busy} onClick={verify}>
            {busy ? "Working…" : "Verify against manifest"}
          </button>
        </div>
        {notice && <div className="alert info">{notice}</div>}
      </Card>

      {result && (
        <Card title={`Verification — ${formatNumber(result.filesChecked)} files checked against manifest from ${result.manifestCreatedAt}`}>
          {changes.length === 0 ? (
            <div className="alert ok">No differences. Every file matches the known-good manifest.</div>
          ) : (
            <>
              <div className={`alert ${execChanges ? "error" : "warn"}`}>
                {result.added.length} added · {result.modified.length} modified · {result.removed.length} removed
                {execChanges > 0 && ` — ${execChanges} executable PHP file(s) changed. Investigate before trusting this server.`}
              </div>
              <ChangeTable rows={changes} />
            </>
          )}
        </Card>
      )}
    </div>
  );
}

function ChangeTable({ rows }: { rows: IntegrityChange[] }) {
  const sorted = [...rows].sort((a, b) => Number(b.executable) - Number(a.executable) || a.path.localeCompare(b.path));
  return (
    <table className="table">
      <thead>
        <tr>
          <th>Change</th>
          <th>Path</th>
          <th>Executable</th>
        </tr>
      </thead>
      <tbody>
        {sorted.map((c) => (
          <tr key={`${c.change}:${c.path}`} className={c.executable && c.change !== "removed" ? "row-bad" : ""}>
            <td>
              <span className={`pill change-${c.change}`}>{c.change}</span>
            </td>
            <td className="mono small">{c.path}</td>
            <td>{c.executable ? "yes" : ""}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
