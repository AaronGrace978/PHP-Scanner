import { useState } from "react";
import { Card } from "../components/ui";
import { DEFAULT_CONFIG, SEVERITIES, type Confidence, type ScanConfig, type Severity } from "../types";

interface Props {
  config: ScanConfig;
  onConfig: (c: ScanConfig) => void;
}

const splitList = (s: string) =>
  s
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter(Boolean);

export function SettingsView({ config, onConfig }: Props) {
  const [exts, setExts] = useState(config.extensions.join(", "));
  const [exclude, setExclude] = useState(config.exclude.join("\n"));
  const set = (patch: Partial<ScanConfig>) => onConfig({ ...config, ...patch });

  const reset = () => {
    onConfig(DEFAULT_CONFIG);
    setExts(DEFAULT_CONFIG.extensions.join(", "));
    setExclude("");
  };

  return (
    <div className="view">
      <header className="view-header">
        <div>
          <h1>Settings</h1>
          <p className="muted">Applied to every scan. Saved locally on this machine.</p>
        </div>
        <button className="btn" onClick={reset}>
          Reset to defaults
        </button>
      </header>

      <div className="grid-2">
        <Card title="Reporting">
          <label className="field-label">Minimum severity</label>
          <select className="input" value={config.minSeverity} onChange={(e) => set({ minSeverity: e.target.value as Severity })}>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <label className="field-label">Minimum confidence</label>
          <select className="input" value={config.minConfidence} onChange={(e) => set({ minConfidence: e.target.value as Confidence })}>
            <option value="low">low</option>
            <option value="medium">medium</option>
            <option value="high">high</option>
          </select>
          <label className="field-label">Context lines around each finding</label>
          <input
            className="input"
            type="number"
            min={0}
            max={20}
            value={config.contextLines}
            onChange={(e) => set({ contextLines: Math.max(0, Math.min(20, Number(e.target.value) || 0)) })}
          />
        </Card>

        <Card title="Performance">
          <label className="field-label">Worker threads (0 = all cores)</label>
          <input className="input" type="number" min={0} max={256} value={config.threads} onChange={(e) => set({ threads: Math.max(0, Number(e.target.value) || 0) })} />
          <label className="field-label">Skip files larger than (MB)</label>
          <input
            className="input"
            type="number"
            min={1}
            max={512}
            value={Math.round(config.maxFileSize / (1024 * 1024))}
            onChange={(e) => set({ maxFileSize: Math.max(1, Number(e.target.value) || 1) * 1024 * 1024 })}
          />
        </Card>
      </div>

      <Card title="File discovery">
        <label className="field-label">PHP file extensions</label>
        <input className="input full mono" value={exts} onChange={(e) => setExts(e.target.value)} onBlur={() => set({ extensions: splitList(exts).map((x) => x.replace(/^\./, "")) })} />
        <label className="field-label">Exclude globs (one per line)</label>
        <textarea
          className="input full mono"
          rows={4}
          placeholder={"tests/**\nstorage/cache/**"}
          value={exclude}
          onChange={(e) => setExclude(e.target.value)}
          onBlur={() => set({ exclude: splitList(exclude) })}
        />
        <label className="check">
          <input type="checkbox" checked={config.scanDependencies} onChange={(e) => set({ scanDependencies: e.target.checked })} />
          Scan vendor/ and node_modules/ (slower; useful when hunting for web shells)
        </label>
        <label className="check">
          <input type="checkbox" checked={config.respectGitignore} onChange={(e) => set({ respectGitignore: e.target.checked })} />
          Respect .gitignore
        </label>
        <label className="check">
          <input type="checkbox" checked={config.includeHidden} onChange={(e) => set({ includeHidden: e.target.checked })} />
          Include hidden files and folders
        </label>
        <label className="check">
          <input type="checkbox" checked={config.followSymlinks} onChange={(e) => set({ followSymlinks: e.target.checked })} />
          Follow symbolic links
        </label>
      </Card>
    </div>
  );
}
