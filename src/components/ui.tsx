import type { ReactNode } from "react";
import type { RuntimeStatus, Severity, Verdict } from "../types";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge sev-${severity}`}>{severity}</span>;
}

const STATUS_LABEL: Record<RuntimeStatus, string> = {
  vulnerable: "Vulnerable",
  unsupported: "Unsupported",
  unverified: "Verify",
  patched: "Patched",
};

export function StatusPill({ status }: { status: RuntimeStatus }) {
  return <span className={`pill status-${status}`}>{STATUS_LABEL[status]}</span>;
}

const VERDICT_LABEL: Record<Verdict, string> = {
  "action-required": "Action required",
  verify: "Verify production runtimes",
  "patched-in-source": "Patched in source",
};

export function VerdictPill({ verdict }: { verdict: Verdict }) {
  return <span className={`pill verdict-${verdict}`}>{VERDICT_LABEL[verdict]}</span>;
}

export function Card({ title, actions, children, className }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`card ${className ?? ""}`}>
      {(title || actions) && (
        <header className="card-header">
          {title && <h3>{title}</h3>}
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <h3>{title}</h3>
      {children && <div className="muted">{children}</div>}
    </div>
  );
}

const PATHS: Record<string, string> = {
  scan: "M11 4a7 7 0 1 0 4.2 12.6l4.1 4.1 1.4-1.4-4.1-4.1A7 7 0 0 0 11 4Zm0 2a5 5 0 1 1 0 10 5 5 0 0 1 0-10Z",
  overview: "M4 4h7v7H4V4Zm9 0h7v4h-7V4ZM4 13h7v7H4v-7Zm9-3h7v10h-7V10Z",
  findings: "M5 4h14v2H5V4Zm0 5h14v2H5V9Zm0 5h9v2H5v-2Zm0 5h6v2H5v-2Z",
  shield: "M12 2 4 5v6c0 5 3.4 9.6 8 11 4.6-1.4 8-6 8-11V5l-8-3Zm0 5a1 1 0 0 1 1 1v5h-2V8a1 1 0 0 1 1-1Zm0 8a1.25 1.25 0 1 1 0 2.5A1.25 1.25 0 0 1 12 15Z",
  integrity: "M12 2a5 5 0 0 0-5 5v3H5v12h14V10h-2V7a5 5 0 0 0-5-5Zm-3 5a3 3 0 0 1 6 0v3H9V7Zm2 7h2v4h-2v-4Z",
  rules: "M4 5h2v2H4V5Zm4 0h12v2H8V5ZM4 11h2v2H4v-2Zm4 0h12v2H8v-2Zm-4 6h2v2H4v-2Zm4 0h12v2H8v-2Z",
  settings: "M19.4 13a7.5 7.5 0 0 0 0-2l2-1.6-2-3.4-2.4 1a7.3 7.3 0 0 0-1.7-1L15 3.5h-4l-.4 2.5a7.3 7.3 0 0 0-1.7 1l-2.4-1-2 3.4 2 1.6a7.5 7.5 0 0 0 0 2l-2 1.6 2 3.4 2.4-1a7.3 7.3 0 0 0 1.7 1l.4 2.5h4l.4-2.5a7.3 7.3 0 0 0 1.7-1l2.4 1 2-3.4-2-1.6ZM13 15a3 3 0 1 1 0-6 3 3 0 0 1 0 6Z",
  folder: "M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6Z",
  file: "M6 2h8l6 6v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2Zm7 1.5V9h5.5L13 3.5Z",
  download: "M11 3h2v9l3-3 1.4 1.4L12 15.8l-5.4-5.4L8 9l3 3V3ZM5 18h14v2H5v-2Z",
  close: "m6.4 5 5.6 5.6L17.6 5 19 6.4 13.4 12l5.6 5.6-1.4 1.4-5.6-5.6L6.4 19 5 17.6l5.6-5.6L5 6.4 6.4 5Z",
  external: "M14 3h7v7h-2V6.4l-8.3 8.3-1.4-1.4L17.6 5H14V3ZM5 5h6v2H7v10h10v-4h2v6H5V5Z",
};

export function Icon({ name, size = 18 }: { name: keyof typeof PATHS | string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d={PATHS[name] ?? ""} />
    </svg>
  );
}

export function formatNumber(n: number) {
  return n.toLocaleString();
}

export function formatDuration(ms: number) {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}
