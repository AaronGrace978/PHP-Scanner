export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface ContextLine {
  line: number;
  text: string;
}

export interface FlowStep {
  line: number;
  description: string;
}

export interface Finding {
  fingerprint: string;
  ruleId: string;
  title: string;
  message: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  cwe: number | null;
  owasp: string | null;
  file: string;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  snippet: string;
  context: ContextLine[];
  flow: FlowStep[];
  remediation: string;
}

export type RuntimeStatus = "patched" | "vulnerable" | "unsupported" | "unverified";

export interface RuntimeDetection {
  advisoryId: string;
  location: string;
  line: number;
  kind: string;
  reference: string;
  version: string | null;
  status: RuntimeStatus;
  note: string;
}

export interface LocalRuntime {
  binary: string;
  version: string | null;
  sapi: string | null;
  ini: Record<string, string>;
  status: RuntimeStatus;
  issues: string[];
}

export interface Advisory {
  id: string;
  title: string;
  cves: string[];
  published: string;
  severity: string;
  summary: string;
  fixed: { branch: string; version: string }[];
  minimumSupportedBranch: string;
  iniMitigations: { directive: string; safeValues: string[]; default: string; cve: string; branches: string[] }[];
  actions: string[];
  sources: { name: string; url: string }[];
}

export interface AdvisoryDb {
  version: string;
  advisories: Advisory[];
}

export type Verdict = "action-required" | "verify" | "patched-in-source";

export interface AdvisoryReport {
  advisory: Advisory;
  verdict: Verdict;
  runtimes: RuntimeDetection[];
  localRuntimes: LocalRuntime[];
  relatedFindings: number;
  compromiseIndicators: number;
  secretsToRotate: number;
}

export interface ScanConfig {
  extensions: string[];
  exclude: string[];
  respectGitignore: boolean;
  includeHidden: boolean;
  followSymlinks: boolean;
  maxFileSize: number;
  enabledRules: string[];
  disabledRules: string[];
  minSeverity: Severity;
  minConfidence: Confidence;
  threads: number;
  contextLines: number;
  scanDependencies: boolean;
}

export interface ScanReport {
  tool: string;
  version: string;
  advisoryDbVersion: string;
  root: string;
  startedAt: string;
  durationMs: number;
  filesScanned: number;
  filesSkipped: number;
  linesScanned: number;
  parseErrors: number;
  cancelled: boolean;
  findings: Finding[];
  summary: {
    bySeverity: Record<string, number>;
    byRule: Record<string, number>;
    byCategory: Record<string, number>;
    total: number;
    suppressed: number;
    baselined: number;
  };
  advisories: AdvisoryReport[];
  errors: string[];
  config: ScanConfig;
}

export interface ScanProgress {
  filesTotal: number;
  filesDone: number;
  findings: number;
  currentFile: string;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  cwe: number | null;
  owasp: string | null;
  description: string;
  remediation: string;
}

export interface IntegrityChange {
  path: string;
  change: "added" | "modified" | "removed";
  executable: boolean;
}

export interface IntegrityReport {
  manifestCreatedAt: string;
  filesChecked: number;
  added: IntegrityChange[];
  modified: IntegrityChange[];
  removed: IntegrityChange[];
}

export interface AppInfo {
  version: string;
  advisoryDbVersion: string;
  ruleCount: number;
}

export const DEFAULT_CONFIG: ScanConfig = {
  extensions: ["php", "phtml", "php3", "php4", "php5", "php7", "php8", "phps", "inc", "module"],
  exclude: [],
  respectGitignore: true,
  includeHidden: false,
  followSymlinks: false,
  maxFileSize: 8 * 1024 * 1024,
  enabledRules: [],
  disabledRules: [],
  minSeverity: "info",
  minConfidence: "low",
  threads: 0,
  contextLines: 3,
  scanDependencies: false,
};
