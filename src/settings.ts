import { useEffect, useState } from "react";
import { DEFAULT_CONFIG, type ScanConfig } from "./types";

const CONFIG_KEY = "php-scanner.config.v1";
const RECENT_KEY = "php-scanner.recent.v1";

function load<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? { ...fallback, ...JSON.parse(raw) } : fallback;
  } catch {
    return fallback;
  }
}

export function useScanConfig(): [ScanConfig, (c: ScanConfig) => void] {
  const [config, setConfig] = useState<ScanConfig>(() => load(CONFIG_KEY, DEFAULT_CONFIG));
  useEffect(() => localStorage.setItem(CONFIG_KEY, JSON.stringify(config)), [config]);
  return [config, setConfig];
}

export function useRecentProjects(): [string[], (path: string) => void, (path: string) => void] {
  const [recent, setRecent] = useState<string[]>(() => {
    try {
      return JSON.parse(localStorage.getItem(RECENT_KEY) || "[]");
    } catch {
      return [];
    }
  });
  useEffect(() => localStorage.setItem(RECENT_KEY, JSON.stringify(recent)), [recent]);
  const add = (p: string) => setRecent((r) => [p, ...r.filter((x) => x !== p)].slice(0, 8));
  const remove = (p: string) => setRecent((r) => r.filter((x) => x !== p));
  return [recent, add, remove];
}
