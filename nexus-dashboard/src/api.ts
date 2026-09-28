const API_BASE = import.meta.env.VITE_NEXUS_API_BASE ?? "http://127.0.0.1:8000";

export interface Probe {
  probe_id: string;
  name: string;
  modules: string[];
  battery_pct: number | null;
  status: "online" | "offline";
  first_seen: string;
  last_seen: string;
}

export interface Finding {
  risk_id: string;
  probe_id: string;
  module: string;
  title: string;
  description: string;
  location: string | null;
  likelihood: string;
  impact: string;
  mitre_attack: string | null;
  control_reference: string;
  recommendation: string;
  raw_data: Record<string, unknown>;
  rating: string;
}

export interface Alert {
  alert_id: string;
  probe_id: string;
  module: string;
  message: string;
  severity: string;
  timestamp: string;
  raw_data: Record<string, unknown>;
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export function fetchProbes(): Promise<Probe[]> {
  return getJson<Probe[]>("/api/v1/probes");
}

export function fetchFindings(): Promise<Finding[]> {
  return getJson<Finding[]>("/api/v1/findings");
}

export function fetchAlerts(): Promise<Alert[]> {
  return getJson<Alert[]>("/api/v1/alerts");
}
