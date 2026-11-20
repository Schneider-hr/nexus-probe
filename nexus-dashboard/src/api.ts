// In production this dashboard is served by the backend itself (see
// nexus_backend/api.py's static mount), so requests are same-origin and this
// stays empty. Local dev overrides it via .env.local to point at a backend
// running separately on :8000.
const API_BASE = import.meta.env.VITE_NEXUS_API_BASE ?? "";

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
  // No Authorization header needed here: fetch's default credentials mode
  // ("same-origin") automatically attaches HTTP Basic Auth credentials the
  // browser already cached for this origin - which it does the moment the
  // top-level page load itself prompted for and got them (see api.py's
  // dashboard_login_middleware). Local dev talks cross-origin to :8000,
  // which should run with NEXUS_AUTH_DISABLED=1 so no login is needed there.
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
