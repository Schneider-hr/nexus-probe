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

export interface TrustedDevice {
  mac: string;
  label: string;
  added_at: string;
}

// No Authorization header needed on any of these: fetch's default
// credentials mode ("same-origin") automatically attaches HTTP Basic Auth
// credentials the browser already cached for this origin - which it does
// the moment the top-level page load itself prompted for and got them (see
// api.py's dashboard_login_middleware). Local dev talks cross-origin to
// :8000, which should run with NEXUS_AUTH_DISABLED=1 so no login is needed
// there.
async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

async function sendJson<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
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

export function fetchTrustedDevices(): Promise<TrustedDevice[]> {
  return getJson<TrustedDevice[]>("/api/v1/trusted-devices");
}

export function addTrustedDevice(mac: string, label: string): Promise<TrustedDevice> {
  return sendJson<TrustedDevice>("POST", "/api/v1/trusted-devices", { mac, label });
}

export function removeTrustedDevice(mac: string): Promise<{ removed: string }> {
  return sendJson<{ removed: string }>("DELETE", `/api/v1/trusted-devices/${encodeURIComponent(mac)}`);
}
