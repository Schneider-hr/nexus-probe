import { useEffect, useMemo, useState, type ComponentType, type FormEvent } from "react";
import {
  Radio, Wifi, Bluetooth, ShieldAlert, AlertTriangle, AlertCircle, Info,
  Battery, Clock, MapPin, Target, FileText, Radar, Activity, Bell, History,
  ShieldCheck, Plus, X,
} from "lucide-react";
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from "recharts";
import {
  addTrustedDevice, fetchAlerts, fetchFindings, fetchProbes, fetchTrustedDevices, removeTrustedDevice,
  type Alert, type Finding, type Probe, type TrustedDevice,
} from "./api";
import { usePolling } from "./usePolling";

// Shared card surface - real depth (shadow) plus a border a shade lighter
// than the panel itself, so cards read as distinct surfaces against the
// page background instead of blending into a flat wall of dark gray.
const CARD = "rounded-xl border border-panel-border bg-panel shadow-lg shadow-black/40";

const RATING_ORDER: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
const RATING_BG: Record<string, string> = { Critical: "bg-critical", High: "bg-high", Medium: "bg-medium", Low: "bg-low" };
const RATING_BORDER: Record<string, string> = {
  Critical: "border-l-critical", High: "border-l-high", Medium: "border-l-medium", Low: "border-l-low",
};
const RATING_BADGE: Record<string, string> = {
  Critical: "bg-critical/15 text-critical border-critical/40",
  High: "bg-high/15 text-high border-high/40",
  Medium: "bg-medium/15 text-medium border-medium/40",
  Low: "bg-low/15 text-low border-low/40",
};
const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-critical/15 text-critical border-critical/40",
  warning: "bg-medium/15 text-medium border-medium/40",
  info: "bg-info/15 text-info border-info/40",
};
const SEVERITY_ACCENT: Record<string, string> = {
  critical: "border-l-critical text-critical",
  warning: "border-l-medium text-medium",
  info: "border-l-info text-info",
};
const SEVERITY_ICON: Record<string, ComponentType<{ className?: string }>> = {
  critical: AlertTriangle, warning: AlertCircle, info: Info,
};
// Thematic icon per detection module - BLE for trackers, WiFi for the rogue
// AP and deauth modules (both are WiFi-layer), Radar for a cross-probe
// correlation finding (backend-synthesized, not a probe module - see
// correlation.py). Falls back to a generic shield for anything unmapped so
// a newly added module never renders with no icon at all.
const MODULE_ICONS: Record<string, ComponentType<{ className?: string }>> = {
  ble_tracker_detect: Bluetooth,
  wifi_rogue_ap_detect: Wifi,
  wifi_deauth_detect: Radio,
  correlated_tracker: Radar,
  returning_presence: History,
};

function timeAgo(iso: string): string {
  const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

// A plain "15s ago" stops being meaningful once you're reading this later
// (a report, a screenshot, a tab left open overnight) - every relative time
// in this dashboard also carries the real timestamp as a hover tooltip.
function TimeAgo({ iso }: { iso: string }) {
  return <time dateTime={iso} title={new Date(iso).toLocaleString()}>{timeAgo(iso)}</time>;
}

function durationSince(iso: string): string {
  const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  if (days > 0) return `${days}d ${hours}h`;
  const minutes = Math.floor((seconds % 3600) / 60);
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

// Buckets alerts into fixed time windows (default: last hour, 5-minute
// bins) for the activity chart - computed client-side from whatever the
// last /api/v1/alerts poll returned, no backend aggregation endpoint needed.
function bucketAlertsByTime(alerts: Alert[], bucketMinutes = 5, bucketCount = 12) {
  const now = Date.now();
  const bucketMs = bucketMinutes * 60_000;
  const buckets = Array.from({ length: bucketCount }, (_, i) => {
    const end = now - (bucketCount - 1 - i) * bucketMs;
    return { label: new Date(end).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }), count: 0 };
  });
  for (const a of alerts) {
    const age = now - new Date(a.timestamp).getTime();
    const idx = bucketCount - 1 - Math.floor(age / bucketMs);
    if (idx >= 0 && idx < bucketCount) buckets[idx].count++;
  }
  return buckets;
}

function ModuleIcon({ module, className }: { module: string; className?: string }) {
  const Icon = MODULE_ICONS[module] ?? ShieldAlert;
  return <Icon className={className} />;
}

function Badge({ text, styles }: { text: string; styles: string }) {
  return (
    <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wide ${styles}`}>
      {text}
    </span>
  );
}

function EmptyState({ text }: { text: string }) {
  return <p className="text-sm text-muted">{text}</p>;
}

function SectionHeader({ icon: Icon, title }: { icon: ComponentType<{ className?: string }>; title: string }) {
  return (
    <div className="mb-3 flex items-center gap-2 border-b border-panel-border pb-2">
      <Icon className="h-4 w-4 text-muted" />
      <h2 className="text-xs font-semibold uppercase tracking-wider text-muted">{title}</h2>
    </div>
  );
}

function StatCard({ icon: Icon, label, children }: { icon: ComponentType<{ className?: string }>; label: string; children: React.ReactNode }) {
  return (
    <div className={`${CARD} p-5`}>
      <div className="mb-3 flex items-center gap-2 text-muted">
        <Icon className="h-4 w-4" />
        <span className="text-xs font-semibold uppercase tracking-wider">{label}</span>
      </div>
      {children}
    </div>
  );
}

function SeverityBar({ counts }: { counts: Record<string, number> }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const order = ["Critical", "High", "Medium", "Low"] as const;
  if (total === 0) {
    return <p className="text-xs text-muted">No findings yet.</p>;
  }
  return (
    <div className="space-y-2">
      <div className="flex h-1.5 overflow-hidden rounded-full bg-panel-border">
        {order.filter((r) => counts[r]).map((r) => (
          <div key={r} style={{ width: `${(counts[r] / total) * 100}%` }} className={RATING_BG[r]} />
        ))}
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted">
        {order.filter((r) => counts[r]).map((r) => (
          <span key={r} className="flex items-center gap-1">
            <span className={`h-1.5 w-1.5 rounded-full ${RATING_BG[r]}`} />
            {counts[r]} {r}
          </span>
        ))}
      </div>
    </div>
  );
}

function ActivityChart({ alerts }: { alerts: Alert[] }) {
  const data = useMemo(() => bucketAlertsByTime(alerts), [alerts]);
  return (
    <div className={`${CARD} p-5 sm:col-span-2 lg:col-span-2`}>
      <div className="mb-3 flex items-center gap-2 text-muted">
        <Activity className="h-4 w-4" />
        <span className="text-xs font-semibold uppercase tracking-wider">Alert activity (last hour)</span>
      </div>
      <div className="h-24">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 4, right: 4, left: -24, bottom: 0 }}>
            <XAxis dataKey="label" tick={{ fontSize: 9, fill: "#64748b" }} interval={1} axisLine={false} tickLine={false} />
            <YAxis allowDecimals={false} tick={{ fontSize: 9, fill: "#64748b" }} axisLine={false} tickLine={false} width={24} />
            <Tooltip
              contentStyle={{ background: "#121821", border: "1px solid #1f2937", borderRadius: 8, fontSize: 12 }}
              labelStyle={{ color: "#e2e8f0" }}
              cursor={{ fill: "#1f2937", opacity: 0.4 }}
            />
            <Bar dataKey="count" fill="#06b6d4" radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function ProbeFleet({ probes }: { probes: Probe[] }) {
  if (probes.length === 0) {
    return <EmptyState text="No probes have checked in yet." />;
  }
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {probes.map((p) => (
        <div
          key={p.probe_id}
          className={`${CARD} p-5 ${p.status === "online" ? "!border-low/50" : "opacity-60"}`}
        >
          <div className="mb-1 flex items-center gap-2">
            <span className={`h-2 w-2 rounded-full ${p.status === "online" ? "bg-low pulse" : "bg-muted"}`} />
            <strong className="text-sm">{p.name}</strong>
          </div>
          <div className="mono text-xs text-muted">{p.probe_id}</div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {p.modules.map((m) => (
              <span key={m} className="inline-flex items-center gap-1 rounded-full bg-panel-border px-2 py-0.5 text-[10px] text-muted">
                <ModuleIcon module={m} className="h-3 w-3" />
                {m}
              </span>
            ))}
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
            {p.battery_pct != null && p.battery_pct >= 0 && (
              <span className="flex items-center gap-1"><Battery className="h-3.5 w-3.5" />{p.battery_pct}%</span>
            )}
            <span className="flex items-center gap-1"><Clock className="h-3.5 w-3.5" />last seen <TimeAgo iso={p.last_seen} /></span>
          </div>
          <div className="mt-1 text-xs text-muted">monitoring for {durationSince(p.first_seen)}</div>
        </div>
      ))}
    </div>
  );
}

function FindingsRegister({ findings }: { findings: Finding[] }) {
  const sorted = [...findings].sort((a, b) => RATING_ORDER[a.rating] - RATING_ORDER[b.rating]);
  if (sorted.length === 0) {
    return <EmptyState text="No findings yet." />;
  }
  return (
    <div className="flex flex-col gap-3">
      {sorted.map((f) => (
        <div key={f.risk_id} className={`${CARD} border-l-4 p-5 ${RATING_BORDER[f.rating]}`}>
          <div className="mb-1 flex flex-wrap items-center gap-2">
            <Badge text={f.rating} styles={RATING_BADGE[f.rating]} />
            <span className="mono text-xs text-muted">{f.risk_id} · probe {f.probe_id}</span>
          </div>
          <h3 className="mt-1 flex items-center gap-2 text-base font-semibold">
            <ModuleIcon module={f.module} className="h-4 w-4 text-muted" />
            {f.title}
          </h3>
          <p className="mt-1.5 text-sm leading-relaxed text-ink/90">{f.description}</p>
          <div className="mt-3 grid grid-cols-1 gap-2.5 text-xs sm:grid-cols-3">
            <div className="flex items-start gap-1.5">
              <MapPin className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted" />
              <div><div className="text-[10px] uppercase text-muted">Location</div>{f.location ?? "Not recorded"}</div>
            </div>
            <div className="flex items-start gap-1.5">
              <Target className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted" />
              <div><div className="text-[10px] uppercase text-muted">MITRE ATT&amp;CK</div>{f.mitre_attack ?? "No direct Enterprise mapping"}</div>
            </div>
            <div className="flex items-start gap-1.5">
              <FileText className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted" />
              <div><div className="text-[10px] uppercase text-muted">Control</div>{f.control_reference}</div>
            </div>
          </div>
          {f.module === "correlated_tracker" && Array.isArray(f.raw_data.probe_ids) && (
            <div className="mt-3 flex flex-wrap items-center gap-1.5 text-xs">
              <Radar className="h-3.5 w-3.5 text-info" />
              <span className="text-[10px] uppercase text-muted">Seen by</span>
              {(f.raw_data.probe_ids as string[]).map((p) => (
                <span key={p} className="mono rounded-full bg-panel-border px-2 py-0.5 text-[10px]">{p}</span>
              ))}
            </div>
          )}
          <p className="mt-3 text-xs text-ink/80"><strong className="text-ink">Recommendation:</strong> {f.recommendation}</p>
        </div>
      ))}
    </div>
  );
}

// BLE devices (Apple Find My in particular) rotate MAC addresses, but
// within one rotation period the same physical device reports the same MAC
// repeatedly every scan window - collapsing those repeats into one entry
// with a sighting count is what actually makes the feed readable instead of
// a wall of near-identical lines. Grouped by probe+module+MAC (extracted
// from the message text - alerts don't carry a structured device-id field,
// see nexus_client.h) rather than by message text verbatim, since RSSI/
// distance-band wording changes sighting to sighting even for the same device.
const MAC_RE = /[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}/;

interface AlertGroup {
  key: string;
  severity: string;
  module: string;
  probe_id: string;
  message: string;
  count: number;
  firstSeen: string;
  lastSeen: string;
  alert_id: string;
}

function groupAlerts(alerts: Alert[]): AlertGroup[] {
  const groups = new Map<string, AlertGroup>();
  for (const a of alerts) {
    const deviceId = a.message.match(MAC_RE)?.[0] ?? a.message;
    const key = `${a.probe_id}:${a.module}:${deviceId}`;
    const existing = groups.get(key);
    if (!existing) {
      groups.set(key, {
        key, severity: a.severity, module: a.module, probe_id: a.probe_id,
        message: a.message, count: 1, firstSeen: a.timestamp, lastSeen: a.timestamp, alert_id: a.alert_id,
      });
      continue;
    }
    existing.count += 1;
    if (new Date(a.timestamp) > new Date(existing.lastSeen)) {
      existing.lastSeen = a.timestamp;
      existing.message = a.message;
      existing.alert_id = a.alert_id;
    }
    if (new Date(a.timestamp) < new Date(existing.firstSeen)) {
      existing.firstSeen = a.timestamp;
    }
  }
  return Array.from(groups.values()).sort((a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime());
}

function AlertFeed({ alerts }: { alerts: Alert[] }) {
  if (alerts.length === 0) {
    return <EmptyState text="No alerts yet." />;
  }
  const groups = groupAlerts(alerts);
  return (
    <div className="flex flex-col gap-2">
      {groups.map((g) => {
        const Icon = SEVERITY_ICON[g.severity] ?? Info;
        return (
          <div
            key={g.key}
            className={`${CARD} flex flex-wrap items-center gap-3 border-l-4 px-4 py-3 text-sm ${SEVERITY_ACCENT[g.severity] ?? SEVERITY_ACCENT.info}`}
          >
            <Icon className="h-4 w-4 shrink-0" />
            <Badge text={g.severity} styles={SEVERITY_BADGE[g.severity] ?? SEVERITY_BADGE.info} />
            <span className="flex-1 text-ink">{g.message}</span>
            {g.count > 1 && (
              <span className="rounded-full bg-panel-border px-2 py-0.5 text-xs font-medium text-muted">
                seen {g.count}x over {durationSince(g.firstSeen)}
              </span>
            )}
            <span className="flex items-center gap-1.5 text-xs text-muted">
              <ModuleIcon module={g.module} className="h-3.5 w-3.5" />
              {g.probe_id} · <TimeAgo iso={g.lastSeen} />
            </span>
          </div>
        );
      })}
    </div>
  );
}

const MAC_FORMAT = /^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$/;

// Devices the operator marks here are excluded fleet-wide from both the
// alert feed and the correlation/escalation logic (see api.py's
// report_alert and correlation.py) - this is how you tell the system
// "that's just my own phone" so it stops looking like a tracker.
function TrustedDevicesPanel() {
  const [devices, setDevices] = useState<TrustedDevice[] | null>(null);
  const [mac, setMac] = useState("");
  const [label, setLabel] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = () => {
    fetchTrustedDevices().then(setDevices).catch((e: Error) => setError(e.message));
  };

  useEffect(refresh, []);

  async function handleAdd(e: FormEvent) {
    e.preventDefault();
    const trimmed = mac.trim();
    if (!MAC_FORMAT.test(trimmed)) {
      setError("Enter a MAC address like AA:BB:CC:DD:EE:FF");
      return;
    }
    setError(null);
    setBusy(true);
    try {
      await addTrustedDevice(trimmed, label.trim() || "Unlabeled");
      setMac("");
      setLabel("");
      refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function handleRemove(deviceMac: string) {
    setBusy(true);
    try {
      await removeTrustedDevice(deviceMac);
      refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={`${CARD} p-5`}>
      <form onSubmit={handleAdd} className="mb-4 flex flex-wrap gap-2">
        <input
          value={mac}
          onChange={(e) => setMac(e.target.value)}
          placeholder="AA:BB:CC:DD:EE:FF"
          disabled={busy}
          className="mono min-w-[170px] flex-1 rounded-md border border-panel-border bg-bg px-2.5 py-1.5 text-xs text-ink placeholder:text-muted/60 focus:border-info focus:outline-none"
        />
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="Label (e.g. My phone)"
          disabled={busy}
          className="min-w-[140px] flex-1 rounded-md border border-panel-border bg-bg px-2.5 py-1.5 text-xs text-ink placeholder:text-muted/60 focus:border-info focus:outline-none"
        />
        <button
          type="submit"
          disabled={busy}
          className="flex items-center gap-1 rounded-md bg-info/15 px-3 py-1.5 text-xs font-semibold text-info hover:bg-info/25 disabled:opacity-50"
        >
          <Plus className="h-3.5 w-3.5" /> Add
        </button>
      </form>

      {error && <p className="mb-3 text-xs text-critical">{error}</p>}

      {devices === null ? (
        <EmptyState text="Loading…" />
      ) : devices.length === 0 ? (
        <EmptyState text="No trusted devices - every detected device is treated as unknown." />
      ) : (
        <div className="flex flex-col gap-2">
          {devices.map((d) => (
            <div key={d.mac} className="flex items-center justify-between rounded-lg bg-panel-border/40 px-3 py-2">
              <div className="flex items-baseline gap-2">
                <span className="mono text-xs text-ink">{d.mac}</span>
                <span className="text-xs text-muted">{d.label}</span>
              </div>
              <button
                onClick={() => handleRemove(d.mac)}
                disabled={busy}
                className="flex items-center gap-1 rounded-md px-2 py-1 text-xs text-muted hover:bg-critical/15 hover:text-critical disabled:opacity-50"
              >
                <X className="h-3 w-3" /> Remove
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function App() {
  const probes = usePolling(fetchProbes, 5000);
  const findings = usePolling(fetchFindings, 5000);
  const alerts = usePolling(fetchAlerts, 5000);

  const anyError = probes.error || findings.error || alerts.error;
  const ready = !anyError && !probes.loading && !findings.loading && !alerts.loading;

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const f of findings.data ?? []) counts[f.rating] = (counts[f.rating] ?? 0) + 1;
    return counts;
  }, [findings.data]);

  const probeList = probes.data ?? [];
  const online = probeList.filter((p) => p.status === "online").length;
  const alertList = alerts.data ?? [];
  const oneHourAgo = Date.now() - 3600_000;
  const alertsLastHour = alertList.filter((a) => new Date(a.timestamp).getTime() >= oneHourAgo).length;

  return (
    <div className="mx-auto max-w-5xl px-6 py-10">
      <header className="mb-8 flex items-start justify-between border-b border-panel-border pb-6">
        <div>
          <div className="flex items-center gap-3">
            <Radio className="h-8 w-8 text-info" />
            <h1 className="text-3xl font-bold tracking-tight">Nexus</h1>
          </div>
          <p className="mt-1.5 text-sm text-muted">Physical / RF security assessment fleet</p>
        </div>
        {ready && (
          <div className="mt-2 flex items-center gap-1.5 rounded-full border border-low/30 bg-low/10 px-3 py-1 text-xs font-medium text-low">
            <span className="h-2 w-2 rounded-full bg-low pulse" />
            live
          </div>
        )}
      </header>

      {anyError && (
        <div className="mb-6 rounded-lg border border-critical/40 bg-critical/10 px-4 py-3 text-sm text-critical">
          Can't reach the Nexus backend ({anyError}). Is it running at the configured API base? If the error
          starts with 401, your dashboard login (browser's Basic Auth prompt) may have been cancelled or expired -
          reload the page to be asked again.
        </div>
      )}

      {ready && (
        <div className="mb-10 grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard icon={Wifi} label="Probes online">
            <div className="text-3xl font-bold">{online}<span className="text-lg font-normal text-muted">/{probeList.length}</span></div>
          </StatCard>
          <StatCard icon={ShieldAlert} label="Findings">
            <div className="mb-3 text-3xl font-bold">{findings.data?.length ?? 0}</div>
            <SeverityBar counts={severityCounts} />
          </StatCard>
          <ActivityChart alerts={alertList} />
        </div>
      )}

      <section className="mb-10">
        <SectionHeader icon={Radio} title="Fleet" />
        {probes.loading ? <EmptyState text="Loading…" /> : <ProbeFleet probes={probeList} />}
      </section>

      <section className="mb-10">
        <SectionHeader icon={ShieldAlert} title="Risk register" />
        {findings.loading ? <EmptyState text="Loading…" /> : <FindingsRegister findings={findings.data ?? []} />}
      </section>

      <section className="mb-10">
        <SectionHeader icon={Bell} title={`Live alerts${alertList.length ? ` (${alertsLastHour} in the last hour)` : ""}`} />
        {alerts.loading ? <EmptyState text="Loading…" /> : <AlertFeed alerts={alertList} />}
      </section>

      <section>
        <SectionHeader icon={ShieldCheck} title="Trusted devices" />
        <TrustedDevicesPanel />
      </section>
    </div>
  );
}
