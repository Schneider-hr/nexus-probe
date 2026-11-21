import { fetchAlerts, fetchFindings, fetchProbes, type Alert, type Finding, type Probe } from "./api";
import { usePolling } from "./usePolling";
import "./App.css";

const RATING_ORDER: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };

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

function FleetSummary({ probes, findings, alerts }: { probes: Probe[]; findings: Finding[]; alerts: Alert[] }) {
  const online = probes.filter((p) => p.status === "online").length;
  const severityCounts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.rating] = (acc[f.rating] ?? 0) + 1;
    return acc;
  }, {});
  const oneHourAgo = Date.now() - 3600_000;
  const alertsLastHour = alerts.filter((a) => new Date(a.timestamp).getTime() >= oneHourAgo).length;

  return (
    <div className="summary-bar">
      <div className="summary-stat">
        <span className="summary-value">{online}/{probes.length}</span>
        <span className="summary-label">probes online</span>
      </div>
      <div className="summary-stat">
        <span className="summary-value">{findings.length}</span>
        <span className="summary-label">
          findings
          {findings.length > 0 && (
            <span className="severity-breakdown">
              {(["Critical", "High", "Medium", "Low"] as const)
                .filter((r) => severityCounts[r])
                .map((r) => (
                  <span key={r} className={`badge ${r.toLowerCase()}`}>{severityCounts[r]} {r}</span>
                ))}
            </span>
          )}
        </span>
      </div>
      <div className="summary-stat">
        <span className="summary-value">{alertsLastHour}</span>
        <span className="summary-label">alerts in the last hour ({alerts.length} total)</span>
      </div>
    </div>
  );
}

function ProbeFleet({ probes }: { probes: Probe[] }) {
  if (probes.length === 0) {
    return <p className="empty">No probes have checked in yet.</p>;
  }
  return (
    <div className="grid">
      {probes.map((p) => (
        <div key={p.probe_id} className={`card probe ${p.status}`}>
          <div className="card-top">
            <span className={`dot ${p.status}`} />
            <strong>{p.name}</strong>
          </div>
          <div className="muted">{p.probe_id}</div>
          <div className="modules">
            {p.modules.map((m) => (
              <span key={m} className="chip">{m}</span>
            ))}
          </div>
          <div className="muted small">
            {p.battery_pct != null && p.battery_pct >= 0 ? `${p.battery_pct}% battery · ` : ""}
            last seen <TimeAgo iso={p.last_seen} />
          </div>
          <div className="muted small">monitoring for {durationSince(p.first_seen)}</div>
        </div>
      ))}
    </div>
  );
}

function FindingsRegister({ findings }: { findings: Finding[] }) {
  const sorted = [...findings].sort((a, b) => RATING_ORDER[a.rating] - RATING_ORDER[b.rating]);
  if (sorted.length === 0) {
    return <p className="empty">No findings yet.</p>;
  }
  return (
    <div className="stack">
      {sorted.map((f) => (
        <div key={f.risk_id} className={`card finding ${f.rating.toLowerCase()}`}>
          <div className="card-top">
            <span className={`badge ${f.rating.toLowerCase()}`}>{f.rating}</span>
            <span className="muted">{f.risk_id} · probe {f.probe_id}</span>
          </div>
          <h3>{f.title}</h3>
          <p>{f.description}</p>
          <div className="meta-grid">
            <div><span className="k">Location</span>{f.location ?? "Not recorded"}</div>
            <div><span className="k">MITRE ATT&amp;CK</span>{f.mitre_attack ?? "No direct Enterprise mapping"}</div>
            <div><span className="k">Control</span>{f.control_reference}</div>
          </div>
          {f.module === "correlated_tracker" && Array.isArray(f.raw_data.probe_ids) && (
            <div className="correlation-trail">
              <span className="k">Seen by</span>
              {(f.raw_data.probe_ids as string[]).map((p) => (
                <span key={p} className="chip">{p}</span>
              ))}
            </div>
          )}
          <p className="recommendation"><strong>Recommendation:</strong> {f.recommendation}</p>
        </div>
      ))}
    </div>
  );
}

function AlertFeed({ alerts }: { alerts: Alert[] }) {
  if (alerts.length === 0) {
    return <p className="empty">No alerts yet.</p>;
  }
  return (
    <div className="stack">
      {alerts.map((a) => (
        <div key={a.alert_id} className={`alert-row ${a.severity}`}>
          <span className={`badge ${a.severity}`}>{a.severity}</span>
          <span className="alert-message">{a.message}</span>
          <span className="muted small">{a.module} · {a.probe_id} · <TimeAgo iso={a.timestamp} /></span>
        </div>
      ))}
    </div>
  );
}

export default function App() {
  const probes = usePolling(fetchProbes, 5000);
  const findings = usePolling(fetchFindings, 5000);
  const alerts = usePolling(fetchAlerts, 5000);

  const anyError = probes.error || findings.error || alerts.error;

  return (
    <div className="app">
      <header>
        <h1>Nexus</h1>
        <p className="subtitle">Physical / RF security assessment fleet</p>
      </header>

      {anyError && (
        <div className="banner error">
          Can't reach the Nexus backend ({anyError}). Is it running at the configured API base? If the error
          starts with 401, your dashboard login (browser's Basic Auth prompt) may have been cancelled or expired -
          reload the page to be asked again.
        </div>
      )}

      {!anyError && !probes.loading && !findings.loading && !alerts.loading && (
        <FleetSummary probes={probes.data ?? []} findings={findings.data ?? []} alerts={alerts.data ?? []} />
      )}

      <section>
        <h2>Fleet</h2>
        {probes.loading ? <p className="empty">Loading…</p> : <ProbeFleet probes={probes.data ?? []} />}
      </section>

      <section>
        <h2>Risk register</h2>
        {findings.loading ? <p className="empty">Loading…</p> : <FindingsRegister findings={findings.data ?? []} />}
      </section>

      <section>
        <h2>Live alerts</h2>
        {alerts.loading ? <p className="empty">Loading…</p> : <AlertFeed alerts={alerts.data ?? []} />}
      </section>
    </div>
  );
}
