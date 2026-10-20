import { fetchAlerts, fetchFindings, fetchProbes, type Alert, type Finding, type Probe } from "./api";
import { usePolling } from "./usePolling";
import "./App.css";

const RATING_ORDER: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };

function timeAgo(iso: string): string {
  const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
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
            last seen {timeAgo(p.last_seen)}
          </div>
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
            <div><span className="k">MITRE ATT&amp;CK</span>{f.mitre_attack ?? "No direct Enterprise mapping"}</div>
            <div><span className="k">Control</span>{f.control_reference}</div>
          </div>
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
          <span className="muted small">{a.module} · {a.probe_id} · {timeAgo(a.timestamp)}</span>
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
          starts with 401, set VITE_NEXUS_READ_TOKEN to the backend's read token.
        </div>
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
