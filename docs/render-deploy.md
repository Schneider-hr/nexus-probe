# Deploying Nexus to Render (free tier)

This repo includes a Render Blueprint (`render.yaml` at the repo root) that
stands up one service:

- **nexus-backend** — the FastAPI API probes report to, and the dashboard
  itself (served as static files from the same service — see
  `nexus-dashboard/README.md` for why it's one service, not two).

## Steps

1. Push this repo to GitHub (already done if you're reading this from the repo).
2. In the [Render dashboard](https://dashboard.render.com), click **New +** → **Blueprint**.
3. Connect your GitHub account and pick this repo. Render reads `render.yaml`
   and shows the service it's about to create.
4. Render will prompt you for the env vars marked "generate a value" below —
   paste in these (keep them somewhere safe, e.g. a password manager; never
   commit them to git):

   | Env var | What to put there |
   |---|---|
   | `NEXUS_PROBE_KEYS` | `nano-1:<a long random key>` (comma-separate more as `id:key,id:key` for more probes) |
   | `NEXUS_DASHBOARD_PASSWORD` | a long random password — this is the real login for the dashboard (username defaults to `nexus`, see `NEXUS_DASHBOARD_USER` in render.yaml if you want to change it) |

   Generate random values with:
   ```
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```
5. Click **Apply**. Render builds and deploys the service — just `pip
   install`, since the dashboard's prebuilt files are already committed in
   `nexus-backend/nexus_backend/static`. First build takes a minute or two.
6. Once it's live, note the actual URL Render assigned
   (`https://<something>.onrender.com`). `render.yaml` assumes the name
   `nexus-backend` is available; if Render had to add a suffix because that
   name was taken, that suffixed URL is what you use everywhere below.

7. Update the probe's `nexus_config.h` (git-ignored, on your own machine —
   never commit real values):
   - `NEXUS_BACKEND_URL` → the real backend URL from step 6
   - `NEXUS_BACKEND_USE_TLS` → `1`
   - `NEXUS_PROBE_KEY` → the key you set for `nano-1` in `NEXUS_PROBE_KEYS`
     in step 4

   Then rebuild and reflash the probe.

## Logging into the dashboard

Open the backend's URL from step 6 directly in a browser — your browser will
show a native login prompt (HTTP Basic Auth) before showing anything. Enter
`nexus` (or whatever you set `NEXUS_DASHBOARD_USER` to) and the
`NEXUS_DASHBOARD_PASSWORD` value from step 4. The browser remembers this for
the rest of that browser session, so it won't ask again until you close the
browser or clear site data.

This is enforced server-side (see `nexus_backend/auth.py` and
`dashboard_login_middleware` in `api.py`) — unlike the dashboard's older
design, where a "read token" was baked into the built JavaScript and anyone
loading the page could read it straight out of the bundle, nothing is sent
back by the server at all until real credentials are presented.

## Known free-tier trade-offs (accepted for now)

- **Data resets on redeploy/restart.** `NEXUS_DB_PATH` points at the service's
  local disk, which Render's free plan does not persist across deploys or
  restarts. The fleet/alert/finding history will reset then. The firmware
  notices (a heartbeat gets rejected) and re-registers itself automatically,
  so the fleet recovers within one loop iteration — only the history is
  lost, not the live system. Fine for testing and demos; not a durable
  store. A persistent disk (Render's paid plans) or an external database
  would fix this later if needed.
- **Cold starts.** Free web services spin down after ~15 minutes idle and
  take 30-60 seconds to wake back up on the next request. The firmware
  retries registration with backoff specifically to survive this (see
  `main.c`) — the first heartbeat or dashboard load after a quiet period
  will just be slow, not broken.

## Giving this to a supervisor (or anyone else) to test independently

Once deployed, anyone with the backend's URL and the dashboard login can view
the fleet and findings from any PC — the dashboard is served from, and talks
straight to, the Render-hosted backend; your PC doesn't need to be running or
on the same network. Share the URL and the login out of band (not over the
same channel as anything sensitive). A probe only needs its own setup-AP
password (see `nexus_wifi.c`) to join whatever WiFi it's plugged into next;
it no longer needs your LAN or your machine at all.
