# Deploying Nexus to Render (free tier)

This repo includes a Render Blueprint (`render.yaml` at the repo root) that
stands up two services from one click:

- **nexus-backend** — the FastAPI API probes report to and the dashboard reads from
- **nexus-dashboard** — the static React dashboard, built against nexus-backend's URL

## Steps

1. Push this repo to GitHub (already done if you're reading this from the repo).
2. In the [Render dashboard](https://dashboard.render.com), click **New +** → **Blueprint**.
3. Connect your GitHub account and pick this repo. Render reads `render.yaml`
   and shows both services it's about to create.
4. Render will prompt you for the env vars marked "generate a value" below —
   paste in these (keep them somewhere safe, e.g. a password manager; never
   commit them to git):

   | Service | Env var | What to put there |
   |---|---|---|
   | nexus-backend | `NEXUS_PROBE_KEYS` | `nano-1:<a long random key>` (comma-separate more as `id:key,id:key` for more probes) |
   | nexus-backend | `NEXUS_READ_TOKEN` | a long random token — the dashboard needs this to read data |
   | nexus-dashboard | `VITE_NEXUS_READ_TOKEN` | the *same* value as `NEXUS_READ_TOKEN` above |

   Generate random values with:
   ```
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```
5. Click **Apply**. Render builds and deploys both services. First build takes
   a few minutes.
6. Once both are live, note the actual URLs Render assigned
   (`https://<something>.onrender.com` for each). `render.yaml` assumes the
   names `nexus-backend` and `nexus-dashboard` are available and the URLs
   come out exactly as `https://nexus-backend.onrender.com` and
   `https://nexus-dashboard.onrender.com`. If Render had to add a suffix
   (because those names were taken), update:
   - `nexus-backend`'s `NEXUS_CORS_ORIGINS` env var to the real dashboard URL
   - `nexus-dashboard`'s `VITE_NEXUS_API_BASE` env var to the real backend URL
   - redeploy both after fixing either

7. Update the probe's `nexus_config.h` (git-ignored, on your own machine —
   never commit real values):
   - `NEXUS_BACKEND_URL` → the real `nexus-backend` URL from step 6
   - `NEXUS_BACKEND_USE_TLS` → `1`
   - `NEXUS_PROBE_KEY` → the key you set for `nano-1` in `NEXUS_PROBE_KEYS`
     in step 4

   Then rebuild and reflash the probe.

## Known free-tier trade-offs (accepted for now)

- **Data resets on redeploy/restart.** `NEXUS_DB_PATH` points at the service's
  local disk, which Render's free plan does not persist across deploys or
  restarts. The fleet/alert/finding history will reset then. Fine for
  testing and demos; not a durable store. A persistent disk (Render's paid
  plans) or an external database would fix this later if needed.
- **Cold starts.** Free web services spin down after ~15 minutes idle and
  take 30-60 seconds to wake back up on the next request. The first probe
  heartbeat or dashboard load after a quiet period will be slow — that's
  normal, not a bug.

## Giving this to a supervisor to test independently

Once deployed, anyone with the dashboard URL and the read token (if you set
one) can view the fleet and findings from any PC — the dashboard talks
straight to the Render-hosted backend, your PC doesn't need to be running or
on the same network. A probe only needs its own setup-AP password (see
`nexus_wifi.c`) to join whatever WiFi it's plugged into next; it no longer
needs your LAN or your machine at all.
