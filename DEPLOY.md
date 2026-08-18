# Deployment Guide

Three pieces deploy independently:

| Component | Where | Why |
|---|---|---|
| Backend API | Render (or any PaaS) | Ordinary HTTP service |
| Frontend | Vercel (or any static host) | Static build output |
| Honeypot engine | A VPS you control | Needs raw TCP ports, not just HTTP |

> **Before you start.** A honeypot is deliberately attractive to attackers.
> Only run it on infrastructure you own or are authorised to use, keep it off
> any network you care about, and confirm your provider's acceptable-use
> policy allows it. Most do; some explicitly do not.

---

## 1. Backend + database on Render

The repository ships a `render.yaml` blueprint that provisions both the API
and its PostgreSQL database.

1. Push the repository to GitHub.
2. In Render: **New +** → **Blueprint** → select the repository.
3. Render reads `render.yaml`, creates `honeysentinel-db` and
   `honeysentinel-api`, and generates `SECRET_KEY`, `ENCRYPTION_KEY` and
   `HONEYPOT_INGEST_TOKEN` automatically.
4. Fill in the variables marked `sync: false` in the dashboard:

   | Variable | Value |
   |---|---|
   | `CORS_ORIGINS` | Your frontend origin, e.g. `https://your-app.vercel.app` |
   | `ALERT_EMAIL_FROM` / `ALERT_EMAIL_TO` | Optional, for email alerts |
   | `BREVO_API_KEY` | Optional; or SendGrid/Resend/SMTP equivalents |
   | `WEBHOOK_URL` / `WEBHOOK_SECRET` | Optional, for webhook alerts |

5. **Copy the generated `HONEYPOT_INGEST_TOKEN`** out of the dashboard. The
   engine needs exactly the same value or every ingest is rejected with 401.

The first boot applies migrations automatically. Once more than one instance
is running, set `RUN_MIGRATIONS_ON_STARTUP=false` and run
`alembic upgrade head` as a release step instead, so two instances cannot
migrate concurrently.

To create the first administrator, set `SEED_ON_STARTUP=true` for one boot —
the generated password is printed once to the service log — then turn it back
off. Alternatively set `ADMIN_SEED_PASSWORD` yourself and nothing is logged.

### Free-tier caveats

Render's free web services sleep after 15 minutes idle and cold-start in
roughly 30–60 seconds. The AI models are fitted at build time, so a cold start
is dominated by process startup rather than training.

---

## 2. Frontend on Vercel

1. **New Project** → import the repository.
2. Vercel detects Vite from `vercel.json`.
3. Set one environment variable:

   ```
   VITE_API_URL = https://your-api.onrender.com/api/v1
   ```

   `VITE_*` variables are read at **build** time, so changing this requires a
   redeploy.
4. Deploy, then add the resulting origin to `CORS_ORIGINS` on the backend.

`vercel.json` sends `X-Content-Type-Options`, `X-Frame-Options`,
`Referrer-Policy` and `Permissions-Policy` on every response, and rewrites all
paths to `index.html` for client-side routing.

---

## 3. Honeypot engine on a VPS

The engine listens on raw TCP ports (2222/2121/8080/8443). PaaS free tiers
expose a single HTTP port behind a TLS-terminating proxy and cannot forward
those connections, so the engine must run somewhere you control the network.

Any small instance works — it has been run on a $4/month DigitalOcean droplet
and on Oracle Cloud's always-free tier.

```bash
git clone https://github.com/mandoof1/honeypot-ui.git
cd honeypot-ui
cp .env.example .env
```

Edit `.env`:

```env
BACKEND_API_URL=https://your-api.onrender.com/api/v1
# Must be byte-identical to the value on the backend.
HONEYPOT_INGEST_TOKEN=<copied from Render>
HONEYPOT_PROTOCOLS=ssh,ftp,http
HONEYPOT_OPERATIONAL_MODE=active
HONEYPOT_ENABLE_ISOLATION=true
```

Start only the engine:

```bash
docker compose up -d --build honeypot
docker compose logs -f honeypot
```

On startup the engine:

1. verifies its isolation and logs any failing check,
2. registers itself with the backend as a node,
3. binds the enabled emulators,
4. starts its control API on `HONEYPOT_CONTROL_PORT` (8000 by default).

### Exposing it to real traffic

Emulators bind unprivileged ports so the container never needs root. Redirect
the well-known ports at the host firewall:

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22   -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 21   -j REDIRECT --to-port 2121
sudo iptables -t nat -A PREROUTING -p tcp --dport 80   -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -p tcp --dport 443  -j REDIRECT --to-port 8443
```

**Move your real SSH daemon to another port first**, and confirm you can log
in on the new port from a second terminal before applying the redirect.

### Letting the backend reach the control API

`/api/v1/honeypot/*` proxies to the engine. Set `HONEYPOT_CONTROL_URL` on the
backend to wherever the control API is reachable. **Do not publish port 8000
to the internet** — it is authenticated only by the shared token. Use a
private network, a WireGuard tunnel, or an SSH tunnel. If the backend cannot
reach it, those routes return a clear "engine unreachable" response rather
than fabricated status data.

---

## 4. Optional: GeoIP

Without a GeoLite2 database, sessions are recorded with no location and the
map shows fewer markers. To enable geolocation:

1. Create a free MaxMind account and download `GeoLite2-City.mmdb`.
2. Place it where `GEOIP_DB_PATH` points (default `./data/GeoLite2-City.mmdb`).

---

## Verifying the deployment

```bash
# API is up
curl https://your-api.onrender.com/health

# Emulators answer
nc your-vps-ip 2222              # SSH banner
curl http://your-vps-ip:8080/    # HTTP response

# Engine reports itself through the backend
curl -H "Authorization: Bearer $TOKEN" \
     https://your-api.onrender.com/api/v1/honeypot/status
```

A healthy response has `"reachable": true` and `"running": true`. If
`reachable` is false, the backend cannot see the control API — check
`HONEYPOT_CONTROL_URL` and the network path.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| Backend exits with "Refusing to start" | A secret is still a placeholder and `ENVIRONMENT` is not `development`. Set real values. |
| Ingest returns 401 | `HONEYPOT_INGEST_TOKEN` differs between backend and engine. |
| `/honeypot/*` returns 502 "rejected the control token" | Same mismatch, on the control API side. |
| CORS errors in the browser | The frontend origin is missing from `CORS_ORIGINS`. |
| Rate limits trigger far too early | Behind a proxy without `TRUST_PROXY_HEADERS=true`, so every client shares the proxy's IP. |
| Sessions have no country | No GeoLite2 database configured — working as intended, not a failure. |
| Isolation checks report failures | Expected outside Docker. Inside Docker, check `cap_drop`, `read_only` and the `internal` network are all set. |
