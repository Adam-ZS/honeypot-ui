# HoneySentinel AI — AI-Integrated Honeypot System

A full-stack honeypot monitoring platform with AI-powered attack analysis, real-time threat visualization, and automated intelligence reporting.

**Live Demo:** https://honeypot-ui-psi.vercel.app  
**API:** https://honeysentinel-api.onrender.com/docs

---

## Architecture

```
Attacker → Honeypot Engine (SSH / FTP / HTTP)
                ↓ session JSON
          Backend API (FastAPI + PostgreSQL)
                ↓ AI analysis
          React Dashboard (Vercel)
```

```
┌─────────────────────────────────────────────────────────┐
│                  Frontend (React 19)                     │
│  Dashboard │ Live Map │ Session Logs │ Settings          │
└──────────────────────┬──────────────────────────────────┘
                       │ REST API (JWT)
┌──────────────────────▼──────────────────────────────────┐
│                  Backend (FastAPI)                       │
│  Auth │ Sessions │ Alerts │ Nodes │ Export │ Settings    │
│                                                         │
│  ┌────────────────── AI Engine ──────────────────────┐  │
│  │  Random Forest │ NLP (SpaCy) │ Isolation Forest   │  │
│  │  Attacker Profiler │ MITRE ATT&CK Mapper          │  │
│  └───────────────────────────────────────────────────┘  │
└──────────────────────┬──────────────────────────────────┘
                       │
                 ┌─────▼──────┐
                 │ PostgreSQL  │
                 └────────────┘
```

---

## Features

### Honeypot Engine (`honeypot/`)
- **SSH emulator** — fake shell accepting common weak credentials, records every command typed
- **FTP + HTTP emulators** — capture all interactions
- **Anti-fingerprinting** — rotates banners, fake OS signatures, fake hostnames so scanners can't detect it's a honeypot
- **Adaptive response** — active and passive monitoring modes
- **Breakout prevention** — Docker network isolation
- **Session capture** — saves everything locally and POSTs to backend for AI analysis

> **Note:** The honeypot engine requires a VPS with open ports (SSH 22, FTP 21, HTTP 80). It cannot run on Render's free tier. See deployment section below.

### AI & Analysis
- **Attack Classification** — Random Forest model (benign, reconnaissance, exploitation, exfiltration)
- **NLP Intent Analysis** — SpaCy detects offensive tools (Metasploit, Mimikatz, Nmap) and attacker objectives
- **Anomaly Detection** — Isolation Forest for unknown attack patterns
- **Attacker Profiling** — APT, Script Kiddie, Automated Bot classification

### Threat Intelligence
- **MITRE ATT&CK Mapping** — auto-correlates to TTPs
- **Export formats** — JSON, CEF, STIX/TAXII
- **IoC Extraction** — IPs, URLs, file hashes, tool signatures

### Dashboard
- **Live stats** — sessions, alerts, honeypot nodes, attack origins
- **Geographical map** — Leaflet.js with real-time threat markers
- **Session logs** — filtering, drill-down, pagination, export
- **Alert thresholds** — configurable severity and anomaly score thresholds
- **Email alerts** — via Brevo (OTP verification + alert notifications)

### Security
- **JWT auth** — access + refresh tokens, RBAC (Admin, Analyst, Viewer)
- **Email OTP verification** — required on signup
- **Rate limiting** — per-IP throttling on all auth endpoints (5/min register, 10/min login)
- **AES-256 encryption** — raw session data encrypted at rest
- **Audit logging** — full trail of all user actions
- **CORS** — restricted to known frontend origins only

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 19, Vite, Tailwind CSS 4, React Router 7, Leaflet |
| Backend | Python 3.12, FastAPI, SQLAlchemy (async), Pydantic v2 |
| AI/ML | scikit-learn (Random Forest, Isolation Forest), SpaCy |
| Database | PostgreSQL 16 |
| Auth | JWT, bcrypt, slowapi rate limiting |
| Email | Brevo API (with SendGrid/Resend/SMTP fallback) |
| Migrations | Alembic |

---

## Deployment

### Current Setup (Live)
| Service | Platform | URL |
|---------|----------|-----|
| Frontend | Vercel | https://honeypot-ui-psi.vercel.app |
| Backend API | Render | https://honeysentinel-api.onrender.com |
| Database | Render PostgreSQL | Internal |
| Email | Brevo | 300 emails/day free |

### Required Environment Variables (Render)

```env
# Database
DATABASE_URL=postgresql+asyncpg://...
DATABASE_URL_SYNC=postgresql+psycopg2://...

# Security — generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=your-secret-key
ENCRYPTION_KEY=your-encryption-key
HONEYPOT_INGEST_TOKEN=your-ingest-token

# Email (Brevo)
BREVO_API_KEY=xkeysib-...
ALERT_EMAIL_FROM=your-verified-sender@email.com

# Optional SMTP fallback
SMTP_HOST=smtp-relay.brevo.com
SMTP_PORT=587
SMTP_USER=your-brevo-smtp-user
SMTP_PASSWORD=your-brevo-smtp-password
```

### Vercel Environment Variables

```env
VITE_API_URL=https://honeysentinel-api.onrender.com/api/v1
```

### Local Development (Docker)

```bash
cp .env.example .env
# Fill in your values
docker compose up --build
```

- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

### Honeypot Engine (VPS Required)

The honeypot engine needs a VPS with a real public IP and open ports:

```bash
# On your VPS
git clone https://github.com/mandoof1/honeypot-ui.git
cd honeypot-ui
cp .env.example .env
# Set BACKEND_URL to your Render API URL
docker compose up --build -d
```

Tested on DigitalOcean ($4/month), Oracle Cloud Free Tier.

---

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/auth/register` | — | Register (sends OTP) |
| POST | `/api/v1/auth/verify-otp` | — | Verify email OTP |
| POST | `/api/v1/auth/login` | — | Login (JWT) |
| POST | `/api/v1/auth/request-password-reset` | — | Request reset OTP |
| POST | `/api/v1/auth/reset-password` | — | Reset with OTP |
| GET | `/api/v1/auth/me` | ✓ | Current user |
| GET | `/api/v1/dashboard/stats` | ✓ | Dashboard stats |
| GET | `/api/v1/dashboard/live-events` | ✓ | Live threat events |
| GET | `/api/v1/sessions/` | ✓ | List sessions |
| GET | `/api/v1/sessions/{id}` | ✓ | Session details |
| POST | `/api/v1/sessions/ingest-internal` | Token | Ingest from honeypot |
| GET | `/api/v1/alerts/` | ✓ | List alerts |
| PATCH | `/api/v1/alerts/{id}` | ✓ | Update alert |
| GET | `/api/v1/nodes/` | ✓ | List honeypot nodes |
| POST | `/api/v1/export/` | ✓ | Export (JSON/CEF/STIX) |
| GET | `/api/v1/settings/thresholds` | ✓ Admin | Alert thresholds |

---

## License

MIT
