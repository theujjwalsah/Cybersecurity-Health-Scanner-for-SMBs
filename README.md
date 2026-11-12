# CyberHealth — Full-stack academic MVP

A working, locally runnable implementation of the **Cybersecurity Health Scanner for Small and Medium Businesses** synopsis.

## Features
- User registration and login with bcrypt password hashing and JWT sessions.
- Per-user domain inventory.
- Public DNS reachability verification without requiring DNS record changes.
- Reachability-gated, passive external checks: DNS A/AAAA/MX, SPF, DMARC, DNSSEC DS lookup, HTTPS response headers and TLS certificate validity/expiry.
- Rule-based severity and transparent health score.
- Findings with evidence and remediation guidance.
- Mark-as-fixed workflow, historical scans and CSV reports.
- SQLite by default for simple laptop setup; PostgreSQL supported through `DATABASE_URL`.

## Requirements
- Python 3.10+
- Internet connection for DNS/TLS/HTTPS checks
- Optional: PostgreSQL

## Windows setup (PowerShell)
1. Extract the ZIP.
2. Open PowerShell in the extracted `cyberhealth_fullstack` folder.
3. Create a virtual environment:
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
4. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
5. Copy `.env.example` to `.env` and replace `SECRET_KEY` with a long random value. (The app reads environment variables; if you use `.env`, install/use your preferred environment loader or set variables in PowerShell.)
6. Start the server:
   ```powershell
   uvicorn app.main:app --reload
   ```
7. Open http://127.0.0.1:8000
8. API documentation: http://127.0.0.1:8000/docs

## Set environment variables in PowerShell
For a local SQLite run:
```powershell
$env:SECRET_KEY = "use-a-long-random-secret"
uvicorn app.main:app --reload
```

For PostgreSQL:
```powershell
$env:DATABASE_URL = "postgresql+psycopg://username:password@localhost:5432/cyberhealth"
$env:SECRET_KEY = "use-a-long-random-secret"
uvicorn app.main:app --reload
```
Create the `cyberhealth` database first.

## Domain verification workflow
1. Register / log in.
2. Open **Domains & assets** and enter a public domain you own or are authorized to assess.
3. Click **Check domain**. The app confirms that the hostname resolves to public IP address(es); no DNS changes are needed.
4. Once reachable, click **Run security assessment**. The scanner performs passive DNS, HTTPS response-header and TLS checks.

## Important MVP limitations
- The scanner deliberately performs safe, non-destructive checks only. It does not exploit vulnerabilities, brute-force credentials, perform denial-of-service tests or scan arbitrary IP ranges.
- DNSSEC status is represented by a DS lookup; DNS provider/parent-zone configuration can affect what a recursive resolver returns. Treat it as an indicator, not a full chain-of-trust validation.
- Asset discovery is currently limited to the verified hostname and its directly queried DNS records. Passive subdomain enumeration and certificate-transparency ingestion are planned extensions.
- The synopsis proposes Redis/Celery scheduled workers. This version provides synchronous scan execution for a reliable student-laptop MVP; recurring scheduling/alerts can be added as a next iteration.
- CSV reports are implemented. PDF reports, email notifications, team roles, billing and production deployment hardening are future enhancements.
- Before public deployment, use HTTPS, a managed secret, rate limiting, audit logging, DNS-rebinding protections, and a production database backup strategy. Only assess domains you own or have explicit permission to test.

## Project structure
```text
cyberhealth_fullstack/
  app/
    main.py
    models.py
    database.py
    security.py
    scanner.py
    static/
      index.html
      styles.css
      app.js
  requirements.txt
  .env.example
  README.md
```
