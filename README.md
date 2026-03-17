# SOC Live Dashboard
Real log file analysis + AbuseIPDB threat intelligence, built with Node.js + Express.

---

## Setup (5 minutes)

### 1. Install dependencies
```powershell
npm install
```

### 2. Configure your API key
```powershell
copy .env.example .env
notepad .env
```
Replace `your_api_key_here` with your AbuseIPDB key.
Get a free key at: https://www.abuseipdb.com/register (free tier = 1000 checks/day)

### 3. Start the server
```powershell
npm start
```

### 4. Open in browser
```
http://localhost:3000
```

---

## Usage

1. **Upload Logs** — drag & drop real `.log` or `.txt` files, or click "Load Sample Logs" to demo instantly
2. **Dashboard** — auto-populated charts from your actual log data
3. **Threat Findings** — auto-detected brute-force, credential stuffing, web attacks, privilege escalation
4. **Threat Intel** — every suspicious IP is checked live against AbuseIPDB
5. **Log Viewer** — searchable/filterable parsed event stream
6. **Incident Report** — auto-generated report with MITRE mapping, export to JSON or print to PDF

---

## Supported Log Formats

| Format | Detection |
|--------|-----------|
| Linux SSH (`/var/log/auth.log`) | Auto-detected |
| Apache access log (Common Log Format) | Auto-detected |
| Windows Event Log (text export) | Auto-detected |

---

## Project Structure

```
soc-live/
├── server.js              # Express entry point
├── .env.example           # Copy to .env and add API key
├── package.json
├── parsers/
│   └── logParser.js       # SSH, Apache, Windows log parsers
├── routes/
│   ├── logs.js            # POST /api/logs/upload
│   ├── threat.js          # POST /api/threat/check (AbuseIPDB)
│   └── report.js          # POST /api/report/generate
└── public/
    ├── index.html
    └── assets/
        ├── style.css
        └── app.js
```

---

## Pushing updates to GitHub

```powershell
git add .
git commit -m "your message here"
git push
```
