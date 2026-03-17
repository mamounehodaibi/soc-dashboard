# SOC Live Dashboard

A real-time Security Operations Center dashboard built with Node.js and Express. Upload actual log files, automatically detect threats, and run live IP reputation checks against AbuseIPDB.

---

## Features

- **Real log parsing** — drop in SSH auth logs, Apache access logs, or Windows Event Log exports and the dashboard analyzes them instantly
- **Live threat intelligence** — every suspicious IP is checked against AbuseIPDB in real time (abuse score, ISP, TOR detection, report count)
- **Auto-generated findings** — brute-force attacks, credential stuffing, web shell attempts, and privilege escalation are detected automatically
- **Incident report** — auto-generated from your data with MITRE ATT&CK mapping, containment steps, and remediation recommendations
- **Log viewer** — searchable and filterable parsed event stream
- **Export** — download the incident report as JSON or print to PDF

---

## Tech Stack

- Node.js + Express (backend)
- Chart.js (data visualization)
- AbuseIPDB API (threat intelligence)
- Vanilla HTML/CSS/JS (frontend, no frameworks)

---

## Setup

### 1. Clone the repo
```bash
git clone https://github.com/mamounehodaibi/soc-dashboard.git
cd soc-dashboard
```

### 2. Install dependencies
```bash
npm install
```

### 3. Configure environment
```bash
cp .env.example .env
```
Open `.env` and add your AbuseIPDB API key:
```
ABUSEIPDB_API_KEY=your_key_here
PORT=3000
```
Get a free key at [abuseipdb.com/register](https://www.abuseipdb.com/register) — free tier includes 1,000 checks/day, no credit card required.

### 4. Start the server
```bash
npm start
```

### 5. Open in browser
```
http://localhost:3000
```

---

## Usage

1. Go to **Upload Logs** and drag in your log files — or click **Load Sample Logs** to demo instantly
2. Click **Analyze Logs** — the server parses every line and extracts events
3. Navigate to **Dashboard** to see live charts built from your data
4. Check **Threat Intelligence** for AbuseIPDB reputation scores on every suspicious IP
5. Review **Threat Findings** for auto-detected attack patterns
6. Open **Incident Report** for a full INC document with MITRE mapping and remediation steps

---

## Supported Log Formats

| Format | Example file |
|--------|-------------|
| Linux SSH auth log | `/var/log/auth.log` |
| Apache access log | `/var/log/apache2/access.log` |
| Windows Event Log | Text export from Event Viewer |

---

## Project Structure

```
soc-dashboard/
├── server.js              # Express entry point
├── .env.example           # Environment variable template
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

## MITRE ATT&CK Coverage

| Technique | ID |
|-----------|----|
| Brute Force: Password Guessing | T1110.001 |
| Credential Stuffing | T1110.004 |
| Valid Accounts | T1078 |
| Web Shell | T1505.003 |
| Scheduled Task / Cron | T1053.003 |
| UAC Bypass | T1548.002 |
| Lateral Movement via RDP | T1021.001 |

---

## Screenshots

> Upload logs → auto-detect threats → live AbuseIPDB lookups → incident report with MITRE mapping

---

*Built as a SOC portfolio project demonstrating real log analysis, threat detection, and incident response documentation.*
