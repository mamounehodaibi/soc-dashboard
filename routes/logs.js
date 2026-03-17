const express = require('express');
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');
const { parseLog } = require('../parsers/logParser');

const router  = express.Router();
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, '../uploads')),
  filename:    (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.log', '.txt', '.csv', '.evtx', ''];
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, allowed.includes(ext));
  }
});

router.post('/upload', upload.array('logs', 10), (req, res) => {
  if (!req.files || req.files.length === 0)
    return res.status(400).json({ error: 'No files uploaded' });

  const results = [];
  for (const file of req.files) {
    try {
      const content = fs.readFileSync(file.path, 'utf8');
      results.push(parseLog(file.originalname, content));
      fs.unlinkSync(file.path);
    } catch (err) {
      results.push({ filename: file.originalname, error: err.message });
    }
  }

  const allEvents = results.flatMap(r => r.events || []);

  // Collect suspicious IPs — include internal IPs for Windows logs since that's realistic
  const ipSet = new Set();
  results.forEach(r => {
    (r.summary?.topIPs || []).forEach(x => ipSet.add(x.ip));
    (r.summary?.bruteForceIPs || []).forEach(x => ipSet.add(x.ip));
    (r.summary?.credStuffing || []).forEach(x => ipSet.add(x.ip));
    // Also grab IPs from high/critical windows events
    (r.summary?.criticalDetails || []).forEach(e => { if (e.ip && e.ip !== '-' && e.ip !== 'local') ipSet.add(e.ip); });
  });
  const suspiciousIPs = [...ipSet].filter(ip => ip && ip !== 'unknown' && ip !== '::1' && ip !== '127.0.0.1');

  const findings = generateFindings(results, allEvents);

  // Build top IPs across all log types
  const ipCountMap = {};
  results.forEach(r => {
    (r.summary?.topIPs || []).forEach(({ ip, count }) => {
      ipCountMap[ip] = (ipCountMap[ip] || 0) + count;
    });
  });
  const topIPs = Object.entries(ipCountMap).sort((a,b)=>b[1]-a[1]).slice(0,10).map(([ip,count])=>({ip,count}));

  res.json({
    files: results,
    aggregate: {
      totalEvents:    allEvents.length,
      criticalEvents: allEvents.filter(e => e.severity === 'critical' || e.severity === 'high').length,
      suspiciousIPs,
      topIPs,
      topFindings:    findings,
      recentEvents:   allEvents.slice(-200).reverse(),
    }
  });
});

function generateFindings(results, allEvents) {
  const findings = [];

  for (const r of results) {
    if (!r.summary) continue;

    // ---- SSH findings ----
    if (r.type === 'ssh') {
      for (const bf of (r.summary.bruteForceIPs || [])) {
        findings.push({
          severity: 'critical',
          title: 'SSH Brute-Force Attack',
          description: `IP ${bf.ip} made ${bf.count} failed SSH login attempts against ${r.filename}. Automated credential attack confirmed.`,
          ip: bf.ip, mitre: 'T1110.001', type: 'brute_force'
        });
      }
      if (r.summary.successfulLogins > 0) {
        findings.push({
          severity: 'critical',
          title: 'Successful Login After Brute-Force',
          description: `${r.summary.successfulLogins} successful SSH login(s) detected in ${r.filename} — possible account compromise following brute-force activity.`,
          mitre: 'T1078', type: 'initial_access'
        });
      }
    }

    // ---- Apache / web findings ----
    if (r.type === 'apache') {
      for (const cs of (r.summary.credStuffing || [])) {
        findings.push({
          severity: 'high',
          title: 'Credential Stuffing Attack',
          description: `IP ${cs.ip} sent ${cs.count} automated login requests — credential stuffing pattern detected.`,
          ip: cs.ip, mitre: 'T1110.004', type: 'credential_stuffing'
        });
      }
      if (r.summary.suspiciousRequests > 0) {
        findings.push({
          severity: 'medium',
          title: `Suspicious Web Requests (${r.summary.suspiciousRequests} detected)`,
          description: `Path traversal, web shell upload attempts, or known exploit patterns detected in ${r.filename}.`,
          mitre: 'T1505.003', type: 'web_attack'
        });
      }
    }

    // ---- Windows findings ----
    if (r.type === 'windows') {
      const byId = r.summary.byEventId || {};

      // Failed logons
      if ((byId['4625'] || 0) > 5) {
        findings.push({
          severity: 'high',
          title: `Repeated Failed Logons (${byId['4625']} events)`,
          description: `EventID 4625 detected ${byId['4625']} times — possible password spraying or brute-force against Windows accounts.`,
          mitre: 'T1110.003', type: 'windows_bruteforce'
        });
      } else if ((byId['4625'] || 0) > 0) {
        findings.push({
          severity: 'medium',
          title: `Failed Logon Attempts (${byId['4625']} events)`,
          description: `${byId['4625']} failed Windows logon(s) recorded — review for unauthorized access attempts.`,
          mitre: 'T1110.001', type: 'windows_failedlogon'
        });
      }

      // Admin group modifications
      if ((byId['4732'] || 0) > 0) {
        findings.push({
          severity: 'critical',
          title: `Admin Group Membership Modified (${byId['4732']} events)`,
          description: `EventID 4732 detected — accounts were added to local Administrators group. Possible privilege escalation.`,
          mitre: 'T1098', type: 'windows_critical'
        });
      }

      // New service installed
      if ((byId['7045'] || 0) > 0) {
        findings.push({
          severity: 'critical',
          title: `New Service Installed (${byId['7045']} events)`,
          description: `EventID 7045 detected — a new Windows service was installed. Common persistence/lateral movement technique (PsExec, malware).`,
          mitre: 'T1543.003', type: 'windows_critical'
        });
      }

      // Audit log cleared
      if ((byId['1102'] || 0) > 0) {
        findings.push({
          severity: 'critical',
          title: 'Security Audit Log Cleared',
          description: `EventID 1102 detected — the Windows Security event log was cleared. Strong indicator of post-compromise anti-forensics.`,
          mitre: 'T1070.001', type: 'windows_critical'
        });
      }

      // Scheduled tasks
      if ((byId['4698'] || 0) > 0) {
        findings.push({
          severity: 'high',
          title: `Scheduled Task Created (${byId['4698']} events)`,
          description: `EventID 4698 detected — new scheduled tasks were created. Common persistence mechanism.`,
          mitre: 'T1053.005', type: 'windows_persistence'
        });
      }

      // PowerShell script blocks
      if ((byId['4104'] || 0) > 0) {
        findings.push({
          severity: 'high',
          title: `PowerShell Script Block Execution (${byId['4104']} events)`,
          description: `EventID 4104 detected — PowerShell script block logging captured script execution. Review for malicious commands.`,
          mitre: 'T1059.001', type: 'windows_execution'
        });
      }

      // Special privileges — only flag if many (SYSTEM logons cause lots of these normally)
      if ((byId['4672'] || 0) > 20) {
        findings.push({
          severity: 'medium',
          title: `High Volume of Privileged Logons (${byId['4672']} events)`,
          description: `EventID 4672 (Special Privileges Assigned) detected ${byId['4672']} times — review for unexpected privileged account usage.`,
          mitre: 'T1078.002', type: 'windows_privilege'
        });
      }

      // Explicit credential use
      if ((byId['4648'] || 0) > 0) {
        findings.push({
          severity: 'medium',
          title: `Explicit Credential Usage (${byId['4648']} events)`,
          description: `EventID 4648 detected — logons using explicitly supplied credentials. Could indicate pass-the-hash or credential theft.`,
          mitre: 'T1550.002', type: 'windows_lateral'
        });
      }

      // User account created
      if ((byId['4720'] || 0) > 0) {
        findings.push({
          severity: 'high',
          title: `New User Account Created (${byId['4720']} events)`,
          description: `EventID 4720 detected — new user accounts were created. Verify these are authorized.`,
          mitre: 'T1136.001', type: 'windows_persistence'
        });
      }
    }
  }

  // Sort by severity
  const order = { critical:0, high:1, medium:2, low:3 };
  return findings.sort((a,b) => (order[a.severity]||9) - (order[b.severity]||9));
}

module.exports = router;
