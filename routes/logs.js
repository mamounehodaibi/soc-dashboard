// routes/logs.js
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
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB max
  fileFilter: (req, file, cb) => {
    const allowed = ['.log', '.txt', '.csv', ''];
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, allowed.includes(ext));
  }
});

// POST /api/logs/upload — accepts multiple log files
router.post('/upload', upload.array('logs', 10), (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'No files uploaded' });
  }

  const results = [];
  for (const file of req.files) {
    try {
      const content = fs.readFileSync(file.path, 'utf8');
      const parsed  = parseLog(file.originalname, content);
      results.push(parsed);
      // Clean up uploaded file
      fs.unlinkSync(file.path);
    } catch (err) {
      results.push({ filename: file.originalname, error: err.message });
    }
  }

  // Aggregate across all files
  const allEvents = results.flatMap(r => r.events || []);
  const allIPs = [...new Set([
    ...results.flatMap(r => r.summary?.topIPs?.map(x => x.ip) || []),
    ...results.flatMap(r => r.summary?.bruteForceIPs?.map(x => x.ip) || []),
    ...results.flatMap(r => r.summary?.credStuffing?.map(x => x.ip) || []),
  ])].filter(ip => ip && ip !== 'unknown' && ip !== '127.0.0.1' && ip !== '::1');

  const criticalEvents = allEvents.filter(e =>
    e.severity === 'critical' || e.severity === 'high'
  ).slice(0, 50);

  res.json({
    files: results,
    aggregate: {
      totalEvents: allEvents.length,
      criticalEvents: criticalEvents.length,
      suspiciousIPs: allIPs.slice(0, 20),
      topFindings: generateFindings(results),
      recentEvents: allEvents.slice(-100).reverse(),
    }
  });
});

function generateFindings(results) {
  const findings = [];

  for (const r of results) {
    if (r.type === 'ssh' && r.summary.bruteForceIPs?.length > 0) {
      for (const bf of r.summary.bruteForceIPs) {
        findings.push({
          severity: 'critical',
          title: `SSH Brute-Force Detected`,
          description: `IP ${bf.ip} made ${bf.count} failed login attempts against ${r.filename}`,
          ip: bf.ip,
          mitre: 'T1110.001',
          type: 'brute_force'
        });
      }
      if (r.summary.successfulLogins > 0) {
        findings.push({
          severity: 'critical',
          title: 'Successful SSH Login After Failures',
          description: `${r.summary.successfulLogins} successful login(s) detected in ${r.filename} — possible breach after brute-force`,
          mitre: 'T1078',
          type: 'initial_access'
        });
      }
    }

    if (r.type === 'apache') {
      if (r.summary.credStuffing?.length > 0) {
        for (const cs of r.summary.credStuffing) {
          findings.push({
            severity: 'high',
            title: 'Credential Stuffing Attack',
            description: `IP ${cs.ip} sent ${cs.count} login requests — automated credential stuffing`,
            ip: cs.ip,
            mitre: 'T1110.004',
            type: 'credential_stuffing'
          });
        }
      }
      if (r.summary.suspiciousRequests > 0) {
        findings.push({
          severity: 'medium',
          title: `Suspicious Web Requests (${r.summary.suspiciousRequests})`,
          description: `Detected path traversal, web shell attempts, or known exploit patterns in ${r.filename}`,
          mitre: 'T1505.003',
          type: 'web_attack'
        });
      }
    }

    if (r.type === 'windows') {
      const critical = r.summary.criticalDetails || [];
      for (const e of critical.slice(0, 3)) {
        findings.push({
          severity: 'critical',
          title: `${e.desc} (EventID ${e.eid})`,
          description: `User: ${e.user} | Source: ${e.ip} | Time: ${e.ts}`,
          mitre: e.eid === '4732' ? 'T1098' : e.eid === '7045' ? 'T1543.003' : 'T1078',
          type: 'windows_critical'
        });
      }
    }
  }

  return findings;
}

module.exports = router;
