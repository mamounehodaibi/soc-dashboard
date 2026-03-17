// routes/report.js
const express = require('express');
const router  = express.Router();

// POST /api/report/generate — generate incident report JSON from analysis results
router.post('/generate', (req, res) => {
  const { files, aggregate, threatIntel } = req.body;
  if (!aggregate) return res.status(400).json({ error: 'No analysis data provided' });

  const now = new Date().toISOString();
  const incId = `INC-${now.slice(0,10).replace(/-/g,'')}-${String(Math.floor(Math.random()*9000)+1000)}`;

  // Determine overall severity
  const critCount = aggregate.criticalEvents || 0;
  const severity = critCount >= 5 ? 'CRITICAL' : critCount >= 2 ? 'HIGH' : critCount >= 1 ? 'MEDIUM' : 'LOW';

  // Collect all suspicious IPs with their intel
  const ipIntel = (threatIntel || []).filter(t => t.abuseConfidenceScore > 10);
  const confirmedMalicious = ipIntel.filter(t => t.abuseConfidenceScore >= 50);

  // Build MITRE mapping from findings
  const mitreMap = {};
  for (const f of aggregate.topFindings || []) {
    if (f.mitre) mitreMap[f.mitre] = f.title;
  }

  // Determine affected systems from filenames
  const affectedSystems = (files || []).map(f => ({
    filename: f.filename,
    type: f.type,
    events: f.events?.length || 0
  }));

  const report = {
    id: incId,
    generatedAt: now,
    severity,
    status: 'OPEN',
    title: buildTitle(aggregate.topFindings || []),
    summary: buildSummary(aggregate, confirmedMalicious),
    affectedSystems,
    findings: aggregate.topFindings || [],
    suspiciousIPs: aggregate.suspiciousIPs || [],
    threatIntel: threatIntel || [],
    mitreAttack: Object.entries(mitreMap).map(([id, title]) => ({ id, title })),
    metrics: {
      totalLogEvents: (files || []).reduce((a, f) => a + (f.summary?.totalLines || f.summary?.totalEvents || 0), 0),
      totalEventsAnalyzed: aggregate.totalEvents || 0,
      criticalEvents: aggregate.criticalEvents || 0,
      suspiciousIPCount: (aggregate.suspiciousIPs || []).length,
      confirmedMaliciousIPs: confirmedMalicious.length,
    },
    containmentSteps: buildContainmentSteps(aggregate.topFindings || [], confirmedMalicious),
    remediationSteps: buildRemediationSteps(aggregate.topFindings || []),
  };

  res.json(report);
});

function buildTitle(findings) {
  if (findings.length === 0) return 'Security Event Analysis';
  const types = findings.map(f => f.type);
  if (types.includes('brute_force') && types.includes('initial_access')) return 'SSH Brute-Force Leading to Unauthorized Access';
  if (types.includes('brute_force')) return 'SSH Brute-Force Attack Detected';
  if (types.includes('credential_stuffing')) return 'Web Application Credential Stuffing Attack';
  if (types.includes('windows_critical')) return 'Critical Windows Security Events Detected';
  return 'Multiple Security Threats Detected';
}

function buildSummary(aggregate, maliciousIPs) {
  const parts = [];
  parts.push(`Analysis of uploaded log files identified ${aggregate.criticalEvents || 0} high-severity security events across ${aggregate.totalEvents || 0} total log entries.`);
  if (maliciousIPs.length > 0) {
    parts.push(`${maliciousIPs.length} IP address(es) were confirmed malicious via AbuseIPDB threat intelligence, with confidence scores ranging from ${Math.min(...maliciousIPs.map(i=>i.abuseConfidenceScore))}% to ${Math.max(...maliciousIPs.map(i=>i.abuseConfidenceScore))}%.`);
  }
  if (aggregate.topFindings?.some(f => f.type === 'brute_force')) {
    parts.push('SSH brute-force activity was detected indicating automated credential attack tooling.');
  }
  if (aggregate.topFindings?.some(f => f.type === 'initial_access')) {
    parts.push('Successful authentication following brute-force attempts suggests possible account compromise — immediate investigation recommended.');
  }
  return parts.join(' ');
}

function buildContainmentSteps(findings, maliciousIPs) {
  const steps = [];
  const types = findings.map(f => f.type);

  if (maliciousIPs.length > 0) {
    steps.push(`Block the following confirmed malicious IPs at perimeter firewall: ${maliciousIPs.map(i=>i.ip).join(', ')}`);
  }
  if (types.includes('brute_force') || types.includes('initial_access')) {
    steps.push('Immediately audit and disable any accounts that successfully authenticated from flagged IPs');
    steps.push('Isolate affected SSH servers from internal network pending investigation');
  }
  if (types.includes('credential_stuffing')) {
    steps.push('Enable CAPTCHA and rate limiting on all authentication endpoints immediately');
    steps.push('Force password reset on all accounts that received excessive login attempts');
  }
  if (types.includes('windows_critical')) {
    steps.push('Review and revoke any privilege changes or new admin group members identified in event logs');
    steps.push('Isolate Windows hosts showing EventID 7045 (new service install) or 4732 (admin group modification)');
  }
  steps.push('Preserve all relevant log files for forensic analysis before any remediation actions');
  return steps;
}

function buildRemediationSteps(findings) {
  const steps = new Set();
  const types = findings.map(f => f.type);

  if (types.includes('brute_force') || types.includes('initial_access')) {
    steps.add('Enforce MFA on all SSH access — use key-based authentication and disable password auth in sshd_config');
    steps.add('Implement account lockout policy: lock after 5 failed attempts for 15 minutes (pam_faillock on Linux)');
    steps.add('Deploy fail2ban or equivalent to auto-block IPs after repeated failures');
    steps.add('Audit all user accounts and rotate passwords against HaveIBeenPwned breach database');
  }
  if (types.includes('credential_stuffing') || types.includes('web_attack')) {
    steps.add('Deploy WAF with rate limiting rules on authentication endpoints');
    steps.add('Implement CAPTCHA on login forms and monitor for unusual login velocity');
    steps.add('Audit and update all web application dependencies and frameworks');
  }
  if (types.includes('windows_critical')) {
    steps.add('Enable Windows Event Forwarding to centralized SIEM with alerting on EventID 4625, 4732, 7045');
    steps.add('Deploy EDR solution (CrowdStrike/Defender for Endpoint) on all Windows hosts');
    steps.add('Review and enforce least-privilege across all service and admin accounts');
  }
  steps.add('Schedule quarterly penetration testing and log review');
  steps.add('Conduct security awareness training for all staff on phishing and credential hygiene');
  return [...steps];
}

module.exports = router;
