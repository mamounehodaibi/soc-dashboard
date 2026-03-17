// parsers/logParser.js
// Parses SSH auth logs, Apache access logs, Windows Event Log (txt export)

function parseSSH(lines) {
  const events = [];
  const failMap = {};   // ip -> count
  const successMap = {};

  const failRe    = /(\w{3}\s+\d+\s[\d:]+).*Failed password for (\S+) from ([\d.]+)/;
  const acceptRe  = /(\w{3}\s+\d+\s[\d:]+).*Accepted (?:password|publickey) for (\S+) from ([\d.]+)/;
  const invalidRe = /(\w{3}\s+\d+\s[\d:]+).*Invalid user (\S+) from ([\d.]+)/;

  for (const line of lines) {
    let m;
    if ((m = failRe.exec(line))) {
      const [, ts, user, ip] = m;
      failMap[ip] = (failMap[ip] || 0) + 1;
      events.push({ type: 'ssh_fail', ts, user, ip, raw: line });
    } else if ((m = acceptRe.exec(line))) {
      const [, ts, user, ip] = m;
      successMap[ip] = (successMap[ip] || 0) + 1;
      events.push({ type: 'ssh_success', ts, user, ip, raw: line, severity: 'high' });
    } else if ((m = invalidRe.exec(line))) {
      const [, ts, user, ip] = m;
      failMap[ip] = (failMap[ip] || 0) + 1;
      events.push({ type: 'ssh_invalid', ts, user, ip, raw: line });
    }
  }

  // Flag IPs with brute-force pattern (>10 failures)
  const bruteForceIPs = Object.entries(failMap)
    .filter(([, c]) => c > 10)
    .map(([ip, count]) => ({ ip, count, type: 'brute_force' }));

  return { events, failMap, successMap, bruteForceIPs };
}

function parseApache(lines) {
  const events = [];
  const ipMap = {};
  const statusMap = {};
  const suspiciousPaths = [
    /\.php$/i, /\/wp-admin/i, /\/\.env/i, /\/etc\/passwd/i,
    /union.*select/i, /<script/i, /\.\.\//,
    /\/shell/i, /\/cmd/i, /\/upload/i, /CVE-/i,
    /\/manager\/html/i, /phpmyadmin/i
  ];

  // Common Log Format: IP - - [timestamp] "METHOD /path HTTP/x" status bytes
  const re = /^([\d.]+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+|-)/;

  for (const line of lines) {
    const m = re.exec(line);
    if (!m) continue;
    const [, ip, ts, method, path, status, bytes] = m;

    ipMap[ip] = (ipMap[ip] || 0) + 1;
    statusMap[status] = (statusMap[status] || 0) + 1;

    const isSuspicious = suspiciousPaths.some(p => p.test(path));
    const isError = parseInt(status) >= 400;

    if (isSuspicious || status === '401' || status === '403') {
      events.push({
        type: 'web_suspicious',
        ts, ip, method, path, status,
        severity: status === '200' && isSuspicious ? 'critical' : 'medium',
        raw: line
      });
    } else if (isError) {
      events.push({ type: 'web_error', ts, ip, method, path, status, severity: 'low', raw: line });
    }
  }

  // Credential stuffing: >50 POST /login from same IP
  const postMap = {};
  for (const line of lines) {
    const m = re.exec(line);
    if (m && m[3] === 'POST' && /login|auth|signin/i.test(m[4])) {
      postMap[m[1]] = (postMap[m[1]] || 0) + 1;
    }
  }
  const credStuffing = Object.entries(postMap)
    .filter(([, c]) => c > 50)
    .map(([ip, count]) => ({ ip, count, type: 'credential_stuffing' }));

  return { events, ipMap, statusMap, credStuffing };
}

function parseWindows(lines) {
  const events = [];
  // Supports both raw EventLog export and CSV-ish formats
  const eventIdRe = /EventID[:\s]+(\d+)/i;
  const ipRe      = /(?:Source(?:Address)?|IP)[:\s]+([\d.]+)/i;
  const userRe    = /(?:Account Name|User)[:\s]+(\S+)/i;
  const timeRe    = /(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})/;

  // Parse block-style Windows event logs
  const text = lines.join('\n');
  const blocks = text.split(/(?=EventID|Event ID|Log Name)/i).filter(b => b.trim());

  for (const block of blocks) {
    const eidM  = eventIdRe.exec(block);
    const ipM   = ipRe.exec(block);
    const userM = userRe.exec(block);
    const tsM   = timeRe.exec(block);
    if (!eidM) continue;

    const eid  = eidM[1];
    const ip   = ipM ? ipM[1] : 'unknown';
    const user = userM ? userM[1] : 'unknown';
    const ts   = tsM ? tsM[1] : 'unknown';

    const knownEvents = {
      '4624': { desc: 'Successful logon',           severity: 'info'     },
      '4625': { desc: 'Failed logon',               severity: 'medium'   },
      '4648': { desc: 'Logon with explicit creds',  severity: 'medium'   },
      '4672': { desc: 'Special privileges assigned',severity: 'high'     },
      '4720': { desc: 'User account created',       severity: 'high'     },
      '4732': { desc: 'Member added to admin group',severity: 'critical' },
      '4768': { desc: 'Kerberos TGT requested',     severity: 'info'     },
      '4771': { desc: 'Kerberos pre-auth failed',   severity: 'medium'   },
      '7045': { desc: 'New service installed',      severity: 'critical' },
      '4698': { desc: 'Scheduled task created',     severity: 'high'     },
      '4104': { desc: 'PowerShell script block',    severity: 'high'     },
    };

    const known = knownEvents[eid] || { desc: `EventID ${eid}`, severity: 'info' };
    events.push({ type: 'windows_event', eid, ts, ip, user, desc: known.desc, severity: known.severity, raw: block.slice(0, 300) });
  }

  return { events };
}

function detectLogType(content) {
  if (/sshd|Failed password|Accepted password|Invalid user/i.test(content)) return 'ssh';
  if (/EventID|Event ID|Security|WinEvent|Log Name/i.test(content)) return 'windows';
  if (/GET |POST |PUT |DELETE |HEAD /.test(content) && /HTTP\//.test(content)) return 'apache';
  return 'unknown';
}

function parseLog(filename, content) {
  const lines = content.split('\n').filter(l => l.trim());
  const type  = detectLogType(content);

  let result = { filename, type, events: [], summary: {} };

  if (type === 'ssh') {
    const parsed = parseSSH(lines);
    result.events = parsed.events;
    result.summary = {
      totalLines: lines.length,
      failedLogins: Object.values(parsed.failMap).reduce((a, b) => a + b, 0),
      successfulLogins: Object.values(parsed.successMap).reduce((a, b) => a + b, 0),
      uniqueIPs: Object.keys(parsed.failMap).length,
      bruteForceIPs: parsed.bruteForceIPs,
      topIPs: Object.entries(parsed.failMap).sort((a,b)=>b[1]-a[1]).slice(0,10).map(([ip,count])=>({ip,count}))
    };
  } else if (type === 'apache') {
    const parsed = parseApache(lines);
    result.events = parsed.events;
    result.summary = {
      totalLines: lines.length,
      suspiciousRequests: parsed.events.filter(e => e.type === 'web_suspicious').length,
      uniqueIPs: Object.keys(parsed.ipMap).length,
      statusCodes: parsed.statusMap,
      credStuffing: parsed.credStuffing,
      topIPs: Object.entries(parsed.ipMap).sort((a,b)=>b[1]-a[1]).slice(0,10).map(([ip,count])=>({ip,count}))
    };
  } else if (type === 'windows') {
    const parsed = parseWindows(lines);
    result.events = parsed.events;
    const criticals = parsed.events.filter(e => e.severity === 'critical');
    result.summary = {
      totalEvents: parsed.events.length,
      criticalEvents: criticals.length,
      criticalDetails: criticals,
      byEventId: parsed.events.reduce((acc, e) => { acc[e.eid] = (acc[e.eid]||0)+1; return acc; }, {})
    };
  }

  return result;
}

module.exports = { parseLog, detectLogType };
