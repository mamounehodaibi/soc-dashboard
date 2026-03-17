// parsers/logParser.js
// Parses SSH auth logs, Apache access logs, Windows Event Log (txt/csv export)

function parseSSH(lines) {
  const events = [];
  const failMap = {};
  const successMap = {};

  const failRe   = /(\w{3}\s+\d+\s[\d:]+).*Failed password for (\S+) from ([\d.]+)/;
  const acceptRe = /(\w{3}\s+\d+\s[\d:]+).*Accepted (?:password|publickey) for (\S+) from ([\d.]+)/;
  const invalidRe= /(\w{3}\s+\d+\s[\d:]+).*Invalid user (\S+) from ([\d.]+)/;

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

  const re = /^([\d.]+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+|-)/;

  for (const line of lines) {
    const m = re.exec(line);
    if (!m) continue;
    const [, ip, ts, method, path, status] = m;
    ipMap[ip] = (ipMap[ip] || 0) + 1;
    statusMap[status] = (statusMap[status] || 0) + 1;
    const isSuspicious = suspiciousPaths.some(p => p.test(path));
    if (isSuspicious || status === '401' || status === '403') {
      events.push({ type: 'web_suspicious', ts, ip, method, path, status,
        severity: status === '200' && isSuspicious ? 'critical' : 'medium', raw: line });
    } else if (parseInt(status) >= 400) {
      events.push({ type: 'web_error', ts, ip, method, path, status, severity: 'low', raw: line });
    }
  }

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

  const knownEvents = {
    '4624': { desc: 'Successful logon',            severity: 'info'     },
    '4625': { desc: 'Failed logon',                severity: 'medium'   },
    '4634': { desc: 'Account logoff',              severity: 'info'     },
    '4647': { desc: 'User initiated logoff',       severity: 'info'     },
    '4648': { desc: 'Logon with explicit creds',   severity: 'medium'   },
    '4672': { desc: 'Special privileges assigned', severity: 'high'     },
    '4720': { desc: 'User account created',        severity: 'high'     },
    '4722': { desc: 'User account enabled',        severity: 'medium'   },
    '4724': { desc: 'Password reset attempt',      severity: 'medium'   },
    '4728': { desc: 'Member added to global group','severity': 'high'   },
    '4732': { desc: 'Member added to local admin', severity: 'critical' },
    '4756': { desc: 'Member added to universal group', severity: 'high' },
    '4768': { desc: 'Kerberos TGT requested',      severity: 'info'     },
    '4769': { desc: 'Kerberos service ticket',     severity: 'info'     },
    '4771': { desc: 'Kerberos pre-auth failed',    severity: 'medium'   },
    '4776': { desc: 'NTLM auth attempt',           severity: 'medium'   },
    '4798': { desc: 'User local group enumerated', severity: 'medium'   },
    '4799': { desc: 'Group membership enumerated', severity: 'medium'   },
    '7045': { desc: 'New service installed',       severity: 'critical' },
    '4698': { desc: 'Scheduled task created',      severity: 'high'     },
    '4702': { desc: 'Scheduled task updated',      severity: 'high'     },
    '4104': { desc: 'PowerShell script block',     severity: 'high'     },
    '4103': { desc: 'PowerShell module logging',   severity: 'medium'   },
    '1102': { desc: 'Audit log cleared',           severity: 'critical' },
    '4657': { desc: 'Registry value modified',     severity: 'medium'   },
  };

  // ---- FORMAT 1: Real Windows Event Viewer tab-separated export ----
  const tabLines = lines.filter(l => l.includes('\t'));
  if (tabLines.length > 0) {
    for (const line of tabLines) {
      if (/^Level\t|^level\t/i.test(line)) continue;
      const parts = line.split('\t');
      if (parts.length < 4) continue;

      const ts       = (parts[1] || '').trim();
      const eid      = (parts[3] || '').trim();
      const category = (parts[4] || '').trim();
      const desc     = parts.slice(5).join(' ').trim();

      if (!eid || !/^\d+$/.test(eid)) continue;

      const accountM  = /Account Name:\s+(\S+)/i.exec(desc);
      const domainM   = /Account Domain:\s+(\S+)/i.exec(desc);
      const ipM       = /(?:Source Network Address|IP Address|Source Address):\s+([\d.:a-fA-F-]+)/i.exec(desc);
      const logonM    = /Logon Type:\s+(\d+)/i.exec(desc);
      const workM     = /Workstation Name:\s+(\S+)/i.exec(desc);

      const user      = accountM ? accountM[1] : 'unknown';
      const domain    = domainM  ? domainM[1]  : '';
      let   ip        = ipM      ? ipM[1]      : '-';
      const logonType = logonM   ? logonM[1]   : '';

      // Normalize local/empty IPs
      if (ip === '::1' || ip === '-' || ip === '') ip = 'local';

      const known    = knownEvents[eid] || { desc: `EventID ${eid} — ${category}`, severity: 'info' };
      let severity   = known.severity;

      // Elevate: remote network logon (type 3) or remote interactive (type 10)
      if (eid === '4624' && (logonType === '3' || logonType === '10')) severity = 'medium';
      // Elevate: failed logon from a real external IP
      if (eid === '4625' && ip !== 'local' && ip !== 'unknown') severity = 'high';

      const fullUser = (domain && domain !== 'NT AUTHORITY' && domain !== 'WORKGROUP')
        ? `${domain}\\${user}` : user;

      events.push({
        type: 'windows_event', eid, ts,
        ip, user: fullUser, logonType,
        workstation: workM ? workM[1] : '',
        desc: known.desc, severity,
        raw: `[${ts}] EventID:${eid} User:${fullUser} IP:${ip} LogonType:${logonType} — ${known.desc}`
      });
    }
  }

  // ---- FORMAT 2: Block-style (generated samples / older exports) ----
  if (events.length === 0) {
    const full      = lines.join('\n');
    const eventIdRe = /EventID[:\s]+(\d+)/i;
    const ipRe      = /(?:Source(?:Address)?|IP)[:\s]+([\d.]+)/i;
    const userRe    = /(?:Account Name|User)[:\s]+(\S+)/i;
    const timeRe    = /(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})/;
    const blocks    = full.split(/(?=EventID)/i).filter(b => b.trim());

    for (const block of blocks) {
      const eidM  = eventIdRe.exec(block);
      if (!eidM) continue;
      const eid   = eidM[1];
      const ip    = (ipRe.exec(block)  || [])[1] || 'unknown';
      const user  = (userRe.exec(block)|| [])[1] || 'unknown';
      const ts    = (timeRe.exec(block)|| [])[1] || 'unknown';
      const known = knownEvents[eid] || { desc: `EventID ${eid}`, severity: 'info' };
      events.push({ type:'windows_event', eid, ts, ip, user, desc:known.desc, severity:known.severity, raw:block.slice(0,300) });
    }
  }

  return buildWindowsSummary(events);
}

function buildWindowsSummary(events) {
  const criticals = events.filter(e => e.severity === 'critical');
  const failures  = events.filter(e => e.eid === '4625');
  const ipMap     = {};
  failures.forEach(e => {
    if (e.ip && e.ip !== '-' && e.ip !== 'unknown' && e.ip !== 'local') {
      ipMap[e.ip] = (ipMap[e.ip] || 0) + 1;
    }
  });

  return {
    events,
    summary: {
      totalEvents:    events.length,
      criticalEvents: criticals.length,
      failedLogons:   failures.length,
      criticalDetails: criticals,
      byEventId: events.reduce((acc, e) => { acc[e.eid]=(acc[e.eid]||0)+1; return acc; }, {}),
      topIPs: Object.entries(ipMap).sort((a,b)=>b[1]-a[1]).slice(0,10).map(([ip,count])=>({ip,count}))
    }
  };
}

function detectLogType(content) {
  if (/^Level\tDate and Time\tSource\tEvent ID/i.test(content)) return 'windows';
  if (/EventID|Event ID/i.test(content) && !/GET |POST /.test(content)) return 'windows';
  if (/sshd|Failed password|Accepted password|Invalid user/i.test(content)) return 'ssh';
  if (/GET |POST |PUT |DELETE |HEAD /.test(content) && /HTTP\//.test(content)) return 'apache';
  return 'unknown';
}

function parseLog(filename, content) {
  const lines = content.split('\n').filter(l => l.trim());
  const type  = detectLogType(content);
  let result  = { filename, type, events: [], summary: {} };

  if (type === 'ssh') {
    const parsed   = parseSSH(lines);
    result.events  = parsed.events;
    result.summary = {
      totalLines: lines.length,
      failedLogins: Object.values(parsed.failMap).reduce((a,b)=>a+b,0),
      successfulLogins: Object.values(parsed.successMap).reduce((a,b)=>a+b,0),
      uniqueIPs: Object.keys(parsed.failMap).length,
      bruteForceIPs: parsed.bruteForceIPs,
      topIPs: Object.entries(parsed.failMap).sort((a,b)=>b[1]-a[1]).slice(0,10).map(([ip,count])=>({ip,count}))
    };
  } else if (type === 'apache') {
    const parsed   = parseApache(lines);
    result.events  = parsed.events;
    result.summary = {
      totalLines: lines.length,
      suspiciousRequests: parsed.events.filter(e=>e.type==='web_suspicious').length,
      uniqueIPs: Object.keys(parsed.ipMap).length,
      statusCodes: parsed.statusMap,
      credStuffing: parsed.credStuffing,
      topIPs: Object.entries(parsed.ipMap).sort((a,b)=>b[1]-a[1]).slice(0,10).map(([ip,count])=>({ip,count}))
    };
  } else if (type === 'windows') {
    const parsed   = parseWindows(lines);
    result.events  = parsed.events;
    result.summary = parsed.summary;
  } else {
    result.summary = {
      totalLines: lines.length,
      note: 'Format not recognized. Supported: SSH auth.log, Apache access.log, Windows Event Viewer .txt export.'
    };
  }

  return result;
}

module.exports = { parseLog, detectLogType };
