/* ============================================
   SOC Live Dashboard — app.js
   Handles: file upload, API calls, chart rendering,
            threat intel display, incident report generation
   ============================================ */

let state = {
  files: [],
  analysis: null,
  threatIntel: [],
  report: null,
  charts: {}
};

/* ---- NAVIGATION ---- */
const TITLES = { upload:'Upload Logs', overview:'Live Dashboard', findings:'Threat Findings', intel:'Threat Intelligence', logs:'Log Viewer', report:'Incident Report' };

function showPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
  const navEl = document.querySelector(`[onclick="showPage('${id}')"]`);
  if (navEl) navEl.classList.add('active');
  document.getElementById('page-title').textContent = TITLES[id] || id;
  if (window.innerWidth <= 768) document.getElementById('sidebar').classList.remove('open');
}

function toggleSidebar() { document.getElementById('sidebar').classList.toggle('open'); }

/* ---- FILE UPLOAD ---- */
const zone = document.getElementById('upload-zone');
zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
zone.addEventListener('drop', e => {
  e.preventDefault();
  zone.classList.remove('drag-over');
  handleFiles(e.dataTransfer.files);
});
zone.addEventListener('click', () => document.getElementById('file-input').click());

function handleFiles(fileList) {
  state.files = [...fileList];
  const listEl = document.getElementById('file-list');
  const actEl  = document.getElementById('upload-actions');
  if (state.files.length === 0) { listEl.style.display='none'; actEl.style.display='none'; return; }

  listEl.innerHTML = state.files.map((f, i) => `
    <div class="file-item">
      <svg width="14" height="14" fill="none" viewBox="0 0 14 14"><rect x="2" y="1" width="10" height="12" rx="1" stroke="currentColor" stroke-width="1.2"/><path d="M5 5h4M5 7.5h3" stroke="currentColor" stroke-width="1.1" stroke-linecap="round"/></svg>
      <span class="file-name">${f.name}</span>
      <span class="file-size">${(f.size/1024).toFixed(1)} KB</span>
      <span class="file-remove" onclick="removeFile(${i})">×</span>
    </div>`).join('');
  listEl.style.display = 'flex';
  actEl.style.display = 'flex';
}

function removeFile(i) {
  state.files.splice(i, 1);
  handleFiles(state.files);
}

function clearFiles() {
  state.files = [];
  document.getElementById('file-list').style.display = 'none';
  document.getElementById('upload-actions').style.display = 'none';
  document.getElementById('file-input').value = '';
}

async function analyzeFiles() {
  if (state.files.length === 0) return;
  setProgress(10, 'Uploading log files...');

  const fd = new FormData();
  state.files.forEach(f => fd.append('logs', f));

  try {
    setProgress(30, 'Parsing log entries...');
    const res  = await fetch('/api/logs/upload', { method:'POST', body:fd });
    const data = await res.json();
    if (data.error) { alert('Error: ' + data.error); hideProgress(); return; }

    state.analysis = data;
    setProgress(60, 'Running threat intelligence lookups...');

    // Run AbuseIPDB checks on extracted IPs
    const ips = data.aggregate.suspiciousIPs || [];
    if (ips.length > 0) {
      const intelRes  = await fetch('/api/threat/check', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ ips })
      });
      const intelData = await intelRes.json();
      state.threatIntel = intelData.results || [];
    }

    setProgress(85, 'Generating incident report...');
    const reportRes  = await fetch('/api/report/generate', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ files: data.files, aggregate: data.aggregate, threatIntel: state.threatIntel })
    });
    state.report = await reportRes.json();

    setProgress(100, 'Done!');
    setTimeout(() => {
      hideProgress();
      buildDashboard();
      showPage('overview');
    }, 500);

  } catch(err) {
    console.error(err);
    alert('Server error: ' + err.message + '\n\nMake sure the Node.js server is running (npm start)');
    hideProgress();
  }
}

function setProgress(pct, label) {
  document.getElementById('upload-progress').style.display = 'block';
  document.getElementById('progress-fill').style.width = pct + '%';
  document.getElementById('progress-label').textContent = label;
}
function hideProgress() { document.getElementById('upload-progress').style.display = 'none'; }

/* ---- SAMPLE DATA ---- */
async function loadSampleData() {
  setProgress(20, 'Loading sample logs...');
  const sampleSSH = generateSampleSSH();
  const sampleApache = generateSampleApache();

  const blob1 = new Blob([sampleSSH],   { type:'text/plain' });
  const blob2 = new Blob([sampleApache],{ type:'text/plain' });
  const f1 = new File([blob1], 'auth.log',         { type:'text/plain' });
  const f2 = new File([blob2], 'access.log',        { type:'text/plain' });

  state.files = [f1, f2];
  handleFiles(state.files);
  setProgress(50, 'Sample files ready...');
  setTimeout(() => { hideProgress(); }, 400);
}

function generateSampleSSH() {
  const lines = [];
  const months = ['Jan','Feb','Mar','Apr','May','Jun'];
  const m = months[new Date().getMonth()] || 'Mar';
  const d = new Date().getDate();
  const users = ['root','admin','ubuntu','backup_user','test','deploy','oracle','postgres'];
  const attackerIP = '185.220.101.47';

  // 800 failed attempts
  for (let i = 0; i < 800; i++) {
    const u = users[i % users.length];
    const port = 40000 + i;
    const h = String(Math.floor(i/60)+2).padStart(2,'0');
    const min = String(i%60).padStart(2,'0');
    lines.push(`${m} ${d} 0${h}:${min}:${String(i%60).padStart(2,'0')} srv-linux-01 sshd[1042]: Failed password for ${u} from ${attackerIP} port ${port} ssh2`);
  }
  // A few from other IPs
  for (let i = 0; i < 50; i++) {
    lines.push(`${m} ${d} 04:${String(i).padStart(2,'0')}:00 srv-linux-01 sshd[1042]: Failed password for root from 45.153.160.2 port ${50000+i} ssh2`);
  }
  // Successful login
  lines.push(`${m} ${d} 03:17:44 srv-linux-01 sshd[1042]: Accepted password for backup_user from ${attackerIP} port 43391 ssh2`);
  lines.push(`${m} ${d} 03:18:01 srv-linux-01 sshd[1042]: pam_unix(sshd:session): session opened for user backup_user by (uid=0)`);
  // Some legit logins
  for (let i = 0; i < 10; i++) {
    lines.push(`${m} ${d} 09:${String(i*3).padStart(2,'0')}:00 srv-linux-01 sshd[1042]: Accepted publickey for deploy from 10.0.0.50 port ${60000+i} ssh2`);
  }
  return lines.join('\n');
}

function generateSampleApache() {
  const lines = [];
  const attackerIPs = ['91.108.4.140','193.32.162.45','198.98.56.87'];
  const legit = ['10.0.0.10','10.0.0.11','10.0.0.12'];
  const d = new Date();
  const ts = `${d.getDate()}/${['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][d.getMonth()]}/${d.getFullYear()}:02:44:00 +0000`;

  // Credential stuffing
  for (let i = 0; i < 400; i++) {
    const ip = attackerIPs[i % attackerIPs.length];
    const ua = i % 2 === 0 ? 'python-requests/2.28' : 'Mozilla/5.0 (compatible; Bot/1.0)';
    lines.push(`${ip} - - [${ts}] "POST /api/login HTTP/1.1" ${i % 20 === 0 ? 200 : 429} 128 "-" "${ua}"`);
  }
  // Web shell attempts
  lines.push(`193.32.162.45 - - [${ts}] "POST /uploads/profile/shell.php HTTP/1.1" 403 0 "-" "curl/7.68"`);
  lines.push(`193.32.162.45 - - [${ts}] "GET /uploads/profile/shell.php HTTP/1.1" 404 0 "-" "curl/7.68"`);
  // Path traversal
  lines.push(`45.153.160.2 - - [${ts}] "GET /../../../../etc/passwd HTTP/1.1" 400 0 "-" "nikto/2.1"`);
  lines.push(`45.153.160.2 - - [${ts}] "GET /.env HTTP/1.1" 404 0 "-" "nikto/2.1"`);
  // Legit traffic
  for (let i = 0; i < 200; i++) {
    const ip = legit[i % legit.length];
    lines.push(`${ip} - - [${ts}] "GET /index.html HTTP/1.1" 200 2048 "-" "Mozilla/5.0"`);
  }
  return lines.join('\n');
}

/* ---- BUILD DASHBOARD ---- */
function buildDashboard() {
  const { analysis, threatIntel, report } = state;
  if (!analysis) return;

  // Update alert badge
  const critCount = analysis.aggregate.criticalEvents || 0;
  const badge = document.getElementById('alert-badge');
  badge.style.display = critCount > 0 ? 'flex' : 'none';
  document.getElementById('alert-count').textContent = critCount;

  buildKPIs();
  buildCharts();
  buildFindings();
  buildThreatIntel();
  buildLogViewer();
  buildReport();
}

function buildKPIs() {
  const { analysis, threatIntel } = state;
  const agg = analysis.aggregate;
  const confirmedMalicious = (threatIntel||[]).filter(t=>t.abuseConfidenceScore>=50).length;

  const kpis = [
    { label:'Total Events',     value: agg.totalEvents || 0,              cls:'' },
    { label:'Critical Alerts',  value: agg.criticalEvents || 0,           cls:'red' },
    { label:'Suspicious IPs',   value: (agg.suspiciousIPs||[]).length,     cls:'amber' },
    { label:'Confirmed Malicious', value: confirmedMalicious,              cls: confirmedMalicious>0?'red':'green' },
    { label:'Files Analyzed',   value: (analysis.files||[]).length,        cls:'blue' },
  ];

  document.getElementById('kpi-row').innerHTML = kpis.map(k => `
    <div class="kpi-card">
      <div class="kpi-label">${k.label}</div>
      <div class="kpi-value ${k.cls}">${k.value.toLocaleString()}</div>
    </div>`).join('');
}

const C = { red:'#e84040', amber:'#f59e2a', green:'#22c55e', blue:'#3b82f6', purple:'#a78bfa', grid:'rgba(255,255,255,0.06)', tick:'#4a5260' };
const TOOLTIP = { backgroundColor:'#161a1e', borderColor:'rgba(255,255,255,0.1)', borderWidth:1, titleColor:'#d4d8de', bodyColor:'#7a8390', padding:10 };

function buildCharts() {
  const { analysis } = state;
  const agg = analysis.aggregate;
  const allEvents = agg.recentEvents || [];

  // Destroy old charts
  Object.values(state.charts).forEach(c => c.destroy());
  state.charts = {};

  // Severity bar chart
  const sevCounts = { critical:0, high:0, medium:0, low:0, info:0 };
  allEvents.forEach(e => { const s = e.severity||'info'; if(sevCounts[s]!==undefined) sevCounts[s]++; });

  state.charts.sevBar = new Chart(document.getElementById('c-severity-bar'), {
    type:'bar',
    data:{
      labels:['Critical','High','Medium','Low','Info'],
      datasets:[{ data:[sevCounts.critical,sevCounts.high,sevCounts.medium,sevCounts.low,sevCounts.info],
        backgroundColor:[C.red,C.amber,C.blue,C.green,'#4a5260'], borderRadius:4, borderSkipped:false }]
    },
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{...TOOLTIP}},
      scales:{x:{ticks:{color:C.tick,font:{size:11}},grid:{display:false}},y:{ticks:{color:C.tick,font:{size:10}},grid:{color:C.grid}}}}
  });

  // Top IPs
  const topIPs = (agg.suspiciousIPs||[]).slice(0,8);
  const ipData = analysis.files.flatMap(f => f.summary?.topIPs || []);
  const ipMap = {};
  ipData.forEach(({ip,count}) => { if(!ipMap[ip]||ipMap[ip]<count) ipMap[ip]=count; });
  const sortedIPs = Object.entries(ipMap).sort((a,b)=>b[1]-a[1]).slice(0,8);

  if(document.getElementById('c-top-ips')) {
    state.charts.ips = new Chart(document.getElementById('c-top-ips'), {
      type:'bar',
      data:{
        labels: sortedIPs.map(([ip])=>ip),
        datasets:[{ data:sortedIPs.map(([,c])=>c), backgroundColor:C.red, borderRadius:3, borderSkipped:false }]
      },
      options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',plugins:{legend:{display:false},tooltip:{...TOOLTIP}},
        scales:{x:{ticks:{color:C.tick,font:{size:10}},grid:{color:C.grid}},y:{ticks:{color:C.tick,font:{size:9,family:"'IBM Plex Mono'"}},grid:{display:false}}}}
    });
  }

  // Log type distribution
  const typeCounts = {};
  (analysis.files||[]).forEach(f => { typeCounts[f.type] = (typeCounts[f.type]||0) + 1; });
  if(document.getElementById('c-log-types')) {
    state.charts.types = new Chart(document.getElementById('c-log-types'), {
      type:'doughnut',
      data:{
        labels: Object.keys(typeCounts).map(t=>t.toUpperCase()),
        datasets:[{ data:Object.values(typeCounts), backgroundColor:[C.red,C.amber,C.blue,C.purple,C.green], borderWidth:0 }]
      },
      options:{responsive:true,maintainAspectRatio:false,cutout:'60%',plugins:{legend:{display:true,position:'bottom',labels:{color:C.tick,font:{size:10},boxWidth:8,padding:10}},tooltip:{...TOOLTIP}}}
    });
  }
}

function buildFindings() {
  const findings = state.analysis.aggregate.topFindings || [];
  const container = document.getElementById('findings-container');

  if (findings.length === 0) {
    container.innerHTML = '<div class="empty-state">No significant threats detected in the uploaded logs.</div>';
    return;
  }

  container.innerHTML = `<div class="findings-list">${findings.map(f => `
    <div class="finding-card ${f.severity}">
      <div class="finding-header">
        <span class="sev-badge ${f.severity}">${f.severity.toUpperCase()}</span>
        ${f.mitre ? `<span class="mitre-tag">${f.mitre}</span>` : ''}
      </div>
      <h2>${f.title}</h2>
      <p class="finding-desc">${f.description}</p>
    </div>`).join('')}</div>`;
}

function buildThreatIntel() {
  const intel = state.threatIntel;
  const container = document.getElementById('intel-container');

  if (!intel || intel.length === 0) {
    container.innerHTML = '<div class="empty-state">No suspicious IPs found to check, or AbuseIPDB API key not configured.</div>';

    // Check if API key is missing
    if (intel?.length === 0 && state.analysis?.aggregate?.suspiciousIPs?.length > 0) {
      container.innerHTML = `<div class="empty-state" style="text-align:left;padding:20px">
        <p style="color:var(--amber);font-size:13px;margin-bottom:8px">⚠ AbuseIPDB API key not configured</p>
        <p style="font-size:12px;color:var(--text2)">Add your free API key to the <code>.env</code> file:<br><br>
        <code>ABUSEIPDB_API_KEY=your_key_here</code><br><br>
        Get a free key at <a href="https://www.abuseipdb.com/register" target="_blank" style="color:var(--blue)">abuseipdb.com/register</a></p>
      </div>`;
    }
    return;
  }

  const sorted = [...intel].sort((a,b)=>(b.abuseConfidenceScore||0)-(a.abuseConfidenceScore||0));

  container.innerHTML = `<div class="intel-grid">${sorted.map(t => {
    const score = t.abuseConfidenceScore || 0;
    const scoreColor = score>=75?C.red:score>=40?C.amber:score>=10?C.blue:C.green;
    if (t.error) {
      return `<div class="intel-card">
        <div><div class="intel-ip">${t.ip}</div><div style="font-size:11px;color:var(--text3)">${t.error}</div></div>
        <div class="intel-score"><span class="risk-badge unknown">UNKNOWN</span></div>
      </div>`;
    }
    return `<div class="intel-card">
      <div>
        <div class="intel-ip">${t.ip}</div>
        <div class="intel-meta">
          <span>${t.countryCode||'??'}</span>
          <span>${t.isp||'Unknown ISP'}</span>
          ${t.isTor?'<span style="color:var(--red)">TOR Exit Node</span>':''}
          <span>${t.totalReports||0} reports</span>
          ${t.lastReportedAt?`<span>Last: ${t.lastReportedAt.slice(0,10)}</span>`:''}
        </div>
        <span class="risk-badge ${t.riskLevel||'unknown'}">${(t.riskLevel||'unknown').toUpperCase()}</span>
      </div>
      <div class="intel-score">
        <div class="score-num" style="color:${scoreColor}">${score}</div>
        <div class="score-label">Abuse Score</div>
        <div class="score-bar-wrap"><div class="score-bar" style="width:${score}%;background:${scoreColor}"></div></div>
      </div>
    </div>`;
  }).join('')}</div>`;

  // Update API status indicator
  document.getElementById('api-status').innerHTML = `<div class="status-dot active"></div><span>AbuseIPDB Live</span>`;
}

function buildLogViewer() {
  const events = state.analysis.aggregate.recentEvents || [];
  const terminal = document.getElementById('log-terminal');

  if (events.length === 0) {
    terminal.innerHTML = '<div class="empty-state" style="padding:2rem">No events parsed.</div>';
    return;
  }

  terminal.innerHTML = events.map(e => {
    const sev = e.severity || 'info';
    const ts  = (e.ts || '').slice(0,16);
    const ip  = e.ip || '';
    const msg = e.raw ? e.raw.slice(0,200) : (e.desc || e.type || '');
    return `<div class="log-row sev-${sev}" data-sev="${sev}" data-text="${(ip+' '+msg).toLowerCase()}">
      <span class="lc ts">${ts}</span>
      <span class="lc sev"><span class="sev-badge ${sev}">${sev.toUpperCase()}</span></span>
      <span class="lc ip">${ip}</span>
      <span class="lc msg">${msg}</span>
    </div>`;
  }).join('');
}

function filterLogViewer() {
  const search = document.getElementById('log-search').value.toLowerCase();
  const sev    = document.getElementById('sev-filter').value.toLowerCase();
  document.querySelectorAll('#log-terminal .log-row').forEach(row => {
    const matchSev  = !sev || row.dataset.sev === sev;
    const matchText = !search || row.dataset.text.includes(search);
    row.classList.toggle('hidden', !(matchSev && matchText));
  });
}

function buildReport() {
  const r = state.report;
  if (!r) return;

  document.getElementById('report-container').innerHTML = `
    <div class="inc-doc">
      <div class="inc-doc-header">
        <div class="inc-num">${r.id}</div>
        <div class="inc-status-row">
          <span class="inc-sev-badge ${r.severity.toLowerCase()}">${r.severity}</span>
          <span class="inc-open">OPEN</span>
        </div>
        <div class="inc-title-text">${r.title}</div>
      </div>

      <div class="inc-section">
        <div class="inc-section-title">Metrics</div>
        <div class="inc-2col">
          <div class="inc-field"><div class="lbl">Generated</div><div class="val">${new Date(r.generatedAt).toUTCString()}</div></div>
          <div class="inc-field"><div class="lbl">Total Log Events</div><div class="val">${r.metrics.totalLogEvents.toLocaleString()}</div></div>
          <div class="inc-field"><div class="lbl">Critical Events</div><div class="val red-text">${r.metrics.criticalEvents}</div></div>
          <div class="inc-field"><div class="lbl">Confirmed Malicious IPs</div><div class="val ${r.metrics.confirmedMaliciousIPs>0?'red-text':''}">${r.metrics.confirmedMaliciousIPs}</div></div>
        </div>
      </div>

      <div class="inc-section">
        <div class="inc-section-title">Executive Summary</div>
        <div class="inc-narrative">${r.summary}</div>
      </div>

      ${r.mitreAttack.length > 0 ? `
      <div class="inc-section">
        <div class="inc-section-title">MITRE ATT&CK Mapping</div>
        <div class="mitre-table">
          <div class="mitre-row header"><span>Technique ID</span><span>Title</span><span></span></div>
          ${r.mitreAttack.map(m=>`<div class="mitre-row"><span class="mitre-id">${m.id}</span><span>${m.title}</span><span></span></div>`).join('')}
        </div>
      </div>` : ''}

      <div class="inc-section">
        <div class="inc-section-title">Containment & Remediation</div>
        <div class="steps-grid">
          <div>
            <div class="steps-col-title red-text">Immediate Containment</div>
            <ol class="steps-ol">${r.containmentSteps.map(s=>`<li>${s}</li>`).join('')}</ol>
          </div>
          <div>
            <div class="steps-col-title green-text">Long-Term Remediation</div>
            <ol class="steps-ol">${r.remediationSteps.map(s=>`<li>${s}</li>`).join('')}</ol>
          </div>
        </div>
      </div>

      <div class="inc-export-row">
        <button class="btn-ghost" onclick="exportReport()">Export JSON Report</button>
        <button class="btn-ghost" onclick="window.print()">Print / Save PDF</button>
      </div>
    </div>`;
}

function exportReport() {
  const blob = new Blob([JSON.stringify(state.report, null, 2)], { type:'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `${state.report.id}.json`;
  a.click();
}

/* ---- CLOSE SIDEBAR ON OUTSIDE CLICK ---- */
document.addEventListener('click', e => {
  const sb = document.getElementById('sidebar');
  if (window.innerWidth<=768 && sb.classList.contains('open') && !sb.contains(e.target) && !e.target.closest('.menu-toggle'))
    sb.classList.remove('open');
});
