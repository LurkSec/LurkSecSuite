
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    loadMasterData();
    setupEventListeners();
    setupFilters();
    setupSorting();
});

let state = {
    masterData: {},
    socChart: null,
    autoRefreshActive: localStorage.getItem('lurksec_auto_refresh') !== 'false',
    autoRefreshInterval: null,
    sortColumn: 'timestamp',
    sortDirection: 'desc'
};


function initNavigation() {
    const parentBtns = document.querySelectorAll('.nav-parent-btn');
    const subBtns = document.querySelectorAll('.nav-sub-btn');
    const tabPages = document.querySelectorAll('.tab-page');

    parentBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const group = btn.closest('.nav-group');
            const isOpen = group.classList.contains('open');
            const arrow = group.querySelector('.arrow');

            if (isOpen) {
                group.classList.remove('open');
                if (arrow) arrow.innerText = '▶';
            } else {
                group.classList.add('open');
                if (arrow) arrow.innerText = '▼';
            }
        });
    });

    subBtns.forEach(sub => {
        sub.addEventListener('click', (e) => {
            e.preventDefault();
            const tabId = sub.getAttribute('data-tab');

            subBtns.forEach(s => s.classList.remove('active'));
            tabPages.forEach(p => p.classList.remove('active'));

            sub.classList.add('active');
            const targetPage = document.getElementById(`tab-${tabId}`);
            if (targetPage) targetPage.classList.add('active');
        });
    });
}

async function loadMasterData() {
    try {
        const res = await fetch('/api/summary?t=' + Date.now());
        if (res.ok) {
            state.masterData = await res.json();
            renderDashboard();
        }
    } catch (e) {
        console.warn("Master API Error:", e);
    }
}

function renderDashboard() {
    const data = state.masterData;
    const hostInfo = data.host_info || {};

    if (document.getElementById('sys-host-display')) {
        document.getElementById('sys-host-display').innerText = `HOST: ${hostInfo.hostname || 'Localhost'}`;
    }
    if (document.getElementById('sys-ip-display')) {
        document.getElementById('sys-ip-display').innerText = `IP: ${hostInfo.local_ip || '127.0.0.1'}`;
    }
    if (document.getElementById('sys-os-display')) {
        document.getElementById('sys-os-display').innerText = `OS: ${hostInfo.os || 'Windows 11'}`;
    }

    // LurkSOC Metrics
    const soc = data.soc_incidents || {};
    if (document.getElementById('metric-soc-incidents')) {
        document.getElementById('metric-soc-incidents').innerText = soc.total_incidents || 0;
    }
    if (document.getElementById('metric-soc-high')) {
        document.getElementById('metric-soc-high').innerText = soc.severity_counts ? soc.severity_counts.HIGH : 0;
    }
    if (document.getElementById('metric-soc-score')) {
        const score = data.audit ? data.audit.score : 100;
        document.getElementById('metric-soc-score').innerText = `${score}%`;
    }

    renderSOCChart();
    renderSOCFeed();
    renderEDRLogs();
    renderSocketsTable();
    renderSIEMTable();
    renderSIEMAlerts();
    renderDecoyTable();
    renderPacketTable();
    renderInspectorTable();
    renderTraceTable();
    renderTraceTree();
    renderAuditFeed();
    renderReportPreview();
    loadSOARData();
}

function renderSOCChart() {
    const socElem = document.getElementById('chart-soc-threats');
    if (!socElem) return;

    const data = state.masterData;

    const sentinelCount = (data.sockets || []).filter(s => s.severity === 'HIGH').length;
    const siemCount = (data.siem_alerts ? data.siem_alerts.alerts || [] : []).length;
    const decoyCount = (data.decoy_summary ? data.decoy_summary.intrusions || [] : []).length;
    const packetCount = (data.packet_alerts ? data.packet_alerts.alerts || [] : []).length;
    const traceCount = (data.process_alerts ? data.process_alerts.alerts || [] : []).length;
    const auditCount = (data.audit ? data.audit.audits || [] : []).filter(a => a.status !== 'PASS').length;
    const edrCount = (data.edr ? data.edr.action_logs || [] : []).length;

    const ctxSoc = socElem.getContext('2d');
    if (state.socChart) state.socChart.destroy();

    state.socChart = new Chart(ctxSoc, {
        type: 'bar',
        data: {
            labels: ['LurkEDR', 'LurkSentinel', 'LurkSIEM', 'LurkDecoy', 'LurkPacket', 'LurkTrace', 'LurkAudit'],
            datasets: [{
                label: 'Correlated Threat Incidents',
                data: [edrCount, sentinelCount, siemCount, decoyCount, packetCount, traceCount, auditCount],
                backgroundColor: ['#f85149', '#58a6ff', '#d29922', '#f85149', '#a371f7', '#3fb950', '#f0883e']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#8b949e', font: { family: 'JetBrains Mono', size: 11 } }, grid: { color: '#21262d' } },
                y: { ticks: { color: '#8b949e', font: { family: 'JetBrains Mono', size: 11 } }, grid: { color: '#21262d' }, beginAtZero: true }
            }
        }
    });
}

function renderSOCFeed(filteredIncidents = null) {
    const container = document.getElementById('soc-incidents-container');
    if (!container) return;
    container.innerHTML = '';

    const soc = state.masterData.soc_incidents || {};
    const incidents = filteredIncidents || soc.incidents || [];

    if (incidents.length === 0) {
        container.innerHTML = `<div class="compliance-card"><div class="compliance-desc">Zero incidents matching filter.</div></div>`;
        return;
    }

    incidents.forEach(inc => {
        const div = document.createElement('div');
        div.className = `compliance-card ${inc.severity}`;
        
        let actions = [];
        if (inc.target_ip || (inc.action_type === 'BLOCK_IP')) {
            const ip = inc.target_ip || (inc.evidence.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/) || [])[0];
            if (ip) {
                actions.push(`
                    <button class="btn btn-outline btn-quick-block" data-ip="${ip}" style="font-size:10px;color:#f85149;border-color:#f85149;display:inline-flex;align-items:center;gap:4px;">
                        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/></svg>
                        Block IP (${ip})
                    </button>
                `);
            }
        }

        const pidMatch = inc.evidence.match(/PID\s+(\d+)/i);
        if (pidMatch) {
            const pid = pidMatch[1];
            actions.push(`
                <button class="btn btn-outline btn-quick-kill" data-pid="${pid}" style="font-size:10px;color:#d29922;border-color:#d29922;display:inline-flex;align-items:center;gap:4px;">
                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/></svg>
                    Kill Process (PID ${pid})
                </button>
            `);
        }

        actions.push(`
            <button class="btn btn-outline btn-quick-soar" data-title="${encodeURIComponent(inc.title)}" data-desc="${encodeURIComponent(inc.evidence)}" data-sev="${inc.severity}" style="font-size:10px;color:#58a6ff;border-color:#58a6ff;display:inline-flex;align-items:center;gap:4px;">
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                Spawn SOAR Case
            </button>
        `);

        div.innerHTML = `
            <div class="compliance-header">
                <span class="compliance-title">${inc.engine} | ${inc.title} (${inc.incident_id})</span>
                <span class="compliance-tag ${inc.severity}">${inc.severity}</span>
            </div>
            <div class="compliance-desc">Category: ${inc.category} | Origin: ${inc.origin} | Time: ${inc.timestamp}</div>
            <div class="compliance-payload">${inc.evidence}</div>
            <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;">${actions.join('')}</div>
        `;
        container.appendChild(div);
    });

    // Attach click handlers for IP Block buttons
    container.querySelectorAll('.btn-quick-block').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const ip = e.target.closest('button').getAttribute('data-ip');
            btn.innerText = `Blocking ${ip}...`;
            const res = await fetch(`/api/edr/block?ip=${encodeURIComponent(ip)}`);
            const d = await res.json();
            btn.innerText = d.success ? `IP ${ip} Blocked` : `Block Failed`;
            loadMasterData();
        });
    });

    // Attach click handlers for Kill Process buttons
    container.querySelectorAll('.btn-quick-kill').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const target = e.target.closest('button');
            const pid = target.getAttribute('data-pid');
            target.innerText = `Killing PID ${pid}...`;
            try {
                const res = await fetch(`/api/edr/kill?pid=${pid}`);
                const d = await res.json();
                target.innerText = d.success ? `PID ${pid} Killed` : `Kill Failed`;
                loadMasterData();
            } catch (err) {
                target.innerText = `Kill Failed`;
            }
        });
    });

    // Attach click handlers for SOAR case creation
    container.querySelectorAll('.btn-quick-soar').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const target = e.target.closest('button');
            const title = decodeURIComponent(target.getAttribute('data-title'));
            const desc = decodeURIComponent(target.getAttribute('data-desc'));
            const sev = target.getAttribute('data-sev');
            target.innerText = `Spawning SOAR Case...`;
            try {
                const res = await fetch(`/api/soar/case/create?title=${encodeURIComponent(title)}&description=${encodeURIComponent(desc)}&severity=${sev}&assigned=SecOps%20Analyst`);
                const d = await res.json();
                target.innerText = d.case_id ? `SOAR Case ${d.case_id} Created` : `SOAR Case Failed`;
                loadMasterData();
            } catch (err) {
                target.innerText = `SOAR Case Failed`;
            }
        });
    });
}

function renderEDRLogs() {
    const logsTbody = document.getElementById('suite-edr-logs-tbody');
    const vaultTbody = document.getElementById('suite-edr-vault-tbody');
    const edr = state.masterData.edr || {};

    if (logsTbody) {
        logsTbody.innerHTML = '';
        const logs = edr.action_logs || [];
        if (logs.length === 0) {
            logsTbody.innerHTML = `<tr><td colspan="5" style="color:#8b949e;">No containment actions logged.</td></tr>`;
        } else {
            logs.forEach(l => {
                const tr = document.createElement('tr');
                const color = l.success ? '#3fb950' : '#f85149';
                tr.innerHTML = `
                    <td><code>${l.timestamp}</code></td>
                    <td><strong style="color:#58a6ff;">${l.action_type}</strong></td>
                    <td><code>${l.target}</code></td>
                    <td><strong style="color:${color};">${l.success ? 'SUCCESS' : 'FAILED'}</strong></td>
                    <td>${l.message}</td>
                `;
                logsTbody.appendChild(tr);
            });
        }
    }

    if (vaultTbody) {
        vaultTbody.innerHTML = '';
        const vault = edr.quarantined_files || [];
        if (vault.length === 0) {
            vaultTbody.innerHTML = `<tr><td colspan="4" style="color:#8b949e;">Quarantine vault is empty.</td></tr>`;
        } else {
            vault.forEach(v => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><code>${v.quarantined_time}</code></td>
                    <td><strong style="color:#f85149;">${v.filename}</strong></td>
                    <td><code>${v.size_bytes}</code></td>
                    <td><code>${v.vault_path}</code></td>
                `;
                vaultTbody.appendChild(tr);
            });
        }
    }
}

function renderSocketsTable(filteredSockets = null) {
    const tbody = document.getElementById('socket-table-body');
    if (!tbody) return;
    tbody.innerHTML = '';
    const sockets = filteredSockets || state.masterData.sockets || [];

    sockets.slice(0, 50).forEach(s => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><code>${s.id}</code></td>
            <td><strong style="color:#58a6ff;">${s.protocol}</strong></td>
            <td><code>${s.local_address}</code></td>
            <td><code>${s.foreign_address}</code></td>
            <td>${s.origin}</td>
            <td><strong>${s.process_name}</strong></td>
        `;
        tbody.appendChild(tr);
    });
}

function renderSIEMTable(filteredEvents = null) {
    const tbody = document.getElementById('siem-table-body');
    if (!tbody) return;
    tbody.innerHTML = '';
    const events = filteredEvents || state.masterData.siem_events || [];

    events.slice(0, 50).forEach(e => {
        const tr = document.createElement('tr');
        const color = e.severity === 'HIGH' ? '#f85149' : (e.severity === 'MEDIUM' ? '#d29922' : '#c9d1d9');
        tr.innerHTML = `
            <td><code>${e.timestamp}</code></td>
            <td><code>${e.event_id}</code></td>
            <td><code>${e.log_name}</code></td>
            <td>${e.provider}</td>
            <td><code>${e.user}</code></td>
            <td><strong style="color:${color};">${e.message}</strong></td>
        `;
        tbody.appendChild(tr);
    });
}

function renderSIEMAlerts() {
    const container = document.getElementById('siem-alerts-container');
    if (!container) return;
    container.innerHTML = '';

    const siem = state.masterData.siem_alerts || {};
    const alerts = siem.alerts || [];

    alerts.forEach(alt => {
        const div = document.createElement('div');
        div.className = `compliance-card ${alt.severity}`;
        div.innerHTML = `
            <div class="compliance-header">
                <span class="compliance-title">${alt.title} (${alt.rule_id})</span>
                <span class="compliance-tag ${alt.severity}">${alt.severity}</span>
            </div>
            <div class="compliance-desc">${alt.description}</div>
            <div class="compliance-payload">${alt.evidence}</div>
        `;
        container.appendChild(div);
    });
}

function renderDecoyTable(filteredDecoys = null) {
    const tbody = document.getElementById('decoy-table-body');
    if (!tbody) return;
    tbody.innerHTML = '';
    const decoy = state.masterData.decoy_summary || {};
    const intrusions = filteredDecoys || decoy.intrusions || [];

    intrusions.slice(0, 50).forEach(i => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><code>${i.timestamp}</code></td>
            <td><code>${i.probe_id}</code></td>
            <td><strong style="color:#f85149;">Port ${i.target_port} (${i.service})</strong></td>
            <td><code>${i.source_ip}</code></td>
            <td>${i.origin}</td>
            <td><code>${i.payload}</code></td>
        `;
        tbody.appendChild(tr);
    });
}

function renderPacketTable() {
    const tbody = document.getElementById('packet-table-body');
    if (!tbody) return;
    tbody.innerHTML = '';
    const packets = state.masterData.packets || [];

    packets.slice(0, 50).forEach(p => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><code>${p.timestamp}</code></td>
            <td><code>${p.packet_id}</code></td>
            <td><code>${p.src_ip}:${p.src_port}</code></td>
            <td><code>${p.dst_ip}:${p.dst_port}</code></td>
            <td><strong style="color:#58a6ff;">${p.protocol}</strong></td>
            <td>${p.message}</td>
        `;
        tbody.appendChild(tr);
    });
}

function renderInspectorTable() {
    const tbody = document.getElementById('inspector-table-body');
    if (!tbody) return;
    tbody.innerHTML = '';
    const packets = state.masterData.packets || [];

    packets.slice(0, 50).forEach(p => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><code>${p.timestamp}</code></td>
            <td><strong style="color:#58a6ff;">${p.protocol}</strong></td>
            <td><code>${p.src_ip}:${p.src_port}</code></td>
            <td><code>${p.dst_ip}:${p.dst_port}</code></td>
            <td><strong>${p.message}</strong></td>
        `;
        tbody.appendChild(tr);
    });
}

function renderTraceTable(filteredTrace = null) {
    const tbody = document.getElementById('trace-table-body');
    if (!tbody) return;
    tbody.innerHTML = '';
    const procs = filteredTrace || state.masterData.processes || [];

    procs.slice(0, 50).forEach(p => {
        const tr = document.createElement('tr');
        const color = p.severity === 'HIGH' ? '#f85149' : (p.severity === 'MEDIUM' ? '#d29922' : '#58a6ff');
        tr.innerHTML = `
            <td><code>${p.pid}</code></td>
            <td><code>${p.ppid}</code></td>
            <td><strong style="color:${color};">${p.name}</strong></td>
            <td>${p.parent_name}</td>
            <td><code>${p.path}</code></td>
            <td><code>${p.cmdline}</code></td>
        `;
        tbody.appendChild(tr);
    });
}

function renderTraceTree() {
    const container = document.getElementById('tree-view-container');
    if (!container) return;

    const procs = state.masterData.processes || [];
    let treeText = `===========================================================\n`;
    treeText += ` WINDOWS PROCESS HIERARCHY TREE (PID -> PPID -> EXEC)\n`;
    treeText += `===========================================================\n\n`;

    procs.slice(0, 35).forEach(p => {
        const indent = p.ppid > 0 ? '  ├── ' : '├── ';
        treeText += `${indent}[PID ${p.pid}] ${p.name} (Parent: ${p.parent_name} [${p.ppid}])\n`;
        treeText += `  │    Path: ${p.path}\n`;
        treeText += `  │    Cmd:  ${p.cmdline}\n\n`;
    });

    container.innerText = treeText;
}

function renderAuditFeed() {
    const container = document.getElementById('audit-list-container');
    if (!container) return;
    container.innerHTML = '';

    const audit = state.masterData.audit || {};
    const items = audit.audits || [];

    items.forEach(a => {
        const div = document.createElement('div');
        div.className = `compliance-card ${a.severity}`;
        div.innerHTML = `
            <div class="compliance-header">
                <span class="compliance-title">${a.component} (${a.audit_id})</span>
                <span class="compliance-tag ${a.status === 'PASS' ? '' : 'HIGH'}">${a.status}</span>
            </div>
            <div class="compliance-desc">${a.details}</div>
            <div class="compliance-payload">Recommendation: ${a.recommendation}</div>
        `;
        container.appendChild(div);
    });
}

function renderReportPreview() {
    const preview = document.getElementById('report-text-preview');
    if (!preview) return;

    const data = state.masterData;
    const hostInfo = data.host_info || {};
    const soc = data.soc_incidents || {};

    let md = `# Master LurkSec Executive Security Report\n`;
    md += `Host: ${hostInfo.hostname} (${hostInfo.local_ip}) | OS: ${hostInfo.os}\n\n`;
    md += `## Master Suite Summary\n`;
    md += `- Total Correlated Incidents: ${soc.total_incidents || 0}\n`;
    md += `- Hardening Score: ${data.audit ? data.audit.score : 100}%\n`;
    md += `- Active Network Sockets: ${(data.sockets || []).length}\n`;
    md += `- Active Processes: ${(data.processes || []).length}\n\n`;
    md += `## High-Priority Incident Feed Sample\n`;
    (soc.incidents || []).slice(0, 8).forEach(inc => {
        md += `- [${inc.engine}] (${inc.severity}) ${inc.title}: ${inc.evidence}\n`;
    });

    preview.innerText = md;
}

function setupSorting() {
    const headers = document.querySelectorAll('th.sortable');
    headers.forEach(header => {
        header.addEventListener('click', () => {
            const col = header.getAttribute('data-sort');
            if (!col) return;
            state.sortColumn = col;
            state.sortDirection = state.sortDirection === 'asc' ? 'desc' : 'asc';

            headers.forEach(h => {
                const icon = h.querySelector('.sort-icon');
                if (icon) {
                    icon.innerText = h.getAttribute('data-sort') === state.sortColumn ? (state.sortDirection === 'asc' ? '▲' : '▼') : '';
                }
            });
        });
    });
}

function setupEventListeners() {
    const outputConsole = document.getElementById('suite-edr-output');

    // LurkEDR Suite Action Handlers
    const btnKill = document.getElementById('btn-suite-kill');
    if (btnKill) {
        btnKill.addEventListener('click', async () => {
            const pidVal = document.getElementById('input-suite-kill-pid').value;
            if (!pidVal) { alert("Please enter a target PID."); return; }

            outputConsole.innerText = `[+] Executing EDR Process Termination for PID ${pidVal}...`;
            try {
                const res = await fetch(`/api/edr/kill?pid=${pidVal}`);
                const result = await res.json();
                outputConsole.innerText = JSON.stringify(result, null, 2);
                try { await loadMasterData(); } catch(err) {}
            } catch (e) { outputConsole.innerText = `[-] EDR Action Output:\n${e.message}`; }
        });
    }

    const btnBlock = document.getElementById('btn-suite-block');
    if (btnBlock) {
        btnBlock.addEventListener('click', async () => {
            const ipVal = document.getElementById('input-suite-block-ip').value;
            if (!ipVal) { alert("Please enter a target remote IP address."); return; }

            outputConsole.innerText = `[+] Executing Windows Firewall Block for IP ${ipVal}...`;
            try {
                const res = await fetch(`/api/edr/block?ip=${encodeURIComponent(ipVal)}`);
                const result = await res.json();
                outputConsole.innerText = JSON.stringify(result, null, 2);
                try { await loadMasterData(); } catch(err) {}
            } catch (e) { outputConsole.innerText = `[-] EDR Action Output:\n${e.message}`; }
        });
    }

    const btnQuarantine = document.getElementById('btn-suite-quarantine');
    if (btnQuarantine) {
        btnQuarantine.addEventListener('click', async () => {
            const pathVal = document.getElementById('input-suite-quarantine-path').value;
            if (!pathVal) { alert("Please enter a target file path."); return; }

            outputConsole.innerText = `[+] Quarantining binary '${pathVal}' to vault...`;
            try {
                const res = await fetch(`/api/edr/quarantine?path=${encodeURIComponent(pathVal)}`);
                const result = await res.json();
                outputConsole.innerText = JSON.stringify(result, null, 2);
                try { await loadMasterData(); } catch(err) {}
            } catch (e) { outputConsole.innerText = `[-] EDR Action Output:\n${e.message}`; }
        });
    }

    const btnCarve = document.getElementById('btn-suite-carve');
    if (btnCarve) {
        btnCarve.addEventListener('click', async () => {
            const pidVal = document.getElementById('input-suite-carve-pid').value;
            if (!pidVal) { alert("Please enter a target PID."); return; }

            outputConsole.innerText = `[+] Carving memory strings for PID ${pidVal}...`;
            try {
                const res = await fetch(`/api/edr/carve?pid=${pidVal}`);
                const result = await res.json();
                outputConsole.innerText = JSON.stringify(result, null, 2);
                try { await loadMasterData(); } catch(err) {}
            } catch (e) { outputConsole.innerText = `[-] EDR Action Output:\n${e.message}`; }
        });
    }

    const btnScanPort = document.getElementById('btn-run-portscan');
    if (btnScanPort) {
        btnScanPort.addEventListener('click', async () => {
            btnScanPort.disabled = true;
            btnScanPort.innerText = 'Scanning 150 Ports...';
            try {
                const res = await fetch('/api/portscan');
                const scanData = await res.json();
                const container = document.getElementById('portscan-results-container');
                if (container) {
                    let html = `<div style="font-weight:bold;margin-bottom:8px;color:#3fb950;">[+] Found ${scanData.total_open} Open Ports:</div>`;
                    scanData.results.forEach(r => {
                        html += `<div style="padding:4px 0;border-bottom:1px solid #30363d;">
                            <strong style="color:#58a6ff;">Port ${r.port} (${r.service})</strong> - ${r.description}
                        </div>`;
                    });
                    container.innerHTML = html;
                }
            } catch (e) { console.error(e); }
            finally {
                btnScanPort.disabled = false;
                btnScanPort.innerText = 'Execute 150-Thread Port Scan';
            }
        });
    }

    const btnQuickScan = document.getElementById('btn-quick-scan');
    if (btnQuickScan) {
        btnQuickScan.addEventListener('click', async () => {
            btnQuickScan.disabled = true;
            btnQuickScan.innerText = 'Refreshing...';
            try { await loadMasterData(); }
            finally {
                setTimeout(() => {
                    btnQuickScan.disabled = false;
                    btnQuickScan.innerText = 'Refresh Suite';
                }, 300);
            }
        });
    }

    const btnAutoRefresh = document.getElementById('btn-auto-refresh');
    function updateAutoRefreshUI() {
        if (!btnAutoRefresh) return;
        if (state.autoRefreshActive) {
            btnAutoRefresh.innerText = `Auto-Refresh: LIVE (1s)`;
            btnAutoRefresh.style.borderColor = "#3fb950";
            btnAutoRefresh.style.color = "#3fb950";
            if (!state.autoRefreshInterval) {
                state.autoRefreshInterval = setInterval(() => loadMasterData(), 1000);
            }
        } else {
            btnAutoRefresh.innerText = `Auto-Refresh: OFF`;
            btnAutoRefresh.style.borderColor = "";
            btnAutoRefresh.style.color = "";
            if (state.autoRefreshInterval) {
                clearInterval(state.autoRefreshInterval);
                state.autoRefreshInterval = null;
            }
        }
    }

    if (btnAutoRefresh) {
        btnAutoRefresh.addEventListener('click', () => {
            state.autoRefreshActive = !state.autoRefreshActive;
            localStorage.setItem('lurksec_auto_refresh', state.autoRefreshActive ? 'true' : 'false');
            updateAutoRefreshUI();
        });
    }

    // Auto-start 1-second live polling on load if enabled
    updateAutoRefreshUI();


    // Per-Module Exports
    const btnSocJson = document.getElementById('btn-export-soc-json');
    if (btnSocJson) {
        btnSocJson.addEventListener('click', () => {
            downloadFile(JSON.stringify(state.masterData.soc_incidents || {}, null, 2), 'LurkSOC_Incidents.json', 'application/json');
        });
    }

    const btnSockJson = document.getElementById('btn-export-sockets-json');
    if (btnSockJson) {
        btnSockJson.addEventListener('click', () => {
            downloadFile(JSON.stringify(state.masterData.sockets || [], null, 2), 'LurkSentinel_Sockets.json', 'application/json');
        });
    }

    const btnSiemJson = document.getElementById('btn-export-siem-json');
    if (btnSiemJson) {
        btnSiemJson.addEventListener('click', () => {
            downloadFile(JSON.stringify(state.masterData.siem_events || [], null, 2), 'LurkSIEM_Events.json', 'application/json');
        });
    }

    const btnDecoyJson = document.getElementById('btn-export-decoy-json');
    if (btnDecoyJson) {
        btnDecoyJson.addEventListener('click', () => {
            downloadFile(JSON.stringify(state.masterData.decoy_summary || {}, null, 2), 'LurkDecoy_Probes.json', 'application/json');
        });
    }

    const btnExportPcap = document.getElementById('btn-export-pcap');
    if (btnExportPcap) {
        btnExportPcap.addEventListener('click', () => window.open('/api/pcap', '_blank'));
    }

    const btnTraceJson = document.getElementById('btn-export-trace-json');
    if (btnTraceJson) {
        btnTraceJson.addEventListener('click', () => {
            downloadFile(JSON.stringify(state.masterData.processes || [], null, 2), 'LurkTrace_Processes.json', 'application/json');
        });
    }

    const btnAuditJson = document.getElementById('btn-export-audit-json');
    if (btnAuditJson) {
        btnAuditJson.addEventListener('click', () => {
            downloadFile(JSON.stringify(state.masterData.audit || {}, null, 2), 'LurkAudit_Hardening.json', 'application/json');
        });
    }

    const btnGenMarkdown = document.getElementById('btn-gen-markdown');
    if (btnGenMarkdown) {
        btnGenMarkdown.addEventListener('click', async () => {
            const res = await fetch('/api/report/md');
            downloadFile(await res.text(), 'Master_LurkSec_Report.md', 'text/markdown');
        });
    }

    const btnGenJson = document.getElementById('btn-gen-json');
    if (btnGenJson) {
        btnGenJson.addEventListener('click', async () => {
            const res = await fetch('/api/report/json');
            downloadFile(JSON.stringify(await res.json(), null, 2), 'Master_LurkSec_Report.json', 'application/json');
        });
    }

    const btnPrintReport = document.getElementById('btn-print-report');
    if (btnPrintReport) {
        btnPrintReport.addEventListener('click', () => window.open('/api/report/html', '_blank'));
    }
}

function downloadFile(content, fileName, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function setupFilters() {
    const socSearch = document.getElementById('soc-search-input');
    if (socSearch) {
        socSearch.addEventListener('input', (e) => {
            const q = e.target.value.toLowerCase();
            const soc = state.masterData.soc_incidents || {};
            const filtered = (soc.incidents || []).filter(i =>
                i.title.toLowerCase().includes(q) ||
                i.engine.toLowerCase().includes(q) ||
                i.category.toLowerCase().includes(q) ||
                i.severity.toLowerCase().includes(q) ||
                (i.evidence || '').toLowerCase().includes(q)
            );
            renderSOCFeed(filtered);
        });
    }

    const socketSearch = document.getElementById('socket-search-input');
    if (socketSearch) {
        socketSearch.addEventListener('input', (e) => {
            const q = e.target.value.toLowerCase();
            const sockets = state.masterData.sockets || [];
            const filtered = sockets.filter(s =>
                s.process_name.toLowerCase().includes(q) ||
                s.local_address.toLowerCase().includes(q) ||
                s.foreign_address.toLowerCase().includes(q) ||
                s.origin.toLowerCase().includes(q)
            );
            renderSocketsTable(filtered);
        });
    }

    const siemSearch = document.getElementById('siem-search-input');
    if (siemSearch) {
        siemSearch.addEventListener('input', (e) => {
            const q = e.target.value.toLowerCase();
            const events = state.masterData.siem_events || [];
            const filtered = events.filter(evt =>
                evt.event_id.toString().includes(q) ||
                evt.log_name.toLowerCase().includes(q) ||
                evt.provider.toLowerCase().includes(q) ||
                evt.user.toLowerCase().includes(q) ||
                evt.message.toLowerCase().includes(q)
            );
            renderSIEMTable(filtered);
        });
    }

    const decoySearch = document.getElementById('decoy-search-input');
    if (decoySearch) {
        decoySearch.addEventListener('input', (e) => {
            const q = e.target.value.toLowerCase();
            const decoy = state.masterData.decoy_summary || {};
            const intrusions = decoy.intrusions || [];
            const filtered = intrusions.filter(i =>
                i.source_ip.toLowerCase().includes(q) ||
                i.service.toLowerCase().includes(q) ||
                i.target_port.toString().includes(q) ||
                i.payload.toLowerCase().includes(q)
            );
            renderDecoyTable(filtered);
        });
    }

    const traceSearch = document.getElementById('trace-search-input');
    if (traceSearch) {
        traceSearch.addEventListener('input', (e) => {
            const q = e.target.value.toLowerCase();
            const procs = state.masterData.processes || [];
            const filtered = procs.filter(p =>
                p.pid.toString().includes(q) ||
                p.name.toLowerCase().includes(q) ||
                p.path.toLowerCase().includes(q) ||
                p.cmdline.toLowerCase().includes(q)
            );
            renderTraceTable(filtered);
        });
    }
}

async function loadShieldData() {
    try {
        const res = await fetch('/api/shield/summary?t=' + Date.now());
        if (res.ok) {
            const d = await res.json();
            document.getElementById('suite-shield-inspected').innerText = d.total_inspected || 0;
            document.getElementById('suite-shield-blocked').innerText = d.total_blocked || 0;
            document.getElementById('suite-shield-high').innerText = d.high_severity_blocks || 0;
            document.getElementById('suite-shield-rules').innerText = (d.active_rules || []).length;
            renderShieldLog(d.block_log || []);
            renderShieldRules(d.active_rules || []);
            renderShieldRateIPs(d.top_ips || [], d.blocked_ips || []);
        }
    } catch(e) { console.warn('Shield API error:', e); }
}

function renderShieldLog(logs) {
    const tbody = document.getElementById('suite-shield-log-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (!logs.length) { tbody.innerHTML = '<tr><td colspan="6" style="color:#8b949e;">No requests inspected yet.</td></tr>'; return; }
    logs.slice(0,20).forEach(r => {
        const tr = document.createElement('tr');
        const color = r.blocked ? '#f85149' : '#3fb950';
        const rules = (r.rules_matched || []).map(m => m.rule_id).join(', ') || '—';
        tr.innerHTML = `<td><code>${r.timestamp}</code></td><td><strong style="color:#58a6ff;">${r.method}</strong></td><td><code>${r.uri}</code></td><td><code>${r.client_ip || '—'}</code></td><td><strong style="color:${color};">[${r.action}]</strong></td><td><code>${rules}</code></td>`;
        tbody.appendChild(tr);
    });
}

function renderShieldRules(rules) {
    const c = document.getElementById('suite-shield-rules-container');
    if (!c) return;
    c.innerHTML = '';
    rules.forEach(r => {
        const div = document.createElement('div');
        div.className = `compliance-card ${r.severity}`;
        div.innerHTML = `<div class="compliance-header"><span class="compliance-title">${r.rule_id} — ${r.name}</span><span class="compliance-tag ${r.severity}">${r.severity}</span></div><div class="compliance-desc">Category: ${r.category}</div>`;
        c.appendChild(div);
    });
}

function renderShieldRateIPs(topIPs, blockedIPs) {
    const topTbody = document.getElementById('suite-shield-topip-tbody');
    const blockedTbody = document.getElementById('suite-shield-blocked-tbody');
    if (topTbody) {
        topTbody.innerHTML = '';
        if (!topIPs.length) { topTbody.innerHTML = '<tr><td colspan="3" style="color:#8b949e;">No IP traffic recorded.</td></tr>'; }
        topIPs.forEach(ip => {
            const tr = document.createElement('tr');
            const color = ip.rate_limited ? '#f85149' : '#c9d1d9';
            tr.innerHTML = `<td><code>${ip.ip}</code></td><td><strong style="color:${color};">${ip.request_count}</strong></td><td style="color:${color};">${ip.rate_limited ? '[RATE LIMITED]' : '[OK]'}</td>`;
            topTbody.appendChild(tr);
        });
    }
    if (blockedTbody) {
        blockedTbody.innerHTML = '';
        if (!blockedIPs.length) { blockedTbody.innerHTML = '<tr><td colspan="2" style="color:#8b949e;">No IPs rate-limited.</td></tr>'; }
        blockedIPs.forEach(ip => {
            const tr = document.createElement('tr');
            tr.innerHTML = `<td><code style="color:#f85149;">${ip.ip}</code></td><td><code>${ip.blocked_since}</code></td>`;
            blockedTbody.appendChild(tr);
        });
    }
}

document.addEventListener('DOMContentLoaded', () => {
    // Shield inspect button
    document.getElementById('btn-suite-shield-inspect')?.addEventListener('click', async () => {
        const method = document.getElementById('suite-shield-method').value;
        const uri = document.getElementById('suite-shield-uri').value;
        const ip = document.getElementById('suite-shield-ip').value || '127.0.0.1';
        if (!uri) { alert('Enter a URI.'); return; }
        document.getElementById('suite-shield-result').innerText = '[+] Running WAF inspection...';
        try {
            const res = await fetch(`/api/shield/inspect?method=${method}&uri=${encodeURIComponent(uri)}&ip=${encodeURIComponent(ip)}`);
            const result = await res.json();
            document.getElementById('suite-shield-result').innerText = JSON.stringify(result, null, 2);
            await loadShieldData();
        } catch(e) { document.getElementById('suite-shield-result').innerText = `Error: ${e.message}`; }
    });

    document.querySelectorAll('.suite-quick-payload').forEach(btn => {
        btn.addEventListener('click', () => {
            document.getElementById('suite-shield-uri').value = btn.getAttribute('data-uri');
            document.getElementById('suite-shield-method').value = btn.getAttribute('data-method');
        });
    });

    document.getElementById('btn-suite-shield-json')?.addEventListener('click', async () => {
        const res = await fetch('/api/shield/summary'); downloadFile(JSON.stringify(await res.json(), null, 2), 'LurkShield_BlockLog.json', 'application/json');
    });
    document.getElementById('btn-suite-shield-csv')?.addEventListener('click', async () => {
        const res = await fetch('/api/shield/summary'); const d = await res.json();
        let csv = "Timestamp,Method,URI,Action,Severity\n";
        (d.block_log || []).forEach(r => { csv += `"${r.timestamp}","${r.method}","${r.uri}","${r.action}","${r.severity}"\n`; });
        downloadFile(csv, 'LurkShield_BlockLog.csv', 'text/csv');
    });

    // Load shield data when WAF tab is shown
    document.querySelectorAll('[data-tab="shield-overview"],[data-tab="shield-inspect"],[data-tab="shield-rate"]').forEach(btn => {
        btn.addEventListener('click', () => setTimeout(loadShieldData, 100));
    });
});

async function loadIntelData() {
    try {
        const res = await fetch('/api/intel/summary?t=' + Date.now());
        if (!res.ok) return;
        const d = await res.json();
        document.getElementById('suite-intel-feed').innerText = d.threat_feed_size || 0;
        document.getElementById('suite-intel-ioc').innerText = (d.ioc_matches || []).length;
        document.getElementById('suite-intel-conns').innerText = d.active_connections || 0;
        document.getElementById('suite-intel-kev').innerText = d.cisa_kev_count || 0;
        renderIntelIOCContainer(d.ioc_matches || []);
        renderIntelIOCTable(d.ioc_matches || []);
        renderIntelKEVTable(d.cisa_kev || []);
    } catch(e) { console.warn('Intel API error:', e); }
}

function renderIntelIOCContainer(matches) {
    const c = document.getElementById('suite-intel-ioc-container');
    if (!c) return;
    c.innerHTML = '';
    if (!matches.length) {
        c.innerHTML = '<div class="compliance-card LOW"><div class="compliance-header"><span class="compliance-title">No Active IOC Matches</span><span class="compliance-tag">CLEAN</span></div><div class="compliance-desc">No system connections matched the CTI threat feed.</div></div>';
        return;
    }
    matches.forEach(m => {
        const div = document.createElement('div');
        div.className = 'compliance-card HIGH';
        div.innerHTML = `<div class="compliance-header"><span class="compliance-title">IOC: ${m.indicator} (${m.foreign_address})</span><span class="compliance-tag HIGH">${m.severity}</span></div><div class="compliance-desc">MITRE: ${m.mitre_technique} — ${m.mitre_name} | ${m.protocol}</div>`;
        c.appendChild(div);
    });
}

function renderIntelIOCTable(matches) {
    const tbody = document.getElementById('suite-intel-ioc-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (!matches.length) { tbody.innerHTML = '<tr><td colspan="6" style="color:#8b949e;">No IOC matches.</td></tr>'; return; }
    matches.forEach(m => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td><code>${m.timestamp}</code></td><td><code style="color:#f85149;">${m.indicator}</code></td><td><code>${m.foreign_address}</code></td><td><strong style="color:#58a6ff;">${m.protocol}</strong></td><td><strong style="color:#f85149;">[${m.severity}]</strong></td><td><code>${m.mitre_technique}</code></td>`;
        tbody.appendChild(tr);
    });
}

function renderIntelKEVTable(kev) {
    const tbody = document.getElementById('suite-intel-kev-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (!kev.length) { tbody.innerHTML = '<tr><td colspan="4" style="color:#8b949e;">CISA KEV feed not available.</td></tr>'; return; }
    kev.forEach(v => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td><code style="color:#d29922;">${v.cveID||'—'}</code></td><td>${v.vendorProject||'—'}/${v.product||'—'}</td><td>${v.vulnerabilityName||'—'}</td><td><code>${v.dueDate||'—'}</code></td>`;
        tbody.appendChild(tr);
    });
}

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-tab="intel-overview"],[data-tab="intel-ioc"],[data-tab="intel-kev"]').forEach(btn => {
        btn.addEventListener('click', () => setTimeout(loadIntelData, 100));
    });
    document.getElementById('btn-suite-intel-json')?.addEventListener('click', async () => {
        const res = await fetch('/api/intel/summary'); downloadFile(JSON.stringify(await res.json(), null, 2), 'LurkIntel_IOC_Report.json', 'application/json');
    });
});

async function loadIdentityData() {
    try {
        const res = await fetch('/api/identity/summary?t=' + Date.now());
        if (!res.ok) return;
        const d = await res.json();
        document.getElementById('suite-id-total').innerText = d.total_findings || 0;
        document.getElementById('suite-id-high').innerText = d.high_severity || 0;
        document.getElementById('suite-id-med').innerText = d.medium_severity || 0;
        document.getElementById('suite-id-policy').innerText = `${d.policy_pass || 0}/${(d.policy_audits || []).length}`;
        renderIdentityFindings(d.findings || []);
        renderIdentityPolicy(d.policy_audits || []);
    } catch(e) { console.warn('Identity API error:', e); }
}

function renderIdentityFindings(findings) {
    const c = document.getElementById('suite-id-findings-container');
    if (!c) return;
    c.innerHTML = '';
    if (!findings.length) {
        c.innerHTML = '<div class="compliance-card LOW"><div class="compliance-header"><span class="compliance-title">No Secret Findings</span><span class="compliance-tag">CLEAN</span></div><div class="compliance-desc">No API keys, credentials, or private keys detected in scanned directories.</div></div>';
        return;
    }
    findings.forEach(f => {
        const div = document.createElement('div');
        div.className = `compliance-card ${f.severity}`;
        div.innerHTML = `<div class="compliance-header"><span class="compliance-title">${f.finding_id} — ${f.secret_type}</span><span class="compliance-tag ${f.severity}">${f.severity}</span></div><div class="compliance-desc">File: <code style="color:#58a6ff;">${f.file_path}</code><br>${f.evidence}</div>`;
        c.appendChild(div);
    });
}

function renderIdentityPolicy(audits) {
    const c = document.getElementById('suite-id-policy-container');
    if (!c) return;
    c.innerHTML = '';
    audits.forEach(a => {
        const severity = a.status === 'FAIL' ? 'HIGH' : a.status === 'WARN' ? 'MEDIUM' : 'LOW';
        const div = document.createElement('div');
        div.className = `compliance-card ${severity}`;
        div.innerHTML = `<div class="compliance-header"><span class="compliance-title">${a.audit_id} — ${a.component}</span><span class="compliance-tag ${severity}">${a.status}</span></div><div class="compliance-desc">Current: <strong>${a.value}</strong> | ${a.recommendation}</div>`;
        c.appendChild(div);
    });
}

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-tab="identity-findings"],[data-tab="identity-policy"],[data-tab="identity-hibp"]').forEach(btn => {
        btn.addEventListener('click', () => setTimeout(loadIdentityData, 100));
    });
    document.getElementById('btn-suite-hibp-check')?.addEventListener('click', async () => {
        const pw = document.getElementById('suite-hibp-pw').value;
        if (!pw) { alert('Enter a password.'); return; }
        document.getElementById('suite-hibp-result').innerText = '[+] Querying HIBP...';
        const res = await fetch(`/api/identity/hibp?pw=${encodeURIComponent(pw)}`);
        const result = await res.json();
        document.getElementById('suite-hibp-result').innerText = JSON.stringify(result, null, 2);
        document.getElementById('suite-hibp-result').style.color = result.found_in_breach ? '#f85149' : '#3fb950';
    });
    document.getElementById('btn-suite-id-json')?.addEventListener('click', async () => {
        const res = await fetch('/api/identity/summary'); downloadFile(JSON.stringify(await res.json(), null, 2), 'LurkIdentity_Findings.json', 'application/json');
    });
    document.getElementById('btn-suite-id-csv')?.addEventListener('click', async () => {
        const res = await fetch('/api/identity/summary'); const d = await res.json();
        let csv = "Timestamp,FindingID,SecretType,Severity,FilePath\n";
        (d.findings || []).forEach(f => { csv += `"${f.timestamp}","${f.finding_id}","${f.secret_type}","${f.severity}","${f.file_path}"\n`; });
        downloadFile(csv, 'LurkIdentity_Findings.csv', 'text/csv');
    });
});

async function loadCloudData() {
    try {
        const res = await fetch('/api/cloud/summary?t=' + Date.now());
        if (!res.ok) return;
        const d = await res.json();
        const awsEl = document.getElementById('suite-cloud-aws');
        if (awsEl) { awsEl.innerText = d.aws_available ? 'ACTIVE' : 'N/A'; awsEl.style.color = d.aws_available ? '#3fb950' : '#f85149'; }
        const azureEl = document.getElementById('suite-cloud-azure');
        if (azureEl) { azureEl.innerText = d.azure_available ? 'ACTIVE' : 'N/A'; azureEl.style.color = d.azure_available ? '#3fb950' : '#f85149'; }
        const totEl = document.getElementById('suite-cloud-total');
        if (totEl) totEl.innerText = d.total_findings || 0;
        const highEl = document.getElementById('suite-cloud-high');
        if (highEl) highEl.innerText = d.high_severity || 0;
        renderCloudFindings(d.all_findings || [], d.aws_available, d.azure_available);
        renderCloudBaseline(d.baseline || []);
    } catch(e) { console.warn('Cloud API error:', e); }
}


function renderCloudFindings(findings, awsOk, azureOk) {
    const c = document.getElementById('suite-cloud-findings-container');
    if (!c) return;
    c.innerHTML = '';
    if (!findings.length) {
        const msg = (!awsOk && !azureOk) ? 'AWS/Azure CLI not configured. Install CLI and authenticate to begin cloud auditing.' : 'No cloud security violations found. Infrastructure appears compliant.';
        c.innerHTML = `<div class="compliance-card LOW"><div class="compliance-header"><span class="compliance-title">${(!awsOk && !azureOk) ? 'CLI Not Configured' : 'No Findings'}</span><span class="compliance-tag">${(!awsOk && !azureOk) ? 'WARN' : 'PASS'}</span></div><div class="compliance-desc">${msg}</div></div>`;
        return;
    }
    findings.forEach(f => {
        const div = document.createElement('div');
        div.className = `compliance-card ${f.severity}`;
        div.innerHTML = `<div class="compliance-header"><span class="compliance-title">${f.resource_type} — ${f.resource_id}</span><span class="compliance-tag ${f.severity}">${f.status} | ${f.severity}</span></div><div class="compliance-desc">${f.finding}<br><em style="color:#58a6ff;">Recommendation: ${f.recommendation}</em></div>`;
        c.appendChild(div);
    });
}

function renderCloudBaseline(baseline) {
    const c = document.getElementById('suite-cloud-baseline-container');
    if (!c) return;
    c.innerHTML = '';
    baseline.forEach(b => {
        const severity = b.status === 'FAIL' ? 'HIGH' : b.status === 'WARN' ? 'MEDIUM' : 'LOW';
        const div = document.createElement('div');
        div.className = `compliance-card ${severity}`;
        div.innerHTML = `<div class="compliance-header"><span class="compliance-title">${b.audit_id} — ${b.component}</span><span class="compliance-tag ${severity}">${b.status}</span></div><div class="compliance-desc">Status: <strong>${b.value}</strong> | ${b.recommendation}</div>`;
        c.appendChild(div);
    });
}

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-tab="cloud-overview"],[data-tab="cloud-baseline"]').forEach(btn => {
        btn.addEventListener('click', () => setTimeout(loadCloudData, 100));
    });
    document.getElementById('btn-suite-cloud-json')?.addEventListener('click', async () => {
        const res = await fetch('/api/cloud/summary'); downloadFile(JSON.stringify(await res.json(), null, 2), 'LurkCloud_Report.json', 'application/json');
    });
    document.getElementById('btn-suite-cloud-csv')?.addEventListener('click', async () => {
        const res = await fetch('/api/cloud/summary'); const d = await res.json();
        let csv = "Timestamp,ResourceType,ResourceID,Severity,Status,Finding\n";
        (d.all_findings || []).forEach(f => { csv += `"${f.timestamp}","${f.resource_type}","${f.resource_id}","${f.severity}","${f.status}","${f.finding}"\n`; });
        downloadFile(csv, 'LurkCloud_Report.csv', 'text/csv');
    });

    // LurkSOAR & LurkHunt Loaders & Click Listeners
    document.querySelectorAll('[data-tab="soar-playbooks"]').forEach(btn => {
        btn.addEventListener('click', () => setTimeout(loadSOARSuiteData, 100));
    });
    document.querySelectorAll('[data-tab="hunt-sigma"]').forEach(btn => {
        btn.addEventListener('click', () => setTimeout(loadHuntSuiteData, 100));
    });

    document.getElementById('btn-suite-hunt-scan')?.addEventListener('click', async () => {
        const input = document.getElementById('suite-hunt-input');
        const output = document.getElementById('suite-hunt-output');
        if (!input || !input.value) {
            alert("Please enter a command line, PID, or payload string to scan.");
            return;
        }

        output.innerText = `[+] Scanning string against SIGMA rules & YARA signatures...`;
        try {
            const res = await fetch(`/api/hunt/scan?sample=${encodeURIComponent(input.value)}`);
            const result = await res.json();
            output.innerText = `[+] SCAN RESULT: Matches Found: ${result.matches_count}\n` + JSON.stringify(result, null, 2);
            await loadHuntSuiteData();
        } catch(e) {
            output.innerText = `[-] Scan Execution Error: ${e.message}`;
        }
    });
});

async function loadSOARSuiteData() {
    try {
        const res = await fetch('/api/soar/summary');
        const d = await res.json();
        document.getElementById('suite-soar-playbooks-count').innerText = d.playbooks_count || 4;
        document.getElementById('suite-soar-cases-count').innerText = d.cases_count || 2;
        document.getElementById('suite-soar-open-count').innerText = d.open_cases || 2;
        document.getElementById('suite-soar-exec-count').innerText = (d.history || []).length;
        renderSOARPlaybooks(d.playbooks || []);
        renderSOARCases(d.cases || []);
    } catch(e) { console.warn('SOAR API error:', e); }
}

function renderSOARPlaybooks(playbooks) {
    const c = document.getElementById('suite-soar-playbooks-container');
    if (!c) return;
    c.innerHTML = playbooks.map(p => `
        <div class="compliance-card ${p.severity_threshold}">
            <div class="compliance-header">
                <span class="compliance-title"><strong>[${p.id}]</strong> ${p.name}</span>
                <span class="compliance-tag ${p.severity_threshold}">${p.severity_threshold}</span>
            </div>
            <div class="compliance-desc">Trigger: <code>${p.trigger_event}</code></div>
        </div>
    `).join("");
}

function renderSOARCases(cases) {
    const c = document.getElementById('suite-soar-cases-container');
    if (!c) return;
    c.innerHTML = cases.map(cs => `
        <div class="compliance-card ${cs.severity}">
            <div class="compliance-header">
                <span class="compliance-title"><strong>[${cs.case_id}]</strong> ${cs.title}</span>
                <span class="compliance-tag ${cs.severity}">${cs.status} | ${cs.severity}</span>
            </div>
            <div class="compliance-desc">${cs.description}<br><em style="color:#58a6ff;">Assigned to: ${cs.assigned_to}</em></div>
        </div>
    `).join("");
}

async function loadHuntSuiteData() {
    try {
        const res = await fetch('/api/hunt/summary');
        const d = await res.json();
        document.getElementById('suite-hunt-sigma-count').innerText = d.sigma_rules_count || 8;
        document.getElementById('suite-hunt-yara-count').innerText = d.yara_sigs_count || 5;
        document.getElementById('suite-hunt-hits-count').innerText = (d.recent_hits || []).length;
        renderHuntHits(d.recent_hits || []);
        renderSigmaRules(d.sigma_rules || []);
        renderYaraSignatures(d.yara_signatures || []);
    } catch(e) { console.warn('Hunt API error:', e); }
}

function renderHuntHits(hits) {
    const c = document.getElementById('suite-hunt-hits-container');
    if (!c) return;
    if (hits.length === 0) {
        c.innerHTML = `<div class="compliance-card PASS"><div class="compliance-header"><span class="compliance-title"><strong>[NO_THREATS_DETECTED]</strong> Zero threat hits recorded</span><span class="compliance-tag PASS">CLEAN</span></div><div class="compliance-desc">Run an interactive payload scan above to trigger SIGMA/YARA detection hits.</div></div>`;
        return;
    }
    c.innerHTML = hits.map(h => `
        <div class="compliance-card ${h.severity === 'CRITICAL' || h.severity === 'HIGH' ? 'HIGH' : 'MEDIUM'}">
            <div class="compliance-header">
                <span class="compliance-title"><strong>[${h.rule_id || h.sig_id}]</strong> ${h.title || h.sig_name}</span>
                <span class="compliance-tag ${h.severity}">${h.severity}</span>
            </div>
            <div class="compliance-desc">Category: <code>${h.category || h.type || 'Detection'}</code> | Source: <code>${h.source || 'System Scan'}</code><br>Matched Payload: <code>${h.matched_sample || h.matched_pattern || ''}</code></div>
        </div>
    `).join("");
}

function renderSigmaRules(rules) {
    const c = document.getElementById('suite-hunt-sigma-container');
    if (!c) return;
    c.innerHTML = rules.map(r => `
        <div class="compliance-card ${r.severity}" style="margin-bottom:8px;">
            <div class="compliance-header">
                <span class="compliance-title"><strong>[${r.id}]</strong> ${r.title}</span>
                <span class="compliance-tag ${r.severity}">${r.severity}</span>
            </div>
            <div class="compliance-desc">${r.description}<br><code style="color:#58a6ff;">MITRE: ${r.mitre_id}</code> | Pattern: <code>${r.pattern}</code></div>
        </div>
    `).join("");
}

function renderYaraSignatures(sigs) {
    const c = document.getElementById('suite-hunt-yara-container');
    if (!c) return;
    c.innerHTML = sigs.map(s => `
        <div class="compliance-card ${s.severity === 'CRITICAL' ? 'HIGH' : s.severity}" style="margin-bottom:8px;">
            <div class="compliance-header">
                <span class="compliance-title"><strong>[${s.id}]</strong> ${s.name}</span>
                <span class="compliance-tag ${s.severity}">${s.severity}</span>
            </div>
            <div class="compliance-desc">${s.description}<br><code style="color:#3fb950;">Type: ${s.type}</code> | Pattern: <code>${s.pattern}</code></div>
        </div>
    `).join("");
}

// Master Incident Containment Console
document.addEventListener('DOMContentLoaded', () => {

    // Master Incident Containment Console Executor
    document.getElementById('btn-soc-execute-action')?.addEventListener('click', async () => {
        const action = document.getElementById('soc-action-type').value;
        const target = document.getElementById('soc-action-target').value;
        const resLabel = document.getElementById('soc-action-result');
        if (!target) {
            if (resLabel) resLabel.innerText = 'Please specify a target IP, PID, or Filepath.';
            return;
        }

        if (resLabel) resLabel.innerText = `Executing ${action} on target '${target}'...`;
        let url = '';
        if (action === 'block_ip') url = `/api/edr/block?ip=${encodeURIComponent(target)}`;
        else if (action === 'kill_pid') url = `/api/edr/kill?pid=${encodeURIComponent(target)}`;
        else url = `/api/edr/quarantine?path=${encodeURIComponent(target)}`;

        try {
            const res = await fetch(url);
            const data = await res.json();
            if (resLabel) resLabel.innerText = `Result: ${data.message || (data.success ? 'Action executed successfully.' : 'Action failed.')}`;
            loadMasterData();
        } catch(err) {
            if (resLabel) resLabel.innerText = `Execution error: ${err.message}`;
        }
    });

    document.querySelectorAll('[data-tab="dns-sinkhole"]').forEach(btn => btn.addEventListener('click', () => setTimeout(loadDNSSuiteData, 100)));
    document.querySelectorAll('[data-tab="zero-trust"]').forEach(btn => btn.addEventListener('click', () => setTimeout(loadZeroSuiteData, 100)));
    document.querySelectorAll('[data-tab="vuln-audit"]').forEach(btn => btn.addEventListener('click', () => setTimeout(loadVulnSuiteData, 100)));
    document.querySelectorAll('[data-tab="sand-box"]').forEach(btn => btn.addEventListener('click', () => setTimeout(loadSandSuiteData, 100)));
    document.querySelectorAll('[data-tab="guard-itdr"]').forEach(btn => btn.addEventListener('click', () => setTimeout(loadGuardSuiteData, 100)));

    // Interactive Malware Sandbox Inspector
    document.getElementById('btn-suite-sand-analyze')?.addEventListener('click', async () => {
        const nameInput = document.getElementById('suite-sand-name-input');
        const name = nameInput ? nameInput.value.trim() : '';
        const out = document.getElementById('suite-sand-output');
        if (!name) {
            alert("Please enter an executable file path on disk (e.g., C:\\Windows\\System32\\cmd.exe)");
            return;
        }
        if (out) out.innerText = `[+] Analyzing binary file '${name}' in LurkSand PE Sandbox...`;

        try {
            const res = await fetch(`/api/sand/analyze?name=${encodeURIComponent(name)}`);
            const d = await res.json();
            if (out) {
                out.innerText = `[+] LurkSand PE Malware Analysis Complete:\n` +
                    `  Sample File: ${d.sample_name}\n` +
                    `  File Found on Disk: ${d.file_exists ? 'YES' : 'NO'}\n` +
                    `  Verdict: ${d.verdict} (Threat Score: ${d.threat_score}/100 | Entropy: ${d.entropy})\n` +
                    `  Packed/Compressed: ${d.is_packed ? 'YES (High Entropy Packer Detected)' : 'NO'}\n` +
                    `  Valid PE Header: ${d.is_pe ? 'YES (MZ Signature Present)' : 'NO'}\n` +
                    `  Suspicious APIs Found: ${d.suspicious_imports_found.join(', ') || 'None'}\n` +
                    `  Highlights: ${d.behavioral_highlights.join(' ')}`;
            }
            loadSandSuiteData();
        } catch(err) {
            if (out) out.innerText = `[-] Sandbox analysis error: ${err.message}`;
        }
    });

    // Interactive DNS Threat Sinkhole Inspector
    document.getElementById('btn-suite-dns-query')?.addEventListener('click', async () => {
        const domain = document.getElementById('suite-dns-input').value.trim();
        const out = document.getElementById('suite-dns-output');
        if (!domain) {
            alert("Please enter a domain name to query.");
            return;
        }
        if (out) out.innerText = `[+] Querying LurkDNS Sinkhole for '${domain}'...`;

        try {
            const res = await fetch(`/api/dns/query?domain=${encodeURIComponent(domain)}`);
            const d = await res.json();
            if (out) {
                out.innerText = `[+] LurkDNS Query Inspection Result:\n` +
                    `  Domain: ${d.domain}\n` +
                    `  Status: ${d.status} -> Resolved IP: ${d.response_ip}\n` +
                    `  Category: ${d.category}\n` +
                    `  Message: ${d.message}`;
            }
            loadDNSSuiteData();
        } catch(err) {
            if (out) out.innerText = `[-] DNS query error: ${err.message}`;
        }
    });

    // Interactive Zero Trust Access Evaluator
    document.getElementById('btn-suite-zero-eval')?.addEventListener('click', async () => {
        const user = document.getElementById('suite-zero-user').value || 'user@lurksec.io';
        const dev = document.getElementById('suite-zero-device').value || 'DEV-001';
        const resource = document.getElementById('suite-zero-resource').value || '/api/vault';
        const mtls = document.getElementById('suite-zero-mtls').value;
        const out = document.getElementById('suite-zero-output');
        if (out) out.innerText = `[+] Evaluating Zero Trust Access for ${user}...`;

        try {
            const res = await fetch(`/api/zero/verify?user=${encodeURIComponent(user)}&device=${encodeURIComponent(dev)}&resource=${encodeURIComponent(resource)}&mtls=${mtls}`);
            const d = await res.json();
            if (out) {
                out.innerText = `[+] LurkZero ZTNA Decision:\n` +
                    `  Access: ${d.access_granted ? 'GRANTED' : 'DENIED'} (${d.severity})\n` +
                    `  mTLS Status: ${d.mtls_status} | Posture Score: ${d.posture_score}/100\n` +
                    `  User: ${d.user} | Resource: ${d.resource}\n` +
                    `  Message: ${d.message}`;
            }
            loadZeroSuiteData();
        } catch(err) {
            if (out) out.innerText = `[-] ZTNA verification error: ${err.message}`;
        }
    });
});

async function loadDNSSuiteData() {
    try {
        const res = await fetch('/api/dns/summary'); const d = await res.json();
        document.getElementById('suite-dns-total').innerText = d.total_queries || 0;
        document.getElementById('suite-dns-sinkholed').innerText = d.sinkholed_queries || 0;
        document.getElementById('suite-dns-bad-count').innerText = d.blocked_domains_count || 8;
        const c = document.getElementById('suite-dns-query-container');
        if (c) {
            c.innerHTML = (d.recent_queries || []).map(q => `
                <div class="compliance-card ${q.status === 'SINKHOLED' ? 'HIGH' : 'PASS'}">
                    <div class="compliance-header">
                        <span class="compliance-title"><strong>[${q.status}]</strong> ${q.domain} (${q.query_type})</span>
                        <span class="compliance-tag ${q.status === 'SINKHOLED' ? 'HIGH' : 'PASS'}">${q.status}</span>
                    </div>
                    <div class="compliance-desc">Client: <code>${q.client_ip}</code> | Response IP: <code>${q.response_ip}</code> | Category: ${q.category}</div>
                </div>
            `).join("");
        }
    } catch(e) {}
}

async function loadZeroSuiteData() {
    try {
        const res = await fetch('/api/zero/summary'); const d = await res.json();
        document.getElementById('suite-zero-total').innerText = d.total_evaluations || 0;
        document.getElementById('suite-zero-granted').innerText = d.access_granted_count || 0;
        document.getElementById('suite-zero-denied').innerText = d.access_denied_count || 0;
        const c = document.getElementById('suite-zero-logs-container');
        if (c) {
            c.innerHTML = (d.recent_evaluations || []).map(z => `
                <div class="compliance-card ${z.access_granted ? 'PASS' : 'HIGH'}">
                    <div class="compliance-header">
                        <span class="compliance-title"><strong>[${z.access_granted ? 'GRANTED' : 'DENIED'}]</strong> ${z.user} on ${z.resource}</span>
                        <span class="compliance-tag ${z.access_granted ? 'PASS' : 'HIGH'}">${z.mtls_status}</span>
                    </div>
                    <div class="compliance-desc">Device ID: <code>${z.device_id}</code> | Posture Score: <strong>${z.posture_score}</strong> | Time: ${z.timestamp}</div>
                </div>
            `).join("");
        }
    } catch(e) {}
}

async function loadVulnSuiteData() {
    try {
        const res = await fetch('/api/vuln/summary'); const d = await res.json();
        document.getElementById('suite-vuln-score').innerText = `${d.patch_compliance_score}%`;
        document.getElementById('suite-vuln-unpatched').innerText = d.unpatched_count || 0;
        document.getElementById('suite-vuln-critical').innerText = d.critical_count || 0;
        const c = document.getElementById('suite-vuln-findings-container');
        if (c) {
            c.innerHTML = (d.findings || []).map(v => `
                <div class="compliance-card ${v.status === 'UNPATCHED' ? v.severity : 'PASS'}">
                    <div class="compliance-header">
                        <span class="compliance-title"><strong>[${v.cve}]</strong> ${v.title}</span>
                        <span class="compliance-tag ${v.status === 'UNPATCHED' ? v.severity : 'PASS'}">${v.status} | CVSS ${v.cvss}</span>
                    </div>
                    <div class="compliance-desc">${v.description}<br><code style="color:#58a6ff;">Component: ${v.component}</code> | Required Security Update: <code style="color:#f85149;">${v.kb_needed}</code></div>
                </div>
            `).join("");
        }
    } catch(e) {}
}

async function loadSandSuiteData() {
    try {
        const res = await fetch('/api/sand/summary'); const d = await res.json();
        document.getElementById('suite-sand-total').innerText = d.total_analyzed || 0;
        document.getElementById('suite-sand-malicious').innerText = d.malicious_count || 0;
        const c = document.getElementById('suite-sand-results-container');
        if (c) {
            c.innerHTML = (d.recent_analyses || []).map(s => `
                <div class="compliance-card ${s.verdict === 'MALICIOUS' ? 'HIGH' : (s.verdict === 'SUSPICIOUS' ? 'MEDIUM' : 'PASS')}">
                    <div class="compliance-header">
                        <span class="compliance-title"><strong>[${s.verdict}]</strong> ${s.sample_name}</span>
                        <span class="compliance-tag ${s.verdict === 'MALICIOUS' ? 'HIGH' : 'PASS'}">Score: ${s.threat_score}/100</span>
                    </div>
                    <div class="compliance-desc">Entropy: <code>${s.entropy}</code> | Packed: <code>${s.is_packed}</code><br>Suspicious Imports: <code>${(s.suspicious_imports_found || []).join(", ") || 'None'}</code></div>
                </div>
            `).join("");
        }
    } catch(e) {}
}

async function loadGuardSuiteData() {
    try {
        const res = await fetch('/api/guard/summary'); const d = await res.json();
        document.getElementById('suite-guard-score').innerText = `${d.identity_health_score}%`;
        document.getElementById('suite-guard-threats').innerText = d.total_threats_found || 0;
        const c = document.getElementById('suite-guard-findings-container');
        if (c) {
            c.innerHTML = (d.findings || []).map(g => `
                <div class="compliance-card ${g.severity}">
                    <div class="compliance-header">
                        <span class="compliance-title"><strong>[${g.id}]</strong> ${g.name}</span>
                        <span class="compliance-tag ${g.severity}">${g.severity}</span>
                    </div>
                    <div class="compliance-desc">Target Account: <code style="color:#58a6ff;">${g.account}</code> | SPN: <code>${g.spn}</code><br>Recommendation: ${g.recommendation}</div>
                </div>
            `).join("");
        }
    } catch(e) {}
}

const SEVERITY_COLOR = { CRITICAL: '#f85149', HIGH: '#f0883e', MEDIUM: '#d29922', LOW: '#3fb950', INFO: '#58a6ff' };
const STATUS_COLOR   = { OPEN: '#f85149', IN_PROGRESS: '#d29922', RESOLVED: '#3fb950', CLOSED: '#8b949e' };

async function loadSOARData() {
    try {
        const res = await fetch('/api/soar/summary');
        if (!res.ok) return;
        const d = await res.json();
        renderSOARPlaybooks(d.playbooks || []);
        renderSOARCases(d.cases || []);
        renderSOARHistory(d.history || []);

        const ec = d.history ? d.history.length : 0;
        const cc = d.cases ? d.cases.length : 0;
        const oc = d.cases ? d.cases.filter(c => ['OPEN','IN_PROGRESS'].includes(c.status)).length : 0;
        el('suite-soar-playbooks-count', d.playbooks ? d.playbooks.length : 4);
        el('suite-soar-cases-count', cc);
        el('suite-soar-open-count', oc);
        el('suite-soar-exec-count', ec);
    } catch(e) { console.warn('SOAR load error:', e); }
}

function el(id, val) {
    const e = document.getElementById(id);
    if (e) e.innerText = val;
}

function renderSOARPlaybooks(playbooks) {
    const c = document.getElementById('suite-soar-playbooks-container');
    if (!c) return;
    if (!playbooks.length) {
        c.innerHTML = '<div class="compliance-card"><div class="compliance-desc">No playbooks loaded.</div></div>';
        return;
    }
    c.innerHTML = playbooks.map(pb => {
        const sevColor = SEVERITY_COLOR[pb.severity_threshold] || '#58a6ff';
        const steps = (pb.actions || []).map(a =>
            `<div style="display:flex;align-items:flex-start;gap:8px;padding:4px 0;border-bottom:1px solid #21262d;">
                <span style="font-family:var(--font-mono);font-size:11px;color:#58a6ff;min-width:20px;">${a.step}.</span>
                <span style="font-family:var(--font-mono);font-size:11px;color:#d29922;min-width:120px;">[${a.type}]</span>
                <span style="font-size:12px;color:#8b949e;">${a.description}</span>
            </div>`
        ).join('');
        return `
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;display:flex;flex-direction:column;gap:10px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <div>
                    <span style="font-family:var(--font-mono);font-size:11px;color:#58a6ff;">${pb.id}</span>
                    <div style="font-weight:600;font-size:14px;color:#e6edf3;margin-top:2px;">${pb.name}</div>
                    <div style="font-size:11px;color:#8b949e;margin-top:2px;">Trigger: ${pb.trigger_event}</div>
                </div>
                <span style="font-family:var(--font-mono);font-size:10px;font-weight:700;color:${sevColor};border:1px solid ${sevColor};border-radius:4px;padding:2px 8px;">${pb.severity_threshold}</span>
            </div>
            <div style="border-top:1px solid #21262d;padding-top:8px;">${steps}</div>
            <div style="display:flex;gap:8px;align-items:center;margin-top:4px;">
                <input type="text" placeholder="Target IP (optional)" id="pb-ip-${pb.id}"
                    style="flex:1;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e6edf3;font-family:var(--font-mono);font-size:12px;padding:6px 10px;">
                <button onclick="executePlaybook('${pb.id}')" class="btn btn-primary" style="padding:6px 16px;font-size:12px;">▶ Execute</button>
            </div>
            <pre id="pb-result-${pb.id}" style="display:none;margin:0;font-size:11px;padding:8px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#3fb950;white-space:pre-wrap;word-break:break-all;"></pre>
        </div>`;
    }).join('');
}

async function executePlaybook(pbId) {
    const ipEl = document.getElementById(`pb-ip-${pbId}`);
    const resEl = document.getElementById(`pb-result-${pbId}`);
    const ip = ipEl ? ipEl.value.trim() : '';
    if (resEl) { resEl.style.display='block'; resEl.style.color='#d29922'; resEl.textContent = `Executing ${pbId}...`; }
    try {
        const res = await fetch('/api/soar/run', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ id: pbId, ip })
        });
        const d = await res.json();
        if (resEl) {
            resEl.style.color = d.status === 'SUCCESS' ? '#3fb950' : '#f85149';
            resEl.textContent = `[${d.status}] Execution ID: ${d.execution_id}\n` +
                (d.steps || []).map(s => `  Step ${s.step} [${s.type}]: ${s.details}`).join('\n');
        }
        loadSOARData(); // refresh counts
    } catch(e) {
        if (resEl) { resEl.style.color='#f85149'; resEl.textContent = `Error: ${e.message}`; }
    }
}

function renderSOARCases(cases) {
    const c = document.getElementById('suite-soar-cases-container');
    if (!c) return;
    if (!cases.length) {
        c.innerHTML = '<div style="color:#8b949e;font-size:13px;padding:8px;">No incident cases. Create one below or let the engine auto-generate them.</div>';
        return;
    }
    c.innerHTML = cases.map(cas => {
        const sc = SEVERITY_COLOR[cas.severity] || '#58a6ff';
        const stc = STATUS_COLOR[cas.status] || '#58a6ff';
        const timeline = (cas.timeline || []).map(t =>
            `<div style="font-size:11px;color:#8b949e;padding:2px 0;"><span style="color:#58a6ff;font-family:var(--font-mono);">[${t.time}]</span> ${t.event}</div>`
        ).join('');
        return `
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;">
                <div style="flex:1;">
                    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
                        <span style="font-family:var(--font-mono);font-size:11px;color:#58a6ff;">${cas.case_id}</span>
                        <span style="font-family:var(--font-mono);font-size:10px;font-weight:700;color:${sc};border:1px solid ${sc};border-radius:4px;padding:1px 6px;">${cas.severity}</span>
                        <span style="font-family:var(--font-mono);font-size:10px;font-weight:700;color:${stc};border:1px solid ${stc};border-radius:4px;padding:1px 6px;">${cas.status}</span>
                    </div>
                    <div style="font-weight:600;font-size:14px;color:#e6edf3;margin-top:4px;">${cas.title}</div>
                    <div style="font-size:12px;color:#8b949e;margin-top:2px;">${cas.description || ''}</div>
                    <div style="font-size:11px;color:#8b949e;margin-top:4px;">Assigned: <span style="color:#e6edf3;">${cas.assigned_to}</span> | Created: ${cas.created_at}</div>
                </div>
                <div style="display:flex;flex-direction:column;gap:6px;min-width:170px;">
                    <select id="case-status-${cas.case_id}" class="filter-input" style="font-size:11px;padding:4px 8px;">
                        ${['OPEN','IN_PROGRESS','RESOLVED','CLOSED'].map(s =>
                            `<option value="${s}" ${cas.status===s?'selected':''}>${s}</option>`).join('')}
                    </select>
                    <button onclick="updateCaseStatus('${cas.case_id}')" class="btn btn-secondary" style="font-size:11px;padding:4px 10px;">Update Status</button>
                    <input type="text" id="case-note-${cas.case_id}" class="filter-input" placeholder="Add analyst note..." style="font-size:11px;padding:4px 8px;">
                    <button onclick="addCaseNote('${cas.case_id}')" class="btn btn-outline" style="font-size:11px;padding:4px 10px;">+ Add Note</button>
                </div>
            </div>
            <details style="margin-top:10px;">
                <summary style="cursor:pointer;font-size:12px;color:#58a6ff;font-family:var(--font-mono);">Timeline (${(cas.timeline||[]).length} events)</summary>
                <div style="margin-top:8px;border-left:2px solid #21262d;padding-left:10px;">${timeline}</div>
            </details>
            <pre id="case-result-${cas.case_id}" style="display:none;margin-top:8px;font-size:11px;padding:8px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#3fb950;white-space:pre-wrap;"></pre>
        </div>`;
    }).join('');
}

async function updateCaseStatus(caseId) {
    const sel = document.getElementById(`case-status-${caseId}`);
    const res = document.getElementById(`case-result-${caseId}`);
    const status = sel ? sel.value : 'OPEN';
    if (res) { res.style.display='block'; res.style.color='#d29922'; res.textContent = `Updating ${caseId} → ${status}...`; }
    try {
        const r = await fetch('/api/soar/case/update', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ id: caseId, status })
        });
        const d = await r.json();
        if (res) { res.style.color = d.success ? '#3fb950' : '#f85149'; res.textContent = d.success ? `✓ Status updated to ${status}` : d.message; }
        setTimeout(loadSOARData, 400);
    } catch(e) { if (res) { res.style.color='#f85149'; res.textContent = `Error: ${e.message}`; } }
}

async function addCaseNote(caseId) {
    const inp = document.getElementById(`case-note-${caseId}`);
    const res = document.getElementById(`case-result-${caseId}`);
    const note = inp ? inp.value.trim() : '';
    if (!note) return;
    if (res) { res.style.display='block'; res.style.color='#d29922'; res.textContent = 'Adding note...'; }
    try {
        const r = await fetch('/api/soar/case/update', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ id: caseId, note })
        });
        const d = await r.json();
        if (res) { res.style.color = d.success ? '#3fb950' : '#f85149'; res.textContent = d.success ? `✓ Note added` : d.message; }
        if (inp) inp.value = '';
        setTimeout(loadSOARData, 400);
    } catch(e) { if (res) { res.style.color='#f85149'; res.textContent = `Error: ${e.message}`; } }
}

function renderSOARHistory(history) {
    const c = document.getElementById('suite-soar-history-container');
    if (!c) return;
    if (!history.length) {
        c.innerHTML = '<div style="color:#8b949e;font-size:13px;padding:8px;">No executions yet. Run a playbook above.</div>';
        return;
    }
    c.innerHTML = history.map(h => `
        <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:10px 14px;margin-bottom:8px;">
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:4px;">
                <span style="font-family:var(--font-mono);font-size:12px;color:#3fb950;">[${h.status}]</span>
                <span style="font-size:13px;color:#e6edf3;font-weight:600;">${h.playbook_name}</span>
                <span style="font-family:var(--font-mono);font-size:11px;color:#8b949e;">${h.timestamp}</span>
                <span style="font-family:var(--font-mono);font-size:10px;color:#58a6ff;">${h.execution_id}</span>
            </div>
            ${(h.steps||[]).map(s => `<div style="font-size:11px;color:#8b949e;padding:2px 0 0 12px;">Step ${s.step} [${s.type}]: ${s.details}</div>`).join('')}
        </div>
    `).join('');
}

// SOAR create-case form handler
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('btn-soar-create-case')?.addEventListener('click', async () => {
        const title    = document.getElementById('soar-new-title')?.value.trim();
        const severity = document.getElementById('soar-new-severity')?.value || 'MEDIUM';
        const desc     = document.getElementById('soar-new-desc')?.value.trim();
        const assigned = document.getElementById('soar-new-assigned')?.value.trim() || 'Unassigned';
        const resEl    = document.getElementById('soar-create-result');
        if (!title) { if (resEl) { resEl.style.display='block'; resEl.style.color='#f85149'; resEl.textContent='Title is required.'; } return; }
        if (resEl) { resEl.style.display='block'; resEl.style.color='#d29922'; resEl.textContent='Creating case...'; }
        try {
            const r = await fetch('/api/soar/case/create', {
                method: 'POST', headers: {'Content-Type':'application/json'},
                body: JSON.stringify({ title, severity, description: desc, assigned })
            });
            const d = await r.json();
            if (resEl) { resEl.style.color = d.success ? '#3fb950' : '#f85149'; resEl.textContent = d.success ? `✓ Case created: ${d.case_id}` : JSON.stringify(d); }
            if (d.success) {
                document.getElementById('soar-new-title').value = '';
                document.getElementById('soar-new-desc').value = '';
                document.getElementById('soar-new-assigned').value = '';
                setTimeout(loadSOARData, 400);
            }
        } catch(e) { if (resEl) { resEl.style.color='#f85149'; resEl.textContent=`Error: ${e.message}`; } }
    });

    document.getElementById('btn-soar-refresh')?.addEventListener('click', loadSOARData);
});

// Process Tree Graph with Vis.js & Text Fallback
let processNetwork = null;
async function renderProcessTreeGraph() {
    const container = document.getElementById('vis-process-tree');
    const textContainer = document.getElementById('tree-view-container');
    try {
        const res = await fetch('/api/trace/tree');
        if (!res.ok) return;
        const data = await res.json();

        if (textContainer && data.tree_text) {
            textContainer.textContent = data.tree_text;
        }

        if (container && window.vis) {
            const nodes = new vis.DataSet(data.nodes.map(n => ({
                id: n.id,
                label: n.label,
                title: n.title,
                color: n.group === 'suspicious' ? { background: '#f85149', border: '#da3633' } : { background: '#1f6feb', border: '#388bfd' },
                font: { color: '#ffffff', face: 'JetBrains Mono', size: 12 }
            })));
            const edges = new vis.DataSet(data.edges.map(e => ({ from: e.from, to: e.to, arrows: 'to', color: '#8b949e' })));
            const options = {
                physics: { solver: 'forceAtlas2Based', forceAtlas2Based: { gravitationalConstant: -30 } },
                interaction: { hover: true, tooltipDelay: 100 }
            };
            if (processNetwork) processNetwork.destroy();
            processNetwork = new vis.Network(container, { nodes, edges }, options);
        }
    } catch(e) { console.warn('Process Tree Graph error:', e); }
}


// EDR Policy Engine Handlers
async function loadEDRPolicies() {
    const c = document.getElementById('edr-policies-container');
    if (!c) return;
    try {
        const res = await fetch('/api/edr/policies');
        const d = await res.json();
        const policies = d.policies || [];
        if (!policies.length) {
            c.innerHTML = '<div style="color:#8b949e;font-size:12px;">No automated policies defined.</div>';
            return;
        }
        c.innerHTML = policies.map(p => `
            <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:10px 14px;display:flex;justify-content:space-between;align-items:center;">
                <div>
                    <span style="font-family:var(--font-mono);font-size:11px;color:#58a6ff;">[${p.id}]</span>
                    <strong style="color:#e6edf3;font-size:13px;margin-left:6px;">${p.name}</strong>
                    <span style="font-size:11px;color:#8b949e;margin-left:10px;">Proc: <code>${p.process_name || '*'}</code> | CMD: <code>${p.cmd_contains || '*'}</code> | Action: <span style="color:#f85149;">${p.action}</span></span>
                </div>
                <div style="display:flex;gap:6px;">
                    <button onclick="toggleEDRPolicy('${p.id}')" class="btn btn-outline" style="font-size:11px;padding:3px 8px;">${p.enabled ? 'Disable' : 'Enable'}</button>
                    <button onclick="deleteEDRPolicy('${p.id}')" class="btn btn-secondary" style="font-size:11px;padding:3px 8px;color:#f85149;">Delete</button>
                </div>
            </div>
        `).join('');
    } catch(e) {}
}

async function addEDRPolicy() {
    const name = document.getElementById('policy-new-name')?.value.trim();
    const proc = document.getElementById('policy-new-proc')?.value.trim();
    const cmd = document.getElementById('policy-new-cmd')?.value.trim();
    const action = document.getElementById('policy-new-action')?.value || 'KILL_PROCESS';

    if (!name) return alert('Policy name is required.');
    try {
        await fetch('/api/edr/policy/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ name, process_name: proc, cmd_contains: cmd, action })
        });
        document.getElementById('policy-new-name').value = '';
        document.getElementById('policy-new-proc').value = '';
        document.getElementById('policy-new-cmd').value = '';
        loadEDRPolicies();
    } catch(e) {}
}

async function toggleEDRPolicy(id) {
    try {
        await fetch('/api/edr/policy/toggle', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ id })
        });
        loadEDRPolicies();
    } catch(e) {}
}

async function deleteEDRPolicy(id) {
    try {
        await fetch('/api/edr/policy/delete', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ id })
        });
        loadEDRPolicies();
    } catch(e) {}
}

// Live Threat Feed Sync
async function syncThreatFeed() {
    const msg = document.getElementById('threat-feed-sync-msg');
    if (msg) msg.textContent = 'Fetching live IOC feed from ThreatFox API...';
    try {
        const res = await fetch('/api/intel/feed/sync');
        const text = await res.text();
        let d = {};
        try {
            d = JSON.parse(text);
        } catch(err) {
            if (msg) msg.textContent = 'Server response error. Please restart lurksec.py to activate Threat Feed endpoint.';
            return;
        }
        if (msg) msg.textContent = d.message || 'Threat feed sync completed.';
        if (document.getElementById('suite-intel-feed')) {
            document.getElementById('suite-intel-feed').innerText = d.count || 0;
        }
    } catch(e) {
        if (msg) msg.textContent = 'Sync error: ' + e.message;
    }
}

// Browser Terminal Execution
async function execTerminalCmd() {
    const input = document.getElementById('terminal-input');
    const output = document.getElementById('terminal-output');
    if (!input || !output) return;
    const cmd = input.value.trim();
    if (!cmd) return;

    output.textContent += `\n\nC:\\LurkSec> ${cmd}\nExecuting...`;
    output.scrollTop = output.scrollHeight;
    input.value = '';

    try {
        const res = await fetch('/api/terminal/exec', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ command: cmd })
        });
        const d = await res.json();
        output.textContent += `\n${d.output}`;
        output.scrollTop = output.scrollHeight;
    } catch(e) {
        output.textContent += `\nExecution error: ${e.message}`;
        output.scrollTop = output.scrollHeight;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('btn-add-policy')?.addEventListener('click', addEDRPolicy);
    document.getElementById('btn-refresh-tree')?.addEventListener('click', renderProcessTreeGraph);
    document.getElementById('btn-sync-threat-feed')?.addEventListener('click', syncThreatFeed);
    document.getElementById('btn-terminal-exec')?.addEventListener('click', execTerminalCmd);
    document.getElementById('terminal-input')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') execTerminalCmd();
    });

    document.querySelectorAll('[data-tab="trace-tree"]').forEach(btn => {
        btn.addEventListener('click', () => setTimeout(renderProcessTreeGraph, 150));
    });

    loadEDRPolicies();
    setTimeout(renderProcessTreeGraph, 800);
});


