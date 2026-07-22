// Master LurkSec Suite Unified Controller with EDR Controls

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
    autoRefreshActive: false,
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
        let actionBtnHTML = '';
        if (inc.action_type === 'BLOCK_IP' && inc.target_ip) {
            actionBtnHTML = `
                <div style="margin-top:8px;">
                    <button class="btn btn-outline btn-quick-block" data-ip="${inc.target_ip}" style="font-size:10px;color:#f85149;border-color:#f85149;display:inline-flex;align-items:center;gap:4px;">
                        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/></svg>
                        Execute EDR IP Block (${inc.target_ip})
                    </button>
                </div>
            `;
        }
        div.innerHTML = `
            <div class="compliance-header">
                <span class="compliance-title">${inc.engine} | ${inc.title} (${inc.incident_id})</span>
                <span class="compliance-tag ${inc.severity}">${inc.severity}</span>
            </div>
            <div class="compliance-desc">Category: ${inc.category} | Origin: ${inc.origin} | Time: ${inc.timestamp}</div>
            <div class="compliance-payload">${inc.evidence}</div>
            ${actionBtnHTML}
        `;
        container.appendChild(div);
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
    if (btnAutoRefresh) {
        btnAutoRefresh.addEventListener('click', () => {
            state.autoRefreshActive = !state.autoRefreshActive;
            if (state.autoRefreshActive) {
                btnAutoRefresh.innerText = `Auto-Refresh: ON (5s)`;
                btnAutoRefresh.style.borderColor = "#3fb950";
                btnAutoRefresh.style.color = "#3fb950";
                state.autoRefreshInterval = setInterval(() => loadMasterData(), 5000);
            } else {
                btnAutoRefresh.innerText = `Auto-Refresh: OFF`;
                btnAutoRefresh.style.borderColor = "";
                btnAutoRefresh.style.color = "";
                if (state.autoRefreshInterval) {
                    clearInterval(state.autoRefreshInterval);
                    state.autoRefreshInterval = null;
                }
            }
        });
    }

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

// ═══════════════════════════════════════════════════════════════════
// LURKSHIELD WAF ENGINE HANDLERS
// ═══════════════════════════════════════════════════════════════════
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

// ═══════════════════════════════════════════════════════════════════
// LURKINTEL CTI ENGINE HANDLERS
// ═══════════════════════════════════════════════════════════════════
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

// ═══════════════════════════════════════════════════════════════════
// LURKIDENTITY ENGINE HANDLERS
// ═══════════════════════════════════════════════════════════════════
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

// ═══════════════════════════════════════════════════════════════════
// LURKCLOUD ENGINE HANDLERS
// ═══════════════════════════════════════════════════════════════════
async function loadCloudData() {
    try {
        const res = await fetch('/api/cloud/summary?t=' + Date.now());
        if (!res.ok) return;
        const d = await res.json();
        const awsEl = document.getElementById('suite-cloud-aws');
        if (awsEl) { awsEl.innerText = d.aws_available ? 'ACTIVE' : 'N/A'; awsEl.style.color = d.aws_available ? '#3fb950' : '#f85149'; }
        const azureEl = document.getElementById('suite-cloud-azure');
        if (azureEl) { azureEl.innerText = d.azure_available ? 'ACTIVE' : 'N/A'; azureEl.style.color = d.azure_available ? '#3fb950' : '#f85149'; }
        document.getElementById('suite-cloud-total').innerText = d.total_findings || 0;
        document.getElementById('suite-cloud-high').innerText = d.high_severity || 0;
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

    document.getElementById('suite-hunt-sample-select')?.addEventListener('change', (e) => {
        const input = document.getElementById('suite-hunt-input');
        if (input && e.target.value) {
            input.value = e.target.value;
        }
    });

    document.getElementById('btn-suite-hunt-scan')?.addEventListener('click', async () => {
        const input = document.getElementById('suite-hunt-input');
        const output = document.getElementById('suite-hunt-output');
        if (!input || !input.value) {
            alert("Please enter or select a payload string to scan.");
            return;
        }

        output.innerText = `[+] Scanning payload string against 8 SIGMA rules & 5 YARA signatures...`;
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

// Telemetry Validation Simulator Handlers
document.addEventListener('DOMContentLoaded', () => {
    const txt = document.getElementById('sim-status-text');

    document.getElementById('btn-sim-ransomware')?.addEventListener('click', async () => {
        if (txt) txt.innerText = 'Injecting Ransomware VSS Deletion Event...';
        const res = await fetch('/api/simulate?type=ransomware');
        const data = await res.json();
        if (txt) txt.innerText = data.message;
        loadMasterData();
    });

    document.getElementById('btn-sim-waf')?.addEventListener('click', async () => {
        if (txt) txt.innerText = 'Injecting WAF SQLi Payload...';
        const res = await fetch('/api/simulate?type=waf_sqli');
        const data = await res.json();
        if (txt) txt.innerText = data.message;
        loadMasterData();
    });

    document.getElementById('btn-sim-decoy')?.addEventListener('click', async () => {
        if (txt) txt.innerText = 'Injecting Honeypot Probe Telemetry...';
        const res = await fetch('/api/simulate?type=honeypot');
        const data = await res.json();
        if (txt) txt.innerText = data.message;
        loadMasterData();
    });

    document.querySelectorAll('[data-tab="dns-sinkhole"]').forEach(btn => btn.addEventListener('click', () => setTimeout(loadDNSSuiteData, 100)));
    document.querySelectorAll('[data-tab="zero-trust"]').forEach(btn => btn.addEventListener('click', () => setTimeout(loadZeroSuiteData, 100)));
    document.querySelectorAll('[data-tab="vuln-audit"]').forEach(btn => btn.addEventListener('click', () => setTimeout(loadVulnSuiteData, 100)));
    document.querySelectorAll('[data-tab="sand-box"]').forEach(btn => btn.addEventListener('click', () => setTimeout(loadSandSuiteData, 100)));
    document.querySelectorAll('[data-tab="guard-itdr"]').forEach(btn => btn.addEventListener('click', () => setTimeout(loadGuardSuiteData, 100)));
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
