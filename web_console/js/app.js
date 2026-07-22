// Master LurkSec Suite Unified Controller with Per-Module Exports

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

    // 1. Parent Button Toggle (Dropdowns are OPEN by default)
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

    // 2. Sub-Item Page Selection
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

    const ctxSoc = socElem.getContext('2d');
    if (state.socChart) state.socChart.destroy();

    state.socChart = new Chart(ctxSoc, {
        type: 'bar',
        data: {
            labels: ['LurkSentinel', 'LurkSIEM', 'LurkDecoy', 'LurkPacket', 'LurkTrace', 'LurkAudit'],
            datasets: [{
                label: 'Correlated Threat Incidents',
                data: [sentinelCount, siemCount, decoyCount, packetCount, traceCount, auditCount],
                backgroundColor: ['#58a6ff', '#d29922', '#f85149', '#a371f7', '#3fb950', '#f0883e']
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
        div.innerHTML = `
            <div class="compliance-header">
                <span class="compliance-title">${inc.engine} | ${inc.title} (${inc.incident_id})</span>
                <span class="compliance-tag ${inc.severity}">${inc.severity}</span>
            </div>
            <div class="compliance-desc">Category: ${inc.category} | Origin: ${inc.origin} | Time: ${inc.timestamp}</div>
            <div class="compliance-payload">${inc.evidence}</div>
        `;
        container.appendChild(div);
    });
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
            } catch (e) {
                console.error(e);
            } finally {
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

    // --- PER-MODULE EXPORT BUTTON HANDLERS ---
    
    // LurkSOC Exports
    const btnSocJson = document.getElementById('btn-export-soc-json');
    if (btnSocJson) {
        btnSocJson.addEventListener('click', () => {
            const data = state.masterData.soc_incidents || {};
            downloadFile(JSON.stringify(data, null, 2), 'LurkSOC_Incidents.json', 'application/json');
        });
    }
    const btnSocMd = document.getElementById('btn-export-soc-md');
    if (btnSocMd) {
        btnSocMd.addEventListener('click', () => {
            const incidents = (state.masterData.soc_incidents || {}).incidents || [];
            let md = `# LurkSOC Master Incident Feed\n\n`;
            incidents.forEach(inc => {
                md += `### [${inc.severity}] ${inc.engine}: ${inc.title}\n`;
                md += `- Incident ID: ${inc.incident_id}\n- Category: ${inc.category}\n- Evidence: ${inc.evidence}\n\n`;
            });
            downloadFile(md, 'LurkSOC_Incidents.md', 'text/markdown');
        });
    }

    // LurkSentinel Exports
    const btnSockJson = document.getElementById('btn-export-sockets-json');
    if (btnSockJson) {
        btnSockJson.addEventListener('click', () => {
            downloadFile(JSON.stringify(state.masterData.sockets || [], null, 2), 'LurkSentinel_Sockets.json', 'application/json');
        });
    }
    const btnSockCsv = document.getElementById('btn-export-sockets-csv');
    if (btnSockCsv) {
        btnSockCsv.addEventListener('click', () => {
            const sockets = state.masterData.sockets || [];
            let csv = "ID,Protocol,LocalAddress,ForeignAddress,Origin,ProcessName\n";
            sockets.forEach(s => {
                csv += `"${s.id}","${s.protocol}","${s.local_address}","${s.foreign_address}","${s.origin}","${s.process_name}"\n`;
            });
            downloadFile(csv, 'LurkSentinel_Sockets.csv', 'text/csv');
        });
    }

    // LurkSIEM Exports
    const btnSiemJson = document.getElementById('btn-export-siem-json');
    if (btnSiemJson) {
        btnSiemJson.addEventListener('click', () => {
            downloadFile(JSON.stringify(state.masterData.siem_events || [], null, 2), 'LurkSIEM_Events.json', 'application/json');
        });
    }
    const btnSiemCsv = document.getElementById('btn-export-siem-csv');
    if (btnSiemCsv) {
        btnSiemCsv.addEventListener('click', () => {
            const events = state.masterData.siem_events || [];
            let csv = "Timestamp,EventID,LogName,Provider,User,Message\n";
            events.forEach(e => {
                csv += `"${e.timestamp}","${e.event_id}","${e.log_name}","${e.provider}","${e.user}","${e.message.replace(/"/g, '""')}"\n`;
            });
            downloadFile(csv, 'LurkSIEM_Events.csv', 'text/csv');
        });
    }

    // LurkDecoy Exports
    const btnDecoyJson = document.getElementById('btn-export-decoy-json');
    if (btnDecoyJson) {
        btnDecoyJson.addEventListener('click', () => {
            const decoy = state.masterData.decoy_summary || {};
            downloadFile(JSON.stringify(decoy, null, 2), 'LurkDecoy_Probes.json', 'application/json');
        });
    }
    const btnDecoyCsv = document.getElementById('btn-export-decoy-csv');
    if (btnDecoyCsv) {
        btnDecoyCsv.addEventListener('click', () => {
            const intrusions = (state.masterData.decoy_summary || {}).intrusions || [];
            let csv = "ProbeID,Timestamp,Port,Service,AttackerIP,Origin,Payload\n";
            intrusions.forEach(i => {
                csv += `"${i.probe_id}","${i.timestamp}","${i.target_port}","${i.service}","${i.source_ip}","${i.origin}","${i.payload.replace(/"/g, '""')}"\n`;
            });
            downloadFile(csv, 'LurkDecoy_Probes.csv', 'text/csv');
        });
    }

    // LurkPacket Exports
    const btnExportPcap = document.getElementById('btn-export-pcap');
    if (btnExportPcap) {
        btnExportPcap.addEventListener('click', () => window.open('/api/pcap', '_blank'));
    }
    const btnPktJson = document.getElementById('btn-export-packet-json');
    if (btnPktJson) {
        btnPktJson.addEventListener('click', () => {
            downloadFile(JSON.stringify(state.masterData.packets || [], null, 2), 'LurkPacket_Packets.json', 'application/json');
        });
    }

    // LurkTrace Exports
    const btnTraceJson = document.getElementById('btn-export-trace-json');
    if (btnTraceJson) {
        btnTraceJson.addEventListener('click', () => {
            downloadFile(JSON.stringify(state.masterData.processes || [], null, 2), 'LurkTrace_Processes.json', 'application/json');
        });
    }
    const btnTraceCsv = document.getElementById('btn-export-trace-csv');
    if (btnTraceCsv) {
        btnTraceCsv.addEventListener('click', () => {
            const procs = state.masterData.processes || [];
            let csv = "PID,PPID,Name,ParentName,Path,CommandLine\n";
            procs.forEach(p => {
                csv += `"${p.pid}","${p.ppid}","${p.name}","${p.parent_name}","${p.path}","${p.cmdline.replace(/"/g, '""')}"\n`;
            });
            downloadFile(csv, 'LurkTrace_Processes.csv', 'text/csv');
        });
    }

    // LurkAudit Exports
    const btnAuditJson = document.getElementById('btn-export-audit-json');
    if (btnAuditJson) {
        btnAuditJson.addEventListener('click', () => {
            downloadFile(JSON.stringify(state.masterData.audit || {}, null, 2), 'LurkAudit_Hardening.json', 'application/json');
        });
    }

    // Master Report Exports
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
