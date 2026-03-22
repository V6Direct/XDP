/* ============================================================
   DDoS Mitigation Platform – app.js
   Full dashboard application: auth, polling, charts, tables
   ============================================================ */

'use strict';

// ── Config ──────────────────────────────────────────────────
const API_BASE      = '';          // same origin (webpanel backend proxies)
const POLL_INTERVAL = 3000;        // ms between metric refreshes
const CHART_WINDOW  = 60;          // data points to keep in sparklines

// ── State ────────────────────────────────────────────────────
let authToken   = localStorage.getItem('ddos_token') || null;
let currentUser = JSON.parse(localStorage.getItem('ddos_user') || 'null');
let pollTimer   = null;
let refreshProgress = 0;
let refreshTimer    = null;

// Chart.js instances
let ppsChart  = null;
let bpsChart  = null;
let dropChart = null;

// Ring-buffer data for sparklines
const ppsData  = Array(CHART_WINDOW).fill(0);
const bpsData  = Array(CHART_WINDOW).fill(0);
const dropData = Array(CHART_WINDOW).fill(0);
const labels   = Array(CHART_WINDOW).fill('');

// ── DOM refs (populated after DOMContentLoaded) ──────────────
const $ = id => document.getElementById(id);

// ── Bootstrap ────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initCharts();

    if (authToken && currentUser) {
        showApp();
    } else {
        showLogin();
    }

    // Tab switching
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });

    // Login form
    $('login-form').addEventListener('submit', handleLogin);

    // Logout
    $('btn-logout').addEventListener('click', handleLogout);

    // Block IP form
    $('btn-block-ip').addEventListener('click', handleManualBlock);

    // Whitelist form
    $('btn-whitelist-ip').addEventListener('click', handleWhitelistAdd);
    $('btn-unwhitelist-ip').addEventListener('click', handleWhitelistRemove);

    // Config save
    $('btn-save-config').addEventListener('click', handleSaveConfig);

    // Mitigation toggle
    $('mitigation-toggle').addEventListener('click', toggleMitigation);
});

// ── Auth ─────────────────────────────────────────────────────

async function handleLogin(e) {
    e.preventDefault();
    const username = $('login-username').value.trim();
    const password = $('login-password').value;
    $('login-error').textContent = '';

    try {
        const resp = await fetch(`${API_BASE}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Login failed');

        authToken   = data.token;
        currentUser = data.user;
        localStorage.setItem('ddos_token', authToken);
        localStorage.setItem('ddos_user', JSON.stringify(currentUser));
        showApp();
    } catch (err) {
        $('login-error').textContent = '⚠ ' + err.message;
    }
}

function handleLogout() {
    authToken   = null;
    currentUser = null;
    localStorage.removeItem('ddos_token');
    localStorage.removeItem('ddos_user');
    stopPolling();
    showLogin();
}

// ── View transitions ─────────────────────────────────────────

function showLogin() {
    $('login-screen').style.display = 'flex';
    $('app').classList.remove('visible');
    $('login-password').value = '';
}

function showApp() {
    $('login-screen').style.display = 'none';
    $('app').classList.add('visible');
    $('nav-username').textContent = currentUser?.username || '';
    $('nav-role').textContent     = currentUser?.role     || '';

    // Hide admin-only controls for viewers
    const isAdmin = currentUser?.role === 'admin';
    document.querySelectorAll('.admin-only').forEach(el => {
        el.style.display = isAdmin ? '' : 'none';
    });

    switchTab('overview');
    startPolling();
}

// ── Tab management ───────────────────────────────────────────

function switchTab(name) {
    document.querySelectorAll('.tab').forEach(t =>
        t.classList.toggle('active', t.dataset.tab === name));
    document.querySelectorAll('.tab-panel').forEach(p =>
        p.classList.toggle('active', p.id === 'tab-' + name));

    // Refresh data for the newly active tab
    if (name === 'blocked')   loadBlockedIPs();
    if (name === 'attackers') loadAttackers();
    if (name === 'alerts')    loadAlerts();
    if (name === 'config')    loadConfig();
}

// ── Polling loop ─────────────────────────────────────────────

function startPolling() {
    fetchMetrics(); // immediate first fetch
    pollTimer = setInterval(fetchMetrics, POLL_INTERVAL);
    startRefreshBar();
}

function stopPolling() {
    if (pollTimer)   { clearInterval(pollTimer);  pollTimer = null; }
    if (refreshTimer){ clearInterval(refreshTimer); refreshTimer = null; }
}

function startRefreshBar() {
    refreshProgress = 0;
    const bar = $('refresh-bar-inner');
    if (!bar) return;
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = setInterval(() => {
        refreshProgress = (refreshProgress + (100 / (POLL_INTERVAL / 100))) % 100;
        bar.style.width = refreshProgress + '%';
    }, 100);
}

// ── API helpers ──────────────────────────────────────────────

async function apiFetch(path, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        ...(authToken ? { 'Authorization': 'Bearer ' + authToken } : {}),
        ...(options.headers || {}),
    };
    const resp = await fetch(API_BASE + path, { ...options, headers });
    if (resp.status === 401) { handleLogout(); return null; }
    return resp;
}

async function apiGet(path) {
    try {
        const resp = await apiFetch(path);
        if (!resp) return null;
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || resp.statusText);
        return data;
    } catch (err) {
        console.error('GET', path, err);
        return null;
    }
}

async function apiPost(path, body) {
    try {
        const resp = await apiFetch(path, { method: 'POST', body: JSON.stringify(body) });
        if (!resp) return null;
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || resp.statusText);
        return data;
    } catch (err) {
        toast(err.message, 'error');
        return null;
    }
}

async function apiDelete(path, body) {
    try {
        const resp = await apiFetch(path, { method: 'DELETE', body: JSON.stringify(body) });
        if (!resp) return null;
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || resp.statusText);
        return data;
    } catch (err) {
        toast(err.message, 'error');
        return null;
    }
}

// ── Metrics fetch & render ───────────────────────────────────

async function fetchMetrics() {
    const m = await apiGet('/api/v1/metrics');
    if (!m) return;
    renderStatCards(m);
    updateCharts(m);
    updateNavStatus(m);
}

function renderStatCards(m) {
    const pps  = fmt(m.pps,  0);
    const bps  = fmtBits(m.bps);
    const drop = m.dropped_packets;
    const pass = m.passed_packets;
    const blk  = m.blocked_ip_count;

    setCard('stat-pps',     pps,  m.pps > 50000 ? 'danger' : m.pps > 10000 ? 'warn' : '');
    setCard('stat-bps',     bps,  '');
    setCard('stat-dropped', fmt(drop, 0), drop > 0 ? 'danger' : 'success');
    setCard('stat-passed',  fmt(pass, 0), 'success');
    setCard('stat-blocked', fmt(blk,  0), blk > 0 ? 'danger' : '');
    setCard('stat-syn',     fmt(m.syn_floods, 0),    m.syn_floods  > 0 ? 'warn' : '');
    setCard('stat-udp',     fmt(m.udp_amplifications, 0), m.udp_amplifications > 0 ? 'warn' : '');
    setCard('stat-icmp',    fmt(m.icmp_floods, 0),   m.icmp_floods > 0 ? 'warn' : '');
}

function setCard(id, value, cls) {
    const el = $(id);
    if (!el) return;
    const valEl = el.querySelector('.stat-value');
    if (valEl) {
        valEl.textContent = value;
        valEl.className   = 'stat-value' + (cls ? ' ' + cls : '');
    }
    el.className = 'stat-card' + (cls === 'danger' ? ' danger' : cls === 'warn' ? ' warn' : cls === 'success' ? ' success' : '');
}

function updateNavStatus(m) {
    const el = $('nav-pps');
    if (el) el.textContent = fmt(m.pps, 0) + ' pps';
}

// ── Charts (Chart.js) ────────────────────────────────────────

function initCharts() {
    const chartDefaults = {
        type: 'line',
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 0 },
            plugins: { legend: { display: false } },
            scales: {
                x: {
                    display: false,
                    grid: { display: false },
                },
                y: {
                    display: true,
                    grid: { color: 'rgba(30,42,58,0.8)', drawBorder: false },
                    ticks: {
                        color: '#6a8090',
                        font: { family: 'Share Tech Mono', size: 10 },
                        maxTicksLimit: 4,
                    },
                },
            },
            elements: {
                point: { radius: 0, hitRadius: 0 },
                line:  { tension: 0.3 },
            },
        },
    };

    const ppsCtx = document.getElementById('chart-pps');
    if (ppsCtx) {
        ppsChart = new Chart(ppsCtx.getContext('2d'), {
            ...chartDefaults,
            data: {
                labels,
                datasets: [{
                    data: ppsData,
                    borderColor: '#00d4ff',
                    borderWidth: 1.5,
                    backgroundColor: 'rgba(0,212,255,0.06)',
                    fill: true,
                }],
            },
        });
    }

    const bpsCtx = document.getElementById('chart-bps');
    if (bpsCtx) {
        bpsChart = new Chart(bpsCtx.getContext('2d'), {
            ...chartDefaults,
            data: {
                labels,
                datasets: [{
                    data: bpsData,
                    borderColor: '#00ff88',
                    borderWidth: 1.5,
                    backgroundColor: 'rgba(0,255,136,0.06)',
                    fill: true,
                }],
            },
        });
    }

    const dropCtx = document.getElementById('chart-drops');
    if (dropCtx) {
        dropChart = new Chart(dropCtx.getContext('2d'), {
            ...chartDefaults,
            data: {
                labels,
                datasets: [{
                    data: dropData,
                    borderColor: '#ff3355',
                    borderWidth: 1.5,
                    backgroundColor: 'rgba(255,51,85,0.06)',
                    fill: true,
                }],
            },
        });
    }
}

let lastDropped = 0;

function updateCharts(m) {
    const now = new Date().toLocaleTimeString('en', { hour12: false });
    const dropDelta = Math.max(0, m.dropped_packets - lastDropped);
    lastDropped = m.dropped_packets;

    push(ppsData,  m.pps);
    push(bpsData,  m.bps / 1_000_000); // Mbps
    push(dropData, dropDelta);
    push(labels,   now);

    if (ppsChart)  { ppsChart.data.labels  = labels; ppsChart.update('none'); }
    if (bpsChart)  { bpsChart.data.labels  = labels; bpsChart.update('none'); }
    if (dropChart) { dropChart.data.labels = labels; dropChart.update('none'); }
}

function push(arr, val) {
    arr.shift();
    arr.push(val);
}

// ── Blocked IPs tab ──────────────────────────────────────────

async function loadBlockedIPs() {
    const list = await apiGet('/api/v1/blocked');
    if (!list) return;
    renderBlockedTable(list);
}

function renderBlockedTable(list) {
    const tbody = $('blocked-tbody');
    if (!tbody) return;

    if (!list || list.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No blocked IPs</td></tr>`;
        return;
    }

    tbody.innerHTML = list.map(entry => {
        const reasonCls = `reason-${entry.reason.split('_')[0]}`;
        const blocked   = new Date(entry.blocked_at).toLocaleString();
        return `
        <tr>
          <td class="ip-cell">${esc(entry.ip)}</td>
          <td><span class="${reasonCls}">${esc(entry.reason)}</span></td>
          <td class="num-cell">${blocked}</td>
          <td>
            <button class="btn-action danger admin-only"
              onclick="unblockIP('${esc(entry.ip)}')">UNBLOCK</button>
          </td>
        </tr>`;
    }).join('');
}

async function handleManualBlock() {
    const ip     = $('block-ip-input').value.trim();
    const reason = parseInt($('block-reason-select').value) || 1;
    if (!ip) { toast('Enter an IP address', 'error'); return; }
    const result = await apiPost('/api/v1/blocked', { ip, reason });
    if (result) {
        toast(`Blocked ${ip}`, 'success');
        $('block-ip-input').value = '';
        loadBlockedIPs();
    }
}

async function unblockIP(ip) {
    const result = await apiDelete('/api/v1/blocked', { ip });
    if (result) {
        toast(`Unblocked ${ip}`, 'success');
        loadBlockedIPs();
    }
}

// ── Attackers tab ────────────────────────────────────────────

async function loadAttackers() {
    const list = await apiGet('/api/v1/attackers');
    if (!list) return;
    renderAttackersTable(list);
}

function renderAttackersTable(list) {
    const tbody = $('attackers-tbody');
    if (!tbody) return;

    if (!list || list.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-state">No attacker data</td></tr>`;
        return;
    }

    tbody.innerHTML = list.map((a, i) => `
    <tr>
      <td class="num-cell" style="color:var(--text-dim)">${i + 1}</td>
      <td class="ip-cell">${esc(a.ip)}</td>
      <td class="num-cell">${fmt(a.total_packets, 0)}</td>
      <td class="num-cell">${fmtBytes(a.total_bytes)}</td>
      <td class="num-cell" style="color:var(--orange)">${fmt(a.syn_count, 0)}</td>
      <td class="num-cell" style="color:var(--yellow)">${fmt(a.udp_count, 0)}</td>
      <td class="num-cell" style="color:var(--red)">${fmt(a.icmp_count, 0)}</td>
      <td class="admin-only">
        <button class="btn-action danger" onclick="blockIPFromAttackers('${esc(a.ip)}')">BLOCK</button>
      </td>
    </tr>`).join('');
}

async function blockIPFromAttackers(ip) {
    const result = await apiPost('/api/v1/blocked', { ip, reason: 1 });
    if (result) {
        toast(`Blocked ${ip}`, 'success');
        switchTab('blocked');
    }
}

// ── Alerts tab ───────────────────────────────────────────────

async function loadAlerts() {
    const list = await apiGet('/api/v1/alerts');
    if (!list) return;
    renderAlertsTable(list);
}

function renderAlertsTable(list) {
    const tbody = $('alerts-tbody');
    if (!tbody) return;

    if (!list || list.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No alerts</td></tr>`;
        return;
    }

    tbody.innerHTML = list.map(a => `
    <tr>
      <td><span class="alert-badge ${esc(a.level)}">${esc(a.level)}</span></td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--accent-dim)">${esc(a.type)}</td>
      <td style="font-size:12px">${esc(a.message)}</td>
      <td class="ip-cell">${esc(a.source_ip || '—')}</td>
      <td class="num-cell">${new Date(a.timestamp).toLocaleTimeString()}</td>
    </tr>`).join('');
}

// ── Config tab ───────────────────────────────────────────────

async function loadConfig() {
    const cfg = await apiGet('/api/v1/config');
    if (!cfg) return;

    if ($('cfg-syn-rate'))  $('cfg-syn-rate').value  = cfg.syn_rate_limit  || 1000;
    if ($('cfg-udp-rate'))  $('cfg-udp-rate').value  = cfg.udp_rate_limit  || 5000;
    if ($('cfg-icmp-rate')) $('cfg-icmp-rate').value = cfg.icmp_rate_limit || 100;

    const toggle = $('mitigation-toggle');
    if (toggle) {
        const track = toggle.querySelector('.toggle-track');
        if (track) track.classList.toggle('on', cfg.enabled !== false);
        toggle.dataset.enabled = cfg.enabled !== false ? '1' : '0';
    }
}

async function handleSaveConfig() {
    const syn  = parseInt($('cfg-syn-rate').value)  || 1000;
    const udp  = parseInt($('cfg-udp-rate').value)  || 5000;
    const icmp = parseInt($('cfg-icmp-rate').value) || 100;
    const enabled = ($('mitigation-toggle').dataset.enabled === '1');

    const result = await apiPost('/api/v1/config', {
        syn_rate_limit:  syn,
        udp_rate_limit:  udp,
        icmp_rate_limit: icmp,
        enabled,
    });
    if (result) toast('Configuration saved', 'success');
}

function toggleMitigation() {
    const btn = $('mitigation-toggle');
    const track = btn.querySelector('.toggle-track');
    const current = btn.dataset.enabled === '1';
    btn.dataset.enabled = current ? '0' : '1';
    track.classList.toggle('on', !current);
    toast(current ? 'Mitigation DISABLED' : 'Mitigation ENABLED',
          current ? 'warn' : 'success');
}

// ── Whitelist management ─────────────────────────────────────

async function handleWhitelistAdd() {
    const ip = $('whitelist-ip-input').value.trim();
    if (!ip) { toast('Enter an IP address', 'error'); return; }
    const result = await apiPost('/api/v1/whitelist', { ip });
    if (result) {
        toast(`Whitelisted ${ip}`, 'success');
        $('whitelist-ip-input').value = '';
    }
}

async function handleWhitelistRemove() {
    const ip = $('whitelist-ip-input').value.trim();
    if (!ip) { toast('Enter an IP address', 'error'); return; }
    const result = await apiDelete('/api/v1/whitelist', { ip });
    if (result) {
        toast(`Removed ${ip} from whitelist`, 'success');
        $('whitelist-ip-input').value = '';
    }
}

// ── Toast notifications ──────────────────────────────────────

function toast(msg, type = 'info') {
    const container = $('toast-container');
    if (!container) return;

    const el = document.createElement('div');
    el.className = 'toast ' + type;
    el.textContent = msg;
    container.appendChild(el);

    setTimeout(() => {
        el.style.opacity = '0';
        el.style.transition = 'opacity 0.3s';
        setTimeout(() => el.remove(), 300);
    }, 3000);
}

// ── Formatters ───────────────────────────────────────────────

function fmt(n, decimals = 2) {
    if (n === undefined || n === null) return '—';
    if (n >= 1_000_000_000) return (n / 1_000_000_000).toFixed(decimals) + 'G';
    if (n >= 1_000_000)     return (n / 1_000_000).toFixed(decimals)     + 'M';
    if (n >= 1_000)         return (n / 1_000).toFixed(decimals)         + 'K';
    return Number(n).toFixed(decimals);
}

function fmtBytes(n) {
    if (!n) return '0 B';
    if (n >= 1e12) return (n / 1e12).toFixed(2) + ' TB';
    if (n >= 1e9)  return (n / 1e9).toFixed(2)  + ' GB';
    if (n >= 1e6)  return (n / 1e6).toFixed(2)  + ' MB';
    if (n >= 1e3)  return (n / 1e3).toFixed(2)  + ' KB';
    return n + ' B';
}

function fmtBits(bps) {
    if (!bps) return '0 bps';
    if (bps >= 1e12) return (bps / 1e12).toFixed(2) + ' Tbps';
    if (bps >= 1e9)  return (bps / 1e9).toFixed(2)  + ' Gbps';
    if (bps >= 1e6)  return (bps / 1e6).toFixed(2)  + ' Mbps';
    if (bps >= 1e3)  return (bps / 1e3).toFixed(2)  + ' Kbps';
    return bps.toFixed(0) + ' bps';
}

function esc(s) {
    if (!s) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
