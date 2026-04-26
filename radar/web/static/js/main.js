// Radar Dashboard Logic
const API = {
    overview: '/api/overview',
    devices: '/api/devices',
    deviceDetail: (mac) => `/api/device/${encodeURIComponent(mac)}`,
    deviceFlows: (mac) => `/api/device/${encodeURIComponent(mac)}/flows`,
    deviceStats: (mac) => `/api/device/${encodeURIComponent(mac)}/stats`,
    topApps: '/api/apps/top',
    scan: '/api/scan'
};

const state = {
    view: 'home',
    selectedMac: null,
    devices: [],
    searchQuery: '',
    refreshInterval: null
};

// "Online" = seen within the last 5 minutes (scan runs every 3 min + jitter)
const ONLINE_THRESHOLD_MS = 5 * 60 * 1000;

// --- Initialization ---
function init() {
    window.addEventListener('hashchange', handleRoute);
    handleRoute();
    
    setInterval(updateClock, 1000);
    updateClock();
    
    // Scan button
    const btnScan = document.getElementById('btn-scan');
    if (btnScan) {
        btnScan.onclick = async () => {
            btnScan.textContent = 'SCANNING...';
            btnScan.disabled = true;
            try {
                const res = await fetch(API.scan, { method: 'POST' });
                const data = await res.json();
                if (data.status === 'error') {
                    alert(data.message);
                }
                refreshData();
            } catch(e) {
                console.error('Scan failed:', e);
            } finally {
                setTimeout(() => {
                    btnScan.textContent = 'SCAN NOW';
                    btnScan.disabled = false;
                }, 3000);
            }
        };
    }
    
    refreshData();
    state.refreshInterval = setInterval(refreshData, 2000);
}

function handleRoute() {
    const hash = window.location.hash;
    
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    
    if (hash.startsWith('#/intelligence/')) {
        state.view = 'intelligence';
        state.selectedMac = decodeURIComponent(hash.replace('#/intelligence/', ''));
    } else if (hash.startsWith('#/device/')) {
        state.view = 'detail';
        state.selectedMac = decodeURIComponent(hash.replace('#/device/', ''));
    } else if (hash === '#/history') {
        state.view = 'history';
        state.selectedMac = null;
        const nav = document.getElementById('nav-history');
        if (nav) nav.classList.add('active');
    } else {
        state.view = 'home';
        state.selectedMac = null;
        const nav = document.getElementById('nav-home');
        if (nav) nav.classList.add('active');
    }
    render();
}

// --- Data Fetching ---
async function refreshData() {
    const indicator = document.getElementById('refresh-indicator');
    if (indicator) indicator.classList.add('active');
    
    try {
        if (state.view === 'home' || state.view === 'history') {
            const [overview, devices, topApps, topBandwidth] = await Promise.all([
                fetch(API.overview).then(r => r.json()),
                fetch(API.devices).then(r => r.json()),
                fetch(API.topApps).then(r => r.json()),
                fetch('/api/bandwidth/leaderboard').then(r => r.json())
            ]);
            
            state.devices = devices;
            if (state.view === 'home') updateHomeView(overview, devices, topApps, topBandwidth);
            else if (state.view === 'history') updateHistoryView(devices);
            
        } else if (state.view === 'detail' && state.selectedMac) {
            const [resDetail, resFlows] = await Promise.all([
                fetch(API.deviceDetail(state.selectedMac)),
                fetch(API.deviceFlows(state.selectedMac)).then(r => r.json())
            ]);
            
            if (resDetail.ok) {
                const detail = await resDetail.json();
                updateDetailView(detail, resFlows);
            }
        } else if (state.view === 'intelligence' && state.selectedMac) {
            const [stats, flows, tactical] = await Promise.all([
                fetch(API.deviceStats(state.selectedMac)).then(r => r.json()),
                fetch(API.deviceFlows(state.selectedMac)).then(r => r.json()),
                fetch(`/api/tactical/${encodeURIComponent(state.selectedMac)}/status`).then(r => r.json()).catch(() => ({intercepting: false}))
            ]);
            updateIntelligenceView(stats, flows, tactical);
        }
    } catch (err) {
        console.error('Data refresh failed:', err);
    } finally {
        setTimeout(() => {
            if (indicator) indicator.classList.remove('active');
        }, 500);
    }
}

// --- Rendering ---
function render() {
    const container = document.getElementById('view-container');
    container.innerHTML = '';
    
    switch (state.view) {
        case 'home':
            const tplHome = document.getElementById('tpl-home').content.cloneNode(true);
            container.appendChild(tplHome);
            const searchInput = document.getElementById('device-search');
            searchInput.value = state.searchQuery;
            searchInput.addEventListener('input', (e) => {
                state.searchQuery = e.target.value.toLowerCase();
                renderDeviceGrid();
            });
            renderDeviceGrid();
            break;
            
        case 'history':
            const tplHist = document.getElementById('tpl-history').content.cloneNode(true);
            container.appendChild(tplHist);
            const hSearch = document.getElementById('history-search');
            hSearch.addEventListener('input', (e) => {
                state.searchQuery = e.target.value.toLowerCase();
                updateHistoryView(state.devices);
            });
            updateHistoryView(state.devices);
            break;

        case 'detail':
            container.innerHTML = document.getElementById('tpl-detail').innerHTML;
            const b1 = document.getElementById('btn-back');
            if (b1) b1.onclick = () => window.location.hash = '#/';
            break;

        case 'intelligence':
            container.innerHTML = document.getElementById('tpl-intelligence').innerHTML;
            const b2 = document.getElementById('btn-back');
            if (b2) b2.onclick = () => window.history.back();
            
            // Tactical Handlers
            const btnStart = document.getElementById('btn-tactical-start');
            const btnStop = document.getElementById('btn-tactical-stop');
            
            if (btnStart) {
                btnStart.onclick = async () => {
                    btnStart.disabled = true;
                    btnStart.textContent = "STARTING...";
                    try {
                        await fetch(`/api/tactical/${encodeURIComponent(state.selectedMac)}/start`, { method: 'POST' });
                        refreshData();
                    } catch (e) {
                        console.error(e);
                        btnStart.disabled = false;
                        btnStart.textContent = "INITIATE INTERCEPTION";
                    }
                };
            }
            
            if (btnStop) {
                btnStop.onclick = async () => {
                    btnStop.disabled = true;
                    btnStop.textContent = "STOPPING...";
                    try {
                        await fetch(`/api/tactical/${encodeURIComponent(state.selectedMac)}/stop`, { method: 'POST' });
                        refreshData();
                    } catch (e) {
                        console.error(e);
                        btnStop.disabled = false;
                        btnStop.textContent = "STOP INTERCEPTION";
                    }
                };
            }
            break;
    }
}

// --- Helpers ---
function setElText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

function setElHtml(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
}

function updateHomeView(overview, devices, topApps, topBandwidth) {
    if (state.view !== 'home') return;
    
    // Stats
    setElText('stat-total-devices', overview.network_stats.total_known);
    setElText('stat-active-today', overview.network_stats.active_today);
    setElText('stat-cpu', `${overview.system.cpu.toFixed(1)}%`);
    
    const cpuBar = document.getElementById('cpu-bar');
    if (cpuBar) cpuBar.style.width = `${overview.system.cpu}%`;
    
    setElText('stat-ram', `${overview.system.ram.toFixed(1)}%`);
    const ramBar = document.getElementById('ram-bar');
    if (ramBar) ramBar.style.width = `${overview.system.ram}%`;
    
    setElText('stat-battery', `${overview.system.battery.toFixed(1)}%`);
    setElText('stat-charging', overview.system.battery_charging ? '⚡' : '🔋');
    
    // App Focus
    setElText('current-app-name', overview.app_focus.current);
    setElText('window-title-text', overview.app_focus.window);
    
    const badge = document.getElementById('idle-badge');
    if (badge) {
        badge.textContent = overview.app_focus.is_idle ? 'IDLE' : 'ACTIVE';
        badge.className = `badge ${overview.app_focus.is_idle ? 'idle' : ''}`;
    }
    
    // Network
    setElText('wifi-ssid', overview.system.wifi_ssid);
    setElText('wifi-signal', `${overview.system.wifi_signal} dBm`);
    
    // Top Apps
    setElHtml('top-apps-ul', topApps.map(app =>
        `<li><span>${app.name}</span><span class="mono">${app.minutes}m</span></li>`
    ).join(''));
    
    // Top Bandwidth
    if (topBandwidth && topBandwidth.length > 0) {
        setElHtml('top-bandwidth-ul', topBandwidth.map(d => {
            const mb = (d.total_bytes / (1024 * 1024)).toFixed(2);
            return `<li><span style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:60%; display:inline-block;" title="${d.name}">${d.name}</span><span class="mono highlight" style="float:right;">${mb} MB</span></li>`;
        }).join(''));
    } else {
        setElHtml('top-bandwidth-ul', '<li class="dim small">No traffic recorded yet</li>');
    }
    
    renderDeviceGrid();
}

function renderDeviceGrid() {
    const grid = document.getElementById('device-grid');
    if (!grid) return;
    
    const now = new Date();
    
    // HOME: show devices seen today, sorted by recency
    const today = now.toISOString().split('T')[0];
    const todayDevices = state.devices.filter(d => {
        const seen = d.last_seen.split('T')[0];
        return seen === today;
    });
    
    const filtered = todayDevices.filter(d => {
        if (!state.searchQuery) return true;
        const name = (d.device_name || d.mdns_hostname || "Unknown").toLowerCase();
        const ip = d.ip_address.toLowerCase();
        const mfr = (d.manufacturer || "").toLowerCase();
        const activity = (d.last_activity || "").toLowerCase();
        return name.includes(state.searchQuery) || ip.includes(state.searchQuery)
            || mfr.includes(state.searchQuery) || activity.includes(state.searchQuery);
    });
    
    // Smart DOM update
    const currentMacs = new Set(filtered.map(d => d.mac_address));
    Array.from(grid.children).forEach(child => {
        if (!currentMacs.has(child.getAttribute('data-mac'))) grid.removeChild(child);
    });
    
    filtered.forEach(d => {
        const isOnline = (now - new Date(d.last_seen)) < ONLINE_THRESHOLD_MS;
        const icon = getDeviceIcon(d);
        const name = getDisplayName(d);
        
        let activity = d.last_activity || 'Idle';
        let subtext = '';
        if (activity.startsWith('Browsing ')) {
            subtext = activity.replace('Browsing ', '');
            activity = 'Browsing';
        }
        
        const cat = getActivityCategory(d.last_activity);
        const statusText = isOnline ? 'ONLINE' : formatLastSeen(d.last_seen);
        
        let card = grid.querySelector(`[data-mac="${d.mac_address}"]`);
        if (!card) {
            card = document.createElement('div');
            card.className = 'device-card';
            card.setAttribute('data-mac', d.mac_address);
            card.onclick = () => location.hash = `#/device/${encodeURIComponent(d.mac_address)}`;
            grid.appendChild(card);
        }

        card.innerHTML = `
            <div class="device-card-header">
                <div class="device-icon">${icon}</div>
                <div class="device-meta">
                    <h4>${name}</h4>
                    <p class="dim small mono">${d.ip_address}</p>
                </div>
            </div>
            <div class="status-row">
                <div class="status-dot ${isOnline ? 'online' : ''}"></div>
                <span class="dim small">${statusText}</span>
            </div>
            <div class="device-activity">
                <span class="activity-badge ${cat}">${activity}</span>
                ${subtext ? `<span class="activity-subtext">${subtext}</span>` : ''}
            </div>
        `;
    });
    
    // Show count
    const header = document.querySelector('.device-section .section-header h2');
    if (header) header.textContent = `NETWORK RECONNAISSANCE (${filtered.length} devices today)`;
}

function updateHistoryView(devices) {
    if (state.view !== 'history') return;
    const body = document.getElementById('history-table-body');
    if (!body) return;
    
    const now = new Date();
    const filtered = devices.filter(d => {
        if (!state.searchQuery) return true;
        const name = (d.device_name || d.mdns_hostname || "Unknown").toLowerCase();
        const ip = d.ip_address.toLowerCase();
        const mfr = (d.manufacturer || "").toLowerCase();
        return name.includes(state.searchQuery) || ip.includes(state.searchQuery) || mfr.includes(state.searchQuery);
    });
    
    body.innerHTML = filtered.map(d => {
        const isOnline = (now - new Date(d.last_seen)) < ONLINE_THRESHOLD_MS;
        const icon = getDeviceIcon(d);
        return `
            <tr onclick="location.hash='#/device/${encodeURIComponent(d.mac_address)}'">
                <td>
                    <span style="margin-right:10px">${icon}</span>
                    <span class="dev-name">${d.device_name || d.mdns_hostname || 'Unknown'}</span>
                    <span class="dev-mfr">${d.manufacturer || 'Unknown'}</span>
                </td>
                <td class="mono small">${d.ip_address}<br>${d.mac_address}</td>
                <td class="small">${new Date(d.first_seen).toLocaleDateString()}</td>
                <td class="small">
                    ${isOnline
                        ? '<span class="highlight">● ONLINE</span>'
                        : formatLastSeen(d.last_seen)}
                </td>
                <td class="small">${d.confidence}%</td>
            </tr>
        `;
    }).join('');
    
    // Update header count
    const header = document.querySelector('.history-view .section-header h2');
    if (header) header.textContent = `DEVICE ARCHIVE (${filtered.length} total)`;
}

function updateDetailView(data) {
    if (state.view !== 'detail') return;
    
    const d = data.info;
    const sessions = data.sessions || [];
    
    setElText('detail-name', getDisplayName(d));
    setElText('detail-mac', d.mac_address);
    setElText('det-mfr', d.manufacturer || "Generic Vendor");
    setElText('det-ip', d.ip_address);
    setElText('det-mac', d.mac_address);
    setElText('det-type', d.device_type || 'Unknown');
    setElText('det-confidence', `${d.confidence}%`);
    setElText('det-first-seen', new Date(d.first_seen).toLocaleString());
    setElText('det-last-seen', new Date(d.last_seen).toLocaleString());
    setElText('det-activity', d.last_activity || 'Passive / No activity detected');
    setElText('det-traffic', d.traffic_summary || 'No traffic pattern captured yet.');
    setElText('det-mdns', d.mdns_hostname || 'Not discovered');
    setElText('det-ssdp', d.ssdp_info || 'Not discovered');
    
    const isOnline = (new Date() - new Date(d.last_seen)) < ONLINE_THRESHOLD_MS;
    const statusBadge = document.getElementById('det-status');
    if (statusBadge) {
        statusBadge.textContent = isOnline ? '● Online' : '○ Offline';
        statusBadge.className = `status-badge ${isOnline ? 'online' : 'offline'}`;
    }
    
    const btnIntel = document.getElementById('btn-deep-intel');
    if (btnIntel) btnIntel.href = `#/intelligence/${encodeURIComponent(d.mac_address)}`;

    setElText('device-icon-large', getDeviceIcon(d));

    // Sessions table
    const sessionsBody = document.getElementById('det-sessions-body');
    if (sessionsBody) {
        if (sessions.length === 0) {
            sessionsBody.innerHTML = '<tr><td colspan="3" class="dim small" style="text-align:center;padding:20px">No session history recorded yet</td></tr>';
        } else {
            sessionsBody.innerHTML = sessions.reverse().map(s => `
                <tr>
                    <td class="mono small">${new Date(s.session_start).toLocaleString()}</td>
                    <td class="mono small">${s.session_end ? new Date(s.session_end).toLocaleString() : '<span class="highlight">Active Now</span>'}</td>
                    <td><span class="badge ${(s.traffic_level || 'light').toLowerCase()}">${s.traffic_level || 'LIGHT'}</span></td>
                </tr>
            `).join('');
        }
    }
}

// --- Helpers ---
function getDisplayName(d) {
    const name = d.device_name;
    if (name && name !== "Unknown Device" && name !== "Unknown") return name;
    if (d.mdns_hostname) return d.mdns_hostname;
    
    let mfr = d.manufacturer;
    if (mfr && mfr !== "Unknown") {
        // Clean up common manufacturer strings: Take first word or part before special chars
        // e.g. "Sony Home Entertainment..." -> "Sony"
        mfr = mfr.split(/[ ,&]/)[0]; 
        return `${mfr} Device`;
    }
    
    // Fallback to MAC suffix
    const suffix = d.mac_address.split(':').slice(-2).join('').toUpperCase();
    return `Device-${suffix}`;
}

function getDeviceIcon(d) {
    const mfr = (d.manufacturer || "").toLowerCase();
    const name = (d.device_name || "").toLowerCase();
    const type = (d.device_type || "").toLowerCase();
    
    if (mfr.includes('apple')) return '🍎';
    if (mfr.includes('samsung')) return '📱';
    if (mfr.includes('google')) return '📱';
    if (mfr.includes('xiaomi') || mfr.includes('huawei') || mfr.includes('oppo') || mfr.includes('vivo')) return '📱';
    if (mfr.includes('sony') || name.includes('playstation')) return '🎮';
    if (mfr.includes('microsoft') || name.includes('xbox')) return '🎮';
    if (mfr.includes('nintendo')) return '🎮';
    if (mfr.includes('hp') || mfr.includes('canon') || mfr.includes('epson') || mfr.includes('brother')) return '🖨️';
    if (mfr.includes('synology') || mfr.includes('qnap') || mfr.includes('western digital')) return '📦';
    if (mfr.includes('hikvision') || mfr.includes('dahua') || mfr.includes('camera')) return '📷';
    if (mfr.includes('ubiquiti') || mfr.includes('cisco') || mfr.includes('tp-link') || mfr.includes('netgear')) return '🌐';
    if (mfr.includes('tcl') || mfr.includes('lg') || mfr.includes('hisense') || mfr.includes('roku')) return '📺';
    if (mfr.includes('intel') || mfr.includes('dell') || mfr.includes('lenovo') || mfr.includes('asus')) return '💻';
    if (mfr.includes('amazon') || mfr.includes('echo')) return '🔊';
    if (type.includes('phone') || type.includes('mobile')) return '📱';
    if (type.includes('laptop') || type.includes('pc')) return '💻';
    if (type.includes('tv') || type.includes('smart')) return '📺';
    return '🔌';
}

function formatLastSeen(dateStr) {
    const delta = Math.floor((new Date() - new Date(dateStr)) / 1000);
    if (delta < 60) return 'Just now';
    if (delta < 3600) return `${Math.floor(delta/60)}m ago`;
    if (delta < 86400) return `${Math.floor(delta/3600)}h ago`;
    return `${Math.floor(delta/86400)}d ago`;
}

function updateClock() {
    const clock = document.getElementById('clock');
    if (clock) clock.textContent = new Date().toLocaleTimeString();
}

function updateIntelligenceView(stats, flows, tactical) {
    if (state.view !== 'intelligence') return;
    
    const device = state.devices.find(d => d.mac_address === state.selectedMac);
    const name = device ? getDisplayName(device) : 'Synchronizing Intelligence...';
    
    setElText('intel-device-name', name);
    
    // Tactical UI
    const btnStart = document.getElementById('btn-tactical-start');
    const btnStop = document.getElementById('btn-tactical-stop');
    const tacticalStatus = document.getElementById('tactical-status');
    const intelHeader = document.querySelector('.intel-header');
    
    if (tactical && tactical.intercepting) {
        if (btnStart) btnStart.style.display = 'none';
        if (btnStop) {
            btnStop.style.display = 'inline-block';
            btnStop.disabled = false;
            btnStop.textContent = "STOP INTERCEPTION";
        }
        if (tacticalStatus) tacticalStatus.innerHTML = '<span class="highlight" style="animation: pulse 1s infinite;">● ACTIVE INTERCEPTION</span>';
        if (intelHeader) intelHeader.style.borderColor = '#e74c3c';
    } else {
        if (btnStart) {
            btnStart.style.display = 'inline-block';
            btnStart.disabled = false;
            btnStart.textContent = "INITIATE INTERCEPTION";
        }
        if (btnStop) btnStop.style.display = 'none';
        if (tacticalStatus) tacticalStatus.textContent = 'Tactical Module Ready';
        if (intelHeader) intelHeader.style.borderColor = 'rgba(255, 255, 255, 0.1)';
    }
    
    const totalBytes = stats.total_bytes || 0;
    const mb = (totalBytes / (1024 * 1024)).toFixed(2);
    setElText('total-usage', `${mb} MB`);
    
    const fill = document.getElementById('bandwidth-fill');
    if (fill) {
        // Simple log-scale for the meter (max 100MB for visual)
        const percent = Math.min((totalBytes / (100 * 1024 * 1024)) * 100, 100);
        fill.style.width = `${percent}%`;
    }
    
    // Top Services
    const list = document.getElementById('top-services-list');
    if (list && stats.top_domains) {
        list.innerHTML = stats.top_domains.map(d => `
            <li>
                <span class="highlight">${d.name}</span>
                <span class="mono small">${d.count} connections</span>
            </li>
        `).join('');
    }
    
    // Live flows
    const body = document.getElementById('intel-flow-body');
    if (body) {
        body.innerHTML = flows.slice(0, 15).map(f => `
            <tr>
                <td class="dim small">${new Date(f.timestamp).toLocaleTimeString()}</td>
                <td class="highlight">${f.service_label || f.protocol}</td>
                <td class="mono small">${(f.byte_count / 1024).toFixed(1)} KB</td>
            </tr>
        `).join('');
    }
}

function getActivityCategory(activity) {
    if (!activity) return 'idle';
    const a = activity.toLowerCase();
    if (a.includes('youtube') || a.includes('netflix') || a.includes('video') || a.includes('streaming') || a.includes('tiktok') || a.includes('disney')) return 'video';
    if (a.includes('facebook') || a.includes('instagram') || a.includes('whatsapp') || a.includes('social') || a.includes('twitter') || a.includes('snapchat')) return 'social';
    if (a.includes('game') || a.includes('gaming') || a.includes('steam') || a.includes('playstation') || a.includes('xbox')) return 'gaming';
    if (a.includes('coding') || a.includes('office') || a.includes('slack') || a.includes('work') || a.includes('zoom')) return 'work';
    if (a.includes('chatgpt') || a.includes('openai') || a.includes('claude') || a.includes('gemini') || a.includes('ai')) return 'ai';
    return 'idle';
}

document.addEventListener('DOMContentLoaded', init);

function updateDetailFlows(flows) {
    if (state.view !== 'detail') return;
    const body = document.getElementById('det-flows-body');
    if (!body) return;
    
    // Safety: If the user is currently selecting text to copy, skip the visual refresh
    // so we don't break their selection/clipboard.
    if (window.getSelection().toString().length > 0) return;

    if (flows.length === 0) {
        body.innerHTML = '<tr><td colspan="4" class="dim small" style="text-align:center;padding:20px">No granular traffic detected yet</td></tr>';
        return;
    }
    
    body.innerHTML = flows.map(f => {
        const website = f.service_label || 'Direct IP';
        const isDomain = website.includes('.') && !/^[0-9.]+$/.test(website);
        
        return `
            <tr>
                <td class="mono small">${new Date(f.timestamp).toLocaleTimeString()}</td>
                <td class="mono small">${f.dst_ip}:${f.dst_port}</td>
                <td><span class="${isDomain ? 'highlight' : 'dim'}">${website}</span></td>
                <td><span class="badge highlight">${f.protocol}</span></td>
            </tr>
        `;
    }).join('');
}
