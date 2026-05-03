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
    refreshInterval: null,
    lastLoggedMac: null,
    // Forensics periodic refresh trackers
    lastHeavyRefresh: 0,
    forensicsHeavyData: { ports: [], dns: [], stats: { top_domains: [], total_bytes: 0 } }
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
        state.view = 'forensics';
        state.selectedMac = decodeURIComponent(hash.replace('#/device/', ''));
    } else if (hash === '#/history') {
        state.view = 'history';
        state.selectedMac = null;
        const nav = document.getElementById('nav-history');
        if (nav) nav.classList.add('active');
    } else if (hash === '#/map') {
        state.view = 'map';
        state.selectedMac = null;
        const nav = document.getElementById('nav-map');
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
            
        } else if (state.view === 'forensics' && state.selectedMac) {
            const mac = state.selectedMac;

            // Always fetch live data (device info + flows + tactical)
            const [resDetail, resFlows, resTactical] = await Promise.all([
                fetch(API.deviceDetail(mac)),
                fetch(API.deviceFlows(mac)).then(r => r.json()).catch(() => []),
                fetch(`/api/tactical/${encodeURIComponent(mac)}/status`).then(r => r.json()).catch(() => ({intercepting:false}))
            ]);

            // Periodic refresh for heavy data (DNS, Ports, Stats) — every ~6 seconds (3 cycles)
            const now = Date.now();
            if (!state.lastHeavyRefresh || (now - state.lastHeavyRefresh > 6000)) {
                state.lastHeavyRefresh = now;
                const [resPorts, resDns, resStats] = await Promise.all([
                    fetch(API.deviceDetail(mac) + '/ports').then(r => r.json()).catch(() => ({open_ports:[]})),
                    fetch(API.deviceDetail(mac) + '/dns-history').then(r => r.json()).catch(() => ({dns_history:[]})),
                    fetch(API.deviceStats(mac)).then(r => r.json()).catch(() => ({top_domains:[],total_bytes:0}))
                ]);
                state.forensicsHeavyData = {
                    ports: resPorts.open_ports || [],
                    dns: resDns.dns_history || [],
                    stats: resStats
                };
            }

            if (resDetail.ok) {
                const detail = await resDetail.json();
                updateForensicsView(
                    detail, resFlows,
                    state.forensicsHeavyData.ports,
                    state.forensicsHeavyData.dns,
                    resTactical,
                    state.forensicsHeavyData.stats
                );
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
    // Reset heavy data cache when navigating to a new view
    state.forensicsHeavyLoaded = false;
    
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

        case 'forensics':
        case 'detail': {
            const tplForensics = document.getElementById('tpl-forensics');
            if (!tplForensics) {
                container.innerHTML = '<div style="padding:40px;text-align:center;color:#94a3b8">⚠️ Forensics template not found. Please hard-refresh the page (Ctrl+Shift+R).</div>';
                return;
            }
            container.innerHTML = tplForensics.innerHTML;
            document.getElementById('btn-back').onclick = () => window.location.hash = '#/';
            _wireTacticalButtons();
            break;
        }

        case 'map':
            container.innerHTML = document.getElementById('tpl-map').innerHTML;
            renderNetworkMap();
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
    const onlineCount = devices.filter(d => (new Date() - new Date(d.last_seen)) < ONLINE_THRESHOLD_MS).length;
    setElText('stat-active-today', onlineCount);
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
    
    const filtered = state.devices.filter(d => {
        const isOnline = (now - new Date(d.last_seen)) < ONLINE_THRESHOLD_MS;
        if (!isOnline) return false;

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
                    <p class="dim small mono">${d.ip_address} | <span class="highlight">${d.os_guess || 'Scanning...'}</span></p>
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
    if (header) header.textContent = `NETWORK RECONNAISSANCE (${filtered.length} devices online)`;
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
    
    if (state.lastLoggedMac !== d.mac_address) {
        console.group(`📡 Device Intelligence Report: ${getDisplayName(d)}`);
        console.log(JSON.stringify({
            network_identity: {
                name: getDisplayName(d),
                mac_address: d.mac_address,
                ip_address: d.ip_address,
                manufacturer: d.manufacturer,
                device_type: d.device_type,
                os_fingerprint: d.os_guess
            },
            activity_metrics: {
                first_seen: d.first_seen,
                last_seen: d.last_seen,
                confidence_score: d.confidence,
                total_bytes_transferred: d.total_bytes,
                last_activity: d.last_activity
            },
            discovery_data: {
                mdns_hostname: d.mdns_hostname,
                ssdp_info: d.ssdp_info,
                open_ports_raw: d.open_ports ? JSON.parse(d.open_ports) : []
            },
            session_history: sessions
        }, null, 2));
        console.groupEnd();
        state.lastLoggedMac = d.mac_address;
    }
    
    setElText('detail-name', getDisplayName(d));
    setElText('detail-mac', d.mac_address);
    setElText('det-mfr', d.manufacturer || "Generic Vendor");
    setElText('det-ip', d.ip_address);
    setElText('det-mac', d.mac_address);
    setElText('det-type', d.device_type || 'Unknown');
    setElText('det-os', d.os_guess || 'Scanning / Unknown');
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
        `;
    }).join('');
}

function updatePortsView(ports) {
    if (state.view !== 'detail') return;
    const container = document.getElementById('det-ports-container');
    if (!container) return;

    if (!ports || ports.length === 0) {
        container.innerHTML = '<span class="dim small">No common ports found open.</span>';
        return;
    }

    container.innerHTML = ports.map(p => `
        <div class="port-badge">
            <span class="port-num">${p.port}</span>
            <span class="port-srv">${p.service}</span>
        </div>
    `).join('');
}

// --- D3 Network Map ---
function renderNetworkMap() {
    const container = document.getElementById('d3-container');
    const tooltip = document.getElementById('d3-tooltip');
    if (!container || !window.d3) return;
    container.innerHTML = '';

    const width = container.clientWidth;
    const height = container.clientHeight;

    // Identify Router/Gateway (usually high traffic + lowest IP ending)
    let routerMac = null;
    let maxConf = -1;
    state.devices.forEach(d => {
        if (d.ip_address.endsWith('.1') && d.confidence > maxConf) {
            routerMac = d.mac_address;
            maxConf = d.confidence;
        }
    });

    // Build graph data
    const nodes = state.devices.map(d => ({
        id: d.mac_address,
        name: getDisplayName(d),
        ip: d.ip_address,
        os: d.os_guess || 'Unknown',
        isRouter: d.mac_address === routerMac,
        isOnline: (new Date() - new Date(d.last_seen)) < ONLINE_THRESHOLD_MS,
        icon: getDeviceIcon(d),
        bandwidth: d.total_bytes
    }));

    const links = [];
    nodes.forEach(n => {
        if (!n.isRouter && routerMac) {
            links.push({ source: n.id, target: routerMac });
        }
    });

    const svg = d3.select('#d3-container')
        .append('svg')
        .attr('width', width)
        .attr('height', height);

    // Zoom container
    const g = svg.append('g');
    svg.call(d3.zoom().on('zoom', (e) => g.attr('transform', e.transform)));

    const simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(150))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collide', d3.forceCollide().radius(40));

    // Links
    const link = g.append('g')
        .attr('class', 'links')
        .selectAll('line')
        .data(links)
        .enter().append('line')
        .attr('class', 'link');

    // Nodes
    const node = g.append('g')
        .attr('class', 'nodes')
        .selectAll('g')
        .data(nodes)
        .enter().append('g')
        .attr('class', 'node')
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended))
        .on('click', (event, d) => {
            window.location.hash = `#/device/${encodeURIComponent(d.id)}`;
        })
        .on('mouseover', (event, d) => {
            const mb = d.bandwidth ? (d.bandwidth / (1024*1024)).toFixed(2) : 0;
            tooltip.style.opacity = 1;
            tooltip.innerHTML = `
                <h4>${d.name}</h4>
                <p>IP: <span class="mono">${d.ip}</span></p>
                <p>OS: <span class="mono">${d.os}</span></p>
                <p>Traffic: <span class="mono">${mb} MB</span></p>
            `;
            const containerRect = container.getBoundingClientRect();
            tooltip.style.left = (event.clientX - containerRect.left + 15) + 'px';
            tooltip.style.top = (event.clientY - containerRect.top + 15) + 'px';
        })
        .on('mouseout', () => tooltip.style.opacity = 0);

    // Circles
    node.append('circle')
        .attr('r', d => d.isRouter ? 30 : 20)
        .attr('fill', d => d.isRouter ? '#00d4ff' : (d.isOnline ? '#00ff88' : '#333'))
        .attr('fill-opacity', 0.2)
        .attr('stroke', d => d.isRouter ? '#00d4ff' : (d.isOnline ? '#00ff88' : '#555'))
        .attr('stroke-width', 2);

    // Icons
    node.append('text')
        .text(d => d.isRouter ? '🌐' : d.icon)
        .attr('text-anchor', 'middle')
        .attr('dominant-baseline', 'central')
        .attr('font-size', d => d.isRouter ? '24px' : '16px');

    // Labels
    node.append('text')
        .text(d => d.isRouter ? 'Gateway' : d.name)
        .attr('y', d => d.isRouter ? 45 : 35)
        .attr('text-anchor', 'middle')
        .attr('fill', '#f0f2f5')
        .attr('font-size', '11px')
        .attr('font-family', 'Inter');

    simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);
        node
            .attr('transform', d => `translate(${d.x},${d.y})`);
    });

    function dragstarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x; d.fy = d.y;
    }
    function dragged(event, d) {
        d.fx = event.x; d.fy = event.y;
    }
    function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null; d.fy = null;
    }
}

// ── Tactical Button Wiring ────────────────────────────────────────────────────
function _wireTacticalButtons() {
    const btnStart = document.getElementById('btn-tactical-start');
    const btnStop  = document.getElementById('btn-tactical-stop');
    const btnExport = document.getElementById('btn-export-logs');

    if (btnStart) {
        btnStart.onclick = async () => {
            btnStart.disabled = true; btnStart.textContent = 'STARTING...';
            await fetch(`/api/tactical/${encodeURIComponent(state.selectedMac)}/start`, {method:'POST'}).catch(()=>{});
            refreshData();
        };
    }
    if (btnStop) {
        btnStop.onclick = async () => {
            btnStop.disabled = true; btnStop.textContent = 'STOPPING...';
            await fetch(`/api/tactical/${encodeURIComponent(state.selectedMac)}/stop`, {method:'POST'}).catch(()=>{});
            refreshData();
        };
    }
    if (btnExport) {
        btnExport.onclick = () => {
            window.location.href = `/api/device/${encodeURIComponent(state.selectedMac)}/export`;
        };
    }
}

// ── OS Icon & Signal Helpers ─────────────────────────────────────────────────
function getOsIcon(osGuess) {
    if (!osGuess) return '❓';
    const os = osGuess.toLowerCase();
    if (os.includes('android')) return '🤖';
    if (os.includes('ios') || os.includes('iphone') || os.includes('ipad')) return '🍎';
    if (os.includes('macos') || os.includes('mac os')) return '🖥️';
    if (os.includes('windows')) return '🪟';
    if (os.includes('linux')) return '🐧';
    if (os.includes('chromeos')) return '🌐';
    if (os.includes('cisco') || os.includes('network') || os.includes('router')) return '📡';
    return '💻';
}

function getOsMethod(osGuess) {
    if (!osGuess) return 'Not detected';
    if (osGuess.includes('(UA)'))    return 'User-Agent HTTP Header — Highest Confidence ✅';
    if (osGuess.includes('(DHCP)')) return 'DHCP Option 55 PRL — High Confidence ✅';
    if (osGuess.includes('NetBIOS'))return 'NetBIOS Name Query — High Confidence ✅';
    return 'TCP SYN Packet Analysis — Medium Confidence ⚠️';
}

// ── Protocol Color Map ────────────────────────────────────────────────────────
const PROTO_COLORS = {
    'HTTPS':     '#00d4ff', 'DNS':       '#00ff88', 'HTTP':      '#ffaa00',
    'SSH':       '#bf40ff', 'SMB':       '#ff4466', 'FTP':       '#ff8800',
    'SMTP':      '#ff6666', 'IMAP':      '#ffcc00', 'POP3':      '#aaaaff',
    'NTP':       '#66ccff', 'mDNS':      '#88ff88', 'HTTP-ALT':  '#ffd080',
    'HTTPS-ALT': '#80e0ff', 'OpenVPN':   '#ff80bf', 'MQTT-TLS':  '#80ffcc',
};
function protoColor(p) { return PROTO_COLORS[p] || '#94a3b8'; }

// ── Main Forensics View Updater ──────────────────────────────────────────────
let _dnsAllRows = [];

function updateForensicsView(data, flows, ports, dnsHistory, tactical, stats) {
    if (state.view !== 'forensics') return;
    const d = data.info;
    if (!d) return;

    const isOnline = (new Date() - new Date(d.last_seen)) < ONLINE_THRESHOLD_MS;
    const name = getDisplayName(d);
    const osGuess = d.os_guess || 'Unknown';

    // ── Hero Section ──────────────────────────────────────────────────────────
    setElText('forensics-name', name);
    document.getElementById('forensics-mac').innerHTML = `${d.mac_address} <button class="copy-btn" onclick="copyToClipboard('${d.mac_address}')" title="Copy MAC">📋</button>`;
    setElText('forensics-manufacturer', d.manufacturer || '');
    setElText('forensics-confidence', `${d.confidence || 0}%`);
    setElText('forensics-os-badge', osGuess.replace(/\s*\(UA\)|\s*\(DHCP\)|\s*\(NetBIOS\)/g, ''));

    const iconEl = document.getElementById('forensics-icon');
    if (iconEl) iconEl.textContent = getDeviceIcon(d);

    const statusEl = document.getElementById('forensics-status');
    if (statusEl) {
        statusEl.textContent = isOnline ? '● Online' : '○ Offline';
        statusEl.className = `forensics-status-badge ${isOnline ? '' : 'offline'}`;
    }

    // ── Identity Panel ────────────────────────────────────────────────────────
    document.getElementById('forensics-ip').innerHTML = `${d.ip_address || '--'} <button class="copy-btn" onclick="copyToClipboard('${d.ip_address}')" title="Copy IP">📋</button>`;
    document.getElementById('forensics-mac2').innerHTML = `${d.mac_address || '--'} <button class="copy-btn" onclick="copyToClipboard('${d.mac_address}')" title="Copy MAC">📋</button>`;
    setElText('forensics-type', d.device_type || 'Unknown');
    setElText('forensics-mdns', d.mdns_hostname || 'Not discovered');
    setElText('forensics-ssdp', d.ssdp_info || 'Not discovered');
    setElText('forensics-first-seen', d.first_seen ? new Date(d.first_seen).toLocaleString() : '--');
    setElText('forensics-last-seen', d.last_seen ? new Date(d.last_seen).toLocaleString() : '--');

    // ── OS Fingerprint Panel ──────────────────────────────────────────────────
    const cleanOs = osGuess.replace(/\s*\(UA\)|\s*\(DHCP\)|\s*\(NetBIOS\)/g, '').trim();
    setElText('forensics-os-name', cleanOs);
    setElText('forensics-os-method', 'Method: ' + getOsMethod(osGuess));
    const osIconEl = document.getElementById('forensics-os-icon');
    if (osIconEl) osIconEl.textContent = getOsIcon(osGuess);

    // OS Signal Confidence Badges
    const signalsEl = document.getElementById('forensics-os-signals');
    if (signalsEl) {
        const hasUA    = osGuess.includes('(UA)');
        const hasDHCP  = osGuess.includes('(DHCP)');
        const hasNB    = osGuess.includes('NetBIOS');
        const hasTCP   = !hasUA && !hasDHCP && !hasNB && osGuess !== 'Unknown';
        signalsEl.innerHTML = `
            <span class="os-signal-badge ${hasUA ? 'confirmed' : 'none'}">
                ${hasUA ? '✅' : '○'} User-Agent Header
            </span>
            <span class="os-signal-badge ${hasDHCP ? 'confirmed' : 'none'}">
                ${hasDHCP ? '✅' : '○'} DHCP Option 55 PRL
            </span>
            <span class="os-signal-badge ${hasNB ? 'confirmed' : 'none'}">
                ${hasNB ? '✅' : '○'} NetBIOS Name
            </span>
            <span class="os-signal-badge ${hasTCP ? 'partial' : 'none'}">
                ${hasTCP ? '⚠️' : '○'} TCP SYN Analysis
            </span>
        `;
    }

    // Activity
    setElText('forensics-activity', d.last_activity || 'Passive / No activity detected');
    setElText('forensics-traffic', d.traffic_summary || 'No traffic pattern captured yet.');

    // ── Protocol Breakdown Chart ──────────────────────────────────────────────
    const chartEl = document.getElementById('forensics-proto-chart');
    if (chartEl && stats && stats.top_domains && stats.top_domains.length > 0) {
        const maxCount = Math.max(...stats.top_domains.map(s => s.count));
        chartEl.innerHTML = stats.top_domains.slice(0, 10).map(s => {
            const pct = maxCount > 0 ? (s.count / maxCount * 100) : 0;
            const color = protoColor(s.name);
            return `
                <div class="proto-bar-row">
                    <span class="proto-label">${s.name}</span>
                    <div class="proto-bar-track">
                        <div class="proto-bar-fill" style="width:${pct}%;background:${color};">${s.count > 5 ? s.count : ''}</div>
                    </div>
                    <span class="proto-count">${s.count}</span>
                </div>`;
        }).join('');
    } else if (chartEl) {
        chartEl.innerHTML = '<span class="dim small">No traffic data yet — traffic will appear as devices communicate.</span>';
    }

    // ── Ports ─────────────────────────────────────────────────────────────────
    const portsEl = document.getElementById('forensics-ports');
    if (portsEl) {
        if (!ports || ports.length === 0) {
            portsEl.innerHTML = '<span class="dim small">No common ports found open.</span>';
        } else {
            portsEl.innerHTML = ports.map(p => `
                <div class="port-badge">
                    <span class="port-num">${p.port}</span>
                    <span class="port-srv">${p.service}</span>
                </div>`).join('');
        }
    }

    // ── Tactical Controls ─────────────────────────────────────────────────────
    const btnStart = document.getElementById('btn-tactical-start');
    const btnStop  = document.getElementById('btn-tactical-stop');
    const tacStatus = document.getElementById('tactical-status');
    if (tactical && tactical.intercepting) {
        if (btnStart) btnStart.style.display = 'none';
        if (btnStop)  { btnStop.style.display = 'inline-block'; btnStop.disabled = false; btnStop.textContent = 'STOP INTERCEPTION'; }
        if (tacStatus) tacStatus.innerHTML = '<span style="color:var(--accent-red)">● ACTIVE INTERCEPTION</span>';
    } else {
        if (btnStart) { btnStart.style.display = 'inline-block'; btnStart.disabled = false; btnStart.textContent = 'INITIATE INTERCEPTION'; }
        if (btnStop)  btnStop.style.display = 'none';
        if (tacStatus) tacStatus.textContent = 'Tactical Module Ready';
    }

    // ── DNS History ───────────────────────────────────────────────────────────
    _dnsAllRows = dnsHistory || [];
    _renderDnsTable(_dnsAllRows);

    const dnsSearch = document.getElementById('dns-search');
    if (dnsSearch && !dnsSearch._bound) {
        dnsSearch._bound = true;
        dnsSearch.addEventListener('input', e => {
            const q = e.target.value.toLowerCase();
            _renderDnsTable(_dnsAllRows.filter(r => (r.domain || '').toLowerCase().includes(q)));
        });
    }

    // ── DPI Flows ─────────────────────────────────────────────────────────────
    const flowBody = document.getElementById('forensics-flows-body');
    if (flowBody) {
        if (!flows || flows.length === 0) {
            flowBody.innerHTML = '<tr><td colspan="6" class="dim small" style="text-align:center;padding:20px">No flows captured yet</td></tr>';
        } else {
            flowBody.innerHTML = flows.slice(0, 60).map(f => {
                const host = f.service_label || '';
                const isDomain = host.includes('.') && !/^[0-9.]+$/.test(host);
                const kb = f.byte_count ? (f.byte_count / 1024).toFixed(1) + ' KB' : '--';
                const cleanHost = host.replace('[HTTP-HOST] ', '').replace(/\.tariq-domain\.?$/i, '');
                
                return `<tr>
                    <td class="mono small dim">${new Date(f.timestamp).toLocaleTimeString()}</td>
                    <td class="mono small">
                        ${f.dst_ip || '--'} 
                        <button class="copy-btn" onclick="copyToClipboard('${f.dst_ip}')" title="Copy IP">📋</button>
                    </td>
                    <td>
                        <span class="${isDomain ? 'highlight' : 'dim small'}">${cleanHost || f.dst_ip || '--'}</span>
                        ${cleanHost ? `<button class="copy-btn" onclick="copyToClipboard('${cleanHost}')" title="Copy Host">📋</button>` : ''}
                    </td>
                    <td class="mono small">${f.dst_port || '--'}</td>
                    <td><span style="color:${protoColor(f.protocol)};font-size:0.75rem;font-weight:600">${f.protocol || '--'}</span></td>
                    <td class="mono small dim">${kb}</td>
                </tr>`;
            }).join('');
        }
    }
}

function _renderDnsTable(rows) {
    const body = document.getElementById('forensics-dns-body');
    if (!body) return;
    if (!rows || rows.length === 0) {
        body.innerHTML = '<tr><td colspan="4" class="dim small" style="text-align:center;padding:20px">No DNS queries captured yet</td></tr>';
        return;
    }
    body.innerHTML = rows.slice(0, 200).map((r, i) => {
        let domain = r.domain || r.query || '';
        const method = domain.startsWith('[HTTP-HOST]') ? 'HTTP Host' : 'DNS Query';
        
        // Clean up domain: remove .tariq-domain and other local search domains
        domain = domain.replace('[HTTP-HOST] ', '');
        domain = domain.replace(/\.tariq-domain\.?$/i, '');
        domain = domain.replace(/\.local\.?$/i, '');

        const ts = r.timestamp ? new Date(r.timestamp).toLocaleTimeString() : '--';
        return `<tr>
            <td class="mono dim small">${i + 1}</td>
            <td>
                <span class="${domain.includes('google') || domain.includes('youtube') || domain.includes('facebook') ? 'highlight' : ''}">${domain}</span>
                <button class="copy-btn" onclick="copyToClipboard('${domain}')" title="Copy Domain">📋</button>
            </td>
            <td><span class="os-signal-badge ${method === 'HTTP Host' ? 'confirmed' : 'partial'}">${method}</span></td>
            <td class="mono small dim">${ts}</td>
        </tr>`;
    }).join('');
}
function copyToClipboard(text) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
        showToast(`Copied: ${text.length > 25 ? text.substring(0, 25) + '...' : text}`);
    }).catch(err => {
        console.error('Copy failed:', err);
    });
}

function showToast(message) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `<span>📋</span> ${message}`;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 2500);
}
