/**
 * Phishing Guard - Popup Script v2.3
 * Premium UI with protection modules, site grade, and dashboard integration
 */

import { CONFIG } from './config.js';
import { applyAutoTheme } from './theme.js';

// See background.js for why this one alias is enough for cross-browser support.
const browserAPI = typeof browser !== 'undefined' ? browser : chrome;

// UI Elements
const elements = {
    app: document.getElementById('app'),
    protectionToggle: document.getElementById('protection-toggle'),
    statusHero: document.getElementById('status-hero'),
    statusPill: document.getElementById('status-pill'),
    statusLabel: document.getElementById('status-label'),
    statusDomain: document.getElementById('status-domain'),
    gradeChip: document.getElementById('grade-chip'),
    gradeChipLetter: document.getElementById('grade-chip-letter'),
    statScans: document.getElementById('stat-scans'),
    statThreats: document.getElementById('stat-threats'),
    statUptime: document.getElementById('stat-uptime'),
    threatsSection: document.getElementById('threats-section'),
    threatsList: document.getElementById('threats-list'),
    rescanBtn: document.getElementById('rescan-btn'),
    whitelistBtn: document.getElementById('whitelist-btn'),
    blacklistBtn: document.getElementById('blacklist-btn'),
    historyList: document.getElementById('history-list'),
    seeAllBtn: document.getElementById('see-all-btn'),
    backendIndicator: document.getElementById('backend-indicator'),
    dashboardBtn: document.getElementById('dashboard-btn'),
    passwordCheckerLink: document.getElementById('password-checker-link'),
    siteScannerLink: document.getElementById('site-scanner-link'),
    historyScanBtn: document.getElementById('history-scan-btn'),
    historyScanBtnLabel: document.getElementById('history-scan-btn-label'),
    historyScanResults: document.getElementById('history-scan-results')
};

// State
let state = {
    isEnabled: true,
    currentUrl: null,
    currentDomain: null,
    settings: {
        modules: {
            phishing_protection: true,
            password_guard: true,
            payment_protection: true,
            link_scanner: true
        }
    },
    stats: {
        totalScans: 0,
        threatsBlocked: 0
    }
};

// Initialize
document.addEventListener('DOMContentLoaded', init);

async function init() {
    // Not awaited deliberately - geolocation can take a couple seconds and
    // must never delay the rest of the popup becoming usable. Once a
    // location is cached (after the first successful lookup), this
    // resolves near-instantly on future opens.
    applyAutoTheme(browserAPI);

    // Load state from background
    const response = await sendMessage({ action: 'getStatus' });

    if (response) {
        state.isEnabled = response.isEnabled;
        state.stats = response.stats || state.stats;
    }

    // Update UI
    updateProtectionToggle();
    updateStats();
    await updateCurrentSite();
    if (response?.siteGrade) {
        updateGradeChip(response.siteGrade);
    } else if (state.currentUrl) {
        // Not cached yet (e.g. the tab loaded before this session started) -
        // ask the background to fetch it now rather than waiting forever
        // for a navigation event that already happened.
        updateGradeChip(null, /* loading */ true);
        sendMessage({ action: 'getSiteGrade', url: state.currentUrl }).then((grade) => {
            if (grade && !grade.error) updateGradeChip(grade);
            else updateGradeChip(null);
        });
    }
    await loadHistory();
    await checkBackend();

    // Setup event listeners
    setupEventListeners();

    // Background broadcasts this once a slow /site-scan finishes - pick it
    // up if it lands while the popup happens to be open.
    browserAPI.runtime.onMessage.addListener((message) => {
        if (message?.action === 'siteGradeUpdated' && message.domain === state.currentDomain) {
            updateGradeChip(message.siteGrade);
        }
    });
}

function setupEventListeners() {
    // Protection toggle
    elements.protectionToggle?.addEventListener('click', toggleProtection);

    // Action buttons
    elements.rescanBtn?.addEventListener('click', rescanCurrentSite);
    elements.whitelistBtn?.addEventListener('click', addToWhitelist);
    elements.blacklistBtn?.addEventListener('click', addToBlacklist);

    // Module toggles
    document.querySelectorAll('.module-toggle input').forEach(toggle => {
        toggle.addEventListener('change', handleModuleToggle);
    });

    // Dashboard buttons
    elements.dashboardBtn?.addEventListener('click', openDashboard);
    elements.seeAllBtn?.addEventListener('click', openDashboard);

    // Public security tools
    elements.passwordCheckerLink?.addEventListener('click', openPasswordChecker);
    elements.siteScannerLink?.addEventListener('click', openSiteScanner);

    // Retroactive history scan
    elements.historyScanBtn?.addEventListener('click', runHistoryScan);
}

// ============================================
// PROTECTION TOGGLE
// ============================================

async function toggleProtection() {
    const response = await sendMessage({ action: 'toggleProtection' });
    if (response) {
        state.isEnabled = response.isEnabled;
        updateProtectionToggle();
    }
}

function updateProtectionToggle() {
    if (state.isEnabled) {
        elements.protectionToggle?.classList.add('active');
        elements.app?.classList.remove('disabled');
    } else {
        elements.protectionToggle?.classList.remove('active');
        elements.app?.classList.add('disabled');
        elements.statusLabel.textContent = 'Disabled';
        setStatusPill(null);
    }
}

// ============================================
// MODULE TOGGLES
// ============================================

async function handleModuleToggle(e) {
    const setting = e.target.dataset.setting;
    const enabled = e.target.checked;
    const card = e.target.closest('.module-card');

    // Update local state
    state.settings.modules[setting] = enabled;

    // Update card UI
    if (enabled) {
        if (card) {
            card.classList.add('active');
            const statusEl = card.querySelector('.module-status');
            if (statusEl) statusEl.textContent = 'Active';
        }
    } else {
        if (card) {
            card.classList.remove('active');
            const statusEl = card.querySelector('.module-status');
            if (statusEl) statusEl.textContent = 'Disabled';
        }
    }

    // Send to background
    await sendMessage({
        action: 'updateSettings',
        settings: state.settings
    });
}

// ============================================
// CURRENT SITE STATUS
// ============================================

async function updateCurrentSite() {
    if (!state.isEnabled) return;

    try {
        const [tab] = await browserAPI.tabs.query({ active: true, currentWindow: true });

        if (!tab?.url) {
            elements.statusDomain.textContent = 'No page';
            return;
        }

        // Skip browser pages
        if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
            elements.statusDomain.textContent = 'Browser page';
            elements.statusLabel.textContent = 'Protected';
            setStatusPill('safe');
            return;
        }

        // Extract domain
        try {
            const url = new URL(tab.url);
            state.currentUrl = tab.url;
            state.currentDomain = url.hostname;
            elements.statusDomain.textContent = url.hostname;
        } catch {
            elements.statusDomain.textContent = tab.url.substring(0, 30);
        }

        // Get scan status
        const status = await sendMessage({ action: 'getStatus' });
        if (status?.currentTab) {
            updateScanResult(status.currentTab);
        } else {
            elements.statusLabel.textContent = 'Monitoring';
            setStatusPill('safe');
        }

    } catch (e) {
        console.error('Error updating current site:', e);
    }
}

async function rescanCurrentSite() {
    elements.rescanBtn?.classList.add('loading');
    elements.statusLabel.textContent = 'Scanning...';
    setStatusPill('scanning');

    const response = await sendMessage({ action: 'scanCurrentTab' });

    if (response && !response.error) {
        updateScanResult(response);
        await loadHistory();
    }

    elements.rescanBtn?.classList.remove('loading');
}

function updateScanResult(result) {
    const { risk_level, risk_score, warnings, threat_intel } = result;

    // Update status text
    if (risk_level === 'safe') {
        elements.statusLabel.textContent = 'Protected';
        setStatusPill('safe');
        hideThreats();
    } else if (risk_level === 'warning') {
        elements.statusLabel.textContent = 'Caution';
        setStatusPill('warning');
        showThreats(warnings, threat_intel);
    } else if (risk_level === 'suspicious') {
        elements.statusLabel.textContent = 'Suspicious';
        setStatusPill('suspicious');
        showThreats(warnings, threat_intel);
    } else if (risk_level === 'dangerous') {
        elements.statusLabel.textContent = 'Dangerous';
        setStatusPill('danger');
        showThreats(warnings, threat_intel);
    } else {
        elements.statusLabel.textContent = 'Monitoring';
        setStatusPill('safe');
        hideThreats();
    }

    void risk_score; // no longer visualized as a ring - risk_level + the threats list already convey severity
}

function showThreats(warnings, threatIntel) {
    if (!elements.threatsSection || !elements.threatsList) return;

    const threats = [];

    // Add warnings as threats
    if (warnings && warnings.length > 0) {
        warnings.forEach(warning => {
            threats.push({
                type: getThreatType(warning),
                description: warning,
                severity: getThreatSeverity(warning)
            });
        });
    }

    // Add threat intel types
    if (threatIntel && threatIntel.threat_types) {
        threatIntel.threat_types.forEach(type => {
            if (!threats.find(t => t.type.toLowerCase().includes(type))) {
                threats.push({
                    type: formatThreatType(type),
                    description: getThreatDescription(type),
                    severity: 'high'
                });
            }
        });
    }

    if (threats.length === 0) {
        hideThreats();
        return;
    }

    elements.threatsList.innerHTML = threats.map(threat => `
        <div class="threat-item">
            <div class="threat-info">
                <div class="threat-type">${threat.type}</div>
                <div class="threat-desc">${threat.description}</div>
            </div>
            <span class="threat-severity ${threat.severity}">${threat.severity}</span>
        </div>
    `).join('');

    elements.threatsSection.style.display = 'block';
}

function hideThreats() {
    if (elements.threatsSection) {
        elements.threatsSection.style.display = 'none';
    }
}

function getThreatType(warning) {
    const lower = warning.toLowerCase();
    if (lower.includes('typosquatting')) return 'Typosquatting';
    if (lower.includes('ssl') || lower.includes('https')) return 'SSL/HTTPS Issue';
    if (lower.includes('phishing')) return 'Phishing Pattern';
    if (lower.includes('suspicious tld')) return 'Suspicious Domain';
    if (lower.includes('ip address')) return 'IP Address URL';
    if (lower.includes('keyword')) return 'Suspicious Keywords';
    if (lower.includes('subdomain')) return 'Excessive Subdomains';
    if (lower.includes('@')) return 'Credential Attack';
    if (lower.includes('age') || lower.includes('new domain')) return 'New Domain';
    return 'Security Warning';
}

function getThreatSeverity(warning) {
    const lower = warning.toLowerCase();
    if (lower.includes('typosquatting') || lower.includes('phishing') || lower.includes('@')) return 'high';
    if (lower.includes('ssl') || lower.includes('ip address')) return 'high';
    if (lower.includes('keyword') || lower.includes('tld')) return 'medium';
    return 'low';
}

function formatThreatType(type) {
    return type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

function getThreatDescription(type) {
    const descriptions = {
        'phishing_pattern': 'URL matches known phishing patterns',
        'ssl_issue': 'SSL certificate problem detected',
        'new_domain': 'Domain was recently registered',
        'typosquatting': 'Domain mimics a legitimate website',
        'suspicious_tld': 'Uses a high-risk domain extension'
    };
    return descriptions[type] || 'Security risk detected';
}

// Status is now a plain colored text pill (see popup.css .status-pill) -
// no icon, the color + label text carry the meaning on their own.
function setStatusPill(status) {
    elements.statusPill?.classList.remove('safe', 'warning', 'suspicious', 'danger', 'scanning');
    elements.statusHero?.classList.remove('safe', 'warning', 'suspicious', 'danger');

    if (status) {
        elements.statusPill?.classList.add(status);
        elements.statusHero?.classList.add(status);
    }
}

// ============================================
// WHITELIST / BLACKLIST
// ============================================

async function addToWhitelist() {
    if (!state.currentDomain) return;

    const response = await sendMessage({
        action: 'addToWhitelist',
        domain: state.currentDomain
    });

    if (response?.success) {
        showNotification('Added to whitelist', 'success');
        await rescanCurrentSite();
    }
}

async function addToBlacklist() {
    if (!state.currentDomain) return;

    const response = await sendMessage({
        action: 'addToBlacklist',
        domain: state.currentDomain
    });

    if (response?.success) {
        showNotification('Added to blacklist', 'danger');
        await rescanCurrentSite();
    }
}

// ============================================
// STATS
// ============================================

function updateStats() {
    if (elements.statScans) {
        elements.statScans.textContent = formatNumber(state.stats.totalScans || 0);
    }
    if (elements.statThreats) {
        elements.statThreats.textContent = formatNumber(state.stats.threatsBlocked || 0);
    }
}

function formatNumber(num) {
    if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'k';
    }
    return num.toString();
}

// ============================================
// HISTORY
// ============================================

async function loadHistory() {
    const response = await sendMessage({ action: 'getHistory' });

    if (!elements.historyList) return;

    if (!response?.history || response.history.length === 0) {
        elements.historyList.innerHTML = `
            <div class="history-empty">
                <span>No activity yet</span>
            </div>
        `;
        return;
    }

    const html = response.history.slice(0, 5).map(item => {
        const hostname = getHostname(item.url);
        const risk = item.risk_level || 'safe';
        const time = getTimeAgo(item.timestamp);

        return `
            <div class="history-row ${risk}">
                <span class="h-site" title="${hostname}">${hostname}</span>
                <span class="h-status">${risk}</span>
                <span class="h-time">${time}</span>
            </div>
        `;
    }).join('');

    elements.historyList.innerHTML = html;
}

function getHostname(url) {
    try {
        return new URL(url).hostname.replace('www.', '');
    } catch {
        return url?.substring(0, 20) || '?';
    }
}

function getTimeAgo(timestamp) {
    if (!timestamp) return '';
    try {
        const diff = Date.now() - new Date(timestamp).getTime();
        if (diff < 60000) return 'now';
        if (diff < 3600000) return Math.floor(diff / 60000) + 'm';
        if (diff < 86400000) return Math.floor(diff / 3600000) + 'h';
        return Math.floor(diff / 86400000) + 'd';
    } catch {
        return '';
    }
}

// ============================================
// RETROACTIVE HISTORY SCAN
// ============================================

async function runHistoryScan() {
    if (!elements.historyScanBtn || !elements.historyScanResults) return;

    elements.historyScanBtn.disabled = true;
    elements.historyScanBtn.classList.add('loading');
    elements.historyScanBtnLabel.textContent = 'Scanning…';
    elements.historyScanResults.style.display = 'none';

    const response = await sendMessage({ action: 'scanBrowsingHistory', days: 7 });

    elements.historyScanBtn.disabled = false;
    elements.historyScanBtn.classList.remove('loading');
    elements.historyScanBtnLabel.textContent = 'Scan My Recent History';

    renderHistoryScanResults(response);
}

function renderHistoryScanResults(response) {
    if (!elements.historyScanResults) return;

    if (!response || response.error) {
        elements.historyScanResults.innerHTML = `
            <div class="history-scan-empty">Couldn't complete the scan${response?.error ? `: ${response.error}` : ''}.</div>
        `;
        elements.historyScanResults.style.display = 'block';
        return;
    }

    if (response.scanned === 0) {
        elements.historyScanResults.innerHTML = `
            <div class="history-scan-empty">No recent history to check (or everything's already whitelisted).</div>
        `;
        elements.historyScanResults.style.display = 'block';
        return;
    }

    if (response.flagged.length === 0) {
        elements.historyScanResults.innerHTML = `
            <div class="history-scan-clean">
                <span>✓</span> Checked ${response.scanned} sites from your recent history - nothing flagged.
            </div>
        `;
        elements.historyScanResults.style.display = 'block';
        return;
    }

    const rows = response.flagged.map((item) => {
        const hostname = getHostname(item.url);
        return `
            <div class="history-scan-row ${item.risk_level || 'suspicious'}">
                <span class="h-site" title="${hostname}">${hostname}</span>
                <span class="h-status">${item.risk_level || 'flagged'}</span>
            </div>
        `;
    }).join('');

    elements.historyScanResults.innerHTML = `
        <div class="history-scan-summary">
            Checked ${response.scanned} sites - ${response.flagged.length} flagged:
        </div>
        ${rows}
    `;
    elements.historyScanResults.style.display = 'block';
}

// ============================================
// BACKEND STATUS
// ============================================

async function checkBackend() {
    const response = await sendMessage({ action: 'checkBackend' });

    if (response?.healthy) {
        elements.backendIndicator?.classList.remove('offline');
        elements.backendIndicator.querySelector('.backend-text').textContent = 'API Connected';
    } else {
        elements.backendIndicator?.classList.add('offline');
        elements.backendIndicator.querySelector('.backend-text').textContent = 'API Offline';
    }
}

// ============================================
// DASHBOARD
// ============================================

function openDashboard() {
    browserAPI.tabs.create({ url: CONFIG.DASHBOARD_URL });
}

function openPasswordChecker() {
    browserAPI.tabs.create({ url: `${CONFIG.DASHBOARD_URL}/tools/password-checker` });
}

function openSiteScanner() {
    // Prefill with the current tab's domain when we have one, so the user
    // lands on a scan already in progress for the site they were just on.
    const url = new URL(`${CONFIG.DASHBOARD_URL}/tools/site-scanner`);
    if (state.currentDomain) {
        url.searchParams.set('url', state.currentDomain);
    }
    browserAPI.tabs.create({ url: url.href });
}

// ============================================
// SITE SECURITY GRADE
// ============================================

function updateGradeChip(siteGrade, loading = false) {
    if (!elements.gradeChip || !elements.gradeChipLetter) return;

    if (loading) {
        elements.gradeChip.style.display = 'inline-flex';
        elements.gradeChip.dataset.grade = 'loading';
        elements.gradeChip.title = 'Checking site security grade…';
        elements.gradeChipLetter.textContent = '·';
        return;
    }

    if (!siteGrade?.grade) {
        elements.gradeChip.style.display = 'none';
        return;
    }

    elements.gradeChip.style.display = 'inline-flex';
    elements.gradeChip.dataset.grade = siteGrade.grade;
    elements.gradeChipLetter.textContent = siteGrade.grade;
    const scoreText = siteGrade.score !== undefined ? ` (${siteGrade.score}/100)` : '';
    elements.gradeChip.title = `Site security grade: ${siteGrade.grade}${scoreText}`;
}

// ============================================
// NOTIFICATIONS
// ============================================

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `popup-notification ${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        bottom: 80px;
        left: 50%;
        transform: translateX(-50%);
        padding: 10px 20px;
        background: ${type === 'success' ? '#22c55e' : type === 'danger' ? '#ef4444' : '#3b82f6'};
        color: white;
        border-radius: 8px;
        font-size: 12px;
        font-weight: 600;
        z-index: 1000;
        animation: slideUp 0.3s ease;
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = 'slideDown 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 2000);
}

// ============================================
// MESSAGING
// ============================================

function sendMessage(message) {
    return new Promise(resolve => {
        browserAPI.runtime.sendMessage(message, response => {
            resolve(browserAPI.runtime.lastError ? null : response);
        });
    });
}

// Add animation keyframes
const style = document.createElement('style');
style.textContent = `
    @keyframes slideUp {
        from { opacity: 0; transform: translateX(-50%) translateY(20px); }
        to { opacity: 1; transform: translateX(-50%) translateY(0); }
    }
    @keyframes slideDown {
        from { opacity: 1; transform: translateX(-50%) translateY(0); }
        to { opacity: 0; transform: translateX(-50%) translateY(20px); }
    }
`;
document.head.appendChild(style);
