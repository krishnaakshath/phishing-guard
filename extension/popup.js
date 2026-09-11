/**
 * Phishing Guard - Popup Script v2.1
 * Premium UI with protection modules, site grade, and dashboard integration
 */

import { CONFIG } from './config.js';

// UI Elements
const elements = {
    app: document.getElementById('app'),
    protectionToggle: document.getElementById('protection-toggle'),
    settingsBtn: document.getElementById('settings-btn'),
    statusHero: document.getElementById('status-hero'),
    statusRing: document.getElementById('status-ring'),
    statusIcon: document.getElementById('status-icon'),
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
    siteScannerLink: document.getElementById('site-scanner-link')
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
    chrome.runtime.onMessage.addListener((message) => {
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

    // Settings/Dashboard buttons
    elements.settingsBtn?.addEventListener('click', openDashboard);
    elements.dashboardBtn?.addEventListener('click', openDashboard);
    elements.seeAllBtn?.addEventListener('click', openDashboard);

    // Public security tools
    elements.passwordCheckerLink?.addEventListener('click', openPasswordChecker);
    elements.siteScannerLink?.addEventListener('click', openSiteScanner);
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
        elements.statusRing?.classList.remove('safe', 'warning', 'danger');
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
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        if (!tab?.url) {
            elements.statusDomain.textContent = 'No page';
            return;
        }

        // Skip browser pages
        if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
            elements.statusDomain.textContent = 'Browser page';
            elements.statusLabel.textContent = 'Protected';
            setStatusRing('safe');
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
            setStatusRing('safe');
        }

    } catch (e) {
        console.error('Error updating current site:', e);
    }
}

async function rescanCurrentSite() {
    elements.rescanBtn?.classList.add('loading');
    elements.statusLabel.textContent = 'Scanning...';
    setStatusRing('scanning');

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
        setStatusRing('safe');
        hideThreats();
    } else if (risk_level === 'warning') {
        elements.statusLabel.textContent = 'Caution';
        setStatusRing('warning');
        showThreats(warnings, threat_intel);
    } else if (risk_level === 'suspicious') {
        elements.statusLabel.textContent = 'Suspicious';
        setStatusRing('suspicious');
        showThreats(warnings, threat_intel);
    } else if (risk_level === 'dangerous') {
        elements.statusLabel.textContent = 'Dangerous';
        setStatusRing('danger');
        showThreats(warnings, threat_intel);
    } else {
        elements.statusLabel.textContent = 'Monitoring';
        setStatusRing('safe');
        hideThreats();
    }

    // Update ring progress based on risk score
    const progress = elements.statusRing?.querySelector('.ring-progress');
    if (progress && risk_score !== undefined) {
        const safeScore = 100 - risk_score;
        const offset = 283 - (283 * safeScore / 100);
        progress.style.strokeDashoffset = offset;
    }
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
                severity: getThreatSeverity(warning),
                icon: getThreatIcon(warning)
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
                    severity: 'high',
                    icon: getThreatIconByType(type)
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
            <div class="threat-icon">${threat.icon}</div>
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

function getThreatIcon(warning) {
    const lower = warning.toLowerCase();
    if (lower.includes('typosquatting')) return '🎭';
    if (lower.includes('ssl') || lower.includes('https')) return '🔓';
    if (lower.includes('phishing')) return '🎣';
    if (lower.includes('tld') || lower.includes('domain')) return '🌐';
    if (lower.includes('ip address')) return '📍';
    if (lower.includes('keyword')) return '🔤';
    if (lower.includes('@')) return '📧';
    if (lower.includes('age')) return '📅';
    return '⚠️';
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

function getThreatIconByType(type) {
    const icons = {
        'phishing_pattern': '🎣',
        'ssl_issue': '🔓',
        'new_domain': '📅',
        'typosquatting': '🎭',
        'suspicious_tld': '🌐'
    };
    return icons[type] || '⚠️';
}

function setStatusRing(status) {
    elements.statusRing?.classList.remove('safe', 'warning', 'suspicious', 'danger', 'scanning');
    elements.statusHero?.classList.remove('safe', 'warning', 'suspicious', 'danger');

    if (status) {
        elements.statusRing?.classList.add(status);
        elements.statusHero?.classList.add(status);
    }

    // Update icon
    const icons = {
        safe: '<path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>',
        warning: '<path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/>',
        suspicious: '<path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/>',
        danger: '<path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>',
        scanning: '<path d="M17.65 6.35C16.2 4.9 14.21 4 12 4C7.58 4 4.01 7.58 4.01 12C4.01 16.42 7.58 20 12 20C15.73 20 18.84 17.45 19.73 14H17.65C16.83 16.33 14.61 18 12 18C8.69 18 6 15.31 6 12C6 8.69 8.69 6 12 6C13.66 6 15.14 6.69 16.22 7.78L13 11H20V4L17.65 6.35Z"/>'
    };

    if (elements.statusIcon && icons[status]) {
        elements.statusIcon.innerHTML = `<svg viewBox="0 0 24 24" fill="currentColor">${icons[status]}</svg>`;
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
                <span class="empty-icon">📊</span>
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
    chrome.tabs.create({ url: CONFIG.DASHBOARD_URL });
}

function openPasswordChecker() {
    chrome.tabs.create({ url: `${CONFIG.DASHBOARD_URL}/tools/password-checker` });
}

function openSiteScanner() {
    // Prefill with the current tab's domain when we have one, so the user
    // lands on a scan already in progress for the site they were just on.
    const url = new URL(`${CONFIG.DASHBOARD_URL}/tools/site-scanner`);
    if (state.currentDomain) {
        url.searchParams.set('url', state.currentDomain);
    }
    chrome.tabs.create({ url: url.href });
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
        chrome.runtime.sendMessage(message, response => {
            resolve(chrome.runtime.lastError ? null : response);
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
