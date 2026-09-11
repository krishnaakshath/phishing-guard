/**
 * Phishing Guard - Background Service Worker v2.1
 * Enhanced monitoring with threat intelligence, settings sync,
 * site security grading, and outbound link scanning
 */

import { CONFIG } from './config.js';

// Firefox provides a native, Promise-based `browser` global; Chrome's MV3
// `chrome.*` APIs also return Promises when no callback is passed (which
// is the only way this file calls them), so this one alias is enough to
// run on both without a bundled polyfill.
const browserAPI = typeof browser !== 'undefined' ? browser : chrome;

const API_BASE = CONFIG.API_URL;

// Site security grades don't change minute to minute, so we cache them
// per-domain for the browser session instead of re-hitting the (slower,
// server-side-fetching) /site-scan endpoint on every visit.
const GRADE_CACHE_KEY = 'pgSiteGradeCache';
const LINK_SCAN_CACHE_KEY = 'pgLinkScanCache';
const MAX_LINK_CACHE_ENTRIES = 500;

// Extension state
const state = {
    isEnabled: true,
    scanHistory: [],
    currentTabStatus: {},
    // domain -> { grade, score, header_findings, tls_findings, cookie_findings, fetchedAt }
    siteGradeCache: {},
    // url -> { is_phishing, risk_score, risk_level, fetchedAt }
    linkScanCache: {},
    settings: {
        protection_level: 'medium',
        modules: {
            phishing_protection: true,
            password_guard: true,
            payment_protection: true,
            link_scanner: true
        },
        preferences: {
            real_time_alerts: true,
            auto_block_dangerous: true,
            notification_sound: false
        }
    },
    whitelist: [],
    blacklist: [],
    stats: {
        totalScans: 0,
        threatsBlocked: 0
    },
    apiKey: null
};

// ============================================
// INITIALIZATION
// ============================================

browserAPI.runtime.onInstalled.addListener(async () => {
    console.log('Phishing Guard v2.1 installed');
    await loadState();
    await loadSessionCaches();
    updateBadge('active');
});

browserAPI.runtime.onStartup.addListener(async () => {
    await loadState();
    await loadSessionCaches();
    updateBadge(state.isEnabled ? 'active' : 'disabled');
});

async function loadState() {
    try {
        const saved = await browserAPI.storage.local.get([
            'isEnabled', 'stats', 'scanHistory', 'settings',
            'whitelist', 'blacklist', 'apiKey'
        ]);

        if (saved.isEnabled !== undefined) state.isEnabled = saved.isEnabled;
        if (saved.stats) state.stats = saved.stats;
        if (saved.scanHistory) state.scanHistory = saved.scanHistory.slice(-100);
        if (saved.settings) state.settings = { ...state.settings, ...saved.settings };
        if (saved.whitelist) state.whitelist = saved.whitelist;
        if (saved.blacklist) state.blacklist = saved.blacklist;
        if (saved.apiKey) state.apiKey = saved.apiKey;
    } catch (e) {
        console.error('Error loading state:', e);
    }
}

// Site-grade and link-scan results are cached in browserAPI.storage.session so
// they survive a service-worker restart but are cleared when the browser
// session ends - matching the "cache for the session" requirement without
// letting stale security grades persist indefinitely like browserAPI.storage.local.
async function loadSessionCaches() {
    try {
        if (!browserAPI.storage.session) return; // older Chrome without session storage
        const saved = await browserAPI.storage.session.get([GRADE_CACHE_KEY, LINK_SCAN_CACHE_KEY]);
        if (saved[GRADE_CACHE_KEY]) state.siteGradeCache = saved[GRADE_CACHE_KEY];
        if (saved[LINK_SCAN_CACHE_KEY]) state.linkScanCache = saved[LINK_SCAN_CACHE_KEY];
    } catch (e) {
        console.error('Error loading session caches:', e);
    }
}

async function saveSiteGradeCache() {
    try {
        if (!browserAPI.storage.session) return;
        await browserAPI.storage.session.set({ [GRADE_CACHE_KEY]: state.siteGradeCache });
    } catch (e) {
        console.error('Error saving site grade cache:', e);
    }
}

async function saveLinkScanCache() {
    try {
        if (!browserAPI.storage.session) return;
        // Keep the cache bounded so a long browsing session doesn't grow forever.
        const entries = Object.entries(state.linkScanCache);
        if (entries.length > MAX_LINK_CACHE_ENTRIES) {
            entries.sort((a, b) => (a[1]?.fetchedAt || 0) - (b[1]?.fetchedAt || 0));
            const toRemove = entries.slice(0, entries.length - MAX_LINK_CACHE_ENTRIES);
            for (const [url] of toRemove) delete state.linkScanCache[url];
        }
        await browserAPI.storage.session.set({ [LINK_SCAN_CACHE_KEY]: state.linkScanCache });
    } catch (e) {
        console.error('Error saving link scan cache:', e);
    }
}

async function saveState() {
    try {
        await browserAPI.storage.local.set({
            isEnabled: state.isEnabled,
            stats: state.stats,
            scanHistory: state.scanHistory.slice(-100),
            settings: state.settings,
            whitelist: state.whitelist,
            blacklist: state.blacklist,
            apiKey: state.apiKey
        });
    } catch (e) {
        console.error('Error saving state:', e);
    }
}

// ============================================
// TAB MONITORING
// ============================================

browserAPI.webNavigation.onCompleted.addListener(async (details) => {
    if (details.frameId !== 0) return;
    if (!state.isEnabled) return;

    try {
        const tab = await browserAPI.tabs.get(details.tabId);
        if (!tab.url) return;

        // Skip chrome:// and extension pages
        if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
            updateBadgeForTab(details.tabId, 'inactive');
            return;
        }

        await scanUrl(tab.url, details.tabId);

        // Fire the (slower, server-side-fetching) site grade check separately
        // so it never blocks or delays the fast phishing scan above.
        getSiteGrade(tab.url, details.tabId).catch((e) => {
            console.error('Site grade fetch error:', e);
        });
    } catch (e) {
        console.error('Navigation handler error:', e);
    }
});

browserAPI.tabs.onActivated.addListener(async (activeInfo) => {
    try {
        const tab = await browserAPI.tabs.get(activeInfo.tabId);
        if (!tab.url) return;

        applyCombinedBadge(activeInfo.tabId, tab.url);
    } catch (e) {
        // Tab might not exist
    }
});

browserAPI.tabs.onRemoved.addListener((tabId) => {
    delete state.currentTabStatus[tabId];
});

// ============================================
// MESSAGE HANDLER
// ============================================

browserAPI.runtime.onMessage.addListener((request, sender, sendResponse) => {
    handleMessage(request, sender).then(sendResponse);
    return true;
});

async function handleMessage(request, sender) {
    switch (request.action) {
        case 'getStatus':
            return {
                isEnabled: state.isEnabled,
                stats: state.stats,
                settings: state.settings,
                currentTab: await getCurrentTabStatus(),
                siteGrade: await getCurrentTabGrade()
            };

        case 'toggleProtection':
            state.isEnabled = !state.isEnabled;
            await saveState();
            updateBadge(state.isEnabled ? 'active' : 'disabled');
            return { isEnabled: state.isEnabled };

        case 'updateSettings':
            if (request.settings) {
                state.settings = { ...state.settings, ...request.settings };
                await saveState();
            }
            return { success: true, settings: state.settings };

        case 'scanCurrentTab':
            const [tab] = await browserAPI.tabs.query({ active: true, currentWindow: true });
            if (tab?.url) {
                return await scanUrl(tab.url, tab.id, true);
            }
            return { error: 'No active tab' };

        case 'getHistory':
            return { history: state.scanHistory.slice(-20).reverse() };

        case 'contentScan':
            if (sender.tab) {
                return await scanWithContent(sender.tab.url, sender.tab.id, request.content);
            }
            return { error: 'No tab context' };

        case 'addToWhitelist':
            if (request.domain) {
                return await addToWhitelist(request.domain);
            }
            return { error: 'Domain required' };

        case 'addToBlacklist':
            if (request.domain) {
                return await addToBlacklist(request.domain);
            }
            return { error: 'Domain required' };

        case 'getWhitelist':
            return { whitelist: state.whitelist };

        case 'getBlacklist':
            return { blacklist: state.blacklist };

        case 'checkBackend':
            return await checkBackendHealth();

        case 'setApiKey':
            state.apiKey = request.apiKey;
            await saveState();
            return { success: true };

        case 'getSiteGrade': {
            const [activeTab] = await browserAPI.tabs.query({ active: true, currentWindow: true });
            const url = request.url || activeTab?.url;
            const tabId = request.tabId ?? activeTab?.id;
            if (!url) return { error: 'No URL available' };
            return await getSiteGrade(url, tabId, !!request.forceRefresh);
        }

        case 'scanLinks':
            if (sender.tab && Array.isArray(request.urls)) {
                return await scanOutboundLinks(request.urls, sender.tab.id);
            }
            return { error: 'No tab context or urls' };

        case 'scanBrowsingHistory':
            // Explicit, user-triggered action from the popup only - never
            // runs automatically, and reads browserAPI.history solely to build
            // a list of domains to check, not to report browsing history
            // anywhere itself.
            return await scanBrowsingHistory(request.days || 7);

        default:
            return { error: 'Unknown action' };
    }
}

// ============================================
// URL SCANNING
// ============================================

async function scanUrl(url, tabId, forceRescan = false) {
    // Check if module is enabled
    if (!state.settings.modules.phishing_protection) {
        return { skipped: true, reason: 'Module disabled' };
    }

    // Check whitelist
    const domain = getDomain(url);
    if (state.whitelist.includes(domain)) {
        const result = {
            url,
            domain,
            is_phishing: false,
            risk_score: 0,
            risk_level: 'safe',
            warnings: [],
            whitelisted: true
        };
        state.currentTabStatus[tabId] = result;
        applyCombinedBadge(tabId, url);
        return result;
    }

    // Check blacklist
    if (state.blacklist.includes(domain)) {
        const result = {
            url,
            domain,
            is_phishing: true,
            risk_score: 100,
            risk_level: 'dangerous',
            warnings: ['Domain is in your blacklist'],
            blacklisted: true
        };
        state.currentTabStatus[tabId] = result;
        applyCombinedBadge(tabId, url);
        showPhishingWarning(tabId, result);
        return result;
    }

    // Check cache if not forcing rescan
    if (!forceRescan && state.currentTabStatus[tabId]?.url === url) {
        return state.currentTabStatus[tabId];
    }

    updateBadgeForTab(tabId, 'scanning');

    try {
        const headers = { 'Content-Type': 'application/json' };
        if (state.apiKey) {
            headers['X-API-Key'] = state.apiKey;
        }

        const response = await fetch(`${API_BASE}/scan`, {
            method: 'POST',
            headers,
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }

        const result = await response.json();

        // Update stats
        state.stats.totalScans++;
        if (result.analysis.is_phishing) {
            state.stats.threatsBlocked++;
        }

        // Store result
        const scanResult = {
            url,
            tabId,
            timestamp: new Date().toISOString(),
            ...result.analysis
        };

        state.currentTabStatus[tabId] = scanResult;
        state.scanHistory.push(scanResult);

        await saveState();

        // Update badge
        applyCombinedBadge(tabId, url);

        // Show warning for dangerous sites
        if (result.analysis.risk_level === 'dangerous') {
            if (state.settings.preferences.auto_block_dangerous) {
                showPhishingWarning(tabId, result.analysis);
            }
        } else if (result.analysis.risk_level === 'suspicious') {
            showSuspiciousWarning(tabId, result.analysis);
        }

        // Notify content script
        notifyContentScript(tabId, result.analysis);

        return scanResult;

    } catch (error) {
        console.error('Scan error:', error);
        updateBadgeForTab(tabId, 'error');

        return {
            url,
            error: error.message,
            risk_level: 'unknown',
            is_phishing: false
        };
    }
}

async function scanWithContent(url, tabId, content) {
    if (!state.settings.modules.phishing_protection) {
        return { skipped: true };
    }

    try {
        const headers = { 'Content-Type': 'application/json' };
        if (state.apiKey) {
            headers['X-API-Key'] = state.apiKey;
        }

        const response = await fetch(`${API_BASE}/scan`, {
            method: 'POST',
            headers,
            body: JSON.stringify({ url, content })
        });

        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }

        const result = await response.json();

        // Update existing result with content analysis
        if (state.currentTabStatus[tabId]) {
            state.currentTabStatus[tabId] = {
                ...state.currentTabStatus[tabId],
                ...result.analysis,
                contentScanned: true
            };
        }

        if (state.currentTabStatus[tabId]) {
            applyCombinedBadge(tabId, state.currentTabStatus[tabId].url || url);
        } else {
            updateBadgeForTab(tabId, result.analysis.risk_level);
        }

        if (result.analysis.is_phishing) {
            state.stats.threatsBlocked++;
            await saveState();

            if (result.analysis.risk_level === 'dangerous') {
                showPhishingWarning(tabId, result.analysis);
            }
        }

        return result.analysis;

    } catch (error) {
        console.error('Content scan error:', error);
        return { error: error.message };
    }
}

// ============================================
// SITE SECURITY GRADE (A-F)
// ============================================

/**
 * Fetches the public /site-scan security posture grade for a URL and
 * caches it per-domain for the browser session. This call is intentionally
 * decoupled from scanUrl()/scanWithContent() - it hits a slower endpoint
 * that fetches the page server-side, so it must never block the fast
 * phishing scan the rest of the extension relies on.
 */
async function getSiteGrade(url, tabId, forceRefresh = false) {
    const domain = getDomain(url);
    if (!domain) return { error: 'Invalid URL' };

    const cached = state.siteGradeCache[domain];
    if (cached && !forceRefresh) {
        if (tabId !== undefined) applyCombinedBadge(tabId, url);
        return { ...cached, cached: true };
    }

    try {
        const response = await fetch(`${API_BASE}/site-scan?url=${encodeURIComponent(url)}`);

        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }

        const data = await response.json();
        const posture = data.posture || {};

        const gradeResult = {
            grade: posture.grade || null,
            score: posture.score,
            header_findings: posture.header_findings || [],
            tls_findings: posture.tls_findings || [],
            cookie_findings: posture.cookie_findings || [],
            threat_intel: data.threat_intel || null,
            fetchedAt: Date.now()
        };

        state.siteGradeCache[domain] = gradeResult;
        await saveSiteGradeCache();

        if (tabId !== undefined) {
            applyCombinedBadge(tabId, url);
            // Let an open popup know a grade just landed, in case it's
            // showing "Grading..." for the tab it's currently displaying.
            browserAPI.runtime.sendMessage({
                action: 'siteGradeUpdated',
                tabId,
                domain,
                siteGrade: gradeResult
            }).catch(() => { });
        }

        return { ...gradeResult, cached: false };

    } catch (error) {
        console.error('Site grade fetch error:', error);
        return { error: error.message };
    }
}

async function getCurrentTabGrade() {
    try {
        const [tab] = await browserAPI.tabs.query({ active: true, currentWindow: true });
        if (!tab?.url) return null;
        const domain = getDomain(tab.url);
        return state.siteGradeCache[domain] || null;
    } catch {
        return null;
    }
}

// ============================================
// OUTBOUND LINK SCANNING
// ============================================

/**
 * Batch-scans a page's outbound links via /batch-scan. Results are cached
 * per-URL for the session so revisiting a page (or hitting several pages
 * that link to the same URL) doesn't re-scan links we've already checked.
 */
async function scanOutboundLinks(urls, tabId) {
    if (!state.settings.modules.link_scanner) {
        return { skipped: true, reason: 'Module disabled' };
    }

    const uniqueUrls = [...new Set(urls)].filter(Boolean).slice(0, 50);
    if (uniqueUrls.length === 0) {
        return { success: true, results: [] };
    }

    const results = [];
    const toFetch = [];

    for (const url of uniqueUrls) {
        const cached = state.linkScanCache[url];
        if (cached) {
            results.push({ url, ...cached });
        } else {
            toFetch.push(url);
        }
    }

    if (toFetch.length > 0) {
        try {
            const headers = { 'Content-Type': 'application/json' };
            if (state.apiKey) {
                headers['X-API-Key'] = state.apiKey;
            }

            const response = await fetch(`${API_BASE}/batch-scan`, {
                method: 'POST',
                headers,
                body: JSON.stringify({ urls: toFetch })
            });

            if (!response.ok) {
                throw new Error(`API error: ${response.status}`);
            }

            const data = await response.json();

            for (const item of data.results || []) {
                const entry = {
                    is_phishing: item.is_phishing,
                    risk_score: item.risk_score,
                    risk_level: item.risk_level,
                    fetchedAt: Date.now()
                };
                state.linkScanCache[item.url] = entry;
                results.push({ url: item.url, ...entry });
            }

            await saveLinkScanCache();

        } catch (error) {
            console.error('Batch link scan error:', error);
            // Degrade gracefully: return whatever we already had cached
            // rather than throwing, so the page just shows fewer markers.
        }
    }

    return { success: true, results };
}

// ============================================
// RETROACTIVE HISTORY SCAN
// ============================================

/**
 * Checks recent browser history against the threat feeds in one pass -
 * opt-in only, triggered by a button in the popup. Only ever sends
 * distinct hostnames (as "https://hostname") to the backend, not full
 * URLs or page paths, to avoid leaking more of the user's actual browsing
 * history than necessary for the check.
 */
async function scanBrowsingHistory(days = 7) {
    if (!browserAPI.history) {
        return { error: 'History permission not available' };
    }

    const startTime = Date.now() - days * 24 * 60 * 60 * 1000;

    const items = await browserAPI.history.search({
        text: '',
        startTime,
        maxResults: 1000
    });

    const domains = new Set();
    for (const item of items) {
        const domain = getDomain(item.url || '');
        if (domain && !state.whitelist.includes(domain)) {
            domains.add(domain);
        }
    }

    const targets = [...domains].slice(0, 50).map((d) => `https://${d}`);
    if (targets.length === 0) {
        return { success: true, scanned: 0, flagged: [] };
    }

    const scanResult = await scanOutboundLinksIgnoringModuleToggle(targets);

    const flagged = scanResult.results.filter(
        (r) => r.risk_level === 'suspicious' || r.risk_level === 'dangerous' || r.is_phishing
    );

    return {
        success: true,
        scanned: targets.length,
        historyItemsChecked: items.length,
        flagged
    };
}

/**
 * Same batch-scan mechanics as scanOutboundLinks(), but callable from the
 * popup's explicit "scan my history" button regardless of whether the
 * passive link_scanner module is toggled on - this is a separate,
 * deliberately-triggered action, not passive page scanning.
 */
async function scanOutboundLinksIgnoringModuleToggle(urls) {
    const uniqueUrls = [...new Set(urls)].filter(Boolean).slice(0, 50);
    if (uniqueUrls.length === 0) {
        return { success: true, results: [] };
    }

    const results = [];
    const toFetch = [];

    for (const url of uniqueUrls) {
        const cached = state.linkScanCache[url];
        if (cached) {
            results.push({ url, ...cached });
        } else {
            toFetch.push(url);
        }
    }

    if (toFetch.length > 0) {
        try {
            const headers = { 'Content-Type': 'application/json' };
            if (state.apiKey) {
                headers['X-API-Key'] = state.apiKey;
            }

            const response = await fetch(`${API_BASE}/batch-scan`, {
                method: 'POST',
                headers,
                body: JSON.stringify({ urls: toFetch })
            });

            if (!response.ok) {
                throw new Error(`API error: ${response.status}`);
            }

            const data = await response.json();

            for (const item of data.results || []) {
                const entry = {
                    is_phishing: item.is_phishing,
                    risk_score: item.risk_score,
                    risk_level: item.risk_level,
                    fetchedAt: Date.now()
                };
                state.linkScanCache[item.url] = entry;
                results.push({ url: item.url, ...entry });
            }

            await saveLinkScanCache();

        } catch (error) {
            console.error('History scan error:', error);
        }
    }

    return { success: true, results };
}

// ============================================
// COMBINED BADGE (risk level + site grade)
// ============================================

const GRADE_BADGE_COLORS = {
    A: '#22c55e',
    B: '#84cc16',
    C: '#f59e0b',
    D: '#f97316',
    F: '#ef4444'
};

/**
 * The toolbar badge can only show one thing at a time. An active threat
 * (suspicious/dangerous/scanning/error) always takes priority since it's
 * actionable right now; otherwise, when the page is clear, we supplement
 * the plain checkmark with the site's A-F security grade if we have one.
 */
function applyCombinedBadge(tabId, url) {
    const status = state.currentTabStatus[tabId];
    const riskLevel = status?.risk_level;

    if (riskLevel && ['dangerous', 'suspicious', 'warning'].includes(riskLevel)) {
        updateBadgeForTab(tabId, riskLevel);
        return;
    }

    const domain = getDomain(url || status?.url || '');
    const grade = domain ? state.siteGradeCache[domain] : null;

    if (grade?.grade && GRADE_BADGE_COLORS[grade.grade]) {
        browserAPI.action.setBadgeText({ tabId, text: grade.grade });
        browserAPI.action.setBadgeBackgroundColor({ tabId, color: GRADE_BADGE_COLORS[grade.grade] });
        return;
    }

    updateBadgeForTab(tabId, riskLevel || 'safe');
}

// ============================================
// WHITELIST / BLACKLIST
// ============================================

async function addToWhitelist(domain) {
    domain = domain.toLowerCase();

    // Remove from blacklist if present
    state.blacklist = state.blacklist.filter(d => d !== domain);

    // Add to whitelist if not present
    if (!state.whitelist.includes(domain)) {
        state.whitelist.push(domain);
    }

    await saveState();

    // Notify backend if authenticated
    if (state.apiKey) {
        try {
            await fetch(`${API_BASE}/whitelist`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': state.apiKey
                },
                body: JSON.stringify({ domain })
            });
        } catch (e) {
            console.error('Failed to sync whitelist:', e);
        }
    }

    return { success: true, domain };
}

async function addToBlacklist(domain) {
    domain = domain.toLowerCase();

    // Remove from whitelist if present
    state.whitelist = state.whitelist.filter(d => d !== domain);

    // Add to blacklist if not present
    if (!state.blacklist.includes(domain)) {
        state.blacklist.push(domain);
    }

    await saveState();

    // Notify backend if authenticated
    if (state.apiKey) {
        try {
            await fetch(`${API_BASE}/blacklist`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': state.apiKey
                },
                body: JSON.stringify({ domain })
            });
        } catch (e) {
            console.error('Failed to sync blacklist:', e);
        }
    }

    return { success: true, domain };
}

// ============================================
// HELPERS
// ============================================

function getDomain(url) {
    try {
        return new URL(url).hostname.toLowerCase();
    } catch {
        return '';
    }
}

async function getCurrentTabStatus() {
    try {
        const [tab] = await browserAPI.tabs.query({ active: true, currentWindow: true });
        if (tab && state.currentTabStatus[tab.id]) {
            return state.currentTabStatus[tab.id];
        }
        return null;
    } catch {
        return null;
    }
}

async function checkBackendHealth() {
    try {
        const response = await fetch(`${API_BASE}/health`);
        const data = await response.json();
        return { healthy: true, ...data };
    } catch (error) {
        return { healthy: false, error: error.message };
    }
}

function notifyContentScript(tabId, result) {
    browserAPI.tabs.sendMessage(tabId, {
        action: 'scanResult',
        result
    }).catch(() => { });
}

// ============================================
// BADGE UPDATES
// ============================================

function updateBadge(status) {
    const badges = {
        active: { text: '✓', color: '#22c55e' },
        disabled: { text: 'OFF', color: '#6b7280' },
        scanning: { text: '...', color: '#3b82f6' },
        safe: { text: '✓', color: '#22c55e' },
        warning: { text: '!', color: '#f59e0b' },
        suspicious: { text: '⚠', color: '#f97316' },
        dangerous: { text: '✕', color: '#ef4444' },
        error: { text: '?', color: '#6b7280' },
        inactive: { text: '', color: '#6b7280' }
    };

    const badge = badges[status] || badges.active;
    browserAPI.action.setBadgeText({ text: badge.text });
    browserAPI.action.setBadgeBackgroundColor({ color: badge.color });
}

function updateBadgeForTab(tabId, status) {
    const badges = {
        scanning: { text: '...', color: '#3b82f6' },
        safe: { text: '✓', color: '#22c55e' },
        warning: { text: '!', color: '#f59e0b' },
        suspicious: { text: '⚠', color: '#f97316' },
        dangerous: { text: '✕', color: '#ef4444' },
        error: { text: '?', color: '#6b7280' },
        inactive: { text: '', color: '#6b7280' },
        unknown: { text: '?', color: '#6b7280' }
    };

    const badge = badges[status] || { text: '?', color: '#6b7280' };

    browserAPI.action.setBadgeText({ tabId, text: badge.text });
    browserAPI.action.setBadgeBackgroundColor({ tabId, color: badge.color });
}

// ============================================
// NOTIFICATIONS
// ============================================

function showPhishingWarning(tabId, analysis) {
    if (!state.settings.preferences.real_time_alerts) return;

    // Browser notification
    browserAPI.notifications.create(`phishing-${tabId}`, {
        type: 'basic',
        iconUrl: 'icons/icon-128.png',
        title: '🚨 Phishing Site Detected',
        message: `This website appears to be a phishing attempt. Risk Score: ${analysis.risk_score}%`,
        priority: 2,
        requireInteraction: true
    });

    // Inject warning into page
    browserAPI.tabs.sendMessage(tabId, {
        action: 'showWarning',
        type: 'danger',
        analysis
    }).catch(() => { });
}

function showSuspiciousWarning(tabId, analysis) {
    if (!state.settings.preferences.real_time_alerts) return;

    browserAPI.notifications.create(`suspicious-${tabId}`, {
        type: 'basic',
        iconUrl: 'icons/icon-128.png',
        title: '⚠️ Suspicious Website',
        message: `This website has suspicious characteristics. Proceed with caution.`,
        priority: 1
    });

    browserAPI.tabs.sendMessage(tabId, {
        action: 'showWarning',
        type: 'warning',
        analysis
    }).catch(() => { });
}

// ============================================
// STARTUP
// ============================================

console.log('Phishing Guard v2.1 background worker started');
