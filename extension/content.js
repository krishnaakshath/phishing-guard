/**
 * Phishing Guard - Content Script v2.1
 * Auto-scans on page load, detects credential access, shows beautiful alerts,
 * flags risky outbound links, and nudges toward stronger new passwords.
 */

(function () {
    'use strict';

    if (window.__phishingGuardInjected) return;
    window.__phishingGuardInjected = true;

    // State
    let alertOverlay = null;
    let scanBadge = null;
    let hasShownAlert = false;
    const trackedPasswordInputs = new WeakSet();
    let activePasswordTip = null;

    // ==========================================
    // INITIALIZATION - Auto scan on load
    // ==========================================

    function init() {
        console.log('Phishing Guard: Active on', location.hostname);

        // Auto-scan page content on load
        if (document.readyState === 'complete') {
            autoScanPage();
            scanOutboundLinksOnPage();
        } else {
            window.addEventListener('load', () => {
                autoScanPage();
                scanOutboundLinksOnPage();
            });
        }

        // Monitor for credential/sensitive input access
        setupInputMonitoring();

        // Listen for messages from background
        chrome.runtime.onMessage.addListener(handleMessage);
    }

    // ==========================================
    // AUTO SCAN
    // ==========================================

    async function autoScanPage() {
        const pageInfo = analyzeCurrentPage();

        // Send to background for full analysis
        try {
            const response = await chrome.runtime.sendMessage({
                action: 'contentScan',
                content: pageInfo
            });

            if (response?.is_phishing || response?.risk_level === 'dangerous') {
                showSecurityAlert('danger', response);
            } else if (response?.risk_level === 'suspicious') {
                showSecurityAlert('warning', response);
            }
        } catch (e) {
            // Background not ready
        }
    }

    function analyzeCurrentPage() {
        return {
            has_password_field: document.querySelector('input[type="password"]') !== null,
            has_login_form: detectLoginForm(),
            has_payment_form: detectPaymentForm(),
            is_https: location.protocol === 'https:',
            external_form_action: checkExternalForms(),
            page_title: document.title,
            hostname: location.hostname
        };
    }

    function detectLoginForm() {
        const forms = document.querySelectorAll('form');
        return Array.from(forms).some(form =>
            form.querySelector('input[type="password"]') ||
            form.querySelector('input[type="email"]') ||
            form.querySelector('input[name*="user"]') ||
            form.querySelector('input[name*="login"]')
        );
    }

    function detectPaymentForm() {
        const inputs = document.querySelectorAll('input');
        return Array.from(inputs).some(input => {
            const name = (input.name + input.id + input.placeholder).toLowerCase();
            return name.includes('card') || name.includes('cvv') ||
                name.includes('credit') || name.includes('payment');
        });
    }

    function checkExternalForms() {
        const forms = document.querySelectorAll('form[action]');
        return Array.from(forms).some(form => {
            const action = form.getAttribute('action');
            if (action && action.startsWith('http')) {
                try {
                    return new URL(action).hostname !== location.hostname;
                } catch { return false; }
            }
            return false;
        });
    }

    // ==========================================
    // OUTBOUND LINK SCANNING
    // ==========================================

    const MAX_LINKS_TO_SCAN = 50;
    const DOWNLOADABLE_EXTENSIONS = [
        '.exe', '.msi', '.dmg', '.pkg', '.apk', '.zip', '.rar', '.7z',
        '.bat', '.cmd', '.scr', '.jar', '.iso', '.vbs', '.js', '.deb', '.appimage'
    ];

    function isDownloadableLink(anchor, url) {
        if (anchor.hasAttribute('download')) return true;
        try {
            const path = new URL(url).pathname.toLowerCase();
            return DOWNLOADABLE_EXTENSIONS.some(ext => path.endsWith(ext));
        } catch {
            return false;
        }
    }

    function isElementVisible(el) {
        if (!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)) return false;
        const rect = el.getBoundingClientRect();
        // "Visible on screen right now" - a reasonable proxy for "the user
        // will actually notice or click this", used to prioritize which
        // links get scanned first when a page has more than our cap.
        return rect.bottom > 0 && rect.top < (window.innerHeight || document.documentElement.clientHeight) &&
            rect.right > 0 && rect.left < (window.innerWidth || document.documentElement.clientWidth);
    }

    async function scanOutboundLinksOnPage() {
        try {
            const anchors = Array.from(document.querySelectorAll('a[href]'));
            if (anchors.length === 0) return;

            // url -> { anchors: [...], visible: bool }
            const candidates = new Map();

            for (const a of anchors) {
                const href = a.getAttribute('href');
                if (!href || href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:') || href.startsWith('tel:')) {
                    continue;
                }

                let absoluteUrl;
                try {
                    absoluteUrl = new URL(href, location.href).href;
                } catch {
                    continue;
                }

                let hostname;
                try {
                    hostname = new URL(absoluteUrl).hostname;
                } catch {
                    continue;
                }

                const isOutbound = hostname && hostname !== location.hostname;
                const isDownload = isDownloadableLink(a, absoluteUrl);
                if (!isOutbound && !isDownload) continue;

                if (!candidates.has(absoluteUrl)) {
                    candidates.set(absoluteUrl, { anchors: [], visible: false });
                }
                const entry = candidates.get(absoluteUrl);
                entry.anchors.push(a);
                if (!entry.visible && isElementVisible(a)) entry.visible = true;
            }

            if (candidates.size === 0) return; // Nothing to scan - skip the message entirely.

            // Prioritize links currently visible in the viewport over ones
            // buried further down a large page, then cap at the batch limit.
            const prioritized = Array.from(candidates.entries())
                .sort((a, b) => (b[1].visible === a[1].visible) ? 0 : (b[1].visible ? 1 : -1))
                .slice(0, MAX_LINKS_TO_SCAN);

            const urls = prioritized.map(([url]) => url);

            const response = await chrome.runtime.sendMessage({ action: 'scanLinks', urls });

            if (!response?.results) return;

            for (const result of response.results) {
                const isRisky = result.is_phishing || result.risk_level === 'suspicious' || result.risk_level === 'dangerous';
                if (!isRisky) continue;

                const entry = candidates.get(result.url);
                if (!entry) continue;

                for (const anchor of entry.anchors) {
                    markRiskyLink(anchor, result);
                }
            }
        } catch (e) {
            // Background may not be ready, or the request may have failed -
            // link scanning is a nice-to-have, never break the page for it.
            console.debug('Phishing Guard: link scan skipped', e);
        }
    }

    function markRiskyLink(anchor, result) {
        if (anchor.__pgMarked) return;
        anchor.__pgMarked = true;

        const isDangerous = result.is_phishing || result.risk_level === 'dangerous';
        const level = isDangerous ? 'dangerous' : 'suspicious';

        anchor.classList.add('pg-risky-link', `pg-risky-link-${level}`);

        const badge = document.createElement('span');
        badge.className = `pg-link-badge pg-link-badge-${level}`;
        badge.setAttribute('role', 'note');
        badge.setAttribute('tabindex', '0');
        badge.setAttribute('aria-label',
            `Phishing Guard warning: this link looks ${level}. Risk score ${result.risk_score ?? '?'} out of 100.`);
        badge.setAttribute('data-pg-tooltip',
            isDangerous
                ? `Flagged as likely dangerous (risk ${result.risk_score ?? '?'}/100)`
                : `Flagged as suspicious (risk ${result.risk_score ?? '?'}/100)`);
        badge.innerHTML = '<svg viewBox="0 0 24 24"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>';

        injectLinkMarkerStyles();
        anchor.insertAdjacentElement('afterend', badge);
    }

    // ==========================================
    // INPUT MONITORING - Credential Detection
    // ==========================================

    function setupInputMonitoring() {
        // Monitor password field focus
        document.addEventListener('focusin', (e) => {
            const input = e.target;
            if (!input?.tagName || input.tagName !== 'INPUT') return;

            const type = input.type?.toLowerCase();
            const name = (input.name + input.id + input.placeholder).toLowerCase();

            // Password field accessed
            if (type === 'password') {
                onCredentialAccess('password', 'Login Credentials');
                // Independent of the risk-based alert above: if this looks
                // like a field for CREATING a new password, watch it for
                // weak-password entropy client-side only (no network call).
                maybeAttachPasswordStrengthTip(input);
            }
            // Card number field accessed
            else if (name.includes('card') || name.includes('credit') || input.maxLength === 16) {
                onCredentialAccess('payment', 'Payment Information');
            }
            // CVV/Security code
            else if (name.includes('cvv') || name.includes('cvc') || name.includes('security')) {
                onCredentialAccess('payment', 'Card Security Code');
            }
            // OTP/Verification code
            else if (name.includes('otp') || name.includes('code') || name.includes('verify')) {
                onCredentialAccess('otp', 'Verification Code');
            }
        }, true);

        // Monitor form submissions
        document.addEventListener('submit', (e) => {
            const form = e.target;
            if (form.querySelector('input[type="password"]')) {
                onFormSubmit('login', form);
            }
        }, true);
    }

    async function onCredentialAccess(type, label) {
        if (hasShownAlert) return;

        // Check if this is a trusted domain
        if (isTrustedDomain()) {
            showQuickBadge('safe', 'Verified Site');
            return;
        }

        // Get risk analysis
        const risks = getLocalRisks();

        if (risks.length > 0) {
            hasShownAlert = true;
            showCredentialAlert(type, label, risks);
        } else if (!location.protocol.startsWith('https')) {
            showQuickBadge('warning', 'Connection Not Secure');
        }
    }

    function onFormSubmit(type, form) {
        if (!isTrustedDomain()) {
            const risks = getLocalRisks();
            if (risks.length > 0) {
                // Don't block, but warn
                showQuickBadge('warning', 'Submitting to unverified site');
            }
        }
    }

    // ==========================================
    // LOCAL RISK ANALYSIS
    // ==========================================

    function isTrustedDomain() {
        const trusted = [
            'google.com', 'gmail.com', 'youtube.com', 'facebook.com', 'instagram.com',
            'twitter.com', 'x.com', 'amazon.com', 'microsoft.com', 'apple.com',
            'paypal.com', 'github.com', 'linkedin.com', 'netflix.com', 'dropbox.com',
            'discord.com', 'slack.com', 'zoom.us', 'notion.so', 'figma.com',
            'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'stripe.com'
        ];
        const host = location.hostname.toLowerCase();
        return trusted.some(d => host === d || host.endsWith('.' + d));
    }

    function getLocalRisks() {
        const risks = [];
        const host = location.hostname.toLowerCase();

        // No HTTPS
        if (!location.protocol.startsWith('https')) {
            risks.push({ severity: 'high', message: 'Connection is not encrypted (no HTTPS)' });
        }

        // IP address URL
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
            risks.push({ severity: 'high', message: 'Site uses IP address instead of domain' });
        }

        // Suspicious TLD
        const badTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw', '.click'];
        if (badTlds.some(tld => host.endsWith(tld))) {
            risks.push({ severity: 'medium', message: 'Suspicious domain extension detected' });
        }

        // Brand impersonation
        const brands = ['google', 'facebook', 'paypal', 'amazon', 'microsoft', 'apple', 'netflix', 'bank'];
        for (const brand of brands) {
            if (host.includes(brand) && !isTrustedDomain()) {
                risks.push({ severity: 'high', message: `May be impersonating ${brand.charAt(0).toUpperCase() + brand.slice(1)}` });
                break;
            }
        }

        // External form submission
        if (checkExternalForms()) {
            risks.push({ severity: 'medium', message: 'Form submits data to different domain' });
        }

        return risks;
    }

    // ==========================================
    // PASSWORD STRENGTH MICRO-TIP
    // (client-side only - the password itself never leaves the page)
    // ==========================================

    const NEW_PASSWORD_CONTEXT_WORDS = [
        'sign up', 'signup', 'create account', 'create your account', 'register',
        'registration', 'new password', 'set password', 'set a password',
        'reset password', 'choose a password', 'choose password', 'get started', 'join'
    ];

    function looksLikeNewPasswordContext(input) {
        // Strongest signal: a second password-type field nearby (confirm/repeat).
        const form = input.closest('form') || document;
        const passwordFields = Array.from(form.querySelectorAll('input[type="password"]'));
        if (passwordFields.length > 1) return true;

        // Weaker signal: page context (title, url, nearby heading/button text)
        // mentions account creation rather than plain login.
        const contextText = (
            document.title + ' ' +
            location.pathname + ' ' +
            (form.textContent || '').slice(0, 400)
        ).toLowerCase();

        return NEW_PASSWORD_CONTEXT_WORDS.some(w => contextText.includes(w));
    }

    function computePasswordStrength(value) {
        if (!value) return { score: 0, label: '', weak: false };

        let variety = 0;
        if (/[a-z]/.test(value)) variety++;
        if (/[A-Z]/.test(value)) variety++;
        if (/[0-9]/.test(value)) variety++;
        if (/[^a-zA-Z0-9]/.test(value)) variety++;

        // Simple entropy estimate: pool size (approximated by variety) ^ length.
        const poolSizes = [0, 26, 52, 62, 95];
        const pool = poolSizes[Math.min(variety, 4)] || 26;
        const bitsPerChar = Math.log2(Math.max(pool, 2));
        const entropyBits = value.length * bitsPerChar;

        const commonPasswords = ['password', '12345678', 'qwerty123', 'letmein', 'password1', 'iloveyou', 'admin123'];
        const isCommon = commonPasswords.includes(value.toLowerCase());

        let label, weak;
        if (isCommon || value.length < 8 || entropyBits < 28) {
            label = 'Weak password';
            weak = true;
        } else if (entropyBits < 45 || variety < 3) {
            label = 'Could be stronger';
            weak = true;
        } else {
            label = 'Good password strength';
            weak = false;
        }

        return { score: entropyBits, label, weak, variety };
    }

    function maybeAttachPasswordStrengthTip(input) {
        if (trackedPasswordInputs.has(input)) return;
        if (!looksLikeNewPasswordContext(input)) return;
        trackedPasswordInputs.add(input);

        const onInput = () => {
            const { weak, label } = computePasswordStrength(input.value);
            if (!input.value) {
                removePasswordTip();
            } else if (weak) {
                showPasswordTip(input, label);
            } else {
                removePasswordTip();
            }
        };

        input.addEventListener('input', onInput);
        input.addEventListener('blur', removePasswordTip);
    }

    function showPasswordTip(input, message) {
        injectPasswordTipStyles();

        if (!activePasswordTip) {
            activePasswordTip = document.createElement('div');
            activePasswordTip.id = 'pg-password-tip';
            activePasswordTip.innerHTML = `
                <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
                <span class="pg-password-tip-text"></span>
            `;
            document.body.appendChild(activePasswordTip);

            // Keep the tip aligned with the field if the page scrolls while typing.
            const reposition = () => positionPasswordTip(input);
            window.addEventListener('scroll', reposition, { passive: true, capture: true });
            input.addEventListener('blur', () => {
                window.removeEventListener('scroll', reposition, { capture: true });
            }, { once: true });
        }

        activePasswordTip.querySelector('.pg-password-tip-text').textContent = message;
        positionPasswordTip(input);
    }

    function positionPasswordTip(input) {
        if (!activePasswordTip) return;
        const rect = input.getBoundingClientRect();
        activePasswordTip.style.top = `${rect.bottom + 6}px`;
        activePasswordTip.style.left = `${rect.left}px`;
        activePasswordTip.style.minWidth = `${Math.min(rect.width, 260)}px`;
    }

    function removePasswordTip() {
        if (activePasswordTip) {
            activePasswordTip.remove();
            activePasswordTip = null;
        }
    }

    // ==========================================
    // BEAUTIFUL ALERTS
    // ==========================================

    function showCredentialAlert(type, label, risks) {
        if (alertOverlay) return;

        const typeIcons = {
            password: '<path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>',
            payment: '<path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"/>',
            otp: '<path d="M17 1H7c-1.1 0-2 .9-2 2v18c0 1.1.9 2 2 2h10c1.1 0 2-.9 2-2V3c0-1.1-.9-2-2-2zm0 18H7V5h10v14z"/>'
        };

        alertOverlay = document.createElement('div');
        alertOverlay.id = 'pg-alert-overlay';
        alertOverlay.innerHTML = `
            <div class="pg-alert-backdrop">
                <div class="pg-alert-card">
                    <span class="pg-alert-brand">Phishing Guard</span>
                    <button class="pg-alert-close" id="pg-close" aria-label="Dismiss">
                        <svg viewBox="0 0 24 24"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>
                    </button>

                    <div class="pg-alert-icon">
                        <svg viewBox="0 0 24 24">${typeIcons[type] || typeIcons.password}</svg>
                    </div>
                    
                    <h2 class="pg-alert-title">Credential Access Detected</h2>
                    <p class="pg-alert-subtitle">You're about to enter: <strong>${label}</strong></p>
                    
                    <div class="pg-alert-site">
                        <span class="pg-site-badge ${location.protocol === 'https:' ? 'secure' : 'insecure'}">
                            ${location.protocol === 'https:' ? 'HTTPS' : 'HTTP'}
                        </span>
                        <span class="pg-site-host">${location.hostname}</span>
                    </div>
                    
                    <div class="pg-alert-risks">
                        <h3>Security Concerns:</h3>
                        ${risks.map(r => `
                            <div class="pg-risk-row ${r.severity}">
                                <span class="pg-risk-icon"></span>
                                <span>${r.message}</span>
                            </div>
                        `).join('')}
                    </div>
                    
                    <div class="pg-alert-tips">
                        <h3>Stay Safe:</h3>
                        <ul>
                            <li>Verify URL matches the official site</li>
                            <li>Look for the padlock icon</li>
                            <li>Don't enter credentials from email links</li>
                        </ul>
                    </div>
                    
                    <div class="pg-alert-actions">
                        <button class="pg-btn-leave" id="pg-leave">Leave Site</button>
                        <button class="pg-btn-proceed" id="pg-proceed">I'll Be Careful</button>
                    </div>
                </div>
            </div>
        `;

        injectAlertStyles();
        document.body.appendChild(alertOverlay);

        // Event handlers
        document.getElementById('pg-close')?.addEventListener('click', dismissAlert);
        document.getElementById('pg-leave')?.addEventListener('click', () => {
            window.location.href = 'about:blank';
        });
        document.getElementById('pg-proceed')?.addEventListener('click', dismissAlert);
    }

    function showSecurityAlert(level, analysis) {
        if (alertOverlay || hasShownAlert) return;
        hasShownAlert = true;

        const config = {
            danger: {
                title: 'Phishing Site Detected',
                subtitle: 'This website may steal your information',
                color: '#ef4444'
            },
            warning: {
                title: 'Suspicious Website',
                subtitle: 'This site has concerning characteristics',
                color: '#f59e0b'
            }
        };

        const cfg = config[level] || config.warning;

        alertOverlay = document.createElement('div');
        alertOverlay.id = 'pg-alert-overlay';
        alertOverlay.innerHTML = `
            <div class="pg-alert-backdrop">
                <div class="pg-alert-card ${level}">
                    <span class="pg-alert-brand">Phishing Guard</span>
                    <button class="pg-alert-close" id="pg-close" aria-label="Dismiss">
                        <svg viewBox="0 0 24 24"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>
                    </button>

                    <div class="pg-alert-icon ${level}">
                        <svg viewBox="0 0 24 24"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>
                    </div>
                    
                    <h2 class="pg-alert-title">${cfg.title}</h2>
                    <p class="pg-alert-subtitle">${cfg.subtitle}</p>
                    
                    <div class="pg-alert-site">
                        <span class="pg-site-badge insecure">WARNING</span>
                        <span class="pg-site-host">${location.hostname}</span>
                    </div>
                    
                    ${analysis?.warnings?.length ? `
                        <div class="pg-alert-risks">
                            <h3>Issues Found:</h3>
                            ${analysis.warnings.slice(0, 4).map(w => `
                                <div class="pg-risk-row high">
                                    <span class="pg-risk-icon"></span>
                                    <span>${w}</span>
                                </div>
                            `).join('')}
                        </div>
                    ` : ''}
                    
                    <div class="pg-alert-tips">
                        <h3>Recommended Action:</h3>
                        <ul>
                            <li>Do not enter any personal information</li>
                            <li>Leave this site immediately</li>
                            <li>Go to the official site directly</li>
                        </ul>
                    </div>
                    
                    <div class="pg-alert-actions">
                        <button class="pg-btn-leave" id="pg-leave">Leave Now</button>
                        <button class="pg-btn-proceed" id="pg-proceed">Dismiss Warning</button>
                    </div>
                </div>
            </div>
        `;

        injectAlertStyles();
        document.body.appendChild(alertOverlay);

        document.getElementById('pg-close')?.addEventListener('click', dismissAlert);
        document.getElementById('pg-leave')?.addEventListener('click', () => {
            window.location.href = 'about:blank';
        });
        document.getElementById('pg-proceed')?.addEventListener('click', dismissAlert);
    }

    function showQuickBadge(type, message) {
        if (scanBadge) scanBadge.remove();

        scanBadge = document.createElement('div');
        scanBadge.id = 'pg-quick-badge';
        scanBadge.className = type;
        scanBadge.innerHTML = `
            <svg viewBox="0 0 24 24">
                ${type === 'safe'
                ? '<path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>'
                : '<path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/>'}
            </svg>
            <span>${message}</span>
        `;

        injectBadgeStyles();
        document.body.appendChild(scanBadge);

        setTimeout(() => {
            scanBadge?.remove();
            scanBadge = null;
        }, 3000);
    }

    function dismissAlert() {
        if (alertOverlay) {
            alertOverlay.style.opacity = '0';
            setTimeout(() => {
                alertOverlay?.remove();
                alertOverlay = null;
            }, 200);
        }
    }

    // ==========================================
    // STYLES
    // ==========================================

    function injectAlertStyles() {
        if (document.getElementById('pg-alert-styles')) return;

        const style = document.createElement('style');
        style.id = 'pg-alert-styles';
        style.textContent = `
            #pg-alert-overlay {
                --pg-danger: #ef4444;
                --pg-warning: #f59e0b;
                --pg-safe: #22c55e;
                --pg-brand: linear-gradient(135deg, #8b5cf6 0%, #3b82f6 50%, #06b6d4 100%);
                position: fixed;
                inset: 0;
                z-index: 2147483647;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                transition: opacity 0.2s;
            }
            .pg-alert-backdrop {
                width: 100%;
                height: 100%;
                background: rgba(2, 6, 16, 0.82);
                backdrop-filter: blur(4px);
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
                animation: pgFadeIn 0.25s ease;
            }
            .pg-alert-card {
                background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%);
                border-radius: 20px;
                max-width: 400px;
                width: 100%;
                padding: 32px 24px 24px;
                text-align: center;
                position: relative;
                box-shadow: 0 25px 60px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.08);
                animation: pgSlideUp 0.35s cubic-bezier(0.16, 1, 0.3, 1);
            }
            .pg-alert-card.danger { border-top: 3px solid var(--pg-danger); box-shadow: 0 25px 60px rgba(239,68,68,0.18), 0 0 0 1px rgba(239,68,68,0.15); }
            .pg-alert-card.warning { border-top: 3px solid var(--pg-warning); box-shadow: 0 25px 60px rgba(245,158,11,0.14), 0 0 0 1px rgba(245,158,11,0.12); }

            .pg-alert-brand {
                position: absolute;
                top: 14px;
                left: 20px;
                display: flex;
                align-items: center;
                gap: 6px;
                font-size: 10px;
                font-weight: 700;
                letter-spacing: 0.6px;
                text-transform: uppercase;
                background: var(--pg-brand);
                -webkit-background-clip: text;
                background-clip: text;
                -webkit-text-fill-color: transparent;
            }

            .pg-alert-close {
                position: absolute;
                top: 12px;
                right: 12px;
                width: 36px;
                height: 36px;
                border: none;
                background: rgba(255,255,255,0.1);
                border-radius: 50%;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                transition: background 0.2s, transform 0.2s;
            }
            .pg-alert-close:hover { background: rgba(255,255,255,0.2); transform: scale(1.08); }
            .pg-alert-close:focus-visible { outline: 2px solid #60a5fa; outline-offset: 2px; }
            .pg-alert-close svg { width: 18px; height: 18px; fill: #94a3b8; }

            .pg-alert-icon {
                width: 60px;
                height: 60px;
                margin: 8px auto 16px;
                background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .pg-alert-icon.danger { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); animation: pgUrgentPop 0.5s cubic-bezier(0.34, 1.56, 0.64, 1); }
            .pg-alert-icon.warning { background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); }
            .pg-alert-icon svg { width: 30px; height: 30px; fill: white; }

            .pg-alert-title {
                font-size: 19px;
                font-weight: 700;
                letter-spacing: -0.01em;
                color: #f1f5f9;
                margin: 0 0 6px;
            }
            .pg-alert-subtitle {
                font-size: 13.5px;
                color: #94a3b8;
                line-height: 1.5;
                margin: 0 0 18px;
            }
            .pg-alert-subtitle strong { color: #f1f5f9; }

            .pg-alert-site {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                background: rgba(255,255,255,0.05);
                padding: 7px 14px;
                border-radius: 8px;
                margin-bottom: 18px;
                border: 1px solid rgba(255,255,255,0.06);
            }
            .pg-site-badge {
                font-size: 10px;
                font-weight: 700;
                letter-spacing: 0.3px;
                padding: 3px 6px;
                border-radius: 4px;
            }
            .pg-site-badge.secure { background: rgba(34,197,94,0.18); color: #4ade80; }
            .pg-site-badge.insecure { background: rgba(239,68,68,0.18); color: #f87171; }
            .pg-site-host {
                font-size: 12.5px;
                color: #94a3b8;
                font-family: 'SF Mono', Monaco, 'Courier New', monospace;
            }

            .pg-alert-risks, .pg-alert-tips {
                text-align: left;
                background: rgba(0,0,0,0.28);
                border-radius: 12px;
                padding: 14px;
                margin-bottom: 14px;
                border: 1px solid rgba(255,255,255,0.04);
            }
            .pg-alert-risks h3, .pg-alert-tips h3 {
                font-size: 10.5px;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.6px;
                color: #64748b;
                margin: 0 0 10px;
            }
            .pg-alert-risks h3 { color: #f59e0b; }
            .pg-alert-tips h3 { color: #22c55e; }

            .pg-risk-row {
                display: flex;
                align-items: flex-start;
                gap: 10px;
                padding: 8px 0;
                font-size: 12.5px;
                line-height: 1.5;
                color: #cbd5e1;
                border-bottom: 1px solid rgba(255,255,255,0.05);
            }
            .pg-risk-row:last-child { border-bottom: none; padding-bottom: 0; }
            .pg-risk-icon {
                width: 7px;
                height: 7px;
                margin-top: 5px;
                border-radius: 50%;
                flex-shrink: 0;
            }
            .pg-risk-row.high .pg-risk-icon { background: var(--pg-danger); }
            .pg-risk-row.medium .pg-risk-icon { background: var(--pg-warning); }
            .pg-risk-row.low .pg-risk-icon { background: #3b82f6; }

            .pg-alert-tips ul {
                margin: 0;
                padding-left: 18px;
                font-size: 12px;
                color: #94a3b8;
                line-height: 1.75;
            }

            .pg-alert-actions {
                display: flex;
                gap: 10px;
                margin-top: 6px;
            }
            .pg-btn-leave, .pg-btn-proceed {
                flex: 1;
                padding: 13px 18px;
                border-radius: 10px;
                font-size: 13.5px;
                font-weight: 600;
                cursor: pointer;
                border: none;
                transition: transform 0.15s, box-shadow 0.15s, background 0.15s, color 0.15s;
            }
            .pg-btn-leave {
                background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
                color: white;
            }
            .pg-btn-leave:hover { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(34,197,94,0.35); }
            .pg-btn-leave:focus-visible { outline: 2px solid #4ade80; outline-offset: 2px; }
            .pg-btn-proceed {
                background: transparent;
                border: 1px solid #475569;
                color: #94a3b8;
            }
            .pg-btn-proceed:hover { background: #1e293b; color: #f1f5f9; }
            .pg-btn-proceed:focus-visible { outline: 2px solid #60a5fa; outline-offset: 2px; }

            @keyframes pgFadeIn { from { opacity: 0; } to { opacity: 1; } }
            @keyframes pgSlideUp { from { opacity: 0; transform: translateY(24px) scale(0.98); } to { opacity: 1; transform: translateY(0) scale(1); } }
            @keyframes pgUrgentPop { 0% { transform: scale(0.85); } 60% { transform: scale(1.05); } 100% { transform: scale(1); } }

            @media (prefers-reduced-motion: reduce) {
                .pg-alert-backdrop, .pg-alert-card, .pg-alert-icon.danger { animation: none !important; }
            }
        `;
        document.head.appendChild(style);
    }

    function injectBadgeStyles() {
        if (document.getElementById('pg-badge-styles')) return;

        const style = document.createElement('style');
        style.id = 'pg-badge-styles';
        style.textContent = `
            #pg-quick-badge {
                position: fixed;
                top: 16px;
                right: 16px;
                z-index: 2147483647;
                display: flex;
                align-items: center;
                gap: 8px;
                padding: 10px 16px;
                border-radius: 10px;
                font-family: -apple-system, sans-serif;
                font-size: 13px;
                font-weight: 500;
                color: white;
                animation: pgBadgeIn 0.3s ease;
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            }
            #pg-quick-badge.safe { background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%); }
            #pg-quick-badge.warning { background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); }
            #pg-quick-badge.danger { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); }
            #pg-quick-badge svg { width: 16px; height: 16px; fill: white; }
            @keyframes pgBadgeIn { from { opacity: 0; transform: translateX(20px); } to { opacity: 1; transform: translateX(0); } }
            @media (prefers-reduced-motion: reduce) { #pg-quick-badge { animation: none !important; } }
        `;
        document.head.appendChild(style);
    }

    function injectLinkMarkerStyles() {
        if (document.getElementById('pg-link-marker-styles')) return;

        const style = document.createElement('style');
        style.id = 'pg-link-marker-styles';
        style.textContent = `
            a.pg-risky-link {
                text-decoration-line: underline;
                text-decoration-style: dotted;
                text-decoration-thickness: 1.5px;
                text-underline-offset: 2px;
            }
            a.pg-risky-link-suspicious { text-decoration-color: #f59e0b; }
            a.pg-risky-link-dangerous { text-decoration-color: #ef4444; }

            .pg-link-badge {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                width: 14px;
                height: 14px;
                margin-left: 3px;
                border-radius: 4px;
                vertical-align: middle;
                cursor: help;
                position: relative;
                line-height: 0;
            }
            .pg-link-badge-suspicious { background: rgba(245,158,11,0.16); }
            .pg-link-badge-dangerous { background: rgba(239,68,68,0.18); }
            .pg-link-badge svg { width: 10px; height: 10px; }
            .pg-link-badge-suspicious svg { fill: #f59e0b; }
            .pg-link-badge-dangerous svg { fill: #ef4444; }
            .pg-link-badge:focus-visible { outline: 2px solid #60a5fa; outline-offset: 2px; }

            .pg-link-badge::after {
                content: attr(data-pg-tooltip);
                position: absolute;
                bottom: calc(100% + 6px);
                left: 50%;
                transform: translateX(-50%) translateY(4px);
                background: #0f172a;
                color: #f1f5f9;
                font: 500 11.5px/1.4 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                padding: 6px 10px;
                border-radius: 6px;
                border: 1px solid rgba(255,255,255,0.08);
                box-shadow: 0 8px 20px rgba(0,0,0,0.4);
                white-space: normal;
                width: max-content;
                max-width: 220px;
                pointer-events: none;
                opacity: 0;
                visibility: hidden;
                transition: opacity 0.15s ease, transform 0.15s ease;
                z-index: 2147483647;
            }
            .pg-link-badge:hover::after,
            .pg-link-badge:focus-visible::after {
                opacity: 1;
                visibility: visible;
                transform: translateX(-50%) translateY(0);
            }
            @media (prefers-reduced-motion: reduce) {
                .pg-link-badge::after { transition: none; }
            }
        `;
        document.head.appendChild(style);
    }

    function injectPasswordTipStyles() {
        if (document.getElementById('pg-password-tip-styles')) return;

        const style = document.createElement('style');
        style.id = 'pg-password-tip-styles';
        style.textContent = `
            #pg-password-tip {
                position: fixed;
                z-index: 2147483646;
                display: flex;
                align-items: center;
                gap: 6px;
                padding: 7px 10px;
                background: rgba(15, 23, 42, 0.97);
                border: 1px solid rgba(245, 158, 11, 0.35);
                border-radius: 8px;
                color: #fcd34d;
                font: 500 11.5px/1.3 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                box-shadow: 0 8px 20px rgba(0,0,0,0.35);
                animation: pgTipIn 0.15s ease;
            }
            #pg-password-tip svg { width: 13px; height: 13px; fill: #fbbf24; flex-shrink: 0; }
            @keyframes pgTipIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            @media (prefers-reduced-motion: reduce) { #pg-password-tip { animation: none !important; } }
        `;
        document.head.appendChild(style);
    }

    // ==========================================
    // MESSAGE HANDLER
    // ==========================================

    function handleMessage(request, sender, sendResponse) {
        if (request.action === 'showWarning') {
            showSecurityAlert(request.type, request.analysis);
        }
        sendResponse({ received: true });
        return true;
    }

    // Initialize
    init();
})();
