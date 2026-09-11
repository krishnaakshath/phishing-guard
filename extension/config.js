/**
 * Phishing Guard - Configuration
 * Production URLs
 *
 * This is a plain ES module so it can be imported both from the
 * background service worker (manifest declares "type": "module") and
 * from popup.js (loaded with <script type="module">).
 */

export const CONFIG = {
    // Backend API URL - Deployed on Render
    API_URL: 'https://phishing-guard.onrender.com/api',

    // Dashboard URL - Deployed on Vercel
    DASHBOARD_URL: 'https://phishing-guard-seven.vercel.app',

    // Extension version
    VERSION: '2.1.0'
};

// Also expose on window for any non-module context (e.g. a future options
// page loaded without type="module"). No-op inside the service worker,
// where `window` doesn't exist.
if (typeof window !== 'undefined') {
    window.PHISHING_GUARD_CONFIG = CONFIG;
}
