export default function PrivacyPolicyPage() {
  return (
    <>
      <header className="page-header">
        <div>
          <h1 className="page-title">Privacy Policy</h1>
          <p className="page-subtitle">Last updated: September 2026</p>
        </div>
      </header>

      <div className="card section-gap">
        <p>
          Phishing Guard is a phishing-detection browser extension and dashboard. This page
          explains, in plain terms, what data it handles and why - written to match what the
          code actually does, not a generic template.
        </p>
      </div>

      <div className="card section-gap">
        <h3 className="card-title">What we collect</h3>
        <ul className="policy-list">
          <li>
            <strong>Account data (only if you register):</strong> your email address and a
            password hash (PBKDF2, salted - we never store or can recover your actual
            password), plus an API key used to authenticate your requests.
          </li>
          <li>
            <strong>URLs you visit:</strong> to detect phishing, the extension sends the URL
            of each page you visit to our backend for analysis, along with a few structured
            yes/no signals (e.g. whether the page has a password field, whether it's served
            over HTTPS). The page's actual content/HTML is not sent from your browser during
            normal browsing.
          </li>
          <li>
            <strong>Site Scanner tool:</strong> when you use the public Site Scanner, our
            server fetches the target page directly (server-to-server) to check its security
            headers and for exposed secrets - this doesn't come from your browser.
          </li>
          <li>
            <strong>Browsing history - opt-in only:</strong> the extension only reads your
            browser history if you explicitly click "Scan My Recent History" in the popup.
            Only domain names (never full URLs or page content) from the selected period are
            checked, and only on that explicit action - never automatically.
          </li>
          <li>
            <strong>Password breach checks:</strong> only a 5-character prefix of a SHA-1
            hash of the password is sent (k-anonymity) - never the password itself, and never
            the full hash.
          </li>
        </ul>
      </div>

      <div className="card section-gap">
        <h3 className="card-title">Third-party services we check against</h3>
        <ul className="policy-list">
          <li><strong>Google Safe Browsing</strong> - if configured, URLs are checked against Google's threat list, which involves sending the URL to Google as part of that check.</li>
          <li><strong>OpenPhish community feed</strong> - a public phishing-URL list; no personal data is sent to check against it.</li>
          <li><strong>Have I Been Pwned</strong> - only the password hash prefix described above.</li>
        </ul>
      </div>

      <div className="card section-gap">
        <h3 className="card-title">What we don't do</h3>
        <ul className="policy-list">
          <li>We don't sell your data to anyone.</li>
          <li>We don't show ads or use your browsing data for advertising.</li>
          <li>We don't track you across sites for any purpose beyond phishing detection.</li>
        </ul>
      </div>

      <div className="card section-gap">
        <h3 className="card-title">Your data, your control</h3>
        <p>
          Scan history, whitelist, and blacklist entries are tied to your account if you
          register. To request deletion of your account and associated data, contact us
          (see below) - we'll remove it manually since this is a small, independently-run
          project without a self-serve deletion flow yet.
        </p>
      </div>

      <div className="card section-gap">
        <h3 className="card-title">Children's privacy</h3>
        <p>Phishing Guard is not directed at children under 13, and we don't knowingly collect data from them.</p>
      </div>

      <div className="card">
        <h3 className="card-title">Changes &amp; contact</h3>
        <p>
          If this policy changes in a way that affects what data is collected, this page will
          be updated and the date at the top revised. Questions or deletion requests: open an
          issue at{' '}
          <a href="https://github.com/krishnaakshath/phishing-guard/issues" target="_blank" rel="noreferrer">
            github.com/krishnaakshath/phishing-guard/issues
          </a>.
        </p>
      </div>
    </>
  )
}
