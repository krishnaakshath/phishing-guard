import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { apiGet } from '../api'
import { AlertIcon, CheckIcon, GlobeIcon } from '../icons'

function FindingGroup({ title, findings }) {
  return (
    <div className="card section-gap">
      <div className="card-header">
        <h3 className="card-title">{title}</h3>
        <span className={`badge ${findings.length === 0 ? 'badge-safe' : 'badge-warning'}`}>
          {findings.length === 0 ? 'No issues' : `${findings.length} issue${findings.length === 1 ? '' : 's'}`}
        </span>
      </div>
      {findings.length === 0 ? (
        <div className="finding-clean">
          <CheckIcon />
          <span>All checks in this category passed.</span>
        </div>
      ) : (
        <div className="finding-list">
          {findings.map((finding, i) => (
            <div className="finding-item" key={i}>
              <AlertIcon />
              <span>{typeof finding === 'string' ? finding : JSON.stringify(finding)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function SiteScannerPage() {
  const [searchParams] = useSearchParams()
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)

  const runScan = async (targetUrl) => {
    if (!targetUrl.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const data = await apiGet(`/site-scan?url=${encodeURIComponent(targetUrl.trim())}`)
      setResult(data)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  const scan = () => runScan(url)

  // Supports being deep-linked with ?url=<domain> (the extension popup's
  // "Scan this site" button links here) - prefill and auto-run once.
  useEffect(() => {
    const prefill = searchParams.get('url')
    if (prefill) {
      setUrl(prefill)
      runScan(prefill)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const grade = result?.posture?.grade
  const score = result?.posture?.score ?? 0
  const barColor =
    grade === 'A' || grade === 'B'
      ? 'var(--color-success)'
      : grade === 'C'
      ? 'var(--color-warning)'
      : 'var(--color-danger)'

  return (
    <>
      <header className="page-header">
        <div>
          <h1 className="page-title">Site Scanner</h1>
          <p className="page-subtitle">Check a website's security headers, TLS setup, cookies, and exposed secrets</p>
        </div>
      </header>

      <p className="tool-lede">
        <GlobeIcon /> Enter any URL to get a Mozilla-Observatory-style security posture grade. No
        account required — this link is safe to share.
      </p>

      <div className="card section-gap">
        <div className="input-group">
          <input
            type="text"
            className="form-input"
            placeholder="example.com or https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && scan()}
          />
          <button className="btn btn-primary" onClick={scan} disabled={loading || !url.trim()}>
            {loading ? 'Scanning…' : 'Scan Site'}
          </button>
        </div>
      </div>

      {error && <div className="flash-banner danger">{error}</div>}

      {result && (
        <>
          <div className="card grade-hero">
            <div className={`grade-circle grade-${grade}`}>{grade}</div>
            <div className="grade-meta">
              <div className="card-title" style={{ marginBottom: 6 }}>{result.domain}</div>
              <div className="grade-score">
                Security score: {score}/100
                {result.threat_intel?.reputation_score != null && (
                  <> · Reputation: {result.threat_intel.reputation_score}</>
                )}
              </div>
              <div className="grade-bar-track">
                <div className="grade-bar-fill" style={{ width: `${score}%`, background: barColor }} />
              </div>
              {result.threat_intel?.threat_types?.length > 0 && (
                <div style={{ marginTop: 'var(--space-3)' }}>
                  {result.threat_intel.threat_types.map((t) => (
                    <span key={t} className="badge badge-danger" style={{ marginRight: 6 }}>
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>

          <FindingGroup title="Security Headers" findings={result.posture?.header_findings || []} />
          <FindingGroup title="TLS Configuration" findings={result.posture?.tls_findings || []} />
          <FindingGroup title="Cookie Flags" findings={result.posture?.cookie_findings || []} />

          <div className="card">
            <div className="card-header">
              <h3 className="card-title">Exposed Secrets</h3>
              <span className={`badge ${(result.secrets || []).length === 0 ? 'badge-safe' : 'badge-danger'}`}>
                {(result.secrets || []).length === 0 ? 'None found' : `${result.secrets.length} found`}
              </span>
            </div>
            {(result.secrets || []).length === 0 ? (
              <div className="finding-clean">
                <CheckIcon />
                <span>No exposed API keys, tokens, or credentials detected in the page source.</span>
              </div>
            ) : (
              <>
                <p className="text-muted" style={{ fontSize: 12.5, marginBottom: 'var(--space-3)' }}>
                  Previews below are partially redacted, but still sensitive — treat this page as
                  confidential and rotate any exposed credentials immediately.
                </p>
                {result.secrets.map((secret, i) => (
                  <div className="secret-item" key={i}>
                    <strong>{secret.type}</strong> · line {secret.line}
                    <code>{secret.match_preview}</code>
                  </div>
                ))}
              </>
            )}
          </div>
        </>
      )}
    </>
  )
}
