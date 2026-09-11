import { useState } from 'react'
import { apiPost } from '../api'
import { AlertIcon, CheckIcon, EyeIcon, EyeOffIcon, KeyIcon, LockIcon } from '../icons'

export default function PasswordCheckerPage() {
  const [password, setPassword] = useState('')
  const [visible, setVisible] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)

  const check = async () => {
    if (!password) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const data = await apiPost('/check-password-breach', { password })
      setResult(data.result)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  const panelClass = !result
    ? ''
    : result.error
    ? 'unknown'
    : result.breached
    ? 'breached'
    : 'safe'

  return (
    <>
      <header className="page-header">
        <div>
          <h1 className="page-title">Password Checker</h1>
          <p className="page-subtitle">Check whether a password has appeared in a known data breach</p>
        </div>
      </header>

      <p className="tool-lede">
        <KeyIcon /> Powered by Have I Been Pwned's breach database. No account required — this
        link is safe to share.
      </p>

      <div className="card section-gap">
        <div className="form-group" style={{ marginBottom: 'var(--space-4)' }}>
          <label className="form-label">Password to check</label>
          <div className="input-with-action">
            <input
              type={visible ? 'text' : 'password'}
              className="form-input"
              placeholder="Enter a password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && check()}
              autoComplete="off"
            />
            <button
              type="button"
              className="input-action-btn"
              onClick={() => setVisible((v) => !v)}
              aria-label={visible ? 'Hide password' : 'Show password'}
            >
              {visible ? <EyeOffIcon /> : <EyeIcon />}
            </button>
          </div>
        </div>
        <button className="btn btn-primary" onClick={check} disabled={loading || !password}>
          {loading ? 'Checking…' : 'Check Password'}
        </button>

        <div className="privacy-note">
          <LockIcon />
          <span>
            Your password is sent securely (HTTPS) to the Phishing Guard backend, which hashes it
            and checks only a partial hash prefix against the breach database using k-anonymity.
            It is checked securely and never stored — but it does leave your browser to reach our
            server, unlike a purely client-side check.
          </span>
        </div>
      </div>

      {error && <div className="flash-banner danger">{error}</div>}

      {result && (
        <div className={`result-panel ${panelClass}`}>
          <div className="result-panel-icon">
            {result.error ? <AlertIcon /> : result.breached ? <AlertIcon /> : <CheckIcon />}
          </div>
          <div>
            {result.error ? (
              <>
                <div className="result-panel-title">Couldn't verify this password</div>
                <div className="result-panel-desc">
                  The breach-check service was unreachable ({result.error}). This does not mean
                  the password is safe — try again shortly.
                </div>
              </>
            ) : result.breached ? (
              <>
                <div className="result-panel-title">This password has been breached</div>
                <div className="result-panel-desc">
                  Found in <strong className="text-mono">{result.count.toLocaleString()}</strong>{' '}
                  known data breaches. Stop using it anywhere and change it immediately.
                </div>
              </>
            ) : (
              <>
                <div className="result-panel-title">No breaches found</div>
                <div className="result-panel-desc">
                  This password was not found in any known breach data set. Still, use a unique
                  password per site and consider a password manager.
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </>
  )
}
