import { useEffect, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { apiGet, API_BASE } from '../api'
import { useAuth } from '../AuthContext'
import { CheckIcon, GlobeIcon, KeyIcon, ShieldIcon } from '../icons'

// This page lives behind ProtectedRoute, so `user` is always set here.
export default function DashboardPage() {
  const { user } = useAuth()
  const location = useLocation()

  const [globalStats, setGlobalStats] = useState({ total_scans: 0, threats_detected: 0 })
  const [userStats, setUserStats] = useState(null)
  const [modules, setModules] = useState(null)
  const [isConnected, setIsConnected] = useState(false)
  const [loading, setLoading] = useState(true)
  const [flash] = useState(location.state?.flash || null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)

      try {
        const res = await fetch(`${API_BASE}/health`)
        if (!cancelled) setIsConnected(res.ok)
      } catch {
        if (!cancelled) setIsConnected(false)
      }

      try {
        const stats = await apiGet('/stats')
        if (!cancelled) setGlobalStats(stats)
      } catch {
        // leave defaults
      }

      try {
        const settingsRes = await apiGet('/settings')
        if (!cancelled) setModules(settingsRes.settings.modules)
      } catch {
        // leave null
      }

      try {
        const statsRes = await apiGet('/stats/user?days=30')
        if (!cancelled) setUserStats(statsRes.statistics)
      } catch {
        // leave null
      }

      if (!cancelled) setLoading(false)
    }

    load()
    return () => {
      cancelled = true
    }
  }, [])

  const activeModules = modules ? Object.values(modules).filter(Boolean).length : 0
  const modulesReady = !!modules

  return (
    <>
      <header className="page-header">
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-subtitle">Monitor your protection status and activity</p>
        </div>
      </header>

      {flash && <div className="flash-banner warning">{flash}</div>}

      <div className={`protection-hero ${modulesReady && activeModules < 4 ? 'at-risk' : ''}`}>
        <div className="protection-ring">
          <svg viewBox="0 0 120 120">
            <circle className="ring-bg" cx="60" cy="60" r="52" />
            <circle
              className="ring-progress"
              cx="60"
              cy="60"
              r="52"
              style={{
                stroke: activeModules === 4 ? 'var(--color-success)' : 'var(--color-warning)',
                strokeDashoffset: modulesReady ? 327 - (327 * activeModules) / 4 : 327,
              }}
            />
          </svg>
          <div className="protection-icon">
            <CheckIcon />
          </div>
        </div>
        <div className="protection-info">
          <div className="protection-status">
            {modulesReady ? 'Protection Active' : 'Loading protection status…'}
          </div>
          <p className="protection-message">
            {modulesReady
              ? `${activeModules} of 4 protection modules are running for ${user.email}.`
              : 'Fetching your current module configuration.'}
          </p>
          <div className="protection-modules">
            <span className={`module-badge ${modules?.phishing_protection ? '' : 'inactive'}`}>
              <ShieldIcon /> Phishing
            </span>
            <span className={`module-badge ${modules?.password_guard ? '' : 'inactive'}`}>
              <KeyIcon /> Password
            </span>
            <span className={`module-badge ${modules?.payment_protection ? '' : 'inactive'}`}>
              <CheckIcon /> Payment
            </span>
            <span className={`module-badge ${modules?.link_scanner ? '' : 'inactive'}`}>
              <GlobeIcon /> Links
            </span>
          </div>
        </div>
        <div className="protection-action">
          <div className={`connection-pill ${isConnected ? 'connected' : 'offline'}`}>
            <div className="connection-dot" />
            <span>{isConnected ? 'API Connected' : 'API Offline'}</span>
          </div>
        </div>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-value">{(globalStats.total_scans || 0).toLocaleString()}</div>
          <div className="stat-label">Total Scans (all users)</div>
          <div className="stat-change positive">Active monitoring</div>
        </div>

        <div className="stat-card danger">
          <div className="stat-value">{(globalStats.threats_detected || 0).toLocaleString()}</div>
          <div className="stat-label">Threats Blocked (all users)</div>
          <div className="stat-change negative">Real-time protection</div>
        </div>

        <div className="stat-card success">
          <div className="stat-value">{modulesReady ? `${activeModules}/4` : '—'}</div>
          <div className="stat-label">Active Modules</div>
          <div className="stat-change positive">Configured in Settings</div>
        </div>

        <div className="stat-card">
          <div className="stat-value">
            {userStats ? userStats.totals.scans.toLocaleString() : '—'}
          </div>
          <div className="stat-label">Your Scans (30d)</div>
          <div className="stat-change">
            {userStats ? `${userStats.totals.threats_blocked} threats blocked` : 'Loading…'}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Quick Actions</h3>
        </div>
        <div className="card-row" style={{ flexWrap: 'wrap' }}>
          <Link to="/tools/site-scanner" className="btn btn-primary">
            <GlobeIcon />
            Scan a Website
          </Link>
          <Link to="/tools/password-checker" className="btn btn-secondary">
            <KeyIcon />
            Check a Password
          </Link>
          <Link to="/whitelist" className="btn btn-secondary">
            <ShieldIcon />
            Manage Whitelist
          </Link>
        </div>
      </div>

      {loading && (
        <p className="text-muted" style={{ marginTop: 'var(--space-4)', fontSize: '12.5px' }}>
          Refreshing…
        </p>
      )}
    </>
  )
}
