import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { apiDelete, apiGet, apiPost } from '../api'
import { useAuth } from '../AuthContext'
import { AdminIcon } from '../icons'

const TABS = ['overview', 'threats', 'users']

export default function AdminPage() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [tab, setTab] = useState('overview')

  const [stats, setStats] = useState(null)
  const [threats, setThreats] = useState([])
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [busyId, setBusyId] = useState(null)

  const loadAll = async () => {
    setLoading(true)
    setError(null)
    try {
      const [statsRes, threatsRes, usersRes] = await Promise.all([
        apiGet('/admin/stats'),
        apiGet('/admin/threats'),
        apiGet('/admin/users'),
      ])
      setStats(statsRes.stats)
      setThreats(threatsRes.threats || [])
      setUsers(usersRes.users || [])
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadAll()
  }, [])

  const verifyThreat = async (id) => {
    setBusyId(id)
    try {
      await apiPost(`/admin/threats/${id}/verify`)
      const data = await apiGet('/admin/threats')
      setThreats(data.threats || [])
    } catch (e) {
      setError(e.message)
    } finally {
      setBusyId(null)
    }
  }

  const deleteThreat = async (id) => {
    setBusyId(id)
    try {
      await apiDelete(`/admin/threats/${id}`)
      const data = await apiGet('/admin/threats')
      setThreats(data.threats || [])
      const statsRes = await apiGet('/admin/stats')
      setStats(statsRes.stats)
    } catch (e) {
      setError(e.message)
    } finally {
      setBusyId(null)
    }
  }

  const exitConsole = () => navigate('/')
  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <div className="admin-console">
      <div className="admin-topbar">
        <div className="admin-topbar-left">
          <AdminIcon />
          <span className="admin-tag">Operator Console</span>
          <span className="admin-title">phishing-guard // admin</span>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span className="text-muted" style={{ fontSize: 12 }}>{user?.email}</span>
          <button className="admin-exit" onClick={exitConsole}>Exit to Dashboard</button>
          <button className="admin-exit" onClick={handleLogout}>Log Out</button>
        </div>
      </div>

      <div className="admin-body">
        <div className="admin-tabs">
          {TABS.map((t) => (
            <button
              key={t}
              className={`admin-tab ${tab === t ? 'active' : ''}`}
              onClick={() => setTab(t)}
            >
              {t}
            </button>
          ))}
        </div>

        {error && <div className="flash-banner danger">{error}</div>}
        {loading && <div className="loading-state">Loading console data…</div>}

        {!loading && tab === 'overview' && stats && (
          <div className="admin-stats-grid">
            <StatCard label="Total Users" value={stats.total_users} />
            <StatCard label="Total Scans" value={stats.total_scans} />
            <StatCard label="Total Threats" value={stats.total_threats} />
            <StatCard label="Reports Pending" value={stats.reports_pending} />
          </div>
        )}

        {!loading && tab === 'threats' && (
          <div className="admin-panel">
            <div className="admin-panel-header">Threat Reports ({threats.length})</div>
            <div className="table-container">
              <table className="admin-table">
                <thead>
                  <tr>
                    <th>Domain</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Reports</th>
                    <th>Verified</th>
                    <th>First Seen</th>
                    <th>Last Seen</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {threats.map((t) => (
                    <tr key={t.id}>
                      <td className="text-mono">{t.domain}</td>
                      <td>{t.threat_type}</td>
                      <td>{t.severity}</td>
                      <td>{t.reported_count}</td>
                      <td>
                        <span className={`admin-verified-chip ${t.verified ? 'yes' : 'no'}`}>
                          {t.verified ? 'verified' : 'unverified'}
                        </span>
                      </td>
                      <td className="text-muted">{t.first_seen}</td>
                      <td className="text-muted">{t.last_seen}</td>
                      <td>
                        <button
                          className="admin-btn"
                          disabled={busyId === t.id || t.verified}
                          onClick={() => verifyThreat(t.id)}
                        >
                          Verify
                        </button>
                        <button
                          className="admin-btn danger"
                          disabled={busyId === t.id}
                          onClick={() => deleteThreat(t.id)}
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                  {threats.length === 0 && (
                    <tr>
                      <td colSpan={8} className="text-muted" style={{ textAlign: 'center', padding: 24 }}>
                        No threat reports.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {!loading && tab === 'users' && (
          <div className="admin-panel">
            <div className="admin-panel-header">Users ({users.length})</div>
            <div className="table-container">
              <table className="admin-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Created</th>
                    <th>Last Login</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id}>
                      <td className="text-mono">{u.id}</td>
                      <td>{u.email}</td>
                      <td>
                        {u.is_admin ? (
                          <span className="admin-verified-chip yes">admin</span>
                        ) : (
                          <span className="admin-verified-chip no">user</span>
                        )}
                      </td>
                      <td className="text-muted">{u.created_at}</td>
                      <td className="text-muted">{u.last_login || '—'}</td>
                    </tr>
                  ))}
                  {users.length === 0 && (
                    <tr>
                      <td colSpan={5} className="text-muted" style={{ textAlign: 'center', padding: 24 }}>
                        No users.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function StatCard({ label, value }) {
  return (
    <div className="admin-stat-card">
      <div className="admin-stat-label">{label}</div>
      <div className="admin-stat-value">{(value ?? 0).toLocaleString()}</div>
    </div>
  )
}
