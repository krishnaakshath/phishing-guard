import { useEffect, useState } from 'react'
import { apiDelete, apiGet, apiPost } from '../api'
import { BlockIcon } from '../icons'

export default function BlacklistPage() {
  const [blacklist, setBlacklist] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [newDomain, setNewDomain] = useState('')
  const [reason, setReason] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const load = () => {
    setLoading(true)
    return apiGet('/blacklist')
      .then((data) => setBlacklist(data.blacklist || []))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
  }, [])

  const addDomain = async () => {
    if (!newDomain.trim()) return
    setSubmitting(true)
    setError(null)
    try {
      await apiPost('/blacklist', { domain: newDomain.trim(), reason: reason.trim() || undefined })
      setNewDomain('')
      setReason('')
      await load()
    } catch (e) {
      setError(e.message)
    } finally {
      setSubmitting(false)
    }
  }

  const removeDomain = async (domain) => {
    setError(null)
    try {
      await apiDelete(`/blacklist/${encodeURIComponent(domain)}`)
      await load()
    } catch (e) {
      setError(e.message)
    }
  }

  return (
    <>
      <header className="page-header">
        <div>
          <h1 className="page-title">Blacklist</h1>
          <p className="page-subtitle">Blocked domains that are always flagged as dangerous</p>
        </div>
      </header>

      {error && <div className="flash-banner danger">{error}</div>}

      <div className="card section-gap">
        <div className="input-group">
          <input
            type="text"
            className="form-input"
            placeholder="Domain to block (e.g. malicious-site.com)"
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && addDomain()}
          />
          <input
            type="text"
            className="form-input"
            placeholder="Reason (optional)"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && addDomain()}
          />
          <button className="btn btn-danger" onClick={addDomain} disabled={submitting || !newDomain.trim()}>
            Block Domain
          </button>
        </div>
      </div>

      <div className="card">
        {loading ? (
          <div className="loading-state">Loading blacklist…</div>
        ) : blacklist.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">
              <BlockIcon />
            </div>
            <p>No blocked domains yet</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Reason</th>
                  <th>Added</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {blacklist.map((entry) => (
                  <tr key={entry.domain}>
                    <td>
                      <code className="text-danger">{entry.domain}</code>
                    </td>
                    <td className="text-secondary">{entry.reason || '—'}</td>
                    <td className="text-secondary">{entry.added_at}</td>
                    <td>
                      <button className="btn btn-sm btn-secondary" onClick={() => removeDomain(entry.domain)}>
                        Unblock
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}
