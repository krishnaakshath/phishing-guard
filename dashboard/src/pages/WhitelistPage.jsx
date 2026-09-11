import { useEffect, useState } from 'react'
import { apiDelete, apiGet, apiPost } from '../api'
import { CheckIcon } from '../icons'

export default function WhitelistPage() {
  const [whitelist, setWhitelist] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [newDomain, setNewDomain] = useState('')
  const [notes, setNotes] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const load = () => {
    setLoading(true)
    return apiGet('/whitelist')
      .then((data) => setWhitelist(data.whitelist || []))
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
      await apiPost('/whitelist', { domain: newDomain.trim(), notes: notes.trim() || undefined })
      setNewDomain('')
      setNotes('')
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
      await apiDelete(`/whitelist/${encodeURIComponent(domain)}`)
      await load()
    } catch (e) {
      setError(e.message)
    }
  }

  return (
    <>
      <header className="page-header">
        <div>
          <h1 className="page-title">Whitelist</h1>
          <p className="page-subtitle">Trusted domains that bypass security checks</p>
        </div>
      </header>

      {error && <div className="flash-banner danger">{error}</div>}

      <div className="card section-gap">
        <div className="input-group">
          <input
            type="text"
            className="form-input"
            placeholder="Domain (e.g. example.com)"
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && addDomain()}
          />
          <input
            type="text"
            className="form-input"
            placeholder="Notes (optional)"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && addDomain()}
          />
          <button className="btn btn-primary" onClick={addDomain} disabled={submitting || !newDomain.trim()}>
            Add Domain
          </button>
        </div>
      </div>

      <div className="card">
        {loading ? (
          <div className="loading-state">Loading whitelist…</div>
        ) : whitelist.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">
              <CheckIcon />
            </div>
            <p>No whitelisted domains yet</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Notes</th>
                  <th>Added</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {whitelist.map((entry) => (
                  <tr key={entry.domain}>
                    <td>
                      <code className="text-success">{entry.domain}</code>
                    </td>
                    <td className="text-secondary">{entry.notes || '—'}</td>
                    <td className="text-secondary">{entry.added_at}</td>
                    <td>
                      <button className="btn btn-sm btn-danger" onClick={() => removeDomain(entry.domain)}>
                        Remove
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
