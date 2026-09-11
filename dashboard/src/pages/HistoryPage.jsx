import { useEffect, useState } from 'react'
import { apiGet } from '../api'
import { HistoryIcon } from '../icons'
import { downloadCsv } from '../csv'

const HISTORY_COLUMNS = [
  { label: 'Domain', key: 'domain' },
  { label: 'URL', key: 'url' },
  { label: 'Risk Level', key: 'risk_level' },
  { label: 'Risk Score', key: 'risk_score' },
  { label: 'Scanned At', key: 'scanned_at' },
]

export default function HistoryPage() {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    apiGet('/history?limit=50')
      .then((data) => {
        if (!cancelled) setHistory(data.history || [])
      })
      .catch((e) => {
        if (!cancelled) setError(e.message)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <>
      <header className="page-header">
        <div>
          <h1 className="page-title">Scan History</h1>
          <p className="page-subtitle">Recent website scans and their results</p>
        </div>
        {history.length > 0 && (
          <button
            className="btn btn-secondary"
            onClick={() => downloadCsv('phishing-guard-history.csv', history, HISTORY_COLUMNS)}
          >
            Export CSV
          </button>
        )}
      </header>

      {error && <div className="flash-banner danger">{error}</div>}

      <div className="card">
        {loading ? (
          <div className="loading-state">Loading history…</div>
        ) : history.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">
              <HistoryIcon />
            </div>
            <p>No scan history yet. Browse the web with the extension active to see results here.</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Website</th>
                  <th>Status</th>
                  <th>Risk Score</th>
                  <th>Scanned</th>
                </tr>
              </thead>
              <tbody>
                {history.map((item, i) => (
                  <tr key={`${item.url}-${i}`}>
                    <td>
                      <code>{item.domain}</code>
                    </td>
                    <td>
                      <span className={`badge badge-${item.risk_level}`}>{item.risk_level}</span>
                    </td>
                    <td className="text-mono">{item.risk_score}%</td>
                    <td className="text-secondary">{item.scanned_at}</td>
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
