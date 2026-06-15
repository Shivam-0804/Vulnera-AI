import { useState, useEffect } from 'react'
import { SCAN_TYPES } from '../scanTypes'
import { formatDate, getHighestRisk } from '../utils/format'
import './ReportHistory.css'

const RISK_COLORS = {
  High: 'var(--danger)',
  Medium: 'var(--warning)',
  Low: 'var(--low)',
  Informational: 'var(--info)',
}

function ReportHistory({ onViewReport }) {
  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchReports()
  }, [])

  const fetchReports = async () => {
    setLoading(true)
    setError('')
    try {
      const response = await fetch('/api/reports')
      const data = await response.json()
      if (!response.ok) throw new Error(data.error || 'Failed to load reports')
      setReports(data.reports || [])
    } catch (err) {
      setError(err.message || 'Failed to load report history')
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="history-loading">
        <div className="spinner" />
        <p>Loading report history...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="history-error">
        <p>⚠️ {error}</p>
        <button type="button" onClick={fetchReports}>Retry</button>
      </div>
    )
  }

  if (reports.length === 0) {
    return (
      <div className="history-empty">
        <span className="empty-icon">📭</span>
        <h3>No reports yet</h3>
        <p>Run your first scan to see results saved here automatically.</p>
      </div>
    )
  }

  return (
    <div className="report-history">
      <div className="history-header">
        <div>
          <h2>Report History</h2>
          <p>{reports.length} saved scan{reports.length !== 1 ? 's' : ''}</p>
        </div>
        <button type="button" className="refresh-btn" onClick={fetchReports}>
          🔄 Refresh
        </button>
      </div>

      <div className="report-grid">
        {reports.map((report) => {
          const typeInfo = SCAN_TYPES[report.scan_type] || { icon: '📄' }
          const highestRisk = getHighestRisk(report.summary)
          const riskColor = highestRisk ? RISK_COLORS[highestRisk] : 'var(--text-muted)'

          return (
            <article
              key={report.id}
              className={`report-card ${report.has_full_data ? 'clickable' : 'legacy'}`}
              onClick={() => report.has_full_data && onViewReport(report.id)}
              role={report.has_full_data ? 'button' : undefined}
              tabIndex={report.has_full_data ? 0 : undefined}
              onKeyDown={(e) => {
                if (report.has_full_data && (e.key === 'Enter' || e.key === ' ')) {
                  e.preventDefault()
                  onViewReport(report.id)
                }
              }}
            >
              <div className="report-card-top">
                <span className="report-type-badge">
                  {typeInfo.icon} {report.scan_label || 'Report'}
                </span>
                {highestRisk && (
                  <span className="report-risk" style={{ color: riskColor }}>
                    {highestRisk}
                  </span>
                )}
              </div>

              <h3 className="report-url">
                {report.url || report.domain || 'Legacy PDF report'}
              </h3>

              {report.domain && report.url && (
                <p className="report-domain">{report.domain}</p>
              )}

              <div className="report-stats">
                <div className="stat">
                  <span className="stat-value">{report.alert_total ?? 0}</span>
                  <span className="stat-label">Alerts</span>
                </div>
                {report.summary?.High > 0 && (
                  <div className="stat high">
                    <span className="stat-value">{report.summary.High}</span>
                    <span className="stat-label">High</span>
                  </div>
                )}
                {report.summary?.Medium > 0 && (
                  <div className="stat medium">
                    <span className="stat-value">{report.summary.Medium}</span>
                    <span className="stat-label">Med</span>
                  </div>
                )}
              </div>

              <div className="report-card-footer">
                <time className="report-date">{formatDate(report.created_at)}</time>
                {report.has_full_data ? (
                  <span className="view-link">View report →</span>
                ) : (
                  <a
                    href={`/download/${report.report_filename}`}
                    className="download-link"
                    onClick={(e) => e.stopPropagation()}
                    download
                  >
                    ⬇️ PDF only
                  </a>
                )}
              </div>
            </article>
          )
        })}
      </div>
    </div>
  )
}

export default ReportHistory
