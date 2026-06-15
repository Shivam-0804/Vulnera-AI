import AlertSummary from './AlertSummary'
import AlertDetails from './AlertDetails'
import NmapSection from './NmapSection'
import GeminiAnalysis from './GeminiAnalysis'
import { SCAN_TYPES } from '../scanTypes'
import { formatDate } from '../utils/format'
import './ResultsView.css'

function ResultsView({
  results,
  onReset,
  resetLabel = '🔁 Scan Another',
  isHistorical = false,
}) {
  const {
    url,
    scan_type,
    scan_label,
    zap_alerts,
    nmap_output,
    report_filename,
    summary,
    gemini,
    scan_meta,
    created_at,
  } = results

  const typeInfo = SCAN_TYPES[scan_type] || { icon: '🔍' }

  return (
    <div className="results-view">
      <div className="results-header">
        <div>
          <h2>{isHistorical ? 'Saved Report' : 'Scan Results'}</h2>
          <p className="results-url">
            <span className="url-label">Target:</span> {url}
          </p>
          <div className="results-meta">
            <div className="scan-type-badge">
              {typeInfo.icon} {scan_label || scan_type}
            </div>
            {created_at && (
              <time className="scan-date">{formatDate(created_at)}</time>
            )}
          </div>
        </div>
        <button className="reset-button" onClick={onReset}>
          {resetLabel}
        </button>
      </div>

      {scan_meta?.zap_error && (
        <div className="scan-warning" role="alert">
          ⚠️ ZAP encountered an issue: {scan_meta.zap_error}. Results may be incomplete.
        </div>
      )}

      <div className="results-grid">
        <AlertSummary summary={summary} total={zap_alerts.length} />
        <GeminiAnalysis gemini={gemini} />
        <AlertDetails alerts={zap_alerts} />
        <NmapSection output={nmap_output} scanType={scan_type} />
      </div>

      <div className="download-section">
        <a
          href={`/download/${report_filename}`}
          className="download-button"
          download
        >
          ⬇️ Download Full PDF Report
        </a>
      </div>
    </div>
  )
}

export default ResultsView
