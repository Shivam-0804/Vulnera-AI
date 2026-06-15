import AlertSummary from './AlertSummary'
import AlertDetails from './AlertDetails'
import NmapSection from './NmapSection'
import GeminiAnalysis from './GeminiAnalysis'
import './ResultsView.css'

function ResultsView({ results, onReset }) {
  const { url, zap_alerts, nmap_output, report_filename, summary, gemini } = results

  return (
    <div className="results-view">
      <div className="results-header">
        <div>
          <h2>Scan Results</h2>
          <p className="results-url">
            <span className="url-label">Target:</span> {url}
          </p>
        </div>
        <button className="reset-button" onClick={onReset}>
          🔁 Scan Another
        </button>
      </div>

      <div className="results-grid">
        <AlertSummary summary={summary} total={zap_alerts.length} />
        <GeminiAnalysis gemini={gemini} />
        <AlertDetails alerts={zap_alerts} />
        <NmapSection output={nmap_output} />
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
