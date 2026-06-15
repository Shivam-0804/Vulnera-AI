import './LoadingOverlay.css'

function LoadingOverlay() {
  return (
    <div className="loading-overlay" role="status" aria-live="polite">
      <div className="loading-content">
        <div className="spinner" />
        <h3>Scanning in progress</h3>
        <p>Running ZAP passive scan, Nmap port scan, and AI analysis...</p>
        <div className="loading-steps">
          <span className="step active">ZAP Scan</span>
          <span className="step active">Nmap</span>
          <span className="step active">Gemini AI</span>
        </div>
      </div>
    </div>
  )
}

export default LoadingOverlay
