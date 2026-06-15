import { useState } from 'react'
import './ScanForm.css'

function ScanForm({ onScan, error, disabled }) {
  const [url, setUrl] = useState('')

  const handleSubmit = (e) => {
    e.preventDefault()
    if (url.trim()) {
      onScan(url.trim())
    }
  }

  return (
    <div className="scan-form-container">
      <div className="scan-card">
        <div className="scan-card-header">
          <h2>Start a Security Scan</h2>
          <p>Enter a target URL to run passive ZAP analysis and an Nmap port scan.</p>
        </div>

        <form onSubmit={handleSubmit} className="scan-form">
          <div className="input-group">
            <label htmlFor="url">Target URL</label>
            <div className="input-wrapper">
              <span className="input-prefix">🔗</span>
              <input
                id="url"
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                required
                disabled={disabled}
                autoFocus
              />
            </div>
          </div>

          {error && (
            <div className="error-banner" role="alert">
              <span>⚠️</span> {error}
            </div>
          )}

          <button type="submit" className="scan-button" disabled={disabled || !url.trim()}>
            <span className="button-icon">🔍</span>
            Start Scan
          </button>
        </form>

        <div className="scan-features">
          <div className="feature">
            <span className="feature-icon">🔐</span>
            <div>
              <strong>ZAP Passive Scan</strong>
              <span>Web vulnerability detection</span>
            </div>
          </div>
          <div className="feature">
            <span className="feature-icon">🧭</span>
            <div>
              <strong>Nmap Port Scan</strong>
              <span>Network exposure analysis</span>
            </div>
          </div>
          <div className="feature">
            <span className="feature-icon">✨</span>
            <div>
              <strong>Gemini AI Analysis</strong>
              <span>Intelligent security insights</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ScanForm
