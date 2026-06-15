import { useState } from 'react'
import { SCAN_TYPES, DEFAULT_SCAN_TYPE } from '../scanTypes'
import './ScanForm.css'

function ScanForm({ onScan, error, disabled }) {
  const [url, setUrl] = useState('')
  const [scanType, setScanType] = useState(DEFAULT_SCAN_TYPE)

  const handleSubmit = (e) => {
    e.preventDefault()
    if (url.trim()) {
      onScan(url.trim(), scanType)
    }
  }

  return (
    <div className="scan-form-container">
      <div className="scan-card">
        <div className="scan-card-header">
          <h2>Start a Security Scan</h2>
          <p>Choose a scan type and enter a target URL to begin vulnerability assessment.</p>
        </div>

        <form onSubmit={handleSubmit} className="scan-form">
          <div className="input-group">
            <label>Scan Type</label>
            <div className="scan-type-grid">
              {Object.entries(SCAN_TYPES).map(([key, type]) => (
                <button
                  key={key}
                  type="button"
                  className={`scan-type-card ${scanType === key ? 'selected' : ''}`}
                  onClick={() => setScanType(key)}
                  disabled={disabled}
                >
                  <span className="scan-type-icon">{type.icon}</span>
                  <span className="scan-type-label">{type.label}</span>
                  <span className="scan-type-desc">{type.description}</span>
                  <span className="scan-type-duration">{type.duration_hint}</span>
                </button>
              ))}
            </div>
          </div>

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
            <span className="button-icon">{SCAN_TYPES[scanType].icon}</span>
            Start {SCAN_TYPES[scanType].label}
          </button>
        </form>

        <div className="scan-features">
          <div className="feature">
            <span className="feature-icon">🔐</span>
            <div>
              <strong>OWASP ZAP</strong>
              <span>Web vulnerability detection</span>
            </div>
          </div>
          <div className="feature">
            <span className="feature-icon">🧭</span>
            <div>
              <strong>Nmap</strong>
              <span>Network exposure analysis</span>
            </div>
          </div>
          <div className="feature">
            <span className="feature-icon">✨</span>
            <div>
              <strong>Gemini AI</strong>
              <span>Intelligent security insights</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ScanForm
