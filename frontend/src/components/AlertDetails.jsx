import { useState } from 'react'
import './AlertDetails.css'

const RISK_CLASS = {
  High: 'risk-high',
  Medium: 'risk-medium',
  Low: 'risk-low',
  Informational: 'risk-info',
}

function AlertDetails({ alerts, defaultExpanded = false }) {
  const [expanded, setExpanded] = useState(defaultExpanded)

  if (!alerts.length) {
    return (
      <section className="card alert-details">
        <h3>🔍 ZAP Vulnerabilities</h3>
        <p className="no-alerts">No vulnerabilities detected by ZAP passive scan.</p>
      </section>
    )
  }

  return (
    <section className="card alert-details">
      <button
        className="details-toggle"
        onClick={() => setExpanded(!expanded)}
        aria-expanded={expanded}
      >
        <h3>🔍 Detailed ZAP Vulnerabilities</h3>
        <span className={`chevron ${expanded ? 'open' : ''}`}>▼</span>
      </button>

      {expanded && (
        <ul className="alert-list">
          {alerts.map((alert, idx) => (
            <li key={idx} className={`alert-item ${RISK_CLASS[alert.risk] || ''}`}>
              <div className="alert-header">
                <strong>{alert.alert}</strong>
                <span className={`risk-badge ${RISK_CLASS[alert.risk] || ''}`}>
                  {alert.risk}
                </span>
              </div>
              {alert.url && (
                <p className="alert-url">{alert.url}</p>
              )}
              {alert.description && (
                <p className="alert-desc">{alert.description}</p>
              )}
              {alert.solution && (
                <p className="alert-fix">
                  <em>Fix:</em> {alert.solution}
                </p>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

export default AlertDetails
