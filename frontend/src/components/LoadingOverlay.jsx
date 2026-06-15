import { LOADING_MESSAGES, SCAN_TYPES, DEFAULT_SCAN_TYPE } from '../scanTypes'
import './LoadingOverlay.css'

function LoadingOverlay({ scanType = DEFAULT_SCAN_TYPE }) {
  const config = LOADING_MESSAGES[scanType] || LOADING_MESSAGES[DEFAULT_SCAN_TYPE]
  const typeInfo = SCAN_TYPES[scanType] || SCAN_TYPES[DEFAULT_SCAN_TYPE]

  return (
    <div className="loading-overlay" role="status" aria-live="polite">
      <div className="loading-content">
        <div className="spinner" />
        <span className="loading-scan-badge">{typeInfo.icon} {typeInfo.label}</span>
        <h3>{config.title}</h3>
        <p>{config.description}</p>
        <div className="loading-steps">
          {config.steps.map((step) => (
            <span key={step} className="step active">{step}</span>
          ))}
        </div>
        {scanType === 'deep' && (
          <p className="loading-warning">Deep scans may take 10–20 minutes. Please keep this tab open.</p>
        )}
      </div>
    </div>
  )
}

export default LoadingOverlay
