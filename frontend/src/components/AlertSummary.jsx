import './AlertSummary.css'

const RISK_CONFIG = {
  High: { color: 'var(--danger)', icon: '🔴' },
  Medium: { color: 'var(--warning)', icon: '🟠' },
  Low: { color: 'var(--low)', icon: '🟡' },
  Informational: { color: 'var(--info)', icon: '🔵' },
}

function AlertSummary({ summary, total }) {
  const risks = ['High', 'Medium', 'Low', 'Informational']

  return (
    <section className="card alert-summary">
      <div className="card-header">
        <h3>🔐 ZAP Alert Summary</h3>
        <span className="badge">{total} alert{total !== 1 ? 's' : ''}</span>
      </div>
      <div className="risk-grid">
        {risks.map((risk) => {
          const config = RISK_CONFIG[risk]
          const count = summary[risk] || 0
          return (
            <div key={risk} className="risk-card" style={{ '--risk-color': config.color }}>
              <span className="risk-icon">{config.icon}</span>
              <span className="risk-count">{count}</span>
              <span className="risk-label">{risk}</span>
            </div>
          )
        })}
      </div>
    </section>
  )
}

export default AlertSummary
