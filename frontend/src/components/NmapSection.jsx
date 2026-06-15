import { SCAN_TYPES } from '../scanTypes'
import './NmapSection.css'

const NMAP_LABELS = {
  passive: 'Fast port scan (-F)',
  normal: 'Service detection (-sV)',
  deep: 'Comprehensive scan (-sV -sC, top 1000 ports)',
}

function NmapSection({ output, scanType = 'passive' }) {
  const label = NMAP_LABELS[scanType] || NMAP_LABELS.passive
  const typeInfo = SCAN_TYPES[scanType]

  return (
    <section className="card nmap-section">
      <div className="nmap-header">
        <h3>🧭 Nmap Port Scan Output</h3>
        {typeInfo && (
          <span className="nmap-mode-badge">{typeInfo.icon} {label}</span>
        )}
      </div>
      <pre className="nmap-output">{output}</pre>
    </section>
  )
}

export default NmapSection
