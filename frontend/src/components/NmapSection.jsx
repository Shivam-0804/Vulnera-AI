import './NmapSection.css'

function NmapSection({ output }) {
  return (
    <section className="card nmap-section">
      <h3>🧭 Nmap Port Scan Output</h3>
      <pre className="nmap-output">{output}</pre>
    </section>
  )
}

export default NmapSection
