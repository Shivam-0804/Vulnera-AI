import ReactMarkdown from 'react-markdown'
import './GeminiAnalysis.css'

function GeminiAnalysis({ gemini }) {
  if (!gemini) return null

  return (
    <section className="card gemini-analysis">
      <div className="gemini-header">
        <h3>✨ AI Security Analysis</h3>
        <span className="gemini-badge">Google Gemini</span>
      </div>

      {gemini.available && gemini.analysis ? (
        <div className="gemini-content">
          <ReactMarkdown>{gemini.analysis}</ReactMarkdown>
        </div>
      ) : (
        <div className="gemini-unavailable">
          <span className="unavailable-icon">ℹ️</span>
          <p>{gemini.message || 'AI analysis is not available.'}</p>
        </div>
      )}
    </section>
  )
}

export default GeminiAnalysis
