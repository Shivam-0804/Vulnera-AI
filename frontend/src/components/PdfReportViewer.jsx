import './PdfReportViewer.css'

function PdfReportViewer({ filename, title, onClose }) {
  if (!filename) return null

  const viewUrl = `/view/${filename}`
  const downloadUrl = `/download/${filename}`

  return (
    <div className="pdf-viewer-overlay" role="dialog" aria-modal="true" aria-label="PDF report viewer">
      <div className="pdf-viewer-panel">
        <div className="pdf-viewer-header">
          <div>
            <h3>PDF Report</h3>
            {title && <p className="pdf-viewer-title">{title}</p>}
          </div>
          <div className="pdf-viewer-actions">
            <a href={downloadUrl} className="pdf-action-btn download" download>
              ⬇️ Download
            </a>
            <button type="button" className="pdf-action-btn close" onClick={onClose}>
              ✕ Close
            </button>
          </div>
        </div>
        <iframe
          className="pdf-viewer-frame"
          src={viewUrl}
          title={title || 'VAPT PDF report'}
        />
      </div>
    </div>
  )
}

export default PdfReportViewer
