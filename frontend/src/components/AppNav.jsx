import './AppNav.css'

function AppNav({ activeView, onNavigate }) {
  return (
    <nav className="app-nav">
      <button
        type="button"
        className={`nav-tab ${activeView === 'scan' ? 'active' : ''}`}
        onClick={() => onNavigate('scan')}
      >
        🔍 New Scan
      </button>
      <button
        type="button"
        className={`nav-tab ${activeView === 'history' ? 'active' : ''}`}
        onClick={() => onNavigate('history')}
      >
        📋 Report History
      </button>
    </nav>
  )
}

export default AppNav
