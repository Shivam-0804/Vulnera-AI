import { useState } from "react";
import ScanForm from "./components/ScanForm";
import LoadingOverlay from "./components/LoadingOverlay";
import ResultsView from "./components/ResultsView";
import { DEFAULT_SCAN_TYPE } from "./scanTypes";
import "./App.css";

function App() {
  const [loading, setLoading] = useState(false);
  const [loadingScanType, setLoadingScanType] = useState(DEFAULT_SCAN_TYPE);
  const [error, setError] = useState("");
  const [results, setResults] = useState(null);

  const handleScan = async (url, scanType = DEFAULT_SCAN_TYPE) => {
    setLoading(true);
    setLoadingScanType(scanType);
    setError("");
    setResults(null);

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, scan_type: scanType }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Scan failed");
      }

      setResults(data);
    } catch (err) {
      setError(err.message || "An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setResults(null);
    setError("");
  };

  return (
    <div className="app">
      <header className="app-header">
        <div className="logo">
          <span className="logo-icon">🛡️</span>
          <div>
            <h1>VAPT Quick Scanner</h1>
            <p className="tagline">
              AI-powered vulnerability assessment with ZAP & Nmap
            </p>
          </div>
        </div>
      </header>

      <main className="app-main">
        {!results ? (
          <ScanForm onScan={handleScan} error={error} disabled={loading} />
        ) : (
          <ResultsView results={results} onReset={handleReset} />
        )}
      </main>

      {loading && <LoadingOverlay scanType={loadingScanType} />}
    </div>
  );
}

export default App;
