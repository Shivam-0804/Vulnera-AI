import { useState } from "react";
import ScanForm from "./components/ScanForm";
import LoadingOverlay from "./components/LoadingOverlay";
import ResultsView from "./components/ResultsView";
import ReportHistory from "./components/ReportHistory";
import PdfReportViewer from "./components/PdfReportViewer";
import AppNav from "./components/AppNav";
import { DEFAULT_SCAN_TYPE } from "./scanTypes";
import "./App.css";

function App() {
  const [view, setView] = useState("scan");
  const [loading, setLoading] = useState(false);
  const [loadingScanType, setLoadingScanType] = useState(DEFAULT_SCAN_TYPE);
  const [error, setError] = useState("");
  const [results, setResults] = useState(null);
  const [viewingFromHistory, setViewingFromHistory] = useState(false);
  const [pdfViewer, setPdfViewer] = useState(null);

  const handleScan = async (url, scanType = DEFAULT_SCAN_TYPE) => {
    setLoading(true);
    setLoadingScanType(scanType);
    setError("");
    setResults(null);
    setViewingFromHistory(false);
    setPdfViewer(null);

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
      setView("scan");
    } catch (err) {
      setError(err.message || "An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  };

  const handleViewPdf = (filename, title = "") => {
    setPdfViewer({ filename, title });
  };

  const handleViewReport = async (reportId) => {
    setLoading(true);
    setError("");
    setPdfViewer(null);

    try {
      const response = await fetch(`/api/reports/${reportId}`);
      const data = await response.json();

      if (!response.ok) {
        if (data.report_filename) {
          handleViewPdf(
            data.report_filename,
            data.url || data.domain || "Saved report"
          );
          return;
        }
        throw new Error(data.error || "Failed to load report");
      }

      setResults(data);
      setViewingFromHistory(true);
      setView("scan");
    } catch (err) {
      setError(err.message || "Failed to load report");
      setView("history");
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setResults(null);
    setViewingFromHistory(false);
    setError("");
    setPdfViewer(null);
  };

  const handleNavigate = (nextView) => {
    setView(nextView);
    setError("");
    setPdfViewer(null);
    if (nextView !== "scan") {
      setResults(null);
      setViewingFromHistory(false);
    }
  };

  const handleBackToHistory = () => {
    setResults(null);
    setViewingFromHistory(false);
    setPdfViewer(null);
    setView("history");
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

      <AppNav activeView={results ? "scan" : view} onNavigate={handleNavigate} />

      <main className="app-main">
        {results ? (
          <ResultsView
            results={results}
            onReset={viewingFromHistory ? handleBackToHistory : handleReset}
            resetLabel={viewingFromHistory ? "← Back to History" : "🔁 Scan Another"}
            isHistorical={viewingFromHistory}
            onViewPdf={handleViewPdf}
          />
        ) : view === "history" ? (
          <ReportHistory
            onViewReport={handleViewReport}
            onViewPdf={handleViewPdf}
          />
        ) : (
          <ScanForm onScan={handleScan} error={error} disabled={loading} />
        )}
      </main>

      {loading && !results && <LoadingOverlay scanType={loadingScanType} />}
      {loading && results === null && view === "history" && (
        <div className="history-overlay">
          <div className="spinner" />
        </div>
      )}

      {pdfViewer && (
        <PdfReportViewer
          filename={pdfViewer.filename}
          title={pdfViewer.title}
          onClose={() => setPdfViewer(null)}
        />
      )}
    </div>
  );
}

export default App;
