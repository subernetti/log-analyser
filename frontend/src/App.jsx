import { useState } from "react";
import "./App.css";

const BACKEND_URL = "http://localhost:8000";

// Returns the parsed JSON body, or null if the body is not valid JSON.
async function readJson(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function App() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [result, setResult] = useState(null);

  async function handleAnalyze() {
    if (!selectedFile) {
      setErrorMessage("Please choose a log file first.");
      return;
    }
    setIsLoading(true);
    setErrorMessage("");
    setResult(null);

    // FormData sends the file as "multipart/form-data", which FastAPI's UploadFile expects.
    const formData = new FormData();
    formData.append("file", selectedFile);

    let response;
    try {
      response = await fetch(`${BACKEND_URL}/analyze`, { method: "POST", body: formData });
    } catch {
      // fetch itself only fails when no response arrived at all (backend down, no network).
      setErrorMessage("Could not reach the backend. Is it running on port 8000?");
      setIsLoading(false);
      return;
    }

    // The backend answered, but the body is not always JSON: an unexpected 500 error
    // is plain text ("Internal Server Error"), so response.json() would throw.
    const data = await readJson(response);
    if (response.ok && data) {
      setResult(data);
    } else if (data && typeof data.detail === "string") {
      setErrorMessage(data.detail);
    } else {
      setErrorMessage(`The backend returned an error (HTTP ${response.status}). Please try again.`);
    }
    setIsLoading(false);
  }

  return (
    <main className="container">
      <h1>Log Analyzer</h1>
      <p className="subtitle">Upload an Nginx access log to get statistics and an AI summary.</p>

      <div className="upload">
        <input type="file" accept=".log,.txt" onChange={(event) => setSelectedFile(event.target.files[0])} />
        <button onClick={handleAnalyze} disabled={isLoading}>
          {isLoading ? "Analyzing..." : "Analyze"}
        </button>
      </div>

      {isLoading && <p>Analyzing the log, this can take a few seconds...</p>}
      {errorMessage && <p className="error">{errorMessage}</p>}

      {result && (
        <>
          <div className="stat-cards">
            <div className="stat-card">
              <span className="stat-value">{result.analysis.total_requests}</span>
              <span className="stat-label">Total requests</span>
            </div>
            <div className="stat-card">
              <span className="stat-value">{result.analysis.unique_ips}</span>
              <span className="stat-label">Unique IPs</span>
            </div>
            <div className="stat-card">
              <span className="stat-value">{result.analysis.error_rate}%</span>
              <span className="stat-label">Error rate</span>
            </div>
          </div>

          <h2>AI summary</h2>
          {result.ai_summary ? (
            <p className="summary">{result.ai_summary}</p>
          ) : (
            <p className="summary unavailable">
              The AI summary is not available right now. The statistics below are still correct.
            </p>
          )}

          <h2>Top IPs</h2>
          <table>
            <thead>
              <tr><th>IP address</th><th>Requests</th></tr>
            </thead>
            <tbody>
              {result.analysis.top_ips.map((item) => (
                <tr key={item.ip}><td>{item.ip}</td><td>{item.requests}</td></tr>
              ))}
            </tbody>
          </table>

          <h2>Suspicious IPs</h2>
          {result.analysis.suspicious_ips.length === 0 ? (
            <p>No suspicious IPs found.</p>
          ) : (
            <ul className="suspicious-list">
              {result.analysis.suspicious_ips.map((item) => (
                <li key={item.ip}>{item.ip}: {item.failed_requests} failed requests (401/403/404)</li>
              ))}
            </ul>
          )}
        </>
      )}
    </main>
  );
}

export default App;
