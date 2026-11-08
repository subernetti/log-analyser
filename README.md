# LogaN - Log Analyzer

A small web app that analyzes an Nginx access log. You upload a log file, the Python backend
computes traffic statistics and flags suspicious IP addresses, and an LLM (Google Gemini) writes a short
plain-English summary. Only the computed statistics are sent to the LLM, never the raw log.

Supported log formats: Nginx `combined` and Nginx's default `main` format (combined + `X-Forwarded-For`).

## Tech stack

- **Backend:** Python 3.11+, FastAPI, python-dotenv, Google GenAI SDK (Gemini), pytest
- **Frontend:** React (Vite), plain JavaScript, plain CSS, fetch API

## Project structure

```
log-analyzer/
├── backend/
│   ├── main.py                 # FastAPI app, CORS, POST /analyze endpoint
│   ├── log_analyzer.py         # parsing, statistics, suspicious IP detection
│   ├── llm_client.py           # sends statistics to Gemini, returns the summary
│   ├── test_log_analyzer.py    # unit tests for parsing and statistics
│   ├── test_main.py            # API tests (the AI call is replaced by a fake)
│   ├── sample_access.log       # example log to try the app
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   └── src/
│       ├── App.jsx             # the whole UI
│       ├── App.css
│       └── main.jsx
├── README.md
└── .gitignore
```

## Run the backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env              # then put your Gemini API key in .env
uvicorn main:app --reload --port 8000
```

The API runs on http://localhost:8000 (interactive docs: http://localhost:8000/docs).
You can get a Gemini API key at https://aistudio.google.com.

## Run the frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 and upload `backend/sample_access.log`.

## Run the tests

```bash
cd backend
source venv/bin/activate
pytest -v
```

The tests need no API key and make no network calls: in the API tests, the AI call is replaced
by a fake function (pytest's `monkeypatch`).

## Example response

`POST /analyze` with `sample_access.log` returns:

```json
{
  "analysis": {
    "total_requests": 24,
    "unique_ips": 5,
    "error_rate": 50.0,
    "top_ips": [
      {"ip": "203.0.113.77", "requests": 8},
      {"ip": "192.168.1.10", "requests": 5},
      {"ip": "198.51.100.23", "requests": 4},
      {"ip": "10.0.0.5", "requests": 4},
      {"ip": "192.0.2.14", "requests": 3}
    ],
    "suspicious_ips": [
      {"ip": "203.0.113.77", "failed_requests": 8}
    ]
  },
  "ai_summary": "..."
}
```

If the AI service is unavailable, `ai_summary` is `null` and the statistics are still returned.

## How it works

1. The user picks a `.log` or `.txt` file in the React page and clicks **Analyze**; the file is sent to `POST /analyze`.
2. FastAPI checks the file (type, size, not empty), and `log_analyzer.py` parses each line with a regular expression (malformed lines are skipped).
3. The backend computes total requests, unique IPs, error rate, top IPs and suspicious IPs (5+ responses with status 401/403/404).
4. Only these statistics are sent to Gemini, which returns a short summary; the backend returns statistics and summary as JSON, and React displays them.

## Security considerations

- **Only statistics go to the LLM, never the raw log.** This keeps most personal data (IP addresses count as personal data under GDPR) on the server. It also reduces prompt injection risk, because log fields like the user agent are written by attackers.
- **The API key stays on the backend.** It is read from an environment variable (`.env`), never hardcoded, and `.env` is in `.gitignore`. The frontend never sees the key.
- **CORS allows only one origin** (`http://localhost:5173`), not every website.
- **Uploads are validated:** only `.log`/`.txt` files, no empty files, and a 5 MB size limit (`413 Payload Too Large`), so a huge file cannot exhaust the server's memory.
- **Errors don't leak details:** the real error is logged on the server; the user gets a short, friendly message.

## Possible improvements

- Process large files line by line (streaming) instead of rejecting files above 5 MB.
- Detect more attack patterns, e.g. many requests in a short time window (rate-based detection) or known scanner paths like `/.env`.
- Deploy it with Docker and add authentication and rate limiting, so only authorized users can upload logs.
