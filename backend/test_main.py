import httpx
import pytest
from fastapi.testclient import TestClient
from httpx import Response

import main

# TestClient sends requests to the app directly, without starting a real server.
client = TestClient(main.app)

VALID_LOG = (
    '192.168.1.10 - - [08/Nov/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" '
    '200 5320 "-" "Mozilla/5.0"\n'
)


def fake_summary(analysis: dict) -> str:
    """Stand-in for the real AI call, so tests are free, fast and need no API key."""
    return "Fake summary for tests."


def failing_summary(analysis: dict) -> str:
    """Stand-in for the AI call that simulates the AI service being down."""
    raise RuntimeError("The AI service is down.")


def timeout_summary(analysis: dict) -> str:
    """Stand-in for the AI call that simulates a timeout: a raw network error, not an APIError."""
    raise httpx.ReadTimeout("The AI service did not answer in time.")


def upload_file(filename: str, content: str) -> Response:
    """Send a file to POST /analyze, like the React page does."""
    return client.post("/analyze", files={"file": (filename, content)})


# monkeypatch replaces main.generate_summary only for the duration of one test.
def test_successful_analysis_returns_stats_and_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "generate_summary", fake_summary)
    response = upload_file("access.log", VALID_LOG)
    assert response.status_code == 200
    assert response.json()["analysis"]["total_requests"] == 1
    assert response.json()["ai_summary"] == "Fake summary for tests."


def test_stats_are_returned_when_ai_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "generate_summary", failing_summary)
    response = upload_file("access.log", VALID_LOG)
    assert response.status_code == 200
    assert response.json()["analysis"]["total_requests"] == 1
    assert response.json()["ai_summary"] is None


def test_stats_are_returned_when_ai_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "generate_summary", timeout_summary)
    response = upload_file("access.log", VALID_LOG)
    assert response.status_code == 200
    assert response.json()["analysis"]["total_requests"] == 1
    assert response.json()["ai_summary"] is None


def test_wrong_file_type_is_rejected() -> None:
    response = upload_file("data.csv", VALID_LOG)
    assert response.status_code == 400
    assert response.json()["detail"] == "Please upload a .log or .txt file."


def test_empty_file_is_rejected() -> None:
    response = upload_file("empty.log", "")
    assert response.status_code == 400
    assert response.json()["detail"] == "The uploaded file is empty."


def test_too_large_file_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    # A 10-byte limit for this test, so we don't have to create a 5 MB file.
    monkeypatch.setattr(main, "MAX_FILE_SIZE_BYTES", 10)
    response = upload_file("access.log", VALID_LOG)
    assert response.status_code == 413
