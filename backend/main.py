from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from llm_client import generate_summary
from log_analyzer import analyze_entries, parse_log_file

load_dotenv()  # copies the values from backend/.env into the environment variables

ALLOWED_EXTENSIONS = (".log", ".txt")
MAX_FILE_SIZE_MB = 5
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

app = FastAPI(title="Log Analyzer")

# The browser blocks requests from the React page (port 5173) to this API (port 8000)
# unless the API explicitly allows that origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["POST"],
    allow_headers=["*"],
)


# A normal "def" (not "async def"): FastAPI runs it in a separate thread,
# so the slow LLM call does not block other requests.
@app.post("/analyze")
def analyze(file: UploadFile = File(...)) -> dict:
    """Parse the uploaded log file, compute statistics and add an AI summary."""
    if not file.filename or not file.filename.lower().endswith(ALLOWED_EXTENSIONS):
        raise HTTPException(status_code=400, detail="Please upload a .log or .txt file.")

    # Read at most one byte more than the limit, so a huge file is never loaded into memory.
    raw_bytes = file.file.read(MAX_FILE_SIZE_BYTES + 1)
    if len(raw_bytes) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"The file is too large. The maximum size is {MAX_FILE_SIZE_MB} MB.",
        )

    content = raw_bytes.decode("utf-8", errors="replace")
    if not content.strip():
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")

    entries = parse_log_file(content)
    if not entries:
        raise HTTPException(status_code=400, detail="No valid Nginx log lines were found in the file.")

    analysis = analyze_entries(entries)

    # If the AI fails, the statistics are still useful, so we return them without a summary.
    # We catch every exception on purpose: besides the SDK's own APIError, a timeout or a
    # lost connection raises a raw network exception (httpx), and none of them may turn a
    # successful analysis into a 500 error. The summary is optional, the statistics are not.
    try:
        ai_summary = generate_summary(analysis)
    except Exception as error:
        print(f"LLM call failed: {type(error).__name__}: {error}")  # for the developer, not the user
        ai_summary = None

    return {"analysis": analysis, "ai_summary": ai_summary}
