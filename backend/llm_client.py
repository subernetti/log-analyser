import json
import os

from google import genai
from google.genai import types

MODEL_NAME = "gemini-3.5-flash-lite"
SYSTEM_PROMPT = (
    "You are a network security assistant. Write a short summary (max 5 sentences) "
    "for a non-expert: what the traffic looks like, anything suspicious, and one "
    "recommended action. Use only the provided numbers; do not invent data."
)


def generate_summary(analysis: dict) -> str:
    """Send the computed statistics (never the raw log) to Gemini and return its summary."""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set. Add it to backend/.env.")

    user_message = "Web server log statistics (JSON):\n" + json.dumps(analysis, indent=2)

    # A 30-second timeout (in milliseconds) so the user is not left waiting if the API is slow.
    client = genai.Client(api_key=api_key, http_options=types.HttpOptions(timeout=30_000))
    response = client.models.generate_content(
        model=MODEL_NAME,
        contents=user_message,
        config=types.GenerateContentConfig(system_instruction=SYSTEM_PROMPT),
    )

    # response.text is empty if Gemini blocked the answer or returned no text.
    if not response.text:
        raise RuntimeError("The AI response did not contain any text.")
    return response.text.strip()
