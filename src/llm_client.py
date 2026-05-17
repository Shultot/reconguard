import os
import json
from google import genai #LLM
# src/io_handler.py
from io_handler import progress_output

MODEL_NAME = "gemini-3-flash-preview"
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()

#PROMPT GENERATION
def generate_prompt(report):
    return f"""
View this from the perspective of a cybersecurity network analyst.

JSON:
{json.dumps(report, indent=2)}

Based on the provided JSON extracted from an Nmap report, do the following:
- Create a list of devices connected to the network
- Explain the Nmap reports findings in plain language
- List any recommendations to improve security
- Present recommendations as a numbered list, each number on a new line
- Sort recommendations based on severity
- Respond ONLY in valid JSON format:

{{
    "devices": [
    {{
        "device_name": "...",
        "ip_address": "...",
        "description": "..."
    }}
    ],
    "findings": [
    {{
        "device_name": "...",
        "details": "...",
        "recommendations": "..."
    }}
    ]
}}
"""

#LLM CALL
@progress_output("Sending prompt to Gemini  ")
def call_LLM(prompt):
    client = genai.Client(api_key=GEMINI_API_KEY)
    response = client.models.generate_content(
        model = MODEL_NAME,
        contents=prompt
    )
    responseText = response.text.strip() if response.text else ""
    if responseText.startswith("```"):
        responseText = responseText.strip("`")
        responseText = responseText.replace("json", "", 1).strip()
    return json.loads(responseText)