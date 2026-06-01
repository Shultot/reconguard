import json
from google import genai #LLM
from src.config import GEMINI_API_KEY, MODEL_NAME
from src.reporter import progress_output


#LLM CALL
@progress_output("Sending prompt to Gemini  ")
def call_LLM(prompt):
    # Send the enriched prompt to Gemini and parse the JSON response
    # Strip markdown code fences if the model wraps its output in them
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