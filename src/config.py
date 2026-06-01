import os
import shutil
import logging
from dotenv import load_dotenv

load_dotenv()

# Global configuration constants used across the pipeline
MODEL_NAME = "gemini-3-flash-preview"
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
DEFAULT_LOG_FILE="app.log"
DEFAULT_XML_FILE = "scan.xml"
DEFAULT_REPORT_FILE = "report.pdf"

logging.basicConfig(
    filename=DEFAULT_LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# Suppress noisy third-party HTTP client logs to prevent external service URLs
# from appearing in app.log
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("google").setLevel(logging.WARNING)
logging.getLogger("google_genai").setLevel(logging.WARNING)

load_dotenv()
def check_environment():
    # Confirms required dependencies are present before the pipeline starts
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    if not GEMINI_API_KEY:
        raise ValueError("Set GEMINI_API_KEY environment variable first.\n$env:GEMINI_API_KEY = 'your-api-key-here' ")

    if not shutil.which("nmap"):
        raise FileNotFoundError("Error: Nmap is not installed. Please install Nmap first.")
