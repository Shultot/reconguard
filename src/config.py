import os
import shutil
import logging
from dotenv import load_dotenv

MODEL_NAME = "gemini-3-flash-preview"
DEFAULT_LOG_FILE="app.log"
DEFAULT_XML_FILE = "scan.xml"
DEFAULT_REPORT_FILE = "report.pdf"

logging.basicConfig(
    filename=DEFAULT_LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

load_dotenv()
def check_environment():
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    if not GEMINI_API_KEY:
        raise ValueError("Set GEMINI_API_KEY environment variable first.")

    if not shutil.which("nmap"):
        raise FileNotFoundError("Error: Nmap is not installed. Please install Nmap first.")