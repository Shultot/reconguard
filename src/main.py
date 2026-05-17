import shutil #used to confirm Nmap is installed in system
from io_handler import get_target, print_report, remove_file
from scanner import nmap_command, run_command, xml_json, rules
from llm_client import generate_prompt, call_LLM
import xml.etree.ElementTree as ET
import os

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()

#CHECK THAT REQUIRED VARIABLES ARE SET
#ie: Nmap is installed and API key is set
def verify_environment():
    # check if nmap is installed
    if not shutil.which("nmap"):
        raise ValueError("Nmap is not installed. Please install Nmap first.")
            
    if not GEMINI_API_KEY:
        raise ValueError("Set GEMINI_API_KEY environment variable first.")
    
def main():
    try:
        verify_environment()

        # validate target IP
        validIP = get_target()

        # construct and run nmap command
        command = nmap_command(validIP)
        run_command(command)

        # convert nmap xml to json and delete xml file
        unfilteredJson = xml_json("scan.xml", isFile=True)
        filteredJson = rules(unfilteredJson)
        remove_file("scan.xml")

        # handle empty scan results
        if not unfilteredJson.get("hosts"):
            print("Error: No scan results found. Please check the target and try again.")
            return

        # create a prompt with the json and send to llm
        prompt = generate_prompt(filteredJson)
        report = call_LLM(prompt)

        # save the report as a text file
        print_report(report)

    except ValueError as error:
        print(f"Error: {error}")
    
    except FileNotFoundError:
        print("Error: Required file was not found. Please try running the scan again.")
    
    except ET.ParseError:
        print("Error: Could not read the scan results. The XML file may be empty or damaged.")
    
    except Exception:
        print("Error: Something went wrong. Please check your input and try again.")

if __name__ == "__main__":
    main()
