import sys
#import functions from other PY files
from src.scanner import get_target, nmap_command, run_command, get_password
from src.parser import xml_json, rules
from src.prompt_builder import generate_prompt
from src.llm_client import call_LLM
from src.reporter import print_report, remove_file, console
from src.config import check_environment
from src.evidence_builder import enrich_with_cve_evidence

# main
def main():
    try:
        check_environment()
        validIP = get_target()
        command = nmap_command(validIP)
        run_command(command)
        unfilteredData = xml_json("scan.xml", isFile=True)
        filteredData = rules(unfilteredData)
        remove_file("scan.xml")
        if not filteredData.get("hosts"):
            print("Scan completed successfully, but no open ports or active services were detected.")
            return
        confirmedData = enrich_with_cve_evidence(filteredData)
        prompt = generate_prompt(confirmedData)
        report = call_LLM(prompt)
        password = get_password()
        print_report(report, password)

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled by user.[/yellow]")

    except ValueError as error:
        print(f"Error: {error}")
        sys.exit(1)

    except FileNotFoundError:
        print("Error: Required file was not found. Please try running the scan again.")

    except Exception as error:
        error_text = str(error)

        if "503" in error_text or "UNAVAILABLE" in error_text:
            print("Error: Gemini is temporarily unavailable or under high demand. Please try again later.")

        elif "GEMINI_API_KEY" in error_text:
            print("Error: Gemini API key is missing. Please set the GEMINI_API_KEY environment variable.")

        else:
            print(f"Error details: {error}")


if __name__ == "__main__":
    main()
