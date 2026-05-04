import shutil
import json
import re
import os
import subprocess
import argparse
import xml.etree.ElementTree as ET #ElementTree instead of xmltodict to avoid having to install xmltodict
from google import genai

BANNER = r"""
  ____                        ____                     _
 |  _ \ ___  ___ ___  _ __  / ___|_   _  __ _ _ __ __| |
 | |_) / _ \/ __/ _ \| '_ \| |  _| | | |/ _` | '__/ _` |
 |  _ <  __/ (_| (_) | | | | |_| | |_| | (_| | | | (_| |
 |_| \_\___|\___\___/|_| |_|\____|\__,_|\__,_|_|  \__,_|
"""

MODEL_NAME = "gemini-3-flash-preview"
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()

#INSTALLATION/VERSION CHECKER?

#LOGGING

#GET TARGET IP
def get_target():

    print(BANNER)
    print("ReconGuard v1.0 | Defensive Recon Tool\n")
    
    parser = argparse.ArgumentParser(
        description="",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target private IPv4 address (example: 192.168.1.10)"
    )
    
    args = parser.parse_args()
    return validate_input(args.target)

#VALIDATE INPUT
def validate_input(targetIP):
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    if not re.match(pattern, targetIP):
        raise ValueError("Invalid format. Please enter a valid IPv4 address.")

    octets = targetIP.split(".")

    for octet in octets:
        if not 0 <= int(octet) <= 255:
            raise ValueError("Invalid IP address. Each number must be between 0 and 255.")

    # allow localhost for safe local testing
    if targetIP == "127.0.0.1":
        return targetIP

    # private ranges       
    if octets[0] == "10":
        return targetIP
    elif octets[0] == "172" and 16 <= int(octets[1]) <= 31:
        return targetIP
    elif octets[0] == "192" and octets[1] == "168":
        return targetIP
    else:
        raise ValueError("Invalid target. Only private IP addresses are allowed.")
                    
#CONSTRUCT COMMAND
def nmap_command(validatedIP):
    #build nmap command to run with target IP
    #nmap -sV <targetIP> -oX scan.xml
    #XML IS READABLE MID-SCAN. SEARCH FOR MITIGATIONS

    return ["nmap", "-sV", validatedIP, "-oX", "scan.xml"]

#RUN COMMAND
def run_command(command):
    print("Scanning with Nmap...")
    #use os.subprocess module to run command in terminal
    subprocess.run(command, capture_output=True, text=True)

    print("Scan complete.")

#XML TO JSON
def xml_json():
    print("Converting to JSON...")
    tree = ET.parse("scan.xml")
    root = tree.getroot()
    result = {}
    hosts = []

    for host in root.findall("host"):
        host_data = {}

        #Name
        hostnames = []
        for hostname in host.findall("./hostnames/hostname"):
            host_data["name"] = hostname.attrib.get("name").split(".")[0]
        #IP
        addr = host.find("address")
        if addr is not None:
            host_data["ip"] = addr.get("addr")
        #Status
        status = host.find("status")
        if status is not None:
            host_data["status"] = status.get("state")
        #Ports
        ports = []
        for port in host.findall(".//port"):
            p = {
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "state": port.find("state").get("state")
            }
            service = port.find("service")
            if service is not None:
                p["service"] = service.get("name")
                p["product"] = service.get("product")
                p["version"] = service.get("version")
            ports.append(p)
        host_data["ports"] = ports
        hosts.append(host_data)

    result["hosts"] = hosts

    print("Conversion complete.")
    return result
    
#RULE BASED DETECTION
#def rules():


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
def call_LLM(prompt):
    print("Sending prompt to Gemini...")
    if not GEMINI_API_KEY:
        raise ValueError("Set GEMINI_API_KEY environment variable first.")
    client = genai.Client(api_key=GEMINI_API_KEY)
    response = client.models.generate_content(
        model = MODEL_NAME,
        contents=prompt
    )
    print("Response received.")
    responseText = response.text.strip() if response.text else ""
    if responseText.startswith("```"):
        responseText = responseText.strip("`")
        responseText = responseText.replace("json", "", 1).strip()
    return json.loads(responseText)

#REPORT GENERATION
def print_report(report, filename="report.txt"):
    print("Printing report...")
    devices = report.get("devices", [])
    findings = report.get("findings", [])
    
    with open(filename, "w", encoding="utf-8") as file:
        print("\n" + "=" * 60, file=file)
        print("CONNECTED DEVICES", file=file)
        print("=" * 60, file=file)

        for i, device in enumerate(devices, 1):
            
            print(f"{i}. {device['device_name']} ({device['ip_address']})", file=file)
            print(f"    Description:  {device['description']}", file=file)


        print("\n" + "=" * 60, file=file)
        print("ANALYSIS AND RECOMMENDATIONS", file=file)
        print("=" * 60, file=file)

        for i, finding in enumerate (findings, 1):

            print(f"{i}. {finding['device_name']}", file=file)
            print(f"    Details:  {finding['details']}", file=file)
            print(f"    Recommendations: {finding['recommendations']}", file=file)

    print("Report complete.")

#FILE DELETION
def remove_file(filename):
    if os.path.exists(filename):
        os.remove(filename)

def main():
    try:
        # check if nmap is installed
        if not shutil.which("nmap"):
            print("Error: Nmap is not installed. Please install Nmap first.")
            return

        # validate target IP
        validIP = get_target()

        # construct and run nmap command
        command = nmap_command(validIP)
        run_command(command)

        # convert nmap xml to json and delete xml file
        nmapJson = xml_json()
        remove_file("scan.xml")

        # handle empty scan results
        if not nmapJson.get("hosts"):
            print("Error: No scan results found. Please check the target and try again.")
            return

        # create a prompt with the json and send to llm
        prompt = generate_prompt(nmapJson)
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