import argparse #used to parse arguments passed to program
import subprocess # nosec B404
import ipaddress
import getpass
from src.parser import validate_input
from src.config import DEFAULT_XML_FILE
from src.reporter import progress_output

BANNER = r"""
  ____                       ____                     _
 |  _ \ ___  ___ ___  _ _   / ___|_   _  __ _ _ __ __| |
 | |_) / _ \/ __/ _ \| '_ \| |  _| | | |/ _` | '__/ _` |
 |  _ <  __/ (_| (_) | | | | |_| | |_| | (_| | | | (_| |
 |_| \_\___|\___\___/|_| |_|\____|\__,_|\__,_|_|  \__,_|
"""
#GET TARGET IP
def get_target():

    print(BANNER)
    print("ReconGuard v1.0 | Defensive Recon Tool\n")
    print("Press Ctrl+C at any time to exit.\n")
    
    parser = argparse.ArgumentParser(
        description="",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target private IPv4/IPv6 address or loopback address (example: 192.168.1.10, 127.0.0.1, ::1)"
    )
    
    args = parser.parse_args()
    return validate_input(args.target)

    #CONSTRUCT COMMAND
def nmap_command(validatedIP):
    #build nmap command to run with target IP
    #nmap -sV <targetIP> -oX scan.xml
    #XML IS READABLE MID-SCAN. SEARCH FOR MITIGATIONS
    ip = ipaddress.ip_address(validatedIP)

    if isinstance(ip, ipaddress.IPv6Address):
        return ["nmap", "-6", "-sV", "-oX", DEFAULT_XML_FILE, validatedIP]

    return ["nmap", "-sV", "-oX", DEFAULT_XML_FILE, validatedIP]

#RUN COMMAND
@progress_output("Scanning with Nmap")
def run_command(command):
    # Command is constructed as a list from validated input
    subprocess.run(command, capture_output=True, text=True) # nosec B603

def get_password():
    while True:
        password = getpass.getpass("Create encrypted password for the output PDF: ")
        if not password:
            print("Error: Password cannot be blank. Please try again.\n")
            continue
        confirm_password = getpass.getpass("Confirm encryption password: ")

        if password == confirm_password:
            return password
        else:
            print("Error: Passwords do not match. Please try again.\n")