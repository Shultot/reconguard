import sys
import re
import itertools
import time
import threading
import functools
import logging
import ipaddress
import argparse #used to parse arguments passed to program
import os #check existence of file for deletion

#HEADER PRINTED AT RUNTIME
BANNER = r"""
  ____                       ____                     _
 |  _ \ ___  ___ ___  _ _   / ___|_   _  __ _ _ __ __| |
 | |_) / _ \/ __/ _ \| '_ \| |  _| | | |/ _` | '__/ _` |
 |  _ <  __/ (_| (_) | | | | |_| | |_| | (_| | | | (_| |
 |_| \_\___|\___\___/|_| |_|\____|\__,_|\__,_|_|  \__,_|
"""

#DEFAULT LOG FILE CONFIGURATION
logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)
#LOGGING AND SPINNER
def progress_output(message):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            logging.info(f"TASK START: {message}")
            stop_event = threading.Event()

            def spinner():
                for char in itertools.cycle("+x"):
                    if stop_event.is_set():
                        break
                    sys.stdout.write(f"\r{message} {char}")
                    sys.stdout.flush()
                    time.sleep(0.1)
                sys.stdout.write(f"\r{message} Done!\n")

            t = threading.Thread(target=spinner)
            t.start()
            start_time = time.perf_counter()

            try:
                result = func(*args, **kwargs)
                duration = time.perf_counter() - start_time
                logging.info(f"COMPLETED: {message} (Duration: {duration:.2f}s)")
                return result
            finally:
                stop_event.set()
                t.join()
        return wrapper
    return decorator

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

    # IPv6 support
    try:
        ip = ipaddress.ip_address(targetIP)

        if isinstance(ip, ipaddress.IPv6Address):
            # REMOVE interface zone index for Nmap compatibility
            return str(ip).split('%')[0]
    except ValueError:
        pass

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
    
    #REPORT GENERATION
@progress_output("Printing report   ")
def print_report(report, filename="report.txt"):
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

#FILE DELETION
def remove_file(filename):
    if os.path.exists(filename):
        os.remove(filename)