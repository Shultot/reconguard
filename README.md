# ReconGuard

ReconGuard is a security reconnaissance tool designed to support network scanning with LLM analysis and recommendations. Users will provide the IP address of a private target to scan and receive a report listing connected devices and assessment findings. Findings consist of: vulnerability severity level, risk summary, possible exploitations, recommended actions, and verification steps to confirm the vulnerability. Information is supported with CVE evidence.

## Features

* Automated network scanning
* Support for IPv4 and IPv6 address formats
* Input validation for secure execution
* Exposed services analysis based on known CVE vulnerabilities
* Structured report generation (clear recommendations)
* Modular architecture (scanner, parser, detector, report)

## Requirements

* Python 3.11+
* Nmap
* pip
* Google Gemini API key

## Project Structure

```
reconguard/
├── .github/workflows/     # CI/CD pipeline configuration
├── src/                   # Source code modules
├── tests/                 # Test code for automatic testing
├── main.py                # Entry point
├── pyproject.toml         # Configuration file for pytest
├── requirements.txt       # Dependencies required to run program
```

## Installation

1. Clone the repository:

```bash
git clone https://github.com/<YOUR-GIT>/reconguard.git
cd reconguard
```


2. Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```


3. Install dependencies:

```bash
pip install -r requirements.txt
```


4. Set up your Gemini API Key:

   - Go to [Google AI Studio](https://aistudio.google.com) and sign in
   - Click **Get API Key** and create a new key
   - Set it as an environment variable:

   
```bash
   $env:GEMINI_API_KEY = "your-api-key-here"
```


## Usage

Run the main program:

```bash
python main.py
```

Example:

```bash
python main.py --target 192.168.1.1
```
## Troubleshooting

**Nmap not installed**
ReconGuard will exit with an error if Nmap is not found. Install it from [nmap.org](https://nmap.org/download.html) and ensure it is available on your system PATH.

```bash
nmap --version  # confirm Nmap is installed
```

**Invalid target input**
Only private and loopback IPv4/IPv6 addresses are accepted. Public IPs will be rejected.
```bash
# Valid examples
python main.py -t 127.0.0.1
python main.py -t 192.168.1.1
python main.py -t ::1
```

**GEMINI_API_KEY not set**
If the environment variable is missing, ReconGuard will exit with setup instructions. Set it before running:

```bash
export GEMINI_API_KEY="your-api-key-here"  
```

**No scan results returned**
If the scan completes but no findings appear, the target may have no open ports detectable from your machine. Try confirming the target is reachable:
```bash
ping 192.168.1.1
```

**Python package errors**
If you see import errors, make sure your virtual environment is activated and dependencies are installed:
```bash
source venv/bin/activate        # Mac/Linux
venv\Scripts\activate           # Windows
pip install -r requirements.txt
```

**Permission issues**
On some systems, Nmap requires elevated privileges for certain scan types. Try running with administrator or sudo access if scans fail silently.

## Security Considerations

* Input validation is enforced to prevent command injection
* Scanning is restricted to authorized targets only
* Logs are stored for auditing and monitoring

## Threat Model

Potential risks include:

* Malicious input injection
* Command injection in scanning module
* Unauthorized scan execution

Mitigations:

* Strict input validation
* Sanitized command execution
* Access control enforcement

## Future Improvements

* Web-based dashboard
* Real-time scan monitoring
* Additional scan options
* Implementation of additional tools (ex. WireShark)
* Ability to pentest based on findings

## Contributors

* Mohamed Ramadan
* Guy Mason
* Ellysa Alvarez
