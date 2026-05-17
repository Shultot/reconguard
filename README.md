# ReconGuard

ReconGuard is a security reconnaissance tool designed to automate network scanning, analyze results, and generate structured reports. It integrates scanning tools with parsing and reporting modules to help identify potential vulnerabilities in a system.

## Features

* Automated network scanning
* Input validation for secure execution
* Parsing of scan results
* Structured report generation
* Modular architecture (scanner, parser, detector, report)

## Project Structure

```
reconguard/
├── detector/     # Detection logic for vulnerabilities
├── llm/          # AI/analysis components (if applicable)
├── logs/         # Log files
├── parser/       # Parses scan output
├── report/       # Generates reports
├── scanner/      # Runs scans (e.g., Nmap)
├── scans/        # Stored scan results
├── main.py       # Entry point
├── requirements.txt
```

## Installation

1. Clone the repository:

```bash
git clone https://github.com/YOUR-ORG/reconguard.git
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

## Usage

Run the main program:

```bash
python main.py
```

Example:

```bash
python main.py --target 192.168.1.1
```

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
* Integration with vulnerability databases (CVE)

## Contributors

* Mohamed
* Guy
* Ellysa Alvarez
