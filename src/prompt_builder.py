#PROMPT GENERATION
import json


def generate_prompt(report):
    return f"""
View this from the perspective of a cybersecurity network analyst.

JSON:
{json.dumps(report, indent=2)}

Based on the provided JSON extracted from an Nmap report, do the following:

- Create a list of devices connected to the network
- Explain the Nmap reports findings in plain language
- List any recommendations to improve security
- Present recommendations as a numbered list, each number on a new line
- Sort recommendations based on severity
- Respond ONLY in valid JSON format:
- Create a list of devices connected to the network.
- Identify each meaningful open service as a separate security finding.
- Assign a severity level to each finding: Critical, High, Medium, Low, or Informational.
- Explain the risk in plain language.
- List potential risks.
- Categorize recommended actions by priority: high, medium, and low.
- Respond ONLY in valid JSON format.

Use this exact JSON structure:


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
            "title": "...",
            "severity": "Critical/High/Medium/Low/Informational",
            "host": "...",
            "ip_address": "...",
            "port": "...",
            "service": "...",
            "version": "...",
            "status": "...",
            "risk_summary": "...",
            "potential_risks": [
                "...",
                "..."
            ],
            "recommended_actions": {{
                "high": [
                    "..."
                ],
                "medium": [
                    "..."
                ],
                "low": [
                    "..."
                ]
            }}
        }}
    ]
}}
"""