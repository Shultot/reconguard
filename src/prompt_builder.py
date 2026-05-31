# PROMPT GENERATION
import json


def generate_prompt(report):
    return f"""
View this from the perspective of a cybersecurity network analyst.

JSON:
{json.dumps(report, indent=2)}

Important rules:
- Respond ONLY in valid JSON format.
- Do not invent CVEs.
- Do not invent exploit steps.
- Do not assign severity yourself.
- Use the evidence_based_severity field created by ReconGuard.
- Use confirmed_cves only if they are provided in the JSON.
- If no official CVE match exists, describe the issue as exposure or hardening guidance, not as a confirmed vulnerability.
- Explain findings in plain language.
- Recommend safe defensive fixes.
- Include how to verify the fix with a rescan.

Based on the provided JSON extracted from an Nmap report and enriched with NVD evidence, do the following:

- Create a list of devices connected to the network.
- Identify each meaningful open service as a separate security finding.
- Use ReconGuard's evidence_based_severity as the severity.
- Explain the risk in plain language.
- List potential risks.
- Include confirmed CVE evidence if available.
- Categorize recommended actions by priority: high, medium, and low.
- Include a verification step for each finding.

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
            "severity": "...",
            "severity_source": "NVD CVSS / No official CVE match",
            "host": "...",
            "ip_address": "...",
            "port": "...",
            "service": "...",
            "product": "...",
            "version": "...",
            "status": "...",
            "confirmed_cves": [
                {{
                    "cve_id": "...",
                    "cvss_version": "...",
                    "cvss_score": "...",
                    "cvss_severity": "...",
                    "source": "NVD"
                }}
            ],
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
            }},
            "verification_step": "..."
        }}
    ]
}}
"""


