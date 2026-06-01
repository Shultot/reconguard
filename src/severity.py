# Severity ranking used to determine the highest CVE severity across multiple matches
SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}


def choose_highest_cve_severity(cves):
    # Iterate all returned CVEs and return the highest severity level found
    # Returns "Unknown" if no CVEs were matched
    if not cves:
        return "Unknown"

    highest = "Unknown"

    for cve in cves:
        severity = str(cve.get("cvss_severity", "Unknown")).upper()

        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(highest.upper(), 0):
            highest = severity.title()

    return highest
