SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}


def choose_highest_cve_severity(cves):
    if not cves:
        return "Unknown"

    highest = "Unknown"

    for cve in cves:
        severity = str(cve.get("cvss_severity", "Unknown")).upper()

        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(highest.upper(), 0):
            highest = severity.title()

    return highest
