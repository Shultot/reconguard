import os
import time
import requests


NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def extract_cvss(cve_record):
    """
    Extract the best available CVSS score and severity from an NVD CVE record.
    Prefer CVSS v3.1, then v3.0, then v2.
    """
    metrics = cve_record.get("metrics", {})

    if "cvssMetricV31" in metrics:
        metric = metrics["cvssMetricV31"][0]
        return {
            "cvss_version": "3.1",
            "cvss_score": metric["cvssData"].get("baseScore"),
            "cvss_severity": metric["cvssData"].get("baseSeverity", "Unknown"),
        }

    if "cvssMetricV30" in metrics:
        metric = metrics["cvssMetricV30"][0]
        return {
            "cvss_version": "3.0",
            "cvss_score": metric["cvssData"].get("baseScore"),
            "cvss_severity": metric["cvssData"].get("baseSeverity", "Unknown"),
        }

    if "cvssMetricV2" in metrics:
        metric = metrics["cvssMetricV2"][0]
        return {
            "cvss_version": "2.0",
            "cvss_score": metric["cvssData"].get("baseScore"),
            "cvss_severity": metric.get("baseSeverity", "Unknown"),
        }

    return {
        "cvss_version": None,
        "cvss_score": None,
        "cvss_severity": "Unknown",
    }


def search_nvd_by_keyword(product, version="", max_results=5):
    """
    Search NVD using product/version keywords.

    Example:
    product='apache httpd'
    version='2.4.49'
    """
    if not product:
        return []

    keyword = product.strip()

    if version:
        keyword = f"{keyword} {version.strip()}"

    headers = {}

    # Optional: if you later get an NVD API key, put it in NVD_API_KEY.
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }

    # Small delay to be gentle with public API rate limits.
    time.sleep(0.7)

    response = requests.get(
        NVD_CVE_API_URL,
        params=params,
        headers=headers,
        timeout=20,
    )

    response.raise_for_status()

    data = response.json()
    results = []

    for item in data.get("vulnerabilities", []):
        cve_record = item.get("cve", {})
        cve_id = cve_record.get("id", "Unknown")

        descriptions = cve_record.get("descriptions", [])
        description = "No description available."

        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", description)
                break

        cvss = extract_cvss(cve_record)

        results.append({
            "cve_id": cve_id,
            "description": description,
            "cvss_version": cvss["cvss_version"],
            "cvss_score": cvss["cvss_score"],
            "cvss_severity": cvss["cvss_severity"],
            "source": "NVD",
        })

    return results
