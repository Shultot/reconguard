import logging
from src.nvd_lookup import search_nvd_by_keyword
from src.severity import choose_highest_cve_severity


def build_product_keyword(port_info):
    """
    Build the best keyword for NVD search from Nmap service data.
    Normalize common Nmap product names to NVD-friendly search terms.
    """
    product = str(port_info.get("product", "")).strip().lower()
    service = str(port_info.get("service", "")).strip().lower()

    # Normalize common product names
    if "apache" in product or "httpd" in product:
        return "apache"

    if "nginx" in product:
        return "nginx"

    if "openssh" in product or "ssh" in product:
        return "openssh"

    if "mysql" in product:
        return "mysql"

    if "postgresql" in product or "postgres" in product:
        return "postgresql"

    if "redis" in product:
        return "redis"

    # Prefer product over generic service
    if product:
        return product

    if service and service != "unknown":
        return service

    return ""

def enrich_with_cve_evidence(filtered_data):
    enriched_hosts = []

    for host in filtered_data.get("hosts", []):
        enriched_ports = []

        for port_info in host.get("open_ports", []):
            product_keyword = build_product_keyword(port_info)
            version = str(port_info.get("version", "")).strip()

            cves = []

            if product_keyword:
                try:
                    logging.info(f"NVD lookup product={product_keyword}, version={version}")

                    cves = search_nvd_by_keyword(
                        product=product_keyword,
                        version=version,
                        max_results=5
                    )

                    logging.info(f"NVD returned {len(cves)} CVEs")

                except Exception as error:
                    logging.warning(
                        f"NVD lookup failed for product={product_keyword}, version={version}: {error}"
                    )
                    port_info["cve_lookup_error"] = str(error)

            evidence_severity = choose_highest_cve_severity(cves)

            enriched_ports.append({
                **port_info,
                "cve_evidence_source": "NVD" if cves else "No official CVE match found",
                "confirmed_cves": cves,
                "evidence_based_severity": evidence_severity,
                "llm_can_assign_severity": False,
            })

        enriched_hosts.append({
            **host,
            "open_ports": enriched_ports,
        })

    return {
        "hosts": enriched_hosts
    }
