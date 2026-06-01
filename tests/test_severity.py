import pytest
from src.severity import choose_highest_cve_severity

#Verifies that choose_highest_cve_severity functions as expected
#Sample cvss severity levels sent to function and result is asserted with the expected outcome
@pytest.mark.parametrize("cves, expected_outcome", [
        (
            [{"cvss_severity": "Unknown"}, {"cvss_severity": "Medium"}, {"cvss_severity": "High"}],
            "High"
        ),
        (
            [{"cvss_severity": "Medium"}, {"cvss_severity": "Medium"}, {"cvss_severity": "High"}, {"cvss_severity": "Low"}],
            "High"
        ),
        (
            [{"cvss_severity": "Unknown"}, {"cvss_severity": "Unknown"}, {"cvss_severity": "Unknown"}],
            "Unknown"
        ),
        (
            [{"cvss_severity": ""}],
            "Unknown"
        ),
        (
            [{"cvss_severity": ""}, {"cvss_severity": ""}],
            "Unknown"
        ),
        (
            [{"cvss_severity": "High"}, {"cvss_severity": "Critical"}, {"cvss_severity": "High"}],
            "Critical"
        )


])

def test_choose_highest_cve_severity(cves, expected_outcome):
    actual_result = choose_highest_cve_severity(cves)
    assert actual_result == expected_outcome