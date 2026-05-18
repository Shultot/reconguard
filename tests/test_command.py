import pytest
from main import nmap_command

@pytest.mark.parametrize("valid_ip, expected_outcome", [
    (
        "192.168.1.1",
        ["nmap", "-sV", "192.168.1.1", "-oX", "scan.xml"]
    ),
    (
        "172.16.0.1",
        ["nmap", "-sV", "172.16.0.1", "-oX", "scan.xml"]
    ),
    (
        "::1",
        ["nmap", "-6", "-sV", "::1", "-oX", "scan.xml"]
    ),
    (
        "fe80::1",
        ["nmap", "-6", "-sV", "fe80::1", "-oX", "scan.xml"]
    )
])

def test_command_construction(valid_ip, expected_outcome):
    actual_output = nmap_command(valid_ip)
    assert actual_output == expected_outcome

def test_list_return():
    actual_outcome = nmap_command("192.168.1.1")
    assert isinstance(actual_outcome, list)
    assert all(isinstance(item, str) for item in actual_outcome)