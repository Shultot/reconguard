import pytest
from src.scanner import nmap_command

@pytest.mark.parametrize("valid_ip, expected_command", [
    (
        "192.168.1.50",
        ["nmap", "-sV", "192.168.1.50", "-oX", "scan.xml"]
    ),
    (
        "10.0.0.0",
        ["nmap", "-sV", "10.0.0.0", "-oX", "scan.xml"]
    ),
    (
        "127.0.0.1",
        ["nmap", "-sV", "127.0.0.1", "-oX", "scan.xml"]
    )
])

def test_command_construction(valid_ip, expected_command):
    actual_output = nmap_command(valid_ip)
    assert actual_output == expected_command