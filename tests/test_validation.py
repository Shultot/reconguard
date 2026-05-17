import pytest
from main import validate_input

@pytest.mark.parametrize("valid_ip", [
    "192.168.1.1",
    "10.0.0.1",
    "172.16.0.1",
    "127.0.0.1",
    "::1",
    "fe80::1"
])

def test_valid_ip(valid_ip):
    actual_output = validate_input(valid_ip)
    assert actual_output == valid_ip

@pytest.mark.parametrize("invalid_ip", [
    "8.8.8.8",
    "999.999.999.999",
    "92.168.1",
    "hello",
    "192.168.1.1;",
    "192.168.1.1 && whoami",
    ""
])

def test_invalid_ipv4(invalid_ip):
    with pytest.raises(ValueError):
        validate_input(invalid_ip)