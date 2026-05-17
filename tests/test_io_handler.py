import pytest
from src.io_handler import validate_input

@pytest.mark.parametrize("valid_ip4", ["192.168.1.1",
    "192.168.56.78",
    "192.168.255.254",
    "172.16.45.200",
    "172.20.10.8",
    "172.31.254.1",
    "10.14.233.91",
    "10.0.0.5",
    "10.255.199.3",
    "127.0.0.1"])

def test_valid_ipv4(valid_ip4):
    actual_output = validate_input(valid_ip4)
    assert actual_output == valid_ip4

@pytest.mark.parametrize("invalid_ip4", ["203.0.113.25",
    "216.58.214.14",
    "abc.def.ghi.jkl",
    "256.100.50.25",
    "192.168.1"])

def test_invalid_ipv4(invalid_ip4):
    with pytest.raises(ValueError):
        validate_input(invalid_ip4)