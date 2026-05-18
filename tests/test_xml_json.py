from main import xml_json, rules

def test_rules():
    sample_data = {
        "hosts": [
            {
                "name": "localhost",
                "ip": "127.0.0.1",
                "status": "up",
                "ports": [
                    {
                        "port": "123",
                        "protocol": "tcp",
                        "state": "open",
                        "service": "test-name",
                        "product": "Mock_Product",
                        "version": ""
                    },
                    {
                        "port": "456",
                        "protocol": "tcp",
                        "state": "open",
                        "service": "mock-service",
                        "product": "",
                        "version": ""
                    }
                ]
            }
        ]
    }

    expected_outcome = {
        "hosts": [
            {
                "ip": "127.0.0.1",
                "hostname": "localhost",
                "open_ports": [
                    {
                        "port": "123",
                        "protocol": "tcp",
                        "service": "test-name",
                        "product": "Mock_Product"
                    },
                    {
                        "port": "456",
                        "protocol": "tcp",
                        "service": "mock-service"
                    }
                ]
            }
        ]
    }

    filtered_data = rules(sample_data)
    assert filtered_data == expected_outcome
