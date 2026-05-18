import pytest
from main import generate_prompt, call_LLM

@pytest.fixture(autouse=True)
def mock_set_key(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake_key")

def test_generate_prompt():
    sample_json = {
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
    prompt = generate_prompt(sample_json)
    
    assert "View this from the perspective of a cybersecurity network analyst." in prompt
    assert '"ip": "127.0.0.1"' in prompt
    assert '"port": "456"' in prompt
    assert '"product": "Mock_Product"' in prompt
