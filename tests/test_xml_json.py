from main import generate_prompt

def test_generate_prompt():
    sample_json = {
        "hosts": [
            {
                "name": "localhost",
                "ip": "127.0.0.1",
                "status": "up",
                "ports": [
                    {
                        "port": 8000,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http",
                        "product": "SimpleHTTPServer",
                        "version": "0.6"
                    }
                ]
            }
        ]
    }

    prompt = generate_prompt(sample_json)

    assert "View this from the perspective of a cybersecurity network analyst." in prompt
    assert '"ip": "127.0.0.1"' in prompt
    assert '"port": 8000' in prompt
    assert '"product": "SimpleHTTPServer"' in prompt

    assert '"severity"' in prompt
    assert '"risk_summary"' in prompt
    assert '"potential_risks"' in prompt
    assert '"recommended_actions"' in prompt
