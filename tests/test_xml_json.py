from src.parser import xml_json

def test_xml_json_basic_structure(monkeypatch, tmp_path):

    sample_xml = """<?xml version="1.0"?>
    <nmaprun>
        <host>
            <status state="up"/>
            <address addr="127.0.0.1" addrtype="ipv4"/>
            <hostnames>
                <hostname name="localhost"/>
            </hostnames>
            <ports>
                <port protocol="tcp" portid="8000">
                    <state state="open"/>
                    <service name="http" product="SimpleHTTPServer" version="0.6"/>
                </port>
            </ports>
        </host>
    </nmaprun>
    """

    scan_file = tmp_path / "scan.xml"
    scan_file.write_text(sample_xml)

    monkeypatch.chdir(tmp_path)

    result = xml_json("scan.xml", isFile=True)

    assert "hosts" in result
    assert result["hosts"][0]["ip"] == "127.0.0.1"
    assert result["hosts"][0]["name"] == "localhost"
    assert result["hosts"][0]["status"] == "up"

    port = result["hosts"][0]["ports"][0]

    assert port["port"] == "8000"
    assert port["protocol"] == "tcp"
    assert port["state"] == "open"
    assert port["service"] == "http"
    assert port["product"] == "SimpleHTTPServer"
    assert port["version"] == "0.6"
