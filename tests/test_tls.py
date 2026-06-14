"""Tests for TLS/network CLI commands (tls-fingerprint, parse-cert)."""
from conftest import ob_run

REAL_CERT_PEM = """\
-----BEGIN CERTIFICATE-----
MIIDTzCCAjegAwIBAgIUb7g6MzkqYdsxQkms3Jf6bSLAkh0wDQYJKoZIhvcNAQEL
BQAwNzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTENMAsGA1UECgwEVGVzdDEL
MAkGA1UEBhMCVVMwHhcNMjYwNjE0MTEzMTQ5WhcNMjYwNzE0MTEzMTQ5WjA3MRkw
FwYDVQQDDBB0ZXN0LmV4YW1wbGUuY29tMQ0wCwYDVQQKDARUZXN0MQswCQYDVQQG
EwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKpxd2zRbb8UvR+/
3JMMmTrWRBCFHauF1nxweizzQCUXrCVvd0/6q9rMGLWKUfCDg6w/nW3ro1iWEi8+
v4WLzOdLcVG2Cc3Wr7fc32yN24q58k+bvNG5Xf5ujbrUwAKL8vUFXuNrBdx8GZnI
bM/q6MDd9sxmM/w7E7EASoP48U7TMjI+0cT1K2wlhGSfPyR3GXHeviEqAqYSiJP/
2FKWCBazREMhl5beTXRPC3FYJKAbKrYQ5aPVx8mcoW3JbuQU2KfySlcnRFKJpS0q
nX6pcQGPBXPPrXVKsPQBaIaFxALah18IrVt3aA6IlZj5F9kI5Vzcjwi0IYG7hffp
aFeQbnkCAwEAAaNTMFEwHQYDVR0OBBYEFBgrZ7N2tj8cduCp+Du/WjITpqEeMB8G
A1UdIwQYMBaAFBgrZ7N2tj8cduCp+Du/WjITpqEeMA8GA1UdEwEB/wQFMAMBAf8w
DQYJKoZIhvcNAQELBQADggEBAKngDZQ3hYLNIF0NZtptdrB3OBXjUkIobqEVFeSE
EVeNI1kxse7J4W5V+f0IRXjiKATLfz7akFYWmEzt+c71fxEQtjRcP4RXi19yqt7Q
fgMp0OmSqmYWLMAofx+hX/XnVkbCcH61fTuW1741gEQ5Mi4hOSFcu5ny7M4VGkfW
c/a0/M+Erc4EzWxJTJuTYCVG2g59DzsQi5lSmfyPB3gOtr86al6YilWEkiKWb9jH
d8ltQmeVis0T4Kl0TmS22lQjYOnOczM51k/iMVX2pkFqYmPhJkNSD/TVF33P5v00
jrH5chwwsE/GewAJ9wOyXiGHhTGuxyv/ZpLZp6JotWiLJis=
-----END CERTIFICATE-----"""


def test_parse_cert():
    rc, out, err = ob_run("parse-cert", input_data=REAL_CERT_PEM)
    assert rc == 0, err
    out_lower = out.lower()
    assert "test.example.com" in out or "test.example.com" in out_lower
    assert "sha-256" in out_lower or "SHA-256" in out
    assert "2048" in out or "rsa" in out_lower


def test_tls_fingerprint():
    """Identify TLS record bytes."""
    tls_record_hex = "16030300" + "05" + "14000000"
    input_hex = tls_record_hex + "00" * 16
    rc, out, err = ob_run("tls-fingerprint", "--hex-input", input_hex)
    assert rc == 0, err
    assert any(w in out.lower() for w in ("tls", "record", "handshake"))


def test_tls_fingerprint_tls13():
    """TLS 1.3 record detection."""
    tls13 = "17030300" + "10" + "00" * 16
    rc, out, err = ob_run("tls-fingerprint", "--hex-input", tls13)
    assert rc == 0, err
