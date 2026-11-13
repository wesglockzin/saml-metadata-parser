import base64
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from saml_ui_parser_logic import parse_file_bytes, sanitize_filename


def make_cert_b64():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-signer")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(255)
        .not_valid_before(datetime(2024, 1, 1))
        .not_valid_after(datetime(2034, 1, 1))
        .sign(key, hashes.SHA256())
    )
    return base64.b64encode(cert.public_bytes(Encoding.DER)).decode()


def idp_xml(cert_b64, location="https://idp.example.invalid/sso"):
    return f"""<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
        xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example.invalid/id">
      <IDPSSODescriptor WantAuthnRequestsSigned="true">
        <KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data>
          <ds:X509Certificate>{cert_b64}</ds:X509Certificate>
        </ds:X509Data></ds:KeyInfo></KeyDescriptor>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
        <SingleSignOnService Binding="urn:b:post" Location="{location}"/>
      </IDPSSODescriptor></EntityDescriptor>""".encode()


def test_idp_metadata_is_parsed():
    info = parse_file_bytes("x", idp_xml(make_cert_b64()))
    assert info["entity_id"] == "https://idp.example.invalid/id"
    assert info["role"] == "IdP"
    assert info["single_sign_on"][0]["location"] == "https://idp.example.invalid/sso"
    assert len(info["certs_signing"]) == 1
    details = info["certs_signing_details"][0]
    assert details["subject"] == "CN=test-signer"
    assert details["serial"] == "FF"
    assert details["not_before"] == "2024-01-01T00:00:00"
    assert details["public_key"]["algorithm"] == "RSA"


def test_idp_want_authn_requests_signed_is_read():
    info = parse_file_bytes("x", idp_xml(make_cert_b64()))
    assert info["authn_requests_signed"] == "true"


def test_bare_ampersand_in_location_is_tolerated():
    info = parse_file_bytes(
        "x", idp_xml(make_cert_b64(), "https://idp.example.invalid/sso?a=1&b=2")
    )
    assert info["single_sign_on"][0]["location"].endswith("?a=1&b=2")


def test_sp_role_and_acs():
    xml = b"""<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="sp1">
      <SPSSODescriptor><AssertionConsumerService index="0" Binding="urn:b:post"
        Location="https://sp.example.invalid/acs"/></SPSSODescriptor></EntityDescriptor>"""
    info = parse_file_bytes("x", xml)
    assert info["role"] == "SP"
    assert info["acs_endpoints"][0]["location"] == "https://sp.example.invalid/acs"


def test_unreadable_certificate_gives_stub_not_crash():
    info = parse_file_bytes("x", idp_xml(base64.b64encode(b"not a certificate").decode()))
    assert len(info["certs_signing"]) == 1
    assert "parse_error" in info["certs_signing_details"][0]


def test_sanitize_filename():
    assert sanitize_filename("../a/b c.xml") == "..ab c.xml"
    assert sanitize_filename("///") == "metadata"
