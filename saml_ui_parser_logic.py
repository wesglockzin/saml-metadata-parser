#!/usr/bin/env python3
import base64
from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

NAMESPACES = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#"
}

def load_xml_bytes(b):
    return etree.fromstring(b)

def to_pem(b64_der):
    der = base64.b64decode(b64_der.encode("ascii"))
    lines = base64.encodebytes(der).decode("ascii").replace("\n", "")
    chunks = [lines[i:i+64] for i in range(0, len(lines), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(chunks) + "\n-----END CERTIFICATE-----\n"

def hex_bytes(b):
    h = b.hex().upper()
    return " ".join(h[i:i+2] for i in range(0, len(h), 2))

def block_hex(b, width=32):
    h = hex_bytes(b).split(" ")
    lines = []
    row = []
    for i, byte in enumerate(h, 1):
        row.append(byte)
        if i % width == 0:
            lines.append(" ".join(row))
            row = []
    if row:
        lines.append(" ".join(row))
    return "\n".join(lines)

def get_attr_value(name, rdn_seq):
    for r in rdn_seq:
        for a in r:
            if a.oid.dotted_string == name:
                return a.value
    return None

def parse_cert_details(pem):
    cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    subj = cert.subject.rfc4514_string()
    iss = cert.issuer.rfc4514_string()
    serial = format(cert.serial_number, "X")
    not_before = cert.not_valid_before.isoformat()
    not_after = cert.not_valid_after.isoformat()
    sha1 = cert.fingerprint(hashes.SHA1())
    sha256 = cert.fingerprint(hashes.SHA256())
    md5 = cert.fingerprint(hashes.MD5())
    pub = cert.public_key()
    if hasattr(pub, "key_size"):
        key_size = pub.key_size
    else:
        key_size = None
    if pub.__class__.__name__.startswith("RSAPublicKey"):
        key_algo = "RSA"
    elif pub.__class__.__name__.startswith("EllipticCurvePublicKey"):
        key_algo = "EC"
    elif pub.__class__.__name__.startswith("DSAPublicKey"):
        key_algo = "DSA"
    else:
        key_algo = pub.__class__.__name__
    spki = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    spki_sha1 = hashes.Hash(hashes.SHA1())
    spki_sha1.update(spki)
    spki_fp = spki_sha1.finalize()
    sig_algo_oid = cert.signature_algorithm_oid.dotted_string if cert.signature_algorithm_oid else ""
    signature = cert.signature
    details = {
        "subject": subj,
        "issuer": iss,
        "serial": serial,
        "not_before": not_before,
        "not_after": not_after,
        "fingerprints": {
            "sha1": hex_bytes(sha1),
            "sha256": hex_bytes(sha256),
            "md5": hex_bytes(md5)
        },
        "public_key": {
            "algorithm": key_algo,
            "size": key_size,
            "spki_sha1": hex_bytes(spki_fp),
            "spki_hex": block_hex(spki)
        },
        "signature": {
            "algorithm_oid": sig_algo_oid,
            "hex": block_hex(signature)
        }
    }
    return details

def parse_metadata(xml_root):
    entity_id = xml_root.get("entityID")
    idpsso = xml_root.find("md:IDPSSODescriptor", namespaces=NAMESPACES)
    spsso = xml_root.find("md:SPSSODescriptor", namespaces=NAMESPACES)
    role = "IdP" if idpsso is not None else ("SP" if spsso is not None else "Unknown")
    node = idpsso if idpsso is not None else spsso
    authn_signed = node.get("AuthnRequestsSigned") if node is not None else None
    want_assert_signed = node.get("WantAssertionsSigned") if node is not None else None
    nameid = []
    if node is not None:
        for n in node.findall("md:NameIDFormat", namespaces=NAMESPACES):
            if n.text:
                nameid.append(n.text)
    acs = []
    for sp in xml_root.findall("md:SPSSODescriptor", namespaces=NAMESPACES):
        for a in sp.findall("md:AssertionConsumerService", namespaces=NAMESPACES):
            acs.append({
                "index": a.get("index"),
                "isDefault": a.get("isDefault"),
                "binding": a.get("Binding"),
                "location": a.get("Location")
            })
    singlesignon = []
    for idp in xml_root.findall("md:IDPSSODescriptor", namespaces=NAMESPACES):
        for sso in idp.findall("md:SingleSignOnService", namespaces=NAMESPACES):
            singlesignon.append({
                "binding": sso.get("Binding"),
                "location": sso.get("Location")
            })
    certs_signing = []
    certs_encryption = []
    certs_signing_details = []
    certs_encryption_details = []
    roles = xml_root.findall(".//md:IDPSSODescriptor", namespaces=NAMESPACES) + xml_root.findall(".//md:SPSSODescriptor", namespaces=NAMESPACES)
    for kd_parent in roles:
        for kd in kd_parent.findall("md:KeyDescriptor", namespaces=NAMESPACES):
            use = kd.get("use") or "unspecified"
            cert_el = kd.find("ds:KeyInfo/ds:X509Data/ds:X509Certificate", namespaces=NAMESPACES)
            if cert_el is not None and cert_el.text:
                pem = to_pem(cert_el.text.strip())
                details = parse_cert_details(pem)
                if use == "encryption":
                    certs_encryption.append(pem)
                    certs_encryption_details.append(details)
                else:
                    certs_signing.append(pem)
                    certs_signing_details.append(details)
    return {
        "entity_id": entity_id,
        "role": role,
        "authn_requests_signed": authn_signed,
        "want_assertions_signed": want_assert_signed,
        "nameid_formats": nameid,
        "acs_endpoints": acs,
        "single_sign_on": singlesignon,
        "certs_signing": certs_signing,
        "certs_encryption": certs_encryption,
        "certs_signing_details": certs_signing_details,
        "certs_encryption_details": certs_encryption_details
    }

def parse_file_bytes(filename, data):
    root = load_xml_bytes(data)
    return parse_metadata(root)

def sanitize_filename(name):
    return "".join(c for c in (name or "") if c.isalnum() or c in ("-", "_", ".", " ")).strip() or "metadata"