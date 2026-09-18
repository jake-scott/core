"""Emulated HUE Bridge for HomeAssistant - Certificate utils.

Mirrors the certificate layout of a real Hue bridge: a leaf certificate with
the bridge id as Common Name, issued by a CA named "root-bridge". The CA is
generated once and persisted, so clients only need to trust it a single time;
the leaf is re-issued whenever the advertised hostname or IP address changes.
"""
import asyncio
import ipaddress
import logging
import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import NameOID

from emulated_hue.controllers.config import Config

LOGGER = logging.getLogger(__name__)

CA_CERT_FILE = "ca.pem"
CA_KEY_FILE = "ca_key.pem"
CA_COMMON_NAME = "root-bridge"
CA_VALIDITY = timedelta(days=365 * 20)
LEAF_VALIDITY = timedelta(days=3650)
# re-issue the leaf if it expires within this window
RENEWAL_MARGIN = timedelta(days=30)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _not_valid_after(cert: x509.Certificate) -> datetime:
    """Return the certificate expiry as an aware UTC datetime (cryptography < 42 compatible)."""
    expiry = getattr(cert, "not_valid_after_utc", None)
    if expiry is None:
        expiry = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return expiry


def _leaf_sans(config: Config) -> list[x509.GeneralName]:
    """Return the Subject Alternative Names the leaf certificate must carry."""
    return [
        x509.DNSName(config.mdns_hostname),
        x509.IPAddress(ipaddress.ip_address(config.ip_addr)),
    ]


def _load_pem_certs(path: str) -> list[x509.Certificate]:
    with open(path, "rb") as fileobj:
        return x509.load_pem_x509_certificates(fileobj.read())


def _load_pem_key(path: str) -> ec.EllipticCurvePrivateKey:
    with open(path, "rb") as fileobj:
        return serialization.load_pem_private_key(fileobj.read(), password=None)


def _write_pem(path: str, *blobs: bytes) -> None:
    with open(path, "wb") as fileobj:
        for blob in blobs:
            fileobj.write(blob)
    os.chmod(path, 0o600)


def check_certificate(cert_file: str, config: Config) -> bool:
    """Check if the existing certificate matches the current bridge configuration.

    Returns False (i.e. regenerate) when the file is missing or unreadable, the
    CN does not match the bridge id, the SAN list is missing the advertised
    hostname or IP address, the certificate is (nearly) expired, or it was not
    issued by our persisted CA.
    """
    ca_file = config.get_path(CA_CERT_FILE)
    if not os.path.isfile(cert_file) or not os.path.isfile(ca_file):
        return False
    try:
        cert = _load_pem_certs(cert_file)[0]
        ca_cert = _load_pem_certs(ca_file)[0]
    except (OSError, ValueError, IndexError) as err:
        LOGGER.warning("Unable to read existing certificate, regenerating: %s", err)
        return False

    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not names or names[0].value != config.bridge_id.lower():
        LOGGER.info("Certificate CN does not match bridge id, regenerating")
        return False

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        LOGGER.info("Certificate has no SAN extension, regenerating")
        return False
    for required in _leaf_sans(config):
        if required not in san.value:
            LOGGER.info("Certificate SAN is missing %s, regenerating", required.value)
            return False

    if _not_valid_after(cert) - RENEWAL_MARGIN < _now():
        LOGGER.info("Certificate is expired or about to expire, regenerating")
        return False

    if cert.issuer != ca_cert.subject:
        LOGGER.info("Certificate was not issued by the bridge CA, regenerating")
        return False
    try:
        ca_cert.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm)
        )
    except Exception:  # pylint: disable=broad-except
        LOGGER.info("Certificate signature does not verify against bridge CA, regenerating")
        return False
    return True


async def async_generate_selfsigned_cert(
    cert_file: str, key_file: str, config: Config
) -> None:
    """Generate self signed certificate compatible with Philips HUE."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, generate_selfsigned_cert, cert_file, key_file, config
    )


def _load_or_create_ca(
    config: Config,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Load the persisted bridge CA, creating it on first run."""
    ca_file = config.get_path(CA_CERT_FILE)
    ca_key_file = config.get_path(CA_KEY_FILE)
    if os.path.isfile(ca_file) and os.path.isfile(ca_key_file):
        try:
            ca_cert = _load_pem_certs(ca_file)[0]
            ca_key = _load_pem_key(ca_key_file)
            if _not_valid_after(ca_cert) - RENEWAL_MARGIN > _now():
                return ca_cert, ca_key
            LOGGER.warning("Bridge CA certificate is expiring, creating a new one")
        except (OSError, ValueError, IndexError, TypeError) as err:
            LOGGER.warning("Unable to load bridge CA, creating a new one: %s", err)

    ca_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NL"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Philips Hue"),
            x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
        ]
    )
    now = _now()
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + CA_VALIDITY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    _write_pem(ca_file, ca_cert.public_bytes(serialization.Encoding.PEM))
    _write_pem(
        ca_key_file,
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    LOGGER.info(
        "Created bridge CA certificate '%s'. Import %s into clients that verify "
        "the bridge certificate.",
        CA_COMMON_NAME,
        ca_file,
    )
    return ca_cert, ca_key


def generate_selfsigned_cert(cert_file: str, key_file: str, config: Config) -> None:
    """Generate the bridge (leaf) certificate, signed by the persisted bridge CA."""
    ca_cert, ca_key = _load_or_create_ca(config)

    # like a real bridge: serial number is the bridge id, CN is the bridge id
    dec_serial = int(config.bridge_id.lower(), 16)
    leaf_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NL"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Philips Hue"),
            x509.NameAttribute(NameOID.COMMON_NAME, config.bridge_id.lower()),
        ]
    )
    now = _now()
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(dec_serial)
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + LEAF_VALIDITY)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(_leaf_sans(config)), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    # write leaf followed by CA so the full chain is served by load_cert_chain
    _write_pem(
        cert_file,
        leaf_cert.public_bytes(serialization.Encoding.PEM),
        ca_cert.public_bytes(serialization.Encoding.PEM),
    )
    _write_pem(
        key_file,
        leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    LOGGER.info(
        "Bridge certificate generated for CN=%s, SAN=%s",
        config.bridge_id.lower(),
        ", ".join(str(san.value) for san in _leaf_sans(config)),
    )
