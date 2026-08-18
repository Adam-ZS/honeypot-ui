"""TLS context for the HTTPS emulator.

The HTTPS listener previously reused the plain HTTP handler, so anything
speaking TLS to port 8443 got a protocol error and no session was ever
captured. This builds a real TLS context: an operator-supplied certificate if
one is configured, otherwise a throwaway self-signed certificate generated at
startup.
"""

from __future__ import annotations

import datetime
import logging
import os
import ssl
import tempfile
from typing import Optional

logger = logging.getLogger(__name__)


def build_tls_context() -> Optional[ssl.SSLContext]:
    cert_path = os.getenv("HONEYPOT_TLS_CERT")
    key_path = os.getenv("HONEYPOT_TLS_KEY")

    if not (cert_path and key_path):
        generated = _generate_self_signed()
        if generated is None:
            logger.error(
                "HTTPS emulator disabled: no HONEYPOT_TLS_CERT/HONEYPOT_TLS_KEY "
                "configured and self-signed generation failed"
            )
            return None
        cert_path, key_path = generated
        logger.warning(
            "HTTPS emulator using a generated self-signed certificate. Set "
            "HONEYPOT_TLS_CERT/HONEYPOT_TLS_KEY to present a stable one."
        )

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    # Accept whatever an attacker's scanner offers; refusing old protocols is
    # itself a fingerprint, and no real secrets travel over this listener.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _generate_self_signed() -> Optional[tuple[str, str]]:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        return None

    from honeypot.adaptive.fingerprint import fingerprint_engine

    common_name = fingerprint_engine.get_fake_hostname()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    tmp_dir = tempfile.mkdtemp(prefix="honeypot-tls-")
    cert_path = os.path.join(tmp_dir, "cert.pem")
    key_path = os.path.join(tmp_dir, "key.pem")
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as fh:
        fh.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    os.chmod(key_path, 0o600)
    return cert_path, key_path
