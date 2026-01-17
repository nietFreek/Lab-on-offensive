
import ssl
import ipaddress
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_self_signed_cert():
    # Generate a private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Save the key
    with open("key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    
    # Self-signed: subject and issuer are the same
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Secure Bank Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mybank.local"), 
    ])
    
    cert_builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        # Backdate slightly to avoid clock-skew issues
        datetime.utcnow() - timedelta(days=1)
    ).not_valid_after(
        # Good for one year
        datetime.utcnow() + timedelta(days=365)
    )

    # SAN is what modern browsers actually check
    cert_builder = cert_builder.add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"mybank.local"),
            x509.IPAddress(ipaddress.IPv4Address("10.0.0.181"))
        ]), 
        critical=False,
    )

    # Mark as a CA so it can be used as a trusted root in demos
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )

    # Spell out allowed key usage
    cert_builder = cert_builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,    # Required for CA
            crl_sign=True,         # Required for CA
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True, 
    )

    # This cert is for a TLS server
    cert_builder = cert_builder.add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=False,
    )

    # Sign the cert with the generated key
    cert = cert_builder.sign(key, hashes.SHA256())

    # Save the cert
    with open("cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print("Successfully generated 'key.pem' and 'cert.pem' in the current directory.")

if __name__ == "__main__":
    try:
        generate_self_signed_cert()
    except Exception as e:
        print(f"Error generating cert: {e}")
