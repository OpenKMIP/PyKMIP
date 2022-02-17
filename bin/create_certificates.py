#!/usr/bin/env python

from cryptography import x509
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import datetime


def create_rsa_private_key(key_size=2048, public_exponent=65537):
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
        backend=backends.default_backend()
    )
    return private_key


def create_self_signed_certificate(subject_name, private_key, days_valid=365):
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"Test, Inc."),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_name)
    ])
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)
    ).sign(private_key, hashes.SHA256(), backends.default_backend())

    return certificate


def create_certificate(subject_name,
                       private_key,
                       signing_certificate,
                       signing_key,
                       days_valid=365,
                       client_auth=False,
                       hostname=None):
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"Test, Inc."),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_name)
    ])
    builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        signing_certificate.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)
    )

    if client_auth:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True
        )

    if hostname:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )

    certificate = builder.sign(
        signing_key,
        hashes.SHA256(),
        backends.default_backend()
    )
    return certificate


def main():
    root_key = create_rsa_private_key()
    root_certificate = create_self_signed_certificate(
        u"Root CA",
        root_key
    )

    server_key = create_rsa_private_key()
    server_certificate = create_certificate(
        u"Server Certificate",
        server_key,
        root_certificate,
        root_key,
        hostname=u"localhost"
    )

    john_doe_client_key = create_rsa_private_key()
    john_doe_client_certificate = create_certificate(
        u"John Doe",
        john_doe_client_key,
        root_certificate,
        root_key,
        client_auth=True
    )
    jane_doe_client_key = create_rsa_private_key()
    jane_doe_client_certificate = create_certificate(
        u"Jane Doe",
        jane_doe_client_key,
        root_certificate,
        root_key,
        client_auth=True
    )
    john_smith_client_key = create_rsa_private_key()
    john_smith_client_certificate = create_certificate(
        u"John Smith",
        john_smith_client_key,
        root_certificate,
        root_key,
        client_auth=True
    )
    jane_smith_client_key = create_rsa_private_key()
    jane_smith_client_certificate = create_certificate(
        u"Jane Smith",
        jane_smith_client_key,
        root_certificate,
        root_key,
    )

    with open("root_key.pem", "wb") as f:
        f.write(root_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("root_certificate.pem", "wb") as f:
        f.write(
            root_certificate.public_bytes(
                serialization.Encoding.PEM
            )
        )
    with open("server_key.pem", "wb") as f:
        f.write(server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("server_certificate.pem", "wb") as f:
        f.write(
            server_certificate.public_bytes(
                serialization.Encoding.PEM
            )
        )
    with open("client_key_john_doe.pem", "wb") as f:
        f.write(john_doe_client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("client_certificate_john_doe.pem", "wb") as f:
        f.write(
            john_doe_client_certificate.public_bytes(
                serialization.Encoding.PEM
            )
        )
    with open("client_key_jane_doe.pem", "wb") as f:
        f.write(jane_doe_client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("client_certificate_jane_doe.pem", "wb") as f:
        f.write(
            jane_doe_client_certificate.public_bytes(
                serialization.Encoding.PEM
            )
        )
    with open("client_key_john_smith.pem", "wb") as f:
        f.write(john_smith_client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("client_certificate_john_smith.pem", "wb") as f:
        f.write(
            john_smith_client_certificate.public_bytes(
                serialization.Encoding.PEM
            )
        )
    with open("client_key_jane_smith.pem", "wb") as f:
        f.write(jane_smith_client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("client_certificate_jane_smith.pem", "wb") as f:
        f.write(
            jane_smith_client_certificate.public_bytes(
                serialization.Encoding.PEM
            )
        )


if __name__ == '__main__':
    main()
