# Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from cryptography import x509
from cryptography.hazmat import backends

from kmip.core import exceptions

def get_certificate_from_connection(connection):
    """
    Extract an X.509 certificate from a socket connection.
    """
    certificate = connection.getpeercert(binary_form=True)
    if certificate:
        return x509.load_der_x509_certificate(
            certificate,
            backends.default_backend()
        )
    return None

def get_extended_key_usage_from_certificate(certificate):
    """
    Given an X.509 certificate, extract and return the extendedKeyUsage
    extension.
    """
    try:
        return certificate.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
        ).value
    except x509.ExtensionNotFound:
        return None

def get_common_names_from_certificate(certificate):
    """
    Given an X.509 certificate, extract and return all common names.
    """

    common_names = certificate.subject.get_attributes_for_oid(
        x509.oid.NameOID.COMMON_NAME
    )
    return [common_name.value for common_name in common_names]

def get_client_identity_from_certificate(certificate):
    """
    Given an X.509 certificate, extract and return the client identity.
    """
    client_ids = get_common_names_from_certificate(certificate)

    if len(client_ids) > 0:
        if len(client_ids) > 1:
            raise exceptions.PermissionDenied(
                "Multiple client identities found."
            )
        return client_ids[0]
    else:
        raise exceptions.PermissionDenied(
            "The certificate does not define any subject common names. "
            "Client identity unavailable."
        )
