# Copyright (c) 2015 The Johns Hopkins University/Applied Physics Laboratory
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

from OpenSSL.crypto import load_pkcs12
from OpenSSL.crypto import dump_certificate, dump_privatekey, dump_publickey
from OpenSSL.crypto import FILETYPE_ASN1, TYPE_RSA

from pyasn1.type import univ
from pyasn1.codec.ber import decoder

from binascii import hexlify

import logging
import sys
import io

from kmip.core.enums import CryptographicUsageMask as UsageMask
from kmip.core.enums import CryptographicAlgorithm as Algorithm
from kmip.core.enums import LinkType, AttributeType, KeyFormatType
from kmip.demos import utils

from kmip.pie import client
from kmip.pie import objects


def _get_certificate_attributes(cert):
    usage_mask_prv = []
    usage_mask_pub = []
    subject_key_id = None
    authority_key_id = None

    extensions_count = cert.get_extension_count()
    for i in range(extensions_count):
        extension = cert.get_extension(i)
        short_name = extension.get_short_name()
        if short_name == b'keyUsage':
            data = extension.get_data()
            key_usage = decoder.decode(data, asn1Spec=univ.BitString())
            for usage in range(0, len(key_usage[0])):
                if key_usage[0][usage]:
                    if usage == 0:
                        # digitalSignature (0)
                        usage_mask_prv.append(UsageMask.SIGN)
                        usage_mask_pub.append(UsageMask.VERIFY)
                    elif usage == 2:
                        # keyEncipherment  (2)
                        usage_mask_prv.append(UsageMask.UNWRAP_KEY)
                        usage_mask_pub.append(UsageMask.WRAP_KEY)
                    elif usage == 3:
                        # dataEncipherment (3)
                        usage_mask_prv.append(UsageMask.DECRYPT)
                        usage_mask_pub.append(UsageMask.ENCRYPT)
                    elif usage == 4:
                        # keyAgreement (4)
                        usage_mask_prv.append(UsageMask.KEY_AGREEMENT)
                        usage_mask_pub.append(UsageMask.KEY_AGREEMENT)
                    elif usage == 5:
                        # keyCertSign (5)
                        usage_mask_prv.append(UsageMask.CERTIFICATE_SIGN)
                        usage_mask_pub.append(UsageMask.CERTIFICATE_SIGN)
                    elif usage == 6:
                        # cRLSign (6)
                        usage_mask_prv.append(UsageMask.CRL_SIGN)
                        usage_mask_pub.append(UsageMask.CRL_SIGN)
        elif short_name == b'subjectKeyIdentifier':
            data = extension.get_data()
            asn1_octets = decoder.decode(data, asn1Spec=univ.OctetString())
            subject_key_id = hexlify(asn1_octets[0].asOctets())
        elif short_name == b'authorityKeyIdentifier':
            data = extension.get_data()
            authority_key_id = hexlify(data)

    setattr(cert, "commonName", cert.get_subject().commonName)
    setattr(cert, "usage_mask_private", usage_mask_prv)
    setattr(cert, "usage_mask_public", usage_mask_pub)
    setattr(cert, "subjectKeyIdentifier", subject_key_id)
    setattr(cert, "authorityKeyIdentifier", authority_key_id)

if __name__ == '__main__':
    logger = utils.build_console_logger(logging.INFO)

    parser = utils.build_cli_parser(operation="Import PKCS#12")
    opts, args = parser.parse_args(sys.argv[1:])

    config = opts.config
    pkcs12_file = opts.pkcs12_file
    pkcs12_password = opts.pkcs12_password

    if pkcs12_file is None or pkcs12_password is None:
        logger.error("Missing mandatory arguments "
                     "pkcs12-file and/or pkcs12-password")
        sys.exit()

    p12 = load_pkcs12(io.open(pkcs12_file, 'rb').read(), pkcs12_password)
    if p12 is None:
        logger.error("Cannot open/parse PKCS#12 file")
        sys.exit()

    cert = p12.get_certificate()
    public_key = cert.get_pubkey()
    private_key = p12.get_privatekey()
    ca_certs = p12.get_ca_certificates()

    _get_certificate_attributes(cert)

    print("Subject {0}".format(cert.commonName))

    algorithm = None
    key_type = private_key.type()
    if key_type == TYPE_RSA:
        algorithm = Algorithm.RSA
    else:
        logger.error("Non supprted key type {0}".format(key_type))
        sys.exit()

    length = private_key.bits()

    co_private_key = objects.PrivateKey(
        algorithm,
        length,
        dump_privatekey(FILETYPE_ASN1, private_key),
        KeyFormatType.PKCS_8,
        cert.usage_mask_private,
        cert.commonName)

    co_public_key = objects.PublicKey(
        algorithm,
        length,
        dump_publickey(FILETYPE_ASN1, public_key),
        KeyFormatType.X_509,
        cert.usage_mask_public,
        cert.commonName)

    setattr(
        cert,
        "cert_object",
        objects.X509Certificate(
            dump_certificate(FILETYPE_ASN1, cert),
            cert.usage_mask_public,
            cert.commonName))

    for ca_cert in ca_certs:
        _get_certificate_attributes(ca_cert)
        setattr(
            ca_cert,
            "cert_object",
            objects.X509Certificate(
                dump_certificate(FILETYPE_ASN1, ca_cert),
                ca_cert.usage_mask_public,
                ca_cert.commonName))

    # Build the client and connect to the server
    with client.ProxyKmipClient(config=config) as client:
        try:
            private_key_uid = client.register(co_private_key)
            logger.info("Successfully registered private key with ID:"
                        "{0}".format(private_key_uid))
            public_key_uid = client.register(co_public_key)
            logger.info("Successfully registered public key with ID:"
                        "{0}".format(public_key_uid))
            certificate_uid = client.register(cert.cert_object)
            logger.info("Successfully registered certificate with ID:"
                        "{0}".format(certificate_uid))
            setattr(cert, "uid", certificate_uid)

            public_key_link = [
                AttributeType.LINK,
                [
                    LinkType.PUBLIC_KEY_LINK,
                    public_key_uid
                ]]
            private_key_link = [
                AttributeType.LINK,
                [
                    LinkType.PRIVATE_KEY_LINK,
                    private_key_uid
                ]]
            certificate_link = [
                AttributeType.LINK,
                [
                    LinkType.CERTIFICATE_LINK,
                    certificate_uid
                ]]

            uid, attribute = client.add_attribute(
                private_key_uid,
                *public_key_link)
            logger.info("Successfully added {0} to object {1}".format(
                attribute, uid))

            uid, attribute = client.add_attribute(
                public_key_uid,
                *private_key_link)
            logger.info("Successfully added {0} to object {1}".format(
                attribute, uid))

            uid, attribute = client.add_attribute(
                public_key_uid,
                *certificate_link)
            logger.info("Successfully added {0} to object {1}".format(
                attribute, uid))

            uid, attribute = client.add_attribute(
                certificate_uid,
                *public_key_link)
            logger.info("Successfully added {0} to object {1}".format(
                attribute, uid))

            for ca_cert in ca_certs:
                uid = client.register(ca_cert.cert_object)
                setattr(ca_cert, "uid", uid)
                logger.info("Successfully registered certificate with "
                            "ID:{0}".format(uid))

            for xx in ca_certs:
                x_subject = xx.subjectKeyIdentifier
                x_authority = xx.authorityKeyIdentifier

                if cert.authorityKeyIdentifier.find(x_subject) != -1:
                    certificate_link[1][1] = xx.uid
                    uid, attribute = client.add_attribute(
                        cert.uid,
                        *certificate_link)
                    logger.info("Successfully added {0} to object {1}".format(
                        attribute, uid))

                for yy in ca_certs:
                    y_subject = yy.subjectKeyIdentifier
                    y_authority = yy.authorityKeyIdentifier

                    if xx == yy:
                        continue

                    if x_authority.find(y_subject) != -1:
                        certificate_link[1][1] = yy.uid
                        uid, attribute = client.add_attribute(
                            xx.uid,
                            *certificate_link)
                        logger.info("Successfully added {0}to object "
                                    "{1}".format(attribute, uid))

        except Exception as e:
            logger.error(e)
