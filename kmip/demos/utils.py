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

import binascii
import logging
import optparse
import sys

from kmip.core.attributes import CryptographicAlgorithm
from kmip.core.attributes import CryptographicLength

from kmip.core.enums import AttributeType
from kmip.core.enums import CertificateTypeEnum
from kmip.core.enums import CryptographicAlgorithm as CryptoAlgorithmEnum
from kmip.core.enums import CryptographicUsageMask
from kmip.core.enums import ObjectType
from kmip.core.enums import Operation
from kmip.core.enums import SecretDataType

from kmip.core.factories.attributes import AttributeFactory

from kmip.core.misc import KeyFormatType

from kmip.core.objects import KeyBlock
from kmip.core.objects import KeyMaterial
from kmip.core.objects import KeyValue

from kmip.core.secrets import Certificate
from kmip.core.secrets import PrivateKey
from kmip.core.secrets import PublicKey
from kmip.core.secrets import SymmetricKey
from kmip.core.secrets import SecretData


def build_console_logger(level):
    logger = logging.getLogger('demo')
    logger.setLevel(level)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def build_cli_parser(operation=None):
    # Build the argument parser and setup expected options
    parser = optparse.OptionParser(
        usage="%prog [options]",
        description="Run KMIP client operation")

    parser.add_option(
        "-u",
        "--username",
        action="store",
        type="str",
        default=None,
        dest="username",
        help="Username for KMIP server account")
    parser.add_option(
        "-p",
        "--password",
        action="store",
        type="str",
        default=None,
        dest="password",
        help="Password for KMIP server account")
    parser.add_option(
        "-c",
        "--config",
        action="store",
        type="str",
        default="client",
        dest="config",
        help="Client configuration group to load from configuration file")

    if operation is Operation.CREATE:
        parser.add_option(
            "-a",
            "--algorithm",
            action="store",
            type="str",
            default=None,
            dest="algorithm",
            help="Encryption algorithm for the secret (e.g., AES)")
        parser.add_option(
            "-l",
            "--length",
            action="store",
            type="int",
            default=None,
            dest="length",
            help="Key length in bits (e.g., 128, 256)")
    elif operation is Operation.CREATE_KEY_PAIR:
        parser.add_option(
            "-a",
            "--algorithm",
            action="store",
            type="str",
            default=None,
            dest="algorithm",
            help="Encryption algorithm for the secret (e.g., AES)")
        parser.add_option(
            "-l",
            "--length",
            action="store",
            type="int",
            default=None,
            dest="length",
            help="Key length in bits (e.g., 128, 256)")
        parser.add_option(
            "-n",
            "--name",
            action="store",
            type="str",
            default=None,
            dest="name",
            help="Name of key pair to create")
    elif operation is Operation.DESTROY:
        parser.add_option(
            "-i",
            "--uuid",
            action="store",
            type="str",
            default=None,
            dest="uuid",
            help="UUID of secret to delete from the KMIP server")
    elif operation is Operation.ACTIVATE:
        parser.add_option(
            "-i",
            "--uuid",
            action="store",
            type="str",
            default=None,
            dest="uuid",
            help="UUID of secret to activate on the KMIP server")
    elif operation is Operation.REVOKE:
        parser.add_option(
            "-i",
            "--uuid",
            action="store",
            type="str",
            default=None,
            dest="uuid",
            help="UUID of secret to revoke on the KMIP server")
    elif operation is Operation.GET:
        parser.add_option(
            "-i",
            "--uuid",
            action="store",
            type="str",
            default=None,
            dest="uuid",
            help="UUID of secret to retrieve from the KMIP server")
        parser.add_option(
            "-f",
            "--format",
            action="store",
            type="str",
            default=None,
            dest="format",
            help=("Format in which to retrieve the secret. Supported formats "
                  "include: RAW, PKCS_1, PKCS_8, X_509"))
    elif operation is Operation.GET_ATTRIBUTE_LIST:
        parser.add_option(
            "-i",
            "--uuid",
            action="store",
            type="str",
            default=None,
            dest="uuid",
            help="UID of a managed object")
    elif operation is Operation.LOCATE:
        parser.add_option(
            "-n",
            "--name",
            action="store",
            type="str",
            default=None,
            dest="name",
            help="Name of secret to retrieve from the KMIP server")
    elif operation is Operation.REGISTER:
        parser.add_option(
            "-f",
            "--format",
            action="store",
            type="str",
            default="RAW",
            dest="format",
            help=("Format in which to store the secret. Supported formats "
                  "include: RAW, PKCS_1, PKCS_8, X_509"))
        parser.add_option(
            "-t",
            "--type",
            action="store",
            type="str",
            default="SYMMETRIC_KEY",
            dest="type",
            help=("Type of the object to register. Supported types include: "
                  "CERTIFICATE, PRIVATE_KEY, PUBLIC_KEY, SYMMETRIC_KEY, "
                  "SECRET_DATA"))
    elif operation is Operation.DISCOVER_VERSIONS:
        parser.add_option(
            "-v",
            "--protocol-versions",
            action="store",
            type="str",
            default=None,
            dest="protocol_versions",
            help=("Protocol versions supported by client. "
                  "ex. '1.1,1.2 1.3'"))
    elif operation is Operation.MAC:
        parser.add_option(
            "-i",
            "--uuid",
            action="store",
            type="str",
            default=None,
            dest="uuid",
            help="The unique ID of the managed object that is the key"
                 "to use for the MAC operation")
        parser.add_option(
            "-a",
            "--algorithm",
            action="store",
            type="str",
            default=None,
            dest="algorithm",
            help="Encryption algorithm for the secret (e.g., AES)")
    return parser


def build_cryptographic_usage_mask(logger, object_type):
    if object_type == ObjectType.CERTIFICATE:
        flags = [CryptographicUsageMask.ENCRYPT,
                 CryptographicUsageMask.VERIFY]
    elif (object_type == ObjectType.SYMMETRIC_KEY or
          object_type == ObjectType.SECRET_DATA):
        flags = [CryptographicUsageMask.ENCRYPT,
                 CryptographicUsageMask.DECRYPT]
    elif object_type == ObjectType.PUBLIC_KEY:
        flags = [CryptographicUsageMask.VERIFY]
    elif object_type == ObjectType.PRIVATE_KEY:
        flags = [CryptographicUsageMask.SIGN]
    else:
        logger.error("Unrecognized object type, could not build cryptographic "
                     "usage mask")
        sys.exit()

    attribute_type = AttributeType.CRYPTOGRAPHIC_USAGE_MASK
    attribute_factory = AttributeFactory()
    usage_mask = attribute_factory.create_attribute(attribute_type, flags)

    return usage_mask


def build_object(logger, object_type, key_format_type):

    if object_type == ObjectType.CERTIFICATE:
        value = build_secret_value(logger, object_type)
        return Certificate(
            certificate_type=CertificateTypeEnum.X_509,
            certificate_value=value)
    else:
        return build_key(logger, object_type, key_format_type)


def build_key(logger, object_type, key_format_type):

    key_value = build_secret_value(logger, object_type)
    cryptographic_algorithm = build_cryptographic_algorithm(
        logger, object_type)
    cryptographic_length = build_cryptographic_length(logger, object_type)

    key_block = build_key_block(
        key_format_type,
        key_value,
        cryptographic_algorithm,
        cryptographic_length)

    if object_type == ObjectType.SYMMETRIC_KEY:
        return SymmetricKey(key_block)
    elif object_type == ObjectType.PUBLIC_KEY:
        return PublicKey(key_block)
    elif object_type == ObjectType.PRIVATE_KEY:
        return PrivateKey(key_block)
    elif object_type == ObjectType.SECRET_DATA:
        kind = SecretData.SecretDataType(SecretDataType.PASSWORD)
        return SecretData(secret_data_type=kind,
                          key_block=key_block)
    else:
        logger.error("Unrecognized object type, could not build key")
        sys.exit()


def build_cryptographic_length(logger, object_type):
    if (object_type == ObjectType.SYMMETRIC_KEY or
       object_type == ObjectType.SECRET_DATA):
        return CryptographicLength(128)
    elif object_type == ObjectType.PUBLIC_KEY:
        return CryptographicLength(1024)
    elif object_type == ObjectType.PRIVATE_KEY:
        return CryptographicLength(1024)
    else:
        logger.error("Unrecognized object type, could not build cryptographic "
                     "length")
        sys.exit()


def build_cryptographic_algorithm(logger, object_type):
    if (object_type == ObjectType.SYMMETRIC_KEY or
       object_type == ObjectType.SECRET_DATA):
        return CryptographicAlgorithm(CryptoAlgorithmEnum.AES)
    elif object_type == ObjectType.PUBLIC_KEY:
        return CryptographicAlgorithm(CryptoAlgorithmEnum.RSA)
    elif object_type == ObjectType.PRIVATE_KEY:
        return CryptographicAlgorithm(CryptoAlgorithmEnum.RSA)
    else:
        logger.error("Unrecognized object type, could not build cryptographic "
                     "algorithm")
        sys.exit()


def build_secret_value(logger, object_type):
    if object_type == ObjectType.CERTIFICATE:
        # Encoding from Section 13.2 of the KMIP 1.1 Test Cases document.
        return (
            b'\x30\x82\x03\x12\x30\x82\x01\xFA\xA0\x03\x02\x01\x02\x02\x01\x01'
            b'\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05\x00\x30'
            b'\x3B\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0D'
            b'\x30\x0B\x06\x03\x55\x04\x0A\x13\x04\x54\x45\x53\x54\x31\x0E\x30'
            b'\x0C\x06\x03\x55\x04\x0B\x13\x05\x4F\x41\x53\x49\x53\x31\x0D\x30'
            b'\x0B\x06\x03\x55\x04\x03\x13\x04\x4B\x4D\x49\x50\x30\x1E\x17\x0D'
            b'\x31\x30\x31\x31\x30\x31\x32\x33\x35\x39\x35\x39\x5A\x17\x0D\x32'
            b'\x30\x31\x31\x30\x31\x32\x33\x35\x39\x35\x39\x5A\x30\x3B\x31\x0B'
            b'\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0D\x30\x0B\x06'
            b'\x03\x55\x04\x0A\x13\x04\x54\x45\x53\x54\x31\x0E\x30\x0C\x06\x03'
            b'\x55\x04\x0B\x13\x05\x4F\x41\x53\x49\x53\x31\x0D\x30\x0B\x06\x03'
            b'\x55\x04\x03\x13\x04\x4B\x4D\x49\x50\x30\x82\x01\x22\x30\x0D\x06'
            b'\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x01\x0F'
            b'\x00\x30\x82\x01\x0A\x02\x82\x01\x01\x00\xAB\x7F\x16\x1C\x00\x42'
            b'\x49\x6C\xCD\x6C\x6D\x4D\xAD\xB9\x19\x97\x34\x35\x35\x77\x76\x00'
            b'\x3A\xCF\x54\xB7\xAF\x1E\x44\x0A\xFB\x80\xB6\x4A\x87\x55\xF8\x00'
            b'\x2C\xFE\xBA\x6B\x18\x45\x40\xA2\xD6\x60\x86\xD7\x46\x48\x34\x6D'
            b'\x75\xB8\xD7\x18\x12\xB2\x05\x38\x7C\x0F\x65\x83\xBC\x4D\x7D\xC7'
            b'\xEC\x11\x4F\x3B\x17\x6B\x79\x57\xC4\x22\xE7\xD0\x3F\xC6\x26\x7F'
            b'\xA2\xA6\xF8\x9B\x9B\xEE\x9E\x60\xA1\xD7\xC2\xD8\x33\xE5\xA5\xF4'
            b'\xBB\x0B\x14\x34\xF4\xE7\x95\xA4\x11\x00\xF8\xAA\x21\x49\x00\xDF'
            b'\x8B\x65\x08\x9F\x98\x13\x5B\x1C\x67\xB7\x01\x67\x5A\xBD\xBC\x7D'
            b'\x57\x21\xAA\xC9\xD1\x4A\x7F\x08\x1F\xCE\xC8\x0B\x64\xE8\xA0\xEC'
            b'\xC8\x29\x53\x53\xC7\x95\x32\x8A\xBF\x70\xE1\xB4\x2E\x7B\xB8\xB7'
            b'\xF4\xE8\xAC\x8C\x81\x0C\xDB\x66\xE3\xD2\x11\x26\xEB\xA8\xDA\x7D'
            b'\x0C\xA3\x41\x42\xCB\x76\xF9\x1F\x01\x3D\xA8\x09\xE9\xC1\xB7\xAE'
            b'\x64\xC5\x41\x30\xFB\xC2\x1D\x80\xE9\xC2\xCB\x06\xC5\xC8\xD7\xCC'
            b'\xE8\x94\x6A\x9A\xC9\x9B\x1C\x28\x15\xC3\x61\x2A\x29\xA8\x2D\x73'
            b'\xA1\xF9\x93\x74\xFE\x30\xE5\x49\x51\x66\x2A\x6E\xDA\x29\xC6\xFC'
            b'\x41\x13\x35\xD5\xDC\x74\x26\xB0\xF6\x05\x02\x03\x01\x00\x01\xA3'
            b'\x21\x30\x1F\x30\x1D\x06\x03\x55\x1D\x0E\x04\x16\x04\x14\x04\xE5'
            b'\x7B\xD2\xC4\x31\xB2\xE8\x16\xE1\x80\xA1\x98\x23\xFA\xC8\x58\x27'
            b'\x3F\x6B\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05'
            b'\x00\x03\x82\x01\x01\x00\xA8\x76\xAD\xBC\x6C\x8E\x0F\xF0\x17\x21'
            b'\x6E\x19\x5F\xEA\x76\xBF\xF6\x1A\x56\x7C\x9A\x13\xDC\x50\xD1\x3F'
            b'\xEC\x12\xA4\x27\x3C\x44\x15\x47\xCF\xAB\xCB\x5D\x61\xD9\x91\xE9'
            b'\x66\x31\x9D\xF7\x2C\x0D\x41\xBA\x82\x6A\x45\x11\x2F\xF2\x60\x89'
            b'\xA2\x34\x4F\x4D\x71\xCF\x7C\x92\x1B\x4B\xDF\xAE\xF1\x60\x0D\x1B'
            b'\xAA\xA1\x53\x36\x05\x7E\x01\x4B\x8B\x49\x6D\x4F\xAE\x9E\x8A\x6C'
            b'\x1D\xA9\xAE\xB6\xCB\xC9\x60\xCB\xF2\xFA\xE7\x7F\x58\x7E\xC4\xBB'
            b'\x28\x20\x45\x33\x88\x45\xB8\x8D\xD9\xAE\xEA\x53\xE4\x82\xA3\x6E'
            b'\x73\x4E\x4F\x5F\x03\xB9\xD0\xDF\xC4\xCA\xFC\x6B\xB3\x4E\xA9\x05'
            b'\x3E\x52\xBD\x60\x9E\xE0\x1E\x86\xD9\xB0\x9F\xB5\x11\x20\xC1\x98'
            b'\x34\xA9\x97\xB0\x9C\xE0\x8D\x79\xE8\x13\x11\x76\x2F\x97\x4B\xB1'
            b'\xC8\xC0\x91\x86\xC4\xD7\x89\x33\xE0\xDB\x38\xE9\x05\x08\x48\x77'
            b'\xE1\x47\xC7\x8A\xF5\x2F\xAE\x07\x19\x2F\xF1\x66\xD1\x9F\xA9\x4A'
            b'\x11\xCC\x11\xB2\x7E\xD0\x50\xF7\xA2\x7F\xAE\x13\xB2\x05\xA5\x74'
            b'\xC4\xEE\x00\xAA\x8B\xD6\x5D\x0D\x70\x57\xC9\x85\xC8\x39\xEF\x33'
            b'\x6A\x44\x1E\xD5\x3A\x53\xC6\xB6\xB6\x96\xF1\xBD\xEB\x5F\x7E\xA8'
            b'\x11\xEB\xB2\x5A\x7F\x86')
    elif (object_type == ObjectType.SYMMETRIC_KEY or
          object_type == ObjectType.SECRET_DATA):
        return (
            b'\x30\x82\x02\x76\x02\x01\x00\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7'
            b'\x0D\x01\x01\x01\x05\x00\x04\x82\x02\x60\x30\x82\x02\x5C\x02\x01'
            b'\x00\x02\x81\x81\x00\x93\x04\x51\xC9\xEC\xD9\x4F\x5B\xB9\xDA\x17'
            b'\xDD\x09\x38\x1B\xD2\x3B\xE4\x3E\xCA\x8C\x75\x39\xF3\x01\xFC\x8A'
            b'\x8C\xD5\xD5\x27\x4C\x3E\x76\x99\xDB\xDC\x71\x1C\x97\xA7\xAA\x91'
            b'\xE2\xC5\x0A\x82\xBD\x0B\x10\x34\xF0\xDF\x49\x3D\xEC\x16\x36\x24'
            b'\x27\xE5\x8A\xCC\xE7\xF6\xCE\x0F\x9B\xCC\x61\x7B\xBD\x8C\x90\xD0'
            b'\x09\x4A\x27\x03\xBA\x0D\x09\xEB\x19\xD1\x00\x5F\x2F\xB2\x65'
            b'\x52')
    elif object_type == ObjectType.PUBLIC_KEY:
        return (
            b'\x30\x81\x9F\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01'
            b'\x05\x00\x03\x81\x8D\x00\x30\x81\x89\x02\x81\x81\x00\x93\x04\x51'
            b'\xC9\xEC\xD9\x4F\x5B\xB9\xDA\x17\xDD\x09\x38\x1B\xD2\x3B\xE4\x3E'
            b'\xCA\x8C\x75\x39\xF3\x01\xFC\x8A\x8C\xD5\xD5\x27\x4C\x3E\x76\x99'
            b'\xDB\xDC\x71\x1C\x97\xA7\xAA\x91\xE2\xC5\x0A\x82\xBD\x0B\x10\x34'
            b'\xF0\xDF\x49\x3D\xEC\x16\x36\x24\x27\xE5\x8A\xCC\xE7\xF6\xCE\x0F'
            b'\x9B\xCC\x61\x7B\xBD\x8C\x90\xD0\x09\x4A\x27\x03\xBA\x0D\x09\xEB'
            b'\x19\xD1\x00\x5F\x2F\xB2\x65\x52\x6A\xAC\x75\xAF\x32\xF8\xBC\x78'
            b'\x2C\xDE\xD2\xA5\x7F\x81\x1E\x03\xEA\xF6\x7A\x94\x4D\xE5\xE7\x84'
            b'\x13\xDC\xA8\xF2\x32\xD0\x74\xE6\xDC\xEA\x4C\xEC\x9F\x02\x03\x01'
            b'\x00\x01')
    elif object_type == ObjectType.PRIVATE_KEY:
        return (
            b'\x30\x82\x02\x76\x02\x01\x00\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7'
            b'\x0D\x01\x01\x01\x05\x00\x04\x82\x02\x60\x30\x82\x02\x5C\x02\x01'
            b'\x00\x02\x81\x81\x00\x93\x04\x51\xC9\xEC\xD9\x4F\x5B\xB9\xDA\x17'
            b'\xDD\x09\x38\x1B\xD2\x3B\xE4\x3E\xCA\x8C\x75\x39\xF3\x01\xFC\x8A'
            b'\x8C\xD5\xD5\x27\x4C\x3E\x76\x99\xDB\xDC\x71\x1C\x97\xA7\xAA\x91'
            b'\xE2\xC5\x0A\x82\xBD\x0B\x10\x34\xF0\xDF\x49\x3D\xEC\x16\x36\x24'
            b'\x27\xE5\x8A\xCC\xE7\xF6\xCE\x0F\x9B\xCC\x61\x7B\xBD\x8C\x90\xD0'
            b'\x09\x4A\x27\x03\xBA\x0D\x09\xEB\x19\xD1\x00\x5F\x2F\xB2\x65\x52'
            b'\x6A\xAC\x75\xAF\x32\xF8\xBC\x78\x2C\xDE\xD2\xA5\x7F\x81\x1E\x03'
            b'\xEA\xF6\x7A\x94\x4D\xE5\xE7\x84\x13\xDC\xA8\xF2\x32\xD0\x74\xE6'
            b'\xDC\xEA\x4C\xEC\x9F\x02\x03\x01\x00\x01\x02\x81\x80\x0B\x6A\x7D'
            b'\x73\x61\x99\xEA\x48\xA4\x20\xE4\x53\x7C\xA0\xC7\xC0\x46\x78\x4D'
            b'\xCB\xEA\xA6\x3B\xAE\xBC\x0B\xC1\x32\x78\x74\x49\xCD\xE8\xD7\xCA'
            b'\xD0\xC0\xC8\x63\xC0\xFE\xFB\x06\xC3\x06\x2B\xEF\xC5\x00\x33\xEC'
            b'\xF8\x7B\x4E\x33\xA9\xBE\x7B\xCB\xC8\xF1\x51\x1A\xE2\x15\xE8\x0D'
            b'\xEB\x5D\x8A\xF2\xBD\x31\x31\x9D\x78\x21\x19\x66\x40\x93\x5A\x0C'
            b'\xD6\x7C\x94\x59\x95\x79\xF2\x10\x0D\x65\xE0\x38\x83\x1F\xDA\xFB'
            b'\x0D\xBE\x2B\xBD\xAC\x00\xA6\x96\xE6\x7E\x75\x63\x50\xE1\xC9\x9A'
            b'\xCE\x11\xA3\x6D\xAB\xAC\x3E\xD3\xE7\x30\x96\x00\x59\x02\x41\x00'
            b'\xDD\xF6\x72\xFB\xCC\x5B\xDA\x3D\x73\xAF\xFC\x4E\x79\x1E\x0C\x03'
            b'\x39\x02\x24\x40\x5D\x69\xCC\xAA\xBC\x74\x9F\xAA\x0D\xCD\x4C\x25'
            b'\x83\xC7\x1D\xDE\x89\x41\xA7\xB9\xAA\x03\x0F\x52\xEF\x14\x51\x46'
            b'\x6C\x07\x4D\x4D\x33\x8F\xE6\x77\x89\x2A\xCD\x9E\x10\xFD\x35\xBD'
            b'\x02\x41\x00\xA9\x8F\xBC\x3E\xD6\xB4\xC6\xF8\x60\xF9\x71\x65\xAC'
            b'\x2F\x7B\xB6\xF2\xE2\xCB\x19\x2A\x9A\xBD\x49\x79\x5B\xE5\xBC\xF3'
            b'\x7D\x8E\xE6\x9A\x6E\x16\x9C\x24\xE5\xC3\x2E\x4E\x7F\xA3\x32\x65'
            b'\x46\x14\x07\xF9\x52\xBA\x49\xE2\x04\x81\x8A\x2F\x78\x5F\x11\x3F'
            b'\x92\x2B\x8B\x02\x40\x25\x3F\x94\x70\x39\x0D\x39\x04\x93\x03\x77'
            b'\x7D\xDB\xC9\x75\x0E\x9D\x64\x84\x9C\xE0\x90\x3E\xAE\x70\x4D\xC9'
            b'\xF5\x89\xB7\x68\x0D\xEB\x9D\x60\x9F\xD5\xBC\xD4\xDE\xCD\x6F\x12'
            b'\x05\x42\xE5\xCF\xF5\xD7\x6F\x2A\x43\xC8\x61\x5F\xB5\xB3\xA9\x21'
            b'\x34\x63\x79\x7A\xA9\x02\x41\x00\xA1\xDD\xF0\x23\xC0\xCD\x94\xC0'
            b'\x19\xBB\x26\xD0\x9B\x9E\x3C\xA8\xFA\x97\x1C\xB1\x6A\xA5\x8B\x9B'
            b'\xAF\x79\xD6\x08\x1A\x1D\xBB\xA4\x52\xBA\x53\x65\x3E\x28\x04\xBA'
            b'\x98\xFF\x69\xE8\xBB\x1B\x3A\x16\x1E\xA2\x25\xEA\x50\x14\x63\x21'
            b'\x6A\x8D\xAB\x9B\x88\xA7\x5E\x5F\x02\x40\x61\x78\x64\x6E\x11\x2C'
            b'\xF7\x9D\x92\x1A\x8A\x84\x3F\x17\xF6\xE7\xFF\x97\x4F\x68\x81\x22'
            b'\x36\x5B\xF6\x69\x0C\xDF\xC9\x96\xE1\x89\x09\x52\xEB\x38\x20\xDD'
            b'\x18\x90\xEC\x1C\x86\x19\xE8\x7A\x2B\xD3\x8F\x9D\x03\xB3\x7F\xAC'
            b'\x74\x2E\xFB\x74\x8C\x78\x85\x94\x2C\x39')
    else:
        logger.error("Unrecognized object type, could not build secret value")
        sys.exit()


def build_key_block(key_format_type, key_value, cryptographic_algorithm,
                    cryptographic_length):
    key_material = KeyMaterial(key_value)
    key_value = KeyValue(key_material)

    return KeyBlock(
        key_format_type=KeyFormatType(key_format_type),
        key_compression_type=None,
        key_value=key_value,
        cryptographic_algorithm=cryptographic_algorithm,
        cryptographic_length=cryptographic_length,
        key_wrapping_data=None)


def log_template_attribute(logger, template_attribute):
    names = template_attribute.names
    attributes = template_attribute.attributes

    logger.info('number of template attribute names: {0}'.format(len(names)))
    for i in range(len(names)):
        name = names[i]
        logger.info('name {0}: {1}'.format(i, name))

    log_attribute_list(logger, attributes)


def log_attribute_list(logger, attributes):
    logger.info('number of attributes: {0}'.format(len(attributes)))
    for i in range(len(attributes)):
        attribute = attributes[i]
        attribute_name = attribute.attribute_name
        attribute_index = attribute.attribute_index
        attribute_value = attribute.attribute_value

        logger.info('attribute {0}:'.format(i))
        logger.info('   attribute_name: {0}'.format(attribute_name))
        logger.info('   attribute_index: {0}'.format(attribute_index))
        logger.info('   attribute_value: {0}'.format(
            repr(attribute_value)))


def log_secret(logger, secret_type, secret_value):
    if secret_type is ObjectType.CERTIFICATE:
        log_certificate(logger, secret_value)
    elif secret_type is ObjectType.PRIVATE_KEY:
        log_private_key(logger, secret_value)
    elif secret_type is ObjectType.PUBLIC_KEY:
        log_public_key(logger, secret_value)
    elif secret_type is ObjectType.SYMMETRIC_KEY:
        log_symmetric_key(logger, secret_value)
    else:
        logger.info('generic secret: {0}'.format(secret_value))


def log_certificate(logger, certificate):
    logger.info('certificate:')
    logger.info('* certificate type: {0}'.format(
        certificate.certificate_type))
    logger.info('* certificate value: {0}'.format(
        binascii.hexlify(certificate.certificate_value.value)))


def log_public_key(logger, public_key):
    key_block = public_key.key_block

    log_key_block(logger, key_block)


def log_private_key(logger, private_key):
    key_block = private_key.key_block

    log_key_block(logger, key_block)


def log_symmetric_key(logger, skey):
    key_block = skey.key_block

    log_key_block(logger, key_block)


def log_key_block(logger, key_block):
    if key_block is not None:
        logger.info('key block:')

        key_format_type = key_block.key_format_type
        key_compression_type = key_block.key_compression_type
        key_value = key_block.key_value
        cryptographic_algorithm = key_block.cryptographic_algorithm
        cryptographic_length = key_block.cryptographic_length
        key_wrapping_data = key_block.key_wrapping_data

        logger.info('* key format type: {0}'.format(key_format_type))
        logger.info('* key compression type: {0}'.format(
            key_compression_type))
        logger.info('* cryptographic algorithm: {0}'.format(
            cryptographic_algorithm))
        logger.info('* cryptographic length: {0}'.format(
            cryptographic_length))

        log_key_value(logger, key_value)
        log_key_wrapping_data(logger, key_wrapping_data)
    else:
        logger.info('key block: {0}'.format(key_block))


def log_key_value(logger, key_value):
    if key_value is not None:
        logger.info('key value:')

        key_material = key_value.key_material
        attributes = key_value.attributes

        logger.info('key material: {0}'.format(repr(key_material)))

        log_attribute_list(logger, attributes)
    else:
        logger.info('key value: {0}'.format(key_value))


def log_key_wrapping_data(logger, key_wrapping_data):
    logger.info('key wrapping data: {0}'.format(key_wrapping_data))
