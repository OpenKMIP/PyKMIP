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

from kmip.core.enums import ObjectType
from kmip.core.enums import Operation

import optparse


def build_cli_parser(operation):
    # Build the argument parser and setup expected options
    parser = optparse.OptionParser(
        usage="%prog [options]",
        description="Run KMIP client {0} operation".format(operation.name))

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
    elif operation is Operation.QUERY:
        pass
    elif operation is Operation.DISCOVER_VERSIONS:
        pass
    else:
        raise ValueError("unrecognized operation: {0}".format(operation))

    return parser


def log_template_attribute(logger, template_attribute):
    names = template_attribute.names
    attributes = template_attribute.attributes

    logger.info('number of template attribute names: {0}'.format(len(names)))
    for i in range(len(names)):
        name = names[i]
        logger.info('name {0}: {1}'.format(i, name))

    log_attribute_list(attributes)


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
    if secret_type is ObjectType.PRIVATE_KEY:
        log_private_key(logger, secret_value)
    elif secret_type is ObjectType.PUBLIC_KEY:
        log_public_key(logger, secret_value)
    else:
        logger.info('generic secret: {0}'.format(secret_value))


def log_public_key(logger, public_key):
    key_block = public_key.key_block

    log_key_block(logger, key_block)


def log_private_key(logger, private_key):
    key_block = private_key.key_block

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
        key_format_type = key_value.key_format_type
        key_value = key_value.key_value

        logger.info('key format type: {0}'.format(key_format_type))

        if key_value is not None:
            logger.info('key value:')

            key_material = key_value.key_material
            attributes = key_value.attributes

            logger.info('key material: {0}'.format(repr(key_material)))

            log_attribute_list(logger, attributes)
        else:
            logger.info('key value: {0}'.format(key_value))
    else:
        logger.info('key value: {0}'.format(key_value))


def log_key_wrapping_data(logger, key_wrapping_data):
    logger.info('key wrapping data: {0}'.format(key_wrapping_data))
