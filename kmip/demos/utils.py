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
