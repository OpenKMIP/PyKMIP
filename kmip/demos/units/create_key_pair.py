# Copyright (c) 2014 The Johns Hopkins University/Applied Physics Laboratory
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

from kmip.core import enums
from kmip.core.enums import AttributeType
from kmip.core.enums import CredentialType
from kmip.core.enums import CryptographicAlgorithm
from kmip.core.enums import CryptographicUsageMask as UsageMaskEnum
from kmip.core.enums import Operation
from kmip.core.enums import ResultStatus
from kmip.core.enums import NameType

from kmip.demos import utils

from kmip.core.factories.attributes import AttributeFactory
from kmip.core.factories.credentials import CredentialFactory

from kmip.core.attributes import Name
from kmip.core.attributes import CryptographicUsageMask

from kmip.core.objects import TemplateAttribute
from kmip.core.objects import Attribute

from kmip.services.kmip_client import KMIPProxy

import logging
import sys

if __name__ == '__main__':
    logger = utils.build_console_logger(logging.INFO)

    # Build and parse arguments
    parser = utils.build_cli_parser(Operation.CREATE_KEY_PAIR)
    opts, args = parser.parse_args(sys.argv[1:])

    username = opts.username
    password = opts.password
    config = opts.config
    algorithm = opts.algorithm
    length = opts.length
    name = opts.name

    # Exit early if the arguments are not specified
    if algorithm is None:
        logger.error('No algorithm provided, exiting early from demo')
        sys.exit()
    if length is None:
        logger.error("No key length provided, exiting early from demo")
        sys.exit()
    if name is None:
        logger.error("No key name provided, exiting early from demo")
        sys.exit()

    attribute_type = AttributeType.CRYPTOGRAPHIC_ALGORITHM
    algorithm_enum = getattr(CryptographicAlgorithm, algorithm, None)

    if algorithm_enum is None:
        logger.error("Invalid algorithm specified; exiting early from demo")
        sys.exit()

    attribute_factory = AttributeFactory()
    credential_factory = CredentialFactory()

    # Build the KMIP server account credentials
    # TODO (peter-hamilton) Move up into KMIPProxy
    if (username is None) and (password is None):
        credential = None
    else:
        credential_type = CredentialType.USERNAME_AND_PASSWORD
        credential_value = {'Username': username,
                            'Password': password}
        credential = credential_factory.create_credential(credential_type,
                                                          credential_value)
    # Build the client and connect to the server
    client = KMIPProxy(config=config, config_file=opts.config_file)
    client.open()

    algorithm_obj = attribute_factory.create_attribute(attribute_type,
                                                       algorithm_enum)

    name_value = Name.NameValue(name)
    name = Attribute.AttributeName('Name')
    name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
    value = Name(name_value=name_value, name_type=name_type)
    name = Attribute(attribute_name=name, attribute_value=value)

    usage_mask = Attribute.AttributeName('Cryptographic Usage Mask')
    value = CryptographicUsageMask(
        UsageMaskEnum.ENCRYPT.value | UsageMaskEnum.DECRYPT.value)
    usage_mask = Attribute(attribute_name=usage_mask, attribute_value=value)

    attribute_type = AttributeType.CRYPTOGRAPHIC_LENGTH
    length_obj = attribute_factory.create_attribute(attribute_type,
                                                    length)

    attributes = [algorithm_obj, length_obj, name, usage_mask]

    if opts.operation_policy_name is not None:
        opn = attribute_factory.create_attribute(
            enums.AttributeType.OPERATION_POLICY_NAME,
            opts.operation_policy_name
        )
        attributes.append(opn)

    common = TemplateAttribute(
        attributes=attributes,
        tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
    )
    private = TemplateAttribute(
        attributes=attributes,
        tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
    )
    public = TemplateAttribute(
        attributes=attributes,
        tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
    )

    # Create the SYMMETRIC_KEY object
    result = client.create_key_pair(
        common_template_attribute=common,
        private_key_template_attribute=private,
        public_key_template_attribute=public
    )
    client.close()

    # Display operation results
    logger.info('create_key_pair() result status: {0}'.format(
        result.result_status.value))

    if result.result_status.value == ResultStatus.SUCCESS:
        logger.info('created private key UUID: {0}'.format(
            result.private_key_uuid))
        logger.info('created public key UUID: {0}'.format(
            result.public_key_uuid))

        if result.private_key_template_attribute is not None:
            logger.info('private key template attribute:')
            utils.log_template_attribute(
                logger, result.private_key_template_attribute)

        if result.public_key_template_attribute is not None:
            logger.info('public key template attribute:')
            utils.log_template_attribute(
                logger, result.public_key_template_attribute)
    else:
        logger.info('create() result reason: {0}'.format(
            result.result_reason.value))
        logger.info('create() result message: {0}'.format(
            result.result_message.value))
