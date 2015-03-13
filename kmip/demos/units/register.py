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

from kmip.core.enums import KeyFormatType
from kmip.core.enums import ObjectType
from kmip.core.enums import Operation
from kmip.core.enums import ResultStatus

from kmip.core.objects import TemplateAttribute

from kmip.demos import utils

from kmip.services.kmip_client import KMIPProxy

import logging
import os
import sys


if __name__ == '__main__':
    parser = utils.build_cli_parser(Operation.REGISTER)
    opts, args = parser.parse_args(sys.argv[1:])

    username = opts.username
    password = opts.password
    config = opts.config
    object_type = opts.type
    format_type = opts.format

    # Exit early if the arguments are not specified
    object_type = getattr(ObjectType, object_type, None)
    if object_type is None:
        logging.error("Invalid object type specified; exiting early from demo")
        sys.exit()

    key_format_type = getattr(KeyFormatType, format_type, None)
    if key_format_type is None:
        logging.error(
            "Invalid key format type specified; exiting early from demo")

    # Build and setup logging and needed factories
    f_log = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir,
                         'logconfig.ini')
    logging.config.fileConfig(f_log)
    logger = logging.getLogger(__name__)

    # Create the template attribute for the secret and then build the secret
    usage_mask = utils.build_cryptographic_usage_mask(logger, object_type)
    attributes = [usage_mask]
    template_attribute = TemplateAttribute(attributes=attributes)

    secret = utils.build_object(logger, object_type, key_format_type)

    # Build the client, connect to the server, register the secret, and
    # disconnect from the server
    client = KMIPProxy(config=config)

    client.open()
    result = client.register(object_type, template_attribute, secret)
    client.close()

    # Display operation results
    logger.debug('register() result status: {0}'.format(
        result.result_status.enum))

    if result.result_status.enum == ResultStatus.SUCCESS:
        logger.debug('registered UUID: {0}'.format(result.uuid.value))
        logger.debug('registered template attribute: {0}'.
                     format(result.template_attribute))
    else:
        logger.debug('register() result reason: {0}'.format(
            result.result_reason.enum))
        logger.debug('register() result message: {0}'.format(
            result.result_message.value))
