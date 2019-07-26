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

import calendar
import logging
import sys
import time

from kmip.core import enums
from kmip.core.factories.attributes import AttributeFactory
from kmip.core.factories.credentials import CredentialFactory
from kmip.demos import utils
from kmip.services import kmip_client


if __name__ == '__main__':
    logger = utils.build_console_logger(logging.INFO)

    # Build and parse arguments
    parser = utils.build_cli_parser(enums.Operation.LOCATE)
    opts, args = parser.parse_args(sys.argv[1:])

    username = opts.username
    password = opts.password
    config = opts.config
    name = opts.name
    initial_dates = opts.initial_dates
    state = opts.state

    attribute_factory = AttributeFactory()
    credential_factory = CredentialFactory()

    # Build the KMIP server account credentials
    # TODO (peter-hamilton) Move up into KMIPProxy
    if (username is None) and (password is None):
        credential = None
    else:
        credential_type = enums.CredentialType.USERNAME_AND_PASSWORD
        credential_value = {
            "Username": username,
            "Password": password
        }
        credential = credential_factory.create_credential(
            credential_type,
            credential_value
        )

    # Build the client and connect to the server
    client = kmip_client.KMIPProxy(config=config, config_file=opts.config_file)
    client.open()

    # Build attributes if any are specified
    attributes = []
    if name:
        attributes.append(
            attribute_factory.create_attribute(enums.AttributeType.NAME, name)
        )
    for initial_date in initial_dates:
        try:
            t = time.strptime(initial_date)
        except ValueError:
            logger.error(
                "Invalid initial date provided: {}".format(initial_date)
            )
            logger.info(
                "Date values should be formatted like this: "
                "'Tue Jul 23 18:39:01 2019'"
            )
            sys.exit(-1)

        try:
            t = calendar.timegm(t)
        except Exception:
            logger.error(
                "Failed to convert initial date time tuple "
                "to an integer: {}".format(t)
            )
            sys.exit(-2)

        attributes.append(
            attribute_factory.create_attribute(
                enums.AttributeType.INITIAL_DATE,
                t
            )
        )
    if state:
        state = getattr(enums.State, state, None)
        if state:
            attributes.append(
                attribute_factory.create_attribute(
                    enums.AttributeType.STATE,
                    state
                )
            )
        else:
            logger.error("Invalid state provided: {}".format(opts.state))
            client.close()
            sys.exit(-1)

    result = client.locate(attributes=attributes, credential=credential)
    client.close()

    # Display operation results
    logger.info('locate() result status: {0}'.format(
        result.result_status.value))

    if result.result_status.value == enums.ResultStatus.SUCCESS:
        logger.info('located UUIDs:')
        for uuid in result.uuids:
            logger.info('{0}'.format(uuid))
    else:
        logger.info('get() result reason: {0}'.format(
            result.result_reason.value))
        logger.info('get() result message: {0}'.format(
            result.result_message.value))
