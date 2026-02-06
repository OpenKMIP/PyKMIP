# Copyright (c) 2017 Pure Storage, Inc. All Rights Reserved.
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
from kmip.demos import utils
from kmip.pie import client

if __name__ == '__main__':
    logger = utils.build_console_logger(logging.INFO)

    # Build and parse arguments
    parser = utils.build_cli_parser(enums.Operation.LOCATE)
    opts, args = parser.parse_args(sys.argv[1:])

    config = opts.config
    offset_items = opts.offset_items
    maximum_items = opts.maximum_items
    name = opts.name
    initial_dates = opts.initial_dates
    state = opts.state
    object_type = opts.object_type
    certificate_type = opts.certificate_type
    cryptographic_algorithm = opts.cryptographic_algorithm
    cryptographic_length = opts.cryptographic_length
    cryptographic_usage_masks = opts.cryptographic_usage_masks
    unique_identifier = opts.unique_identifier
    operation_policy_name = opts.operation_policy_name

    attribute_factory = AttributeFactory()

    if offset_items and (offset_items < 0):
        logger.error("Invalid offset items value provided.")
        sys.exit(-1)
    if maximum_items and (maximum_items < 0):
        logger.error("Invalid maximum items value provided.")
        sys.exit(-1)

    # Build attributes if any are specified
    attributes = []
    if name:
        attributes.append(
            attribute_factory.create_attribute(enums.AttributeType.NAME, name)
        )
    for initial_date in initial_dates:
        try:
            t = time.strptime(initial_date)
        except (ValueError, TypeError):
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
            sys.exit(-3)
    if object_type:
        object_type = getattr(enums.ObjectType, object_type, None)
        if object_type:
            attributes.append(
                attribute_factory.create_attribute(
                    enums.AttributeType.OBJECT_TYPE,
                    object_type
                )
            )
        else:
            logger.error(
                "Invalid object type provided: {}".format(opts.object_type)
            )
            sys.exit(-4)
    if cryptographic_algorithm:
        cryptographic_algorithm = getattr(
            enums.CryptographicAlgorithm,
            cryptographic_algorithm,
            None
        )
        if cryptographic_algorithm:
            attributes.append(
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    cryptographic_algorithm
                )
            )
        else:
            logger.error(
                "Invalid cryptographic algorithm provided: {}".format(
                    opts.cryptographic_algorithm
                )
            )
            sys.exit(-5)
    if cryptographic_length:
        if cryptographic_length > 0:
            attributes.append(
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    cryptographic_length
                )
            )
        else:
            logger.error(
                "Invalid cryptographic length provided: {}".format(
                    opts.cryptographic_length
                )
            )
            sys.exit(-6)
    if cryptographic_usage_masks:
        masks = []
        for cryptographic_usage_mask in cryptographic_usage_masks:
            mask = getattr(
                enums.CryptographicUsageMask,
                cryptographic_usage_mask,
                None
            )
            if mask:
                masks.append(mask)
            else:
                logger.error(
                    "Invalid cryptographic usage mask provided: {}".format(
                        cryptographic_usage_mask
                    )
                )
                sys.exit(-7)
        attributes.append(
            attribute_factory.create_attribute(
                enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                masks
            )
        )
    if certificate_type:
        certificate_type = getattr(
            enums.CertificateType,
            certificate_type,
            None
        )
        if certificate_type:
            attributes.append(
                attribute_factory.create_attribute(
                    enums.AttributeType.CERTIFICATE_TYPE,
                    certificate_type
                )
            )
        else:
            logger.error(
                "Invalid certificate type provided: {}".format(
                    opts.certificate_type
                )
            )
            sys.exit(-8)
    if unique_identifier:
        attributes.append(
            attribute_factory.create_attribute(
                enums.AttributeType.UNIQUE_IDENTIFIER,
                unique_identifier
            )
        )
    if operation_policy_name:
        attributes.append(
            attribute_factory.create_attribute(
                enums.AttributeType.OPERATION_POLICY_NAME,
                operation_policy_name
            )
        )

    # Build the client and connect to the server
    with client.ProxyKmipClient(
            config=config,
            config_file=opts.config_file
    ) as client:
        try:
            uuids = client.locate(
                attributes=attributes,
                offset_items=offset_items,
                maximum_items=maximum_items
            )
            logger.info("Located uuids: {0}".format(uuids))
        except Exception as e:
            logger.error(e)
