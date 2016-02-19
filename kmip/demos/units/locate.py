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

from kmip.core.enums import CredentialType
from kmip.core.enums import NameType
from kmip.core.enums import Operation
from kmip.core.enums import ResultStatus
from kmip.core.enums import ObjectGroupMember
from kmip.core.enums import StorageStatusMask

from kmip.core.attributes import Name

from kmip.core.factories.attributes import AttributeFactory
from kmip.core.factories.credentials import CredentialFactory

from kmip.core.objects import Attribute

from kmip.demos import utils

from kmip.services.kmip_client import KMIPProxy

import logging
import os
import sys


if __name__ == '__main__':
    # Build and parse arguments
    parser = utils.build_cli_parser(Operation.LOCATE)
    opts, args = parser.parse_args(sys.argv[1:])

    username = opts.username
    password = opts.password
    config = opts.config
    name = opts.name
    storage_status_mask = opts.storage_status_mask
    object_group_member = opts.object_group_member
    maximum_items = opts.maximum_items

    # Exit early if the UUID is not specified
    if name is None:
        logging.debug('No name provided, exiting early from demo')
        sys.exit()

    # Build and setup logging and needed factories
    f_log = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir,
                         'logconfig.ini')
    logging.config.fileConfig(f_log)
    logger = logging.getLogger(__name__)

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
    # Build name attribute
    # TODO (peter-hamilton) Push this into the AttributeFactory
    attribute_name = Attribute.AttributeName('Name')
    name_value = Name.NameValue(name)
    name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
    value = Name.create(name_value=name_value, name_type=name_type)
    name_obj = Attribute(attribute_name=attribute_name, attribute_value=value)

    attributes = [name_obj]

    ssmask = None
    if storage_status_mask is not None:
        if storage_status_mask == 'online':
            ssmask = StorageStatusMask.ONLINE_STORAGE
        elif storage_status_mask == 'archival':
            ssmask = StorageStatusMask.ARCHIVAL_STORAGE
        else:
            logging.debug('Invalid storage-status-mask value')
            sys.exit()

    if object_group_member is not None:
        if object_group_member == 'fresh':
            object_group_member = ObjectGroupMember.GROUP_MEMBER_FRESH
        elif object_group_member == 'default':
            object_group_member = ObjectGroupMember.GROUP_MEMBER_DEFAULT
        else:
            logging.debug('Invalid object-group-member value')
            sys.exit()

    # Build the client and connect to the server
    client = KMIPProxy(config=config)
    client.open()

    # Locate UUID of specified SYMMETRIC_KEY object
    result = client.locate(maximum_items=maximum_items,
                           storage_status_mask=ssmask,
                           object_group_member=object_group_member,
                           attributes=attributes,
                           credential=credential)
    client.close()

    # Display operation results
    logger.info('locate() result status: {0}'.format(
        result.result_status.value))

    if result.result_status.value == ResultStatus.SUCCESS:
        logger.info('located UUIDs:')
        for uuid in result.uuids:
            logger.info('{0}'.format(uuid))
    else:
        logger.info('get() result reason: {0}'.format(
            result.result_reason.value))
        logger.info('get() result message: {0}'.format(
            result.result_message.value))
