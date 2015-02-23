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

from kmip.core.enums import AttributeType
from kmip.core.enums import CredentialType
from kmip.core.enums import ObjectType
from kmip.core.enums import ResultStatus
from kmip.core.enums import CryptographicAlgorithm
from kmip.core.enums import CryptographicUsageMask
from kmip.core.enums import NameType

from kmip.core.attributes import Name

from kmip.core.factories.attributes import AttributeFactory
from kmip.core.factories.credentials import CredentialFactory

from kmip.core.objects import TemplateAttribute, Attribute

from kmip.services.kmip_client import KMIPProxy

import logging
import os

if __name__ == '__main__':
    f_log = os.path.join(os.path.dirname(__file__), '..', 'logconfig.ini')
    logging.config.fileConfig(f_log)
    logger = logging.getLogger(__name__)

    attribute_factory = AttributeFactory()
    credential_factory = CredentialFactory()

    credential_type = CredentialType.USERNAME_AND_PASSWORD
    credential_value = {'Username': 'Peter', 'Password': 'abc123'}
    credential = credential_factory.create_credential(credential_type,
                                                      credential_value)
    client = KMIPProxy()
    client.open()

    object_type = ObjectType.SYMMETRIC_KEY
    attribute_type = AttributeType.CRYPTOGRAPHIC_ALGORITHM
    algorithm = attribute_factory.create_attribute(attribute_type,
                                                   CryptographicAlgorithm.AES)
    mask_flags = [CryptographicUsageMask.ENCRYPT,
                  CryptographicUsageMask.DECRYPT]
    attribute_type = AttributeType.CRYPTOGRAPHIC_USAGE_MASK
    usage_mask = attribute_factory.create_attribute(attribute_type,
                                                    mask_flags)
    name = Attribute.AttributeName('Name')
    name_value = Name.NameValue('FOOBAR')
    name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
    value = Name(name_value=name_value, name_type=name_type)
    nameattr = Attribute(attribute_name=name, attribute_value=value)

    attributes = [algorithm, usage_mask, nameattr]

    template_attribute = TemplateAttribute(attributes=attributes)

    result = client.create(object_type, template_attribute,
                           credential)

    attrs = [nameattr]
    result = client.locate(attributes=attrs, credential=credential)
    client.close()

    logger.debug('locate() result status: {0}'.
                 format(result.result_status.enum))
    if result.result_status.enum == ResultStatus.SUCCESS:
        logger.debug('retrieved object type: {0}'.
                     format(result.object_type.enum))
        logger.debug('Located UUIDs: {0}'.format(','.join([u.value for u in
                                                           result.uuids])))
