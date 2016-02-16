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

import logging
import os

from kmip.core.attributes import CryptographicLength
from kmip.core.attributes import CryptographicAlgorithm
from kmip.core.attributes import ObjectType
from kmip.core.attributes import UniqueIdentifier
from kmip.core.enums import AttributeType as AT
from kmip.core.enums import CryptographicAlgorithm as CA
from kmip.core.enums import KeyFormatType as KeyFormatTypeEnum
from kmip.core.enums import ObjectType as OT
from kmip.core.enums import ResultReason as ResultReasonEnum
from kmip.core.enums import ResultStatus as RS
from kmip.core.factories.attributes import AttributeFactory
from kmip.core.factories.keys import KeyFactory
from kmip.core.factories.secrets import SecretFactory

from kmip.core.messages.contents import ResultStatus
from kmip.core.messages.contents import ResultReason
from kmip.core.messages.contents import ResultMessage
from kmip.core.messages.contents import ProtocolVersion

from kmip.core.misc import KeyFormatType

from kmip.core.objects import KeyBlock
from kmip.core.objects import KeyMaterial
from kmip.core.objects import KeyValue
from kmip.core.objects import TemplateAttribute
from kmip.core.secrets import SymmetricKey
from kmip.services.server.repo.mem_repo import MemRepo
from kmip.services.results import CreateResult
from kmip.services.results import DestroyResult
from kmip.services.results import GetResult
from kmip.services.results import OperationResult
from kmip.services.results import RegisterResult
from kmip.services.results import LocateResult
from kmip.services.results import DiscoverVersionsResult


class KMIP(object):

    def __init__(self):
        pass

    def create(self, object_type, template_attribute, credential=None):
        raise NotImplementedError()

    def create_key_pair(self, common_template_attribute,
                        private_key_template_attribute,
                        public_key_template_attribute):
        raise NotImplementedError()

    def register(self, object_type, template_attribute, secret,
                 credential=None):
        raise NotImplementedError()

    def rekey_key_pair(self, private_key_unique_identifier,
                       offset, common_template_attribute,
                       private_key_template_attribute,
                       public_key_template_attribute):
        raise NotImplementedError()

    def get(self, uuid=None, key_format_type=None, key_compression_type=None,
            key_wrapping_specification=None, credential=None):
        raise NotImplementedError()

    def destroy(self, uuid, credential=None):
        raise NotImplementedError()

    def locate(self, maximum_items=None, storate_status_mask=None,
               object_group_member=None, attributes=None,
               credential=None):
        raise NotImplementedError()

    def discover_versions(self, protocol_versions=None):
        raise NotImplementedError()


class KMIPImpl(KMIP):

    def __init__(self):
        super(KMIPImpl, self).__init__()
        self.logger = logging.getLogger(__name__)
        self.key_factory = KeyFactory()
        self.secret_factory = SecretFactory()
        self.attribute_factory = AttributeFactory()
        self.repo = MemRepo()
        self.protocol_versions = [
                ProtocolVersion.create(1, 1),
                ProtocolVersion.create(1, 0)
        ]

    def create(self, object_type, template_attribute, credential=None):
        self.logger.debug('create() called')
        self.logger.debug('object type = %s' % object_type)
        bit_length = 256
        attributes = template_attribute.attributes
        ret_attributes = []
        if object_type.value != OT.SYMMETRIC_KEY:
            self.logger.debug('invalid object type')
            return self._get_invalid_field_result('invalid object type')
        try:
            alg_attr = self._validate_req_field(
                attributes, AT.CRYPTOGRAPHIC_ALGORITHM.value,
                (CA.AES,), 'unsupported algorithm')
            len_attr = self._validate_req_field(
                attributes, AT.CRYPTOGRAPHIC_LENGTH.value,
                (128, 256, 512), 'unsupported key length', False)
            self._validate_req_field(
                attributes, AT.CRYPTOGRAPHIC_USAGE_MASK.value, (), '')
        except InvalidFieldException as e:
            self.logger.debug('InvalidFieldException raised')
            return e.result

        crypto_alg = CryptographicAlgorithm(CA(alg_attr.attribute_value.value))

        if len_attr is None:
            self.logger.debug('cryptographic length not supplied')
            attribute_type = AT.CRYPTOGRAPHIC_LENGTH
            length_attribute = self.attribute_factory.\
                create_attribute(attribute_type, bit_length)
            attributes.append(length_attribute)
            ret_attributes.append(length_attribute)
        else:
            bit_length = len_attr.attribute_value.value

        key = self._gen_symmetric_key(bit_length, crypto_alg)
        s_uuid, uuid_attribute = self._save(key, attributes)
        ret_attributes.append(uuid_attribute)
        template_attribute = TemplateAttribute(attributes=ret_attributes)
        return CreateResult(ResultStatus(RS.SUCCESS), object_type=object_type,
                            uuid=UniqueIdentifier(s_uuid),
                            template_attribute=template_attribute)

    def create_key_pair(self, common_template_attribute,
                        private_key_template_attribute,
                        public_key_template_attribute):
        raise NotImplementedError()

    def register(self, object_type, template_attribute, secret,
                 credential=None):
        self.logger.debug('register() called')
        self.logger.debug('object type = %s' % object_type)
        attributes = template_attribute.attributes
        ret_attributes = []
        if object_type is None:
            self.logger.debug('invalid object type')
            return self._get_missing_field_result('object type')
        if object_type.value != OT.SYMMETRIC_KEY:
            self.logger.debug('invalid object type')
            return self._get_invalid_field_result('invalid object type')
        if secret is None or not isinstance(secret, SymmetricKey):
            msg = 'object type does not match that of secret'
            self.logger.debug(msg)
            return self._get_invalid_field_result(msg)

        self.logger.debug('Collecting all attributes')
        if attributes is None:
            attributes = []
        attributes.extend(self._get_key_block_attributes(secret.key_block))

        self.logger.debug('Verifying all attributes are valid and set')
        try:
            self._validate_req_field(
                attributes, AT.CRYPTOGRAPHIC_ALGORITHM.value, (CA.AES,),
                'unsupported algorithm')
            self._validate_req_field(
                attributes, AT.CRYPTOGRAPHIC_LENGTH.value, (128, 256, 512),
                'unsupported key length')
            self._validate_req_field(
                attributes, AT.CRYPTOGRAPHIC_USAGE_MASK.value, (), '')
        except InvalidFieldException as e:
            self.logger.debug('InvalidFieldException raised')
            return RegisterResult(e.result.result_status,
                                  e.result.result_reason,
                                  e.result.result_message)

        s_uuid, uuid_attribute = self._save(secret, attributes)
        ret_attributes.append(uuid_attribute)
        template_attribute = TemplateAttribute(attributes=ret_attributes)
        return RegisterResult(ResultStatus(RS.SUCCESS),
                              uuid=UniqueIdentifier(s_uuid),
                              template_attribute=template_attribute)

    def rekey_key_pair(self, private_key_unique_identifier,
                       offset, common_template_attribute,
                       private_key_template_attribute,
                       public_key_template_attribute):
        raise NotImplementedError()

    def get(self,
            uuid=None,
            key_format_type=None,
            key_compression_type=None,
            key_wrapping_specification=None,
            credential=None):
        self.logger.debug('get() called')
        ret_value = RS.OPERATION_FAILED
        if uuid is None or not hasattr(uuid, 'value'):
            self.logger.debug('no uuid provided')
            reason = ResultReason(ResultReasonEnum.ITEM_NOT_FOUND)
            message = ResultMessage('')
            return GetResult(ResultStatus(ret_value), reason, message)
        if key_format_type is None:
            self.logger.debug('key format type is None, setting to raw')
            key_format_type = KeyFormatType(KeyFormatTypeEnum.RAW)
        if key_format_type.value != KeyFormatTypeEnum.RAW:
            self.logger.debug('key format type is not raw')
            reason = ResultReason(ResultReasonEnum.
                                  KEY_FORMAT_TYPE_NOT_SUPPORTED)
            message = ResultMessage('')
            return GetResult(ResultStatus(ret_value), reason, message)
        if key_compression_type is not None:
            self.logger.debug('key compression type is not None')
            reason = ResultReason(ResultReasonEnum.
                                  KEY_COMPRESSION_TYPE_NOT_SUPPORTED)
            message = ResultMessage('')
            return GetResult(ResultStatus(ret_value), reason, message)
        if key_wrapping_specification is not None:
            self.logger.debug('key wrapping specification is not None')
            reason = ResultReason(ResultReasonEnum.FEATURE_NOT_SUPPORTED)
            message = ResultMessage('key wrapping is not currently supported')
            return GetResult(ResultStatus(ret_value), reason, message)

        self.logger.debug('retrieving object from repo')
        managed_object, _ = self.repo.get(uuid.value)

        if managed_object is None:
            self.logger.debug('object not found in repo')
            reason = ResultReason(ResultReasonEnum.ITEM_NOT_FOUND)
            message = ResultMessage('')
            return GetResult(ResultStatus(ret_value), reason, message)

        # currently only symmetric keys are supported, fix this in future
        object_type = ObjectType(OT.SYMMETRIC_KEY)
        ret_value = RS.SUCCESS
        return GetResult(ResultStatus(ret_value), object_type=object_type,
                         uuid=uuid, secret=managed_object)

    def destroy(self, uuid):
        self.logger.debug('destroy() called')
        ret_value = RS.OPERATION_FAILED
        if uuid is None or not hasattr(uuid, 'value'):
            self.logger.debug('no uuid provided')
            reason = ResultReason(ResultReasonEnum.ITEM_NOT_FOUND)
            message = ResultMessage('')
            return DestroyResult(ResultStatus(ret_value), reason, message)

        msg = 'deleting object from repo: {0}'.format(uuid)
        self.logger.debug(msg)
        if not self.repo.delete(uuid.value):
            self.logger.debug('repo did not find and delete managed object')
            reason = ResultReason(ResultReasonEnum.ITEM_NOT_FOUND)
            message = ResultMessage('')
            return DestroyResult(ResultStatus(ret_value), reason, message)

        ret_value = RS.SUCCESS
        return DestroyResult(ResultStatus(ret_value), uuid=uuid)

    def locate(self, maximum_items=None, storage_status_mask=None,
               object_group_member=None, attributes=None,
               credential=None):
        self.logger.debug('locate() called')
        msg = 'locating object(s) from repo'
        self.logger.debug(msg)
        try:
            uuids = self.repo.locate(maximum_items, storage_status_mask,
                                     object_group_member, attributes)
            return LocateResult(ResultStatus(RS.SUCCESS), uuids=uuids)
        except NotImplementedError:
            msg = ResultMessage('Locate Operation Not Supported')
            reason = ResultReason(ResultReasonEnum.OPERATION_NOT_SUPPORTED)
            return LocateResult(ResultStatus(RS.OPERATION_FAILED),
                                result_reason=reason, result_message=msg)

    def discover_versions(self, protocol_versions=None):
        self.logger.debug(
            "discover_versions(protocol_versions={0}) called".format(
                protocol_versions))
        msg = 'get protocol versions supported by server'

        result_versions = list()
        if protocol_versions:
            msg += " and client; client versions {0}".format(protocol_versions)
            for version in protocol_versions:
                if version in self.protocol_versions:
                    result_versions.append(version)
        else:
            result_versions = self.protocol_versions

        self.logger.debug(msg)
        try:
            return DiscoverVersionsResult(ResultStatus(RS.SUCCESS),
                                          protocol_versions=result_versions)
        except Exception:
            msg = ResultMessage('DiscoverVersions Operation Failed')
            reason = ResultReason(ResultReasonEnum.GENERAL_FAILURE)
            return DiscoverVersionsResult(ResultStatus(RS.OPERATION_FAILED),
                                          result_reason=reason,
                                          result_message=msg)

    def _validate_req_field(self, attrs, name, expected, msg, required=True):
        self.logger.debug('Validating attribute %s' % name)
        seen = False
        found_attr = None
        for attr in attrs:
            if self._validate_field(attr, name, expected, msg):
                if seen:
                    # TODO check what spec says to do on this
                    msg = 'duplicate attribute: %s' % name
                    self.logger.debug(msg)
                    result = self._get_duplicate_attribute_result(name)
                    raise InvalidFieldException(result)
                seen = True
                found_attr = attr
        if required and not seen:
            result = self._get_missing_field_result(name)
            raise InvalidFieldException(result)
        return found_attr

    def _validate_field(self, attr, name, expected, msg):
        if attr.attribute_name.value == name:
            self.logger.debug('validating attribute %s' % name)
            if not expected or attr.attribute_value.value in expected:
                self.logger.debug('attribute validated')
                return True
            else:
                self.logger.debug('attribute not validated')
                result = self._get_invalid_field_result(msg)
                raise InvalidFieldException(result)
        else:
            return False

    def _get_invalid_field_result(self, msg):
        status = ResultStatus(RS.OPERATION_FAILED)
        reason = ResultReason(ResultReasonEnum.INVALID_FIELD)
        message = ResultMessage(msg)
        return OperationResult(status, reason, message)

    def _get_missing_field_result(self, name):
        msg = '%s not supplied' % name
        self.logger.debug(msg)
        status = ResultStatus(RS.OPERATION_FAILED)
        reason = ResultReason(ResultReasonEnum.ITEM_NOT_FOUND)
        message = ResultMessage(msg)
        return OperationResult(status, reason, message)

    def _get_duplicate_attribute_result(self, name):
        msg = '%s supplied multiple times' % name
        self.logger.debug(msg)
        status = ResultStatus(RS.OPERATION_FAILED)
        reason = ResultReason(ResultReasonEnum.INDEX_OUT_OF_BOUNDS)
        message = ResultMessage(msg)
        return OperationResult(status, reason, message)

    def _gen_symmetric_key(self, bit_length, crypto_alg):
        key_format_type = KeyFormatType(KeyFormatTypeEnum.RAW)
        key_material = KeyMaterial(os.urandom(int(bit_length/8)))
        key_value = KeyValue(key_material)
        crypto_length = CryptographicLength(bit_length)
        key_block = KeyBlock(key_format_type, None, key_value, crypto_alg,
                             crypto_length, None)
        return SymmetricKey(key_block)

    def _save(self, key, attributes):
        s_uuid = self.repo.save(key, attributes)
        self.logger.debug('creating object with uuid = %s' % s_uuid)
        attribute_type = AT.UNIQUE_IDENTIFIER
        attribute = self.attribute_factory.create_attribute(attribute_type,
                                                            s_uuid)
        attributes.append(attribute)
        # Calling update to also store the UUID
        self.repo.update(s_uuid, key, attributes)
        return s_uuid, attribute

    def _get_key_block_attributes(self, key_block):
        self.logger.debug('getting all key attributes from key block')
        attributes = []
        if key_block.cryptographic_algorithm is not None:
            self.logger.debug('crypto_alg set on key block')
            self.logger.debug('adding crypto algorithm attribute')
            at = AT.CRYPTOGRAPHIC_ALGORITHM
            alg = key_block.cryptographic_algorithm.value
            attributes.append(self.attribute_factory.create_attribute(at, alg))
        if key_block.cryptographic_length is not None:
            self.logger.debug('crypto_length set on key block')
            self.logger.debug('adding crypto length attribute')
            at = AT.CRYPTOGRAPHIC_LENGTH
            len = key_block.cryptographic_length.value
            attributes.append(self.attribute_factory.create_attribute(at, len))
        self.logger.debug('getting key value attributes')
        if key_block.key_wrapping_data is not None:
            self.logger.debug('no wrapping data so key value is struct')
            kv = key_block.key_value
            if isinstance(kv, KeyValue):
                kv = key_block.key_value
                if kv.attributes is not None:
                    self.logger.debug('adding the key value struct attributes')
                    attributes.extend(kv.attributes)
        return attributes


class InvalidFieldException(Exception):

    def __init__(self, result):
        super(InvalidFieldException, self).__init__()
        self.result = result
