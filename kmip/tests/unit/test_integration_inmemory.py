# Copyright (c) 2026 The Johns Hopkins University/Applied Physics Laboratory
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

import time

import testtools

from kmip.core import attributes
from kmip.core import enums
from kmip.core import objects as core_objects
from kmip.core import policy as operation_policy
from kmip.core.factories import attributes as attribute_factory
from kmip.core.factories import secrets as secret_factory
from kmip.core.messages import contents
from kmip.core.messages import messages
from kmip.core.messages import payloads
from kmip.services.server import engine as kmip_engine


class TestIntegrationInMemory(testtools.TestCase):
    def setUp(self):
        super(TestIntegrationInMemory, self).setUp()
        self.engine = kmip_engine.KmipEngine(
            policies=operation_policy.policies,
            database_path=':memory:'
        )
        self.attr_factory = attribute_factory.AttributeFactory()
        self.secret_factory = secret_factory.SecretFactory()
        self.protocol_version = contents.ProtocolVersion(1, 2)
        self.default_credential = ["user-a", None]

    def _batch_item(self, operation, request_payload, batch_id=None):
        unique_batch_item_id = None
        if batch_id is not None:
            unique_batch_item_id = contents.UniqueBatchItemID(batch_id)
        return messages.RequestBatchItem(
            operation=contents.Operation(operation),
            unique_batch_item_id=unique_batch_item_id,
            request_payload=request_payload
        )

    def _build_request(self, batch_items):
        if len(batch_items) > 1:
            for index, batch_item in enumerate(batch_items, start=1):
                if batch_item.unique_batch_item_id is None:
                    batch_item.unique_batch_item_id = \
                        contents.UniqueBatchItemID(index)

        header = messages.RequestHeader(
            protocol_version=self.protocol_version,
            maximum_response_size=contents.MaximumResponseSize(2 ** 20),
            authentication=contents.Authentication(),
            batch_error_cont_option=contents.BatchErrorContinuationOption(
                enums.BatchErrorContinuationOption.STOP
            ),
            batch_order_option=contents.BatchOrderOption(True),
            time_stamp=contents.TimeStamp(int(time.time())),
            batch_count=contents.BatchCount(len(batch_items))
        )

        return messages.RequestMessage(
            request_header=header,
            batch_items=batch_items
        )

    def _send_request(self, batch_items, credential=None):
        if credential is None:
            credential = self.default_credential
        request = self._build_request(batch_items)
        response, _, _ = self.engine.process_request(
            request,
            credential=credential
        )
        return response

    def _assert_success(self, response, index=0):
        batch_item = response.batch_items[index]
        self.assertEqual(
            enums.ResultStatus.SUCCESS,
            batch_item.result_status.value
        )
        return batch_item.response_payload

    def _assert_error(self, response, reason=None, index=0):
        batch_item = response.batch_items[index]
        self.assertEqual(
            enums.ResultStatus.OPERATION_FAILED,
            batch_item.result_status.value
        )
        if reason is not None:
            self.assertEqual(reason, batch_item.result_reason.value)
        return batch_item

    def _name_attribute(self, name):
        return self.attr_factory.create_attribute(
            enums.AttributeType.NAME,
            attributes.Name.create(
                name,
                enums.NameType.UNINTERPRETED_TEXT_STRING
            )
        )

    def _symmetric_template(
            self,
            name,
            algorithm,
            length,
            masks,
            policy_name="default"):
        attrs = []
        if name is not None:
            attrs.append(self._name_attribute(name))
        if algorithm is not None:
            attrs.append(self.attr_factory.create_attribute(
                enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                algorithm
            ))
        if length is not None:
            attrs.append(self.attr_factory.create_attribute(
                enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                length
            ))
        if masks is not None:
            attrs.append(self.attr_factory.create_attribute(
                enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                masks
            ))
        if policy_name is not None:
            attrs.append(self.attr_factory.create_attribute(
                enums.AttributeType.OPERATION_POLICY_NAME,
                policy_name
            ))
        return core_objects.TemplateAttribute(attributes=attrs)

    def _attributes_to_dict(self, attribute_list):
        result = {}
        for attribute in attribute_list:
            name = attribute.attribute_name.value
            value = attribute.attribute_value
            if name == "Name":
                result.setdefault(name, []).append(value.name_value.value)
            elif name == "Cryptographic Usage Mask":
                result[name] = enums.get_enumerations_from_bit_mask(
                    enums.CryptographicUsageMask,
                    value.value
                )
            elif hasattr(value, "value"):
                result[name] = value.value
            else:
                result[name] = value
        return result

    def _get_state(self, unique_identifier, credential=None):
        payload = payloads.GetAttributesRequestPayload(
            unique_identifier=unique_identifier,
            attribute_names=["State"]
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.GET_ATTRIBUTES, payload)],
            credential=credential
        )
        response_payload = self._assert_success(response)
        attrs = self._attributes_to_dict(response_payload.attributes)
        return attrs.get("State")

    def _aes_cbc_parameters(self):
        return attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES
        )

    def _rsa_signature_parameters(self):
        return attributes.CryptographicParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.RSA,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256,
            digital_signature_algorithm=(
                enums.DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION
            ),
            padding_method=enums.PaddingMethod.PKCS1v15
        )

    def test_full_key_lifecycle(self):
        template = self._symmetric_template(
            name="lifecycle-aes-256",
            algorithm=enums.CryptographicAlgorithm.AES,
            length=256,
            masks=[
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ]
        )
        create_payload = payloads.CreateRequestPayload(
            enums.ObjectType.SYMMETRIC_KEY,
            template
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.CREATE, create_payload)]
        )
        create_response = self._assert_success(response)
        key_id = create_response.unique_identifier

        self.assertEqual(enums.State.PRE_ACTIVE, self._get_state(key_id))

        activate_payload = payloads.ActivateRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(key_id)
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.ACTIVATE, activate_payload)]
        )
        self._assert_success(response)
        self.assertEqual(enums.State.ACTIVE, self._get_state(key_id))

        data = b"kmip integration data"
        crypto_params = self._aes_cbc_parameters()
        encrypt_payload = payloads.EncryptRequestPayload(
            unique_identifier=key_id,
            cryptographic_parameters=crypto_params,
            data=data,
            iv_counter_nonce=None
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.ENCRYPT, encrypt_payload)]
        )
        encrypt_response = self._assert_success(response)

        decrypt_payload = payloads.DecryptRequestPayload(
            unique_identifier=key_id,
            cryptographic_parameters=crypto_params,
            data=encrypt_response.data,
            iv_counter_nonce=encrypt_response.iv_counter_nonce
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.DECRYPT, decrypt_payload)]
        )
        decrypt_response = self._assert_success(response)
        self.assertEqual(data, decrypt_response.data)

        revoke_payload = payloads.RevokeRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(key_id),
            revocation_reason=core_objects.RevocationReason(
                code=enums.RevocationReasonCode.CESSATION_OF_OPERATION
            )
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.REVOKE, revoke_payload)]
        )
        self._assert_success(response)
        self.assertEqual(enums.State.DEACTIVATED, self._get_state(key_id))

        destroy_payload = payloads.DestroyRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(key_id)
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.DESTROY, destroy_payload)]
        )
        self._assert_success(response)

        get_payload = payloads.GetRequestPayload(unique_identifier=key_id)
        response = self._send_request(
            [self._batch_item(enums.Operation.GET, get_payload)]
        )
        self._assert_error(response, enums.ResultReason.ITEM_NOT_FOUND)

    def test_key_pair_lifecycle(self):
        common_template = core_objects.TemplateAttribute(
            attributes=[
                self._name_attribute("rsa-keypair"),
                self.attr_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                ),
                self.attr_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                ),
                self.attr_factory.create_attribute(
                    enums.AttributeType.OPERATION_POLICY_NAME,
                    "default"
                )
            ],
            tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
        )
        public_template = core_objects.TemplateAttribute(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [enums.CryptographicUsageMask.VERIFY]
                )
            ],
            tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
        )
        private_template = core_objects.TemplateAttribute(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [enums.CryptographicUsageMask.SIGN]
                )
            ],
            tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
        )
        create_pair_payload = payloads.CreateKeyPairRequestPayload(
            common_template_attribute=common_template,
            public_key_template_attribute=public_template,
            private_key_template_attribute=private_template
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.CREATE_KEY_PAIR,
                              create_pair_payload)]
        )
        create_pair_response = self._assert_success(response)
        public_id = create_pair_response.public_key_unique_identifier
        private_id = create_pair_response.private_key_unique_identifier

        response = self._send_request(
            [
                self._batch_item(
                    enums.Operation.ACTIVATE,
                    payloads.ActivateRequestPayload(
                        unique_identifier=attributes.UniqueIdentifier(public_id)
                    )
                ),
                self._batch_item(
                    enums.Operation.ACTIVATE,
                    payloads.ActivateRequestPayload(
                        unique_identifier=attributes.UniqueIdentifier(private_id)
                    )
                )
            ]
        )
        self._assert_success(response, index=0)
        self._assert_success(response, index=1)

        data = b"sign me"
        sig_params = self._rsa_signature_parameters()
        sign_payload = payloads.SignRequestPayload(
            unique_identifier=private_id,
            cryptographic_parameters=sig_params,
            data=data
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.SIGN, sign_payload)]
        )
        sign_response = self._assert_success(response)

        verify_payload = payloads.SignatureVerifyRequestPayload(
            unique_identifier=public_id,
            cryptographic_parameters=sig_params,
            data=data,
            signature_data=sign_response.signature_data
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.SIGNATURE_VERIFY,
                              verify_payload)]
        )
        verify_response = self._assert_success(response)
        self.assertEqual(
            enums.ValidityIndicator.VALID,
            verify_response.validity_indicator
        )

        revoke_reason = core_objects.RevocationReason(
            code=enums.RevocationReasonCode.CESSATION_OF_OPERATION
        )
        response = self._send_request(
            [
                self._batch_item(
                    enums.Operation.REVOKE,
                    payloads.RevokeRequestPayload(
                        unique_identifier=attributes.UniqueIdentifier(public_id),
                        revocation_reason=revoke_reason
                    )
                ),
                self._batch_item(
                    enums.Operation.REVOKE,
                    payloads.RevokeRequestPayload(
                        unique_identifier=attributes.UniqueIdentifier(private_id),
                        revocation_reason=revoke_reason
                    )
                )
            ]
        )
        self._assert_success(response, index=0)
        self._assert_success(response, index=1)

        response = self._send_request(
            [
                self._batch_item(
                    enums.Operation.DESTROY,
                    payloads.DestroyRequestPayload(
                        unique_identifier=attributes.UniqueIdentifier(public_id)
                    )
                ),
                self._batch_item(
                    enums.Operation.DESTROY,
                    payloads.DestroyRequestPayload(
                        unique_identifier=attributes.UniqueIdentifier(private_id)
                    )
                )
            ]
        )
        self._assert_success(response, index=0)
        self._assert_success(response, index=1)

    def test_registration_and_retrieval(self):
        key_bytes = b"\x11" * 32
        secret = self.secret_factory.create(
            enums.ObjectType.SYMMETRIC_KEY,
            {
                "key_format_type": enums.KeyFormatType.RAW,
                "key_value": key_bytes,
                "cryptographic_algorithm": enums.CryptographicAlgorithm.AES,
                "cryptographic_length": 256
            }
        )
        template = core_objects.TemplateAttribute(
            attributes=[
                self._name_attribute("external-key"),
                self.attr_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.ENCRYPT,
                        enums.CryptographicUsageMask.DECRYPT
                    ]
                ),
                self.attr_factory.create_attribute(
                    enums.AttributeType.OPERATION_POLICY_NAME,
                    "default"
                )
            ]
        )
        register_payload = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            template_attribute=template,
            managed_object=secret
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.REGISTER, register_payload)]
        )
        register_response = self._assert_success(response)
        key_id = register_response.unique_identifier

        get_payload = payloads.GetRequestPayload(unique_identifier=key_id)
        response = self._send_request(
            [self._batch_item(enums.Operation.GET, get_payload)]
        )
        get_response = self._assert_success(response)
        self.assertEqual(enums.ObjectType.SYMMETRIC_KEY, get_response.object_type)
        self.assertEqual(key_bytes,
                         get_response.secret.key_block.key_value.key_material
                         .value)
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            get_response.secret.key_block.cryptographic_algorithm.value
        )
        self.assertEqual(
            256,
            get_response.secret.key_block.cryptographic_length.value
        )

        attrs_payload = payloads.GetAttributesRequestPayload(
            unique_identifier=key_id,
            attribute_names=[
                "Name",
                "Cryptographic Algorithm",
                "Cryptographic Length",
                "Cryptographic Usage Mask",
                "Operation Policy Name"
            ]
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.GET_ATTRIBUTES, attrs_payload)]
        )
        attrs_response = self._assert_success(response)
        attrs = self._attributes_to_dict(attrs_response.attributes)
        self.assertIn("external-key", attrs.get("Name"))
        self.assertEqual(enums.CryptographicAlgorithm.AES,
                         attrs.get("Cryptographic Algorithm"))
        self.assertEqual(256, attrs.get("Cryptographic Length"))
        self.assertEqual(
            set([
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ]),
            set(attrs.get("Cryptographic Usage Mask"))
        )
        self.assertEqual("default", attrs.get("Operation Policy Name"))

    def test_locate_with_filters(self):
        created_ids = []
        key_specs = [
            ("locate-0", enums.CryptographicAlgorithm.AES, 128),
            ("locate-1", enums.CryptographicAlgorithm.AES, 256),
            ("locate-2", enums.CryptographicAlgorithm.BLOWFISH, 128),
            ("locate-3", enums.CryptographicAlgorithm.CAMELLIA, 128),
            ("locate-4", enums.CryptographicAlgorithm.TRIPLE_DES, 192)
        ]
        for name, algorithm, length in key_specs:
            template = self._symmetric_template(
                name=name,
                algorithm=algorithm,
                length=length,
                masks=[
                    enums.CryptographicUsageMask.ENCRYPT,
                    enums.CryptographicUsageMask.DECRYPT
                ]
            )
            payload = payloads.CreateRequestPayload(
                enums.ObjectType.SYMMETRIC_KEY,
                template
            )
            response = self._send_request(
                [self._batch_item(enums.Operation.CREATE, payload)]
            )
            create_response = self._assert_success(response)
            created_ids.append(create_response.unique_identifier)

        locate_name_payload = payloads.LocateRequestPayload(
            attributes=[
                self._name_attribute("locate-3")
            ]
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.LOCATE, locate_name_payload)]
        )
        locate_name_response = self._assert_success(response)
        self.assertEqual([created_ids[3]],
                         locate_name_response.unique_identifiers)

        locate_algo_payload = payloads.LocateRequestPayload(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.AES
                )
            ]
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.LOCATE, locate_algo_payload)]
        )
        locate_algo_response = self._assert_success(response)
        self.assertEqual(
            set([created_ids[0], created_ids[1]]),
            set(locate_algo_response.unique_identifiers)
        )

        locate_slice_payload = payloads.LocateRequestPayload(
            offset_items=2,
            maximum_items=2
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.LOCATE, locate_slice_payload)]
        )
        locate_slice_response = self._assert_success(response)
        self.assertEqual(2, len(locate_slice_response.unique_identifiers))
        self.assertEqual(
            created_ids[2:4],
            locate_slice_response.unique_identifiers
        )

    def test_access_control(self):
        template = self._symmetric_template(
            name="access-control",
            algorithm=enums.CryptographicAlgorithm.AES,
            length=128,
            masks=[
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ]
        )
        create_payload = payloads.CreateRequestPayload(
            enums.ObjectType.SYMMETRIC_KEY,
            template
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.CREATE, create_payload)],
            credential=["user-a", None]
        )
        create_response = self._assert_success(response)
        key_id = create_response.unique_identifier

        get_payload = payloads.GetRequestPayload(unique_identifier=key_id)
        response = self._send_request(
            [self._batch_item(enums.Operation.GET, get_payload)],
            credential=["user-b", None]
        )
        self._assert_error(response, enums.ResultReason.PERMISSION_DENIED)

    def test_derive_key_workflow(self):
        base_template = self._symmetric_template(
            name="derive-base",
            algorithm=enums.CryptographicAlgorithm.AES,
            length=256,
            masks=[enums.CryptographicUsageMask.DERIVE_KEY]
        )
        create_payload = payloads.CreateRequestPayload(
            enums.ObjectType.SYMMETRIC_KEY,
            base_template
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.CREATE, create_payload)]
        )
        create_response = self._assert_success(response)
        base_id = create_response.unique_identifier

        derived_template = self._symmetric_template(
            name="derive-result",
            algorithm=enums.CryptographicAlgorithm.AES,
            length=256,
            masks=[
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ]
        )
        derive_payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[base_id],
            derivation_method=enums.DerivationMethod.PBKDF2,
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                salt=b"kmip-salt",
                iteration_count=1000
            ),
            template_attribute=derived_template
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.DERIVE_KEY, derive_payload)]
        )
        derive_response = self._assert_success(response)
        derived_id = derive_response.unique_identifier

        activate_payload = payloads.ActivateRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(derived_id)
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.ACTIVATE, activate_payload)]
        )
        self._assert_success(response)

        data = b"derived data"
        crypto_params = self._aes_cbc_parameters()
        encrypt_payload = payloads.EncryptRequestPayload(
            unique_identifier=derived_id,
            cryptographic_parameters=crypto_params,
            data=data,
            iv_counter_nonce=None
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.ENCRYPT, encrypt_payload)]
        )
        encrypt_response = self._assert_success(response)

        decrypt_payload = payloads.DecryptRequestPayload(
            unique_identifier=derived_id,
            cryptographic_parameters=crypto_params,
            data=encrypt_response.data,
            iv_counter_nonce=encrypt_response.iv_counter_nonce
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.DECRYPT, decrypt_payload)]
        )
        decrypt_response = self._assert_success(response)
        self.assertEqual(data, decrypt_response.data)

    def test_certificate_handling(self):
        cert_bytes = b"dummy-x509-cert"
        cert = self.secret_factory.create(
            enums.ObjectType.CERTIFICATE,
            {
                "certificate_type": enums.CertificateType.X_509,
                "certificate_value": cert_bytes
            }
        )
        template = core_objects.TemplateAttribute(
            attributes=[
                self._name_attribute("certificate"),
                self.attr_factory.create_attribute(
                    enums.AttributeType.OPERATION_POLICY_NAME,
                    "default"
                )
            ]
        )
        register_payload = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.CERTIFICATE,
            template_attribute=template,
            managed_object=cert
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.REGISTER, register_payload)]
        )
        register_response = self._assert_success(response)
        cert_id = register_response.unique_identifier

        get_payload = payloads.GetRequestPayload(unique_identifier=cert_id)
        response = self._send_request(
            [self._batch_item(enums.Operation.GET, get_payload)]
        )
        get_response = self._assert_success(response)
        self.assertEqual(enums.ObjectType.CERTIFICATE, get_response.object_type)
        self.assertEqual(
            enums.CertificateType.X_509,
            get_response.secret.certificate_type.value
        )
        self.assertEqual(
            cert_bytes,
            get_response.secret.certificate_value.value
        )

    def test_batch_processing(self):
        template = self._symmetric_template(
            name="batch-key",
            algorithm=enums.CryptographicAlgorithm.AES,
            length=128,
            masks=[
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ]
        )
        create_payload = payloads.CreateRequestPayload(
            enums.ObjectType.SYMMETRIC_KEY,
            template
        )
        activate_payload = payloads.ActivateRequestPayload()
        get_payload = payloads.GetRequestPayload()
        response = self._send_request(
            [
                self._batch_item(enums.Operation.CREATE, create_payload),
                self._batch_item(enums.Operation.ACTIVATE, activate_payload),
                self._batch_item(enums.Operation.GET, get_payload)
            ]
        )
        create_response = self._assert_success(response, index=0)
        self._assert_success(response, index=1)
        get_response = self._assert_success(response, index=2)
        self.assertEqual(
            create_response.unique_identifier,
            get_response.unique_identifier
        )

    def test_discover_versions(self):
        payload = payloads.DiscoverVersionsRequestPayload(
            protocol_versions=[]
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.DISCOVER_VERSIONS, payload)]
        )
        discover_response = self._assert_success(response)
        versions = [
            (version.major, version.minor)
            for version in discover_response.protocol_versions
        ]
        self.assertIn((1, 2), versions)

    def test_error_recovery(self):
        invalid_template = self._symmetric_template(
            name="invalid-key",
            algorithm=enums.CryptographicAlgorithm.AES,
            length=128,
            masks=None
        )
        invalid_payload = payloads.CreateRequestPayload(
            enums.ObjectType.SYMMETRIC_KEY,
            invalid_template
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.CREATE, invalid_payload)]
        )
        self._assert_error(response, enums.ResultReason.INVALID_FIELD)

        valid_template = self._symmetric_template(
            name="valid-key",
            algorithm=enums.CryptographicAlgorithm.AES,
            length=128,
            masks=[
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ]
        )
        valid_payload = payloads.CreateRequestPayload(
            enums.ObjectType.SYMMETRIC_KEY,
            valid_template
        )
        response = self._send_request(
            [self._batch_item(enums.Operation.CREATE, valid_payload)]
        )
        self._assert_success(response)
