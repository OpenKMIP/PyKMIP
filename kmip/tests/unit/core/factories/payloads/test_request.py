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

import testtools

from kmip.core import enums
from kmip.core.factories.payloads.request import RequestPayloadFactory

from kmip.core.messages import payloads

class TestRequestPayloadFactory(testtools.TestCase):

    def setUp(self):
        super(TestRequestPayloadFactory, self).setUp()
        self.factory = RequestPayloadFactory()

    def tearDown(self):
        super(TestRequestPayloadFactory, self).tearDown()

    def _test_not_implemented(self, func, args):
        self.assertRaises(NotImplementedError, func, args)

    def _test_payload_type(self, payload, payload_type):
        msg = "expected {0}, received {1}".format(payload_type, payload)
        self.assertIsInstance(payload, payload_type, msg)

    def test_create_create_payload(self):
        payload = self.factory.create(enums.Operation.CREATE)
        self._test_payload_type(payload, payloads.CreateRequestPayload)

    def test_create_create_key_pair_payload(self):
        payload = self.factory.create(enums.Operation.CREATE_KEY_PAIR)
        self._test_payload_type(
            payload,
            payloads.CreateKeyPairRequestPayload
        )

    def test_create_register_payload(self):
        payload = self.factory.create(enums.Operation.REGISTER)
        self._test_payload_type(payload, payloads.RegisterRequestPayload)

    def test_create_rekey_payload(self):
        payload = self.factory.create(enums.Operation.REKEY)
        self._test_payload_type(payload, payloads.RekeyRequestPayload)

    def test_create_derive_key_payload(self):
        payload = self.factory.create(enums.Operation.DERIVE_KEY)
        self._test_payload_type(payload, payloads.DeriveKeyRequestPayload)

    def test_create_certify_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.CERTIFY
        )

    def test_create_recertify_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.RECERTIFY
        )

    def test_create_locate_payload(self):
        payload = self.factory.create(enums.Operation.LOCATE)
        self._test_payload_type(payload, payloads.LocateRequestPayload)

    def test_create_check_payload(self):
        payload = self.factory.create(enums.Operation.CHECK)
        self._test_payload_type(payload, payloads.CheckRequestPayload)

    def test_create_get_payload(self):
        payload = self.factory.create(enums.Operation.GET)
        self._test_payload_type(payload, payloads.GetRequestPayload)

    def test_create_get_attributes_payload(self):
        payload = self.factory.create(enums.Operation.GET_ATTRIBUTES)
        self._test_payload_type(
            payload,
            payloads.GetAttributesRequestPayload
        )

    def test_create_get_attributes_list_payload(self):
        payload = self.factory.create(enums.Operation.GET_ATTRIBUTE_LIST)
        self._test_payload_type(
            payload,
            payloads.GetAttributeListRequestPayload
        )

    def test_create_add_attribute_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.ADD_ATTRIBUTE
        )

    def test_create_modify_attribute_payload(self):
        payload = self.factory.create(enums.Operation.MODIFY_ATTRIBUTE)
        self.assertIsInstance(payload, payloads.ModifyAttributeRequestPayload)

    def test_create_delete_attribute_payload(self):
        payload = self.factory.create(enums.Operation.DELETE_ATTRIBUTE)
        self.assertIsInstance(payload, payloads.DeleteAttributeRequestPayload)

    def test_create_set_attribute_payload(self):
        payload = self.factory.create(enums.Operation.SET_ATTRIBUTE)
        self.assertIsInstance(payload, payloads.SetAttributeRequestPayload)

    def test_create_obtain_lease_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.OBTAIN_LEASE
        )

    def test_create_get_usage_allocation_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.GET_USAGE_ALLOCATION
        )

    def test_create_activate_payload(self):
        payload = self.factory.create(enums.Operation.ACTIVATE)
        self._test_payload_type(payload, payloads.ActivateRequestPayload)

    def test_create_revoke_payload(self):
        payload = self.factory.create(enums.Operation.REVOKE)
        self._test_payload_type(payload, payloads.RevokeRequestPayload)

    def test_create_destroy_payload(self):
        payload = self.factory.create(enums.Operation.DESTROY)
        self._test_payload_type(payload, payloads.DestroyRequestPayload)

    def test_create_archive_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.ARCHIVE
        )

    def test_create_recover_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.RECOVER
        )

    def test_create_validate_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.VALIDATE
        )

    def test_create_query_payload(self):
        payload = self.factory.create(enums.Operation.QUERY)
        self._test_payload_type(payload, payloads.QueryRequestPayload)

    def test_create_cancel_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.CANCEL
        )

    def test_create_poll_payload(self):
        self._test_not_implemented(self.factory.create, enums.Operation.POLL)

    def test_create_notify_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.NOTIFY
        )

    def test_create_put_payload(self):
        self._test_not_implemented(self.factory.create, enums.Operation.PUT)

    def test_create_rekey_key_pair_payload(self):
        payload = self.factory.create(enums.Operation.REKEY_KEY_PAIR)
        self._test_payload_type(
            payload,
            payloads.RekeyKeyPairRequestPayload
        )

    def test_create_discover_versions_payload(self):
        payload = self.factory.create(enums.Operation.DISCOVER_VERSIONS)
        self._test_payload_type(
            payload,
            payloads.DiscoverVersionsRequestPayload
        )

    def test_create_encrypt_payload(self):
        payload = self.factory.create(enums.Operation.ENCRYPT)
        self._test_payload_type(payload, payloads.EncryptRequestPayload)

    def test_create_decrypt_payload(self):
        payload = self.factory.create(enums.Operation.DECRYPT)
        self._test_payload_type(payload, payloads.DecryptRequestPayload)

    def test_create_sign_payload(self):
        payload = self.factory.create(enums.Operation.SIGN)
        self._test_payload_type(payload, payloads.SignRequestPayload)

    def test_create_signature_verify_payload(self):
        payload = self.factory.create(enums.Operation.SIGNATURE_VERIFY)
        self._test_payload_type(
            payload,
            payloads.SignatureVerifyRequestPayload
        )

    def test_create_mac_payload(self):
        payload = self.factory.create(enums.Operation.MAC)
        self._test_payload_type(payload, payloads.MACRequestPayload)

    def test_create_mac_verify_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.MAC_VERIFY
        )

    def test_create_rng_retrieve_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.RNG_RETRIEVE
        )

    def test_create_rng_seed_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.RNG_SEED
        )

    def test_create_hash_payload(self):
        self._test_not_implemented(self.factory.create, enums.Operation.HASH)

    def test_create_create_split_key_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.CREATE_SPLIT_KEY
        )

    def test_create_join_split_key_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.JOIN_SPLIT_KEY
        )
