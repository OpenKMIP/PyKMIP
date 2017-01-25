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

from kmip.core.messages.payloads import activate
from kmip.core.messages.payloads import create
from kmip.core.messages.payloads import create_key_pair
from kmip.core.messages.payloads import destroy
from kmip.core.messages.payloads import discover_versions
from kmip.core.messages.payloads import get
from kmip.core.messages.payloads import get_attribute_list
from kmip.core.messages.payloads import get_attributes
from kmip.core.messages.payloads import locate
from kmip.core.messages.payloads import query
from kmip.core.messages.payloads import rekey_key_pair
from kmip.core.messages.payloads import register
from kmip.core.messages.payloads import revoke
from kmip.core.messages.payloads import mac


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
        self._test_payload_type(payload, create.CreateRequestPayload)

    def test_create_create_key_pair_payload(self):
        payload = self.factory.create(enums.Operation.CREATE_KEY_PAIR)
        self._test_payload_type(
            payload,
            create_key_pair.CreateKeyPairRequestPayload
        )

    def test_create_register_payload(self):
        payload = self.factory.create(enums.Operation.REGISTER)
        self._test_payload_type(payload, register.RegisterRequestPayload)

    def test_create_rekey_payload(self):
        self._test_not_implemented(self.factory.create, enums.Operation.REKEY)

    def test_create_derive_key_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.DERIVE_KEY
        )

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
        self._test_payload_type(payload, locate.LocateRequestPayload)

    def test_create_check_payload(self):
        self._test_not_implemented(self.factory.create, enums.Operation.CHECK)

    def test_create_get_payload(self):
        payload = self.factory.create(enums.Operation.GET)
        self._test_payload_type(payload, get.GetRequestPayload)

    def test_create_get_attributes_payload(self):
        payload = self.factory.create(enums.Operation.GET_ATTRIBUTES)
        self._test_payload_type(
            payload,
            get_attributes.GetAttributesRequestPayload
        )

    def test_create_get_attributes_list_payload(self):
        payload = self.factory.create(enums.Operation.GET_ATTRIBUTE_LIST)
        self._test_payload_type(
            payload,
            get_attribute_list.GetAttributeListRequestPayload
        )

    def test_create_add_attribute_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.ADD_ATTRIBUTE
        )

    def test_create_modify_attribute_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.MODIFY_ATTRIBUTE
        )

    def test_create_delete_attribute_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.DELETE_ATTRIBUTE
        )

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
        self._test_payload_type(payload, activate.ActivateRequestPayload)

    def test_create_revoke_payload(self):
        payload = self.factory.create(enums.Operation.REVOKE)
        self._test_payload_type(payload, revoke.RevokeRequestPayload)

    def test_create_destroy_payload(self):
        payload = self.factory.create(enums.Operation.DESTROY)
        self._test_payload_type(payload, destroy.DestroyRequestPayload)

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
        self._test_payload_type(payload, query.QueryRequestPayload)

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
            rekey_key_pair.RekeyKeyPairRequestPayload
        )

    def test_create_discover_versions_payload(self):
        payload = self.factory.create(enums.Operation.DISCOVER_VERSIONS)
        self._test_payload_type(
            payload,
            discover_versions.DiscoverVersionsRequestPayload
        )

    def test_create_encrypt_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.ENCRYPT
        )

    def test_create_decrypt_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.DECRYPT
        )

    def test_create_sign_payload(self):
        self._test_not_implemented(self.factory.create, enums.Operation.SIGN)

    def test_create_signature_verify_payload(self):
        self._test_not_implemented(
            self.factory.create,
            enums.Operation.SIGNATURE_VERIFY
        )

    def test_create_mac_payload(self):
        payload = self.factory.create(enums.Operation.MAC)
        self._test_payload_type(payload, mac.MACRequestPayload)

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
