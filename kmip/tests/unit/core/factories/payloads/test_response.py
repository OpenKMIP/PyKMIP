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

from kmip.core.enums import Operation
from kmip.core.factories.payloads.response import ResponsePayloadFactory

from kmip.core.messages.payloads import activate
from kmip.core.messages.payloads import add_attribute
from kmip.core.messages.payloads import create
from kmip.core.messages.payloads import create_key_pair
from kmip.core.messages.payloads import destroy
from kmip.core.messages.payloads import discover_versions
from kmip.core.messages.payloads import get
from kmip.core.messages.payloads import get_attribute_list
from kmip.core.messages.payloads import locate
from kmip.core.messages.payloads import query
from kmip.core.messages.payloads import rekey_key_pair
from kmip.core.messages.payloads import register
from kmip.core.messages.payloads import revoke


class TestResponsePayloadFactory(testtools.TestCase):

    def setUp(self):
        super(TestResponsePayloadFactory, self).setUp()
        self.factory = ResponsePayloadFactory()

    def tearDown(self):
        super(TestResponsePayloadFactory, self).tearDown()

    def _test_not_implemented(self, func, args):
        self.assertRaises(NotImplementedError, func, args)

    def _test_payload_type(self, payload, payload_type):
        msg = "expected {0}, received {1}".format(payload_type, payload)
        self.assertIsInstance(payload, payload_type, msg)

    def test_create_create_payload(self):
        payload = self.factory.create(Operation.CREATE)
        self._test_payload_type(payload, create.CreateResponsePayload)

    def test_create_create_key_pair_payload(self):
        payload = self.factory.create(Operation.CREATE_KEY_PAIR)
        self._test_payload_type(
            payload, create_key_pair.CreateKeyPairResponsePayload)

    def test_create_register_payload(self):
        payload = self.factory.create(Operation.REGISTER)
        self._test_payload_type(payload, register.RegisterResponsePayload)

    def test_create_rekey_payload(self):
        self._test_not_implemented(
            self.factory.create, Operation.REKEY)

    def test_create_derive_key_payload(self):
        self._test_not_implemented(
            self.factory.create, Operation.DERIVE_KEY)

    def test_create_certify_payload(self):
        self._test_not_implemented(
            self.factory.create, Operation.CERTIFY)

    def test_create_recertify_payload(self):
        self._test_not_implemented(
            self.factory.create, Operation.RECERTIFY)

    def test_create_locate_payload(self):
        payload = self.factory.create(Operation.LOCATE)
        self._test_payload_type(payload, locate.LocateResponsePayload)

    def test_create_check_payload(self):
        self._test_not_implemented(
            self.factory.create, Operation.CHECK)

    def test_create_get_payload(self):
        payload = self.factory.create(Operation.GET)
        self._test_payload_type(payload, get.GetResponsePayload)

    def test_create_get_attributes_payload(self):
        self._test_not_implemented(
            self.factory.create, Operation.GET_ATTRIBUTES)

    def test_create_get_attributes_list_payload(self):
        payload = self.factory.create(Operation.GET_ATTRIBUTE_LIST)
        self._test_payload_type(
            payload, get_attribute_list.GetAttributeListResponsePayload)

    def test_create_add_attribute_payload(self):
        payload = self.factory.create(Operation.ADD_ATTRIBUTE)
        self._test_payload_type(
            payload, add_attribute.AddAttributeResponsePayload)

    def test_create_modify_attribute_payload(self):
        self._test_not_implemented(
            self.factory.create, Operation.MODIFY_ATTRIBUTE)

    def test_create_delete_attribute_payload(self):
        self._test_not_implemented(
            self.factory.create, Operation.DELETE_ATTRIBUTE)

    def test_create_obtain_lease_payload(self):
        self._test_not_implemented(
            self.factory.create, Operation.OBTAIN_LEASE)

    def test_create_get_usage_allocation_payload(self):
        self._test_not_implemented(
            self.factory.create, Operation.GET_USAGE_ALLOCATION)

    def test_create_activate_payload(self):
        payload = self.factory.create(Operation.ACTIVATE)
        self._test_payload_type(payload, activate.ActivateResponsePayload)

    def test_create_revoke_payload(self):
        payload = self.factory.create(Operation.REVOKE)
        self._test_payload_type(payload, revoke.RevokeResponsePayload)

    def test_create_destroy_payload(self):
        payload = self.factory.create(Operation.DESTROY)
        self._test_payload_type(payload, destroy.DestroyResponsePayload)

    def test_create_archive_payload(self):
        self._test_not_implemented(
            self.factory.create, Operation.ARCHIVE)

    def test_create_recover_payload(self):
        self._test_not_implemented(
            self.factory.create, Operation.RECOVER)

    def test_create_validate_payload(self):
        self._test_not_implemented(
            self.factory.create, Operation.VALIDATE)

    def test_create_query_payload(self):
        payload = self.factory.create(Operation.QUERY)
        self._test_payload_type(payload, query.QueryResponsePayload)

    def test_create_cancel_payload(self):
        self._test_not_implemented(
            self.factory.create, Operation.CANCEL)

    def test_create_poll_payload(self):
        self._test_not_implemented(
            self.factory.create, Operation.POLL)

    def test_create_notify_payload(self):
        self._test_not_implemented(
            self.factory.create, Operation.NOTIFY)

    def test_create_put_payload(self):
        self._test_not_implemented(
            self.factory.create, Operation.PUT)

    def test_create_rekey_key_pair_payload(self):
        payload = self.factory.create(Operation.REKEY_KEY_PAIR)
        self._test_payload_type(
            payload, rekey_key_pair.RekeyKeyPairResponsePayload)

    def test_create_discover_versions_payload(self):
        payload = self.factory.create(Operation.DISCOVER_VERSIONS)
        self._test_payload_type(
            payload, discover_versions.DiscoverVersionsResponsePayload)
