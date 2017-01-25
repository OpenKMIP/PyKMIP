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

from kmip.core.factories.payloads import PayloadFactory

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


class RequestPayloadFactory(PayloadFactory):

    def _create_create_payload(self):
        return create.CreateRequestPayload()

    def _create_create_key_pair_payload(self):
        return create_key_pair.CreateKeyPairRequestPayload()

    def _create_register_payload(self):
        return register.RegisterRequestPayload()

    def _create_rekey_key_pair_payload(self):
        return rekey_key_pair.RekeyKeyPairRequestPayload()

    def _create_locate_payload(self):
        return locate.LocateRequestPayload()

    def _create_get_payload(self):
        return get.GetRequestPayload()

    def _create_get_attribute_list_payload(self):
        return get_attribute_list.GetAttributeListRequestPayload()

    def _create_get_attributes_payload(self):
        return get_attributes.GetAttributesRequestPayload()

    def _create_destroy_payload(self):
        return destroy.DestroyRequestPayload()

    def _create_query_payload(self):
        return query.QueryRequestPayload()

    def _create_discover_versions_payload(self):
        return discover_versions.DiscoverVersionsRequestPayload()

    def _create_activate_payload(self):
        return activate.ActivateRequestPayload()

    def _create_revoke_payload(self):
        return revoke.RevokeRequestPayload()

    def _create_mac_payload(self):
        return mac.MACRequestPayload()
