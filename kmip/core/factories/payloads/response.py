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
from kmip.core.messages import payloads

class ResponsePayloadFactory(PayloadFactory):

    # TODO (peterhamilton) Alphabetize these
    def _create_create_payload(self):
        return payloads.CreateResponsePayload()

    def _create_create_key_pair_payload(self):
        return payloads.CreateKeyPairResponsePayload()

    def _create_register_payload(self):
        return payloads.RegisterResponsePayload()

    def _create_derive_key_payload(self):
        return payloads.DeriveKeyResponsePayload()

    def _create_rekey_payload(self):
        return payloads.RekeyResponsePayload()

    def _create_rekey_key_pair_payload(self):
        return payloads.RekeyKeyPairResponsePayload()

    def _create_locate_payload(self):
        return payloads.LocateResponsePayload()

    def _create_check_payload(self):
        return payloads.CheckResponsePayload()

    def _create_get_payload(self):
        return payloads.GetResponsePayload()

    def _create_get_attribute_list_payload(self):
        return payloads.GetAttributeListResponsePayload()

    def _create_get_attributes_payload(self):
        return payloads.GetAttributesResponsePayload()

    def _create_delete_attribute_payload(self):
        return payloads.DeleteAttributeResponsePayload()

    def _create_set_attribute_payload(self):
        return payloads.SetAttributeResponsePayload()

    def _create_modify_attribute_payload(self):
        return payloads.ModifyAttributeResponsePayload()

    def _create_destroy_payload(self):
        return payloads.DestroyResponsePayload()

    def _create_query_payload(self):
        return payloads.QueryResponsePayload()

    def _create_discover_versions_payload(self):
        return payloads.DiscoverVersionsResponsePayload()

    def _create_activate_payload(self):
        return payloads.ActivateResponsePayload()

    def _create_revoke_payload(self):
        return payloads.RevokeResponsePayload()

    def _create_mac_payload(self):
        return payloads.MACResponsePayload()

    def _create_encrypt_payload(self):
        return payloads.EncryptResponsePayload()

    def _create_decrypt_payload(self):
        return payloads.DecryptResponsePayload()

    def _create_sign_payload(self):
        return payloads.SignResponsePayload()

    def _create_signature_verify_payload(self):
        return payloads.SignatureVerifyResponsePayload()
