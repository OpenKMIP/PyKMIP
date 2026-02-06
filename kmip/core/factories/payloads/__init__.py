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

from kmip.core import enums

class PayloadFactory():

    def create(self, operation):
        # Switch on operation enum
        if operation is enums.Operation.CREATE:
            return self._create_create_payload()
        elif operation is enums.Operation.CREATE_KEY_PAIR:
            return self._create_create_key_pair_payload()
        elif operation is enums.Operation.REGISTER:
            return self._create_register_payload()
        elif operation is enums.Operation.REKEY:
            return self._create_rekey_payload()
        elif operation is enums.Operation.DERIVE_KEY:
            return self._create_derive_key_payload()
        elif operation is enums.Operation.CERTIFY:
            return self._create_certify_payload()
        elif operation is enums.Operation.RECERTIFY:
            return self._create_recertify_payload()
        elif operation is enums.Operation.LOCATE:
            return self._create_locate_payload()
        elif operation is enums.Operation.CHECK:
            return self._create_check_payload()
        elif operation is enums.Operation.GET:
            return self._create_get_payload()
        elif operation is enums.Operation.GET_ATTRIBUTES:
            return self._create_get_attributes_payload()
        elif operation is enums.Operation.GET_ATTRIBUTE_LIST:
            return self._create_get_attribute_list_payload()
        elif operation is enums.Operation.ADD_ATTRIBUTE:
            return self._create_add_attribute_payload()
        elif operation is enums.Operation.SET_ATTRIBUTE:
            return self._create_set_attribute_payload()
        elif operation is enums.Operation.MODIFY_ATTRIBUTE:
            return self._create_modify_attribute_payload()
        elif operation is enums.Operation.DELETE_ATTRIBUTE:
            return self._create_delete_attribute_payload()
        elif operation is enums.Operation.OBTAIN_LEASE:
            return self._create_obtain_lease_payload()
        elif operation is enums.Operation.GET_USAGE_ALLOCATION:
            return self._create_get_usage_allocation_payload()
        elif operation is enums.Operation.ACTIVATE:
            return self._create_activate_payload()
        elif operation is enums.Operation.REVOKE:
            return self._create_revoke_payload()
        elif operation is enums.Operation.DESTROY:
            return self._create_destroy_payload()
        elif operation is enums.Operation.ARCHIVE:
            return self._create_archive_payload()
        elif operation is enums.Operation.RECOVER:
            return self._create_recover_payload()
        elif operation is enums.Operation.VALIDATE:
            return self._create_validate_payload()
        elif operation is enums.Operation.QUERY:
            return self._create_query_payload()
        elif operation is enums.Operation.CANCEL:
            return self._create_cancel_payload()
        elif operation is enums.Operation.POLL:
            return self._create_poll_payload()
        elif operation is enums.Operation.NOTIFY:
            return self._create_notify_payload()
        elif operation is enums.Operation.PUT:
            return self._create_put_payload()
        elif operation is enums.Operation.REKEY_KEY_PAIR:
            return self._create_rekey_key_pair_payload()
        elif operation is enums.Operation.DISCOVER_VERSIONS:
            return self._create_discover_versions_payload()
        elif operation is enums.Operation.ENCRYPT:
            return self._create_encrypt_payload()
        elif operation is enums.Operation.DECRYPT:
            return self._create_decrypt_payload()
        elif operation is enums.Operation.SIGN:
            return self._create_sign_payload()
        elif operation is enums.Operation.SIGNATURE_VERIFY:
            return self._create_signature_verify_payload()
        elif operation is enums.Operation.MAC:
            return self._create_mac_payload()
        elif operation is enums.Operation.MAC_VERIFY:
            return self._create_mac_verify_payload()
        elif operation is enums.Operation.RNG_RETRIEVE:
            return self._create_rng_retrieve_payload()
        elif operation is enums.Operation.RNG_SEED:
            return self._create_rng_seed_payload()
        elif operation is enums.Operation.HASH:
            return self._create_hash_payload()
        elif operation is enums.Operation.CREATE_SPLIT_KEY:
            return self._create_create_split_key_payload()
        elif operation is enums.Operation.JOIN_SPLIT_KEY:
            return self._create_join_split_key_payload()
        else:
            raise ValueError('unsupported operation: {0}'.format(operation))

    def _create_create_payload(self):
        raise NotImplementedError()

    def _create_create_key_pair_payload(self):
        raise NotImplementedError()

    def _create_register_payload(self):
        raise NotImplementedError()

    def _create_rekey_payload(self):
        raise NotImplementedError()

    def _create_derive_key_payload(self):
        raise NotImplementedError()

    def _create_certify_payload(self):
        raise NotImplementedError()

    def _create_recertify_payload(self):
        raise NotImplementedError()

    def _create_locate_payload(self):
        raise NotImplementedError()

    def _create_check_payload(self):
        raise NotImplementedError()

    def _create_get_payload(self):
        raise NotImplementedError()

    def _create_get_attributes_payload(self):
        raise NotImplementedError()

    def _create_get_attribute_list_payload(self):
        raise NotImplementedError()

    def _create_add_attribute_payload(self):
        raise NotImplementedError()

    def _create_set_attribute_payload(self):
        raise NotImplementedError()

    def _create_modify_attribute_payload(self):
        raise NotImplementedError()

    def _create_delete_attribute_payload(self):
        raise NotImplementedError()

    def _create_obtain_lease_payload(self):
        raise NotImplementedError()

    def _create_get_usage_allocation_payload(self):
        raise NotImplementedError()

    def _create_activate_payload(self):
        raise NotImplementedError()

    def _create_revoke_payload(self):
        raise NotImplementedError()

    def _create_destroy_payload(self):
        raise NotImplementedError()

    def _create_archive_payload(self):
        raise NotImplementedError()

    def _create_recover_payload(self):
        raise NotImplementedError()

    def _create_validate_payload(self):
        raise NotImplementedError()

    def _create_query_payload(self):
        raise NotImplementedError()

    def _create_cancel_payload(self):
        raise NotImplementedError()

    def _create_poll_payload(self):
        raise NotImplementedError()

    def _create_notify_payload(self):
        raise NotImplementedError()

    def _create_put_payload(self):
        raise NotImplementedError()

    def _create_rekey_key_pair_payload(self):
        raise NotImplementedError()

    def _create_discover_versions_payload(self):
        raise NotImplementedError()

    def _create_encrypt_payload(self):
        raise NotImplementedError()

    def _create_decrypt_payload(self):
        raise NotImplementedError()

    def _create_sign_payload(self):
        raise NotImplementedError()

    def _create_signature_verify_payload(self):
        raise NotImplementedError()

    def _create_mac_payload(self):
        raise NotImplementedError()

    def _create_mac_verify_payload(self):
        raise NotImplementedError()

    def _create_rng_retrieve_payload(self):
        raise NotImplementedError()

    def _create_rng_seed_payload(self):
        raise NotImplementedError()

    def _create_hash_payload(self):
        raise NotImplementedError()

    def _create_create_split_key_payload(self):
        raise NotImplementedError()

    def _create_join_split_key_payload(self):
        raise NotImplementedError()
