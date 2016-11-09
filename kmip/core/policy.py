# Copyright (c) 2016 The Johns Hopkins University/Applied Physics Laboratory
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

import json
import six

from kmip.core import enums


def read_policy_from_file(path):
    with open(path, 'r') as f:
        try:
            policy_blob = json.loads(f.read())
        except Exception as e:
            raise ValueError(
                "An error occurred while attempting to parse the JSON "
                "file. {0}".format(e)
            )

    policies = dict()

    for name, object_policies in six.iteritems(policy_blob):
        processed_object_policies = dict()

        for object_type, operation_policies in six.iteritems(object_policies):
            processed_operation_policies = dict()

            for operation, permission in six.iteritems(operation_policies):

                try:
                    enum_operation = enums.Operation[operation]
                except Exception:
                    raise ValueError(
                        "'{0}' is not a valid Operation value.".format(
                            operation
                        )
                    )
                try:
                    enum_policy = enums.Policy[permission]
                except Exception:
                    raise ValueError(
                        "'{0}' is not a valid Policy value.".format(
                            permission
                        )
                    )

                processed_operation_policies.update([
                    (enum_operation, enum_policy)
                ])

            try:
                enum_type = enums.ObjectType[object_type]
            except Exception:
                raise ValueError(
                    "'{0}' is not a valid ObjectType value.".format(
                        object_type
                    )
                )

            processed_object_policies.update([
                (enum_type, processed_operation_policies)
            ])

        policies.update([(name, processed_object_policies)])

    return policies


policies = {
    'default': {
        enums.ObjectType.CERTIFICATE: {
            enums.Operation.LOCATE:             enums.Policy.ALLOW_ALL,
            enums.Operation.CHECK:              enums.Policy.ALLOW_ALL,
            enums.Operation.GET:                enums.Policy.ALLOW_ALL,
            enums.Operation.GET_ATTRIBUTES:     enums.Policy.ALLOW_ALL,
            enums.Operation.GET_ATTRIBUTE_LIST: enums.Policy.ALLOW_ALL,
            enums.Operation.ADD_ATTRIBUTE:      enums.Policy.ALLOW_OWNER,
            enums.Operation.MODIFY_ATTRIBUTE:   enums.Policy.ALLOW_OWNER,
            enums.Operation.DELETE_ATTRIBUTE:   enums.Policy.ALLOW_OWNER,
            enums.Operation.OBTAIN_LEASE:       enums.Policy.ALLOW_ALL,
            enums.Operation.ACTIVATE:           enums.Policy.ALLOW_OWNER,
            enums.Operation.REVOKE:             enums.Policy.ALLOW_OWNER,
            enums.Operation.DESTROY:            enums.Policy.ALLOW_OWNER,
            enums.Operation.ARCHIVE:            enums.Policy.ALLOW_OWNER,
            enums.Operation.RECOVER:            enums.Policy.ALLOW_OWNER
        },
        enums.ObjectType.SYMMETRIC_KEY: {
            enums.Operation.REKEY:                enums.Policy.ALLOW_OWNER,
            enums.Operation.REKEY_KEY_PAIR:       enums.Policy.ALLOW_OWNER,
            enums.Operation.DERIVE_KEY:           enums.Policy.ALLOW_OWNER,
            enums.Operation.LOCATE:               enums.Policy.ALLOW_OWNER,
            enums.Operation.CHECK:                enums.Policy.ALLOW_OWNER,
            enums.Operation.GET:                  enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_ATTRIBUTES:       enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_ATTRIBUTE_LIST:   enums.Policy.ALLOW_OWNER,
            enums.Operation.ADD_ATTRIBUTE:        enums.Policy.ALLOW_OWNER,
            enums.Operation.MODIFY_ATTRIBUTE:     enums.Policy.ALLOW_OWNER,
            enums.Operation.DELETE_ATTRIBUTE:     enums.Policy.ALLOW_OWNER,
            enums.Operation.OBTAIN_LEASE:         enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_USAGE_ALLOCATION: enums.Policy.ALLOW_OWNER,
            enums.Operation.ACTIVATE:             enums.Policy.ALLOW_OWNER,
            enums.Operation.REVOKE:               enums.Policy.ALLOW_OWNER,
            enums.Operation.DESTROY:              enums.Policy.ALLOW_OWNER,
            enums.Operation.ARCHIVE:              enums.Policy.ALLOW_OWNER,
            enums.Operation.RECOVER:              enums.Policy.ALLOW_OWNER
        },
        enums.ObjectType.PUBLIC_KEY: {
            enums.Operation.LOCATE:             enums.Policy.ALLOW_ALL,
            enums.Operation.CHECK:              enums.Policy.ALLOW_ALL,
            enums.Operation.GET:                enums.Policy.ALLOW_ALL,
            enums.Operation.GET_ATTRIBUTES:     enums.Policy.ALLOW_ALL,
            enums.Operation.GET_ATTRIBUTE_LIST: enums.Policy.ALLOW_ALL,
            enums.Operation.ADD_ATTRIBUTE:      enums.Policy.ALLOW_OWNER,
            enums.Operation.MODIFY_ATTRIBUTE:   enums.Policy.ALLOW_OWNER,
            enums.Operation.DELETE_ATTRIBUTE:   enums.Policy.ALLOW_OWNER,
            enums.Operation.OBTAIN_LEASE:       enums.Policy.ALLOW_ALL,
            enums.Operation.ACTIVATE:           enums.Policy.ALLOW_OWNER,
            enums.Operation.REVOKE:             enums.Policy.ALLOW_OWNER,
            enums.Operation.DESTROY:            enums.Policy.ALLOW_OWNER,
            enums.Operation.ARCHIVE:            enums.Policy.ALLOW_OWNER,
            enums.Operation.RECOVER:            enums.Policy.ALLOW_OWNER
        },
        enums.ObjectType.PRIVATE_KEY: {
            enums.Operation.REKEY:                enums.Policy.ALLOW_OWNER,
            enums.Operation.REKEY_KEY_PAIR:       enums.Policy.ALLOW_OWNER,
            enums.Operation.DERIVE_KEY:           enums.Policy.ALLOW_OWNER,
            enums.Operation.LOCATE:               enums.Policy.ALLOW_OWNER,
            enums.Operation.CHECK:                enums.Policy.ALLOW_OWNER,
            enums.Operation.GET:                  enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_ATTRIBUTES:       enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_ATTRIBUTE_LIST:   enums.Policy.ALLOW_OWNER,
            enums.Operation.ADD_ATTRIBUTE:        enums.Policy.ALLOW_OWNER,
            enums.Operation.MODIFY_ATTRIBUTE:     enums.Policy.ALLOW_OWNER,
            enums.Operation.DELETE_ATTRIBUTE:     enums.Policy.ALLOW_OWNER,
            enums.Operation.OBTAIN_LEASE:         enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_USAGE_ALLOCATION: enums.Policy.ALLOW_OWNER,
            enums.Operation.ACTIVATE:             enums.Policy.ALLOW_OWNER,
            enums.Operation.REVOKE:               enums.Policy.ALLOW_OWNER,
            enums.Operation.DESTROY:              enums.Policy.ALLOW_OWNER,
            enums.Operation.ARCHIVE:              enums.Policy.ALLOW_OWNER,
            enums.Operation.RECOVER:              enums.Policy.ALLOW_OWNER
        },
        enums.ObjectType.SPLIT_KEY: {
            enums.Operation.REKEY:                enums.Policy.ALLOW_OWNER,
            enums.Operation.REKEY_KEY_PAIR:       enums.Policy.ALLOW_OWNER,
            enums.Operation.DERIVE_KEY:           enums.Policy.ALLOW_OWNER,
            enums.Operation.LOCATE:               enums.Policy.ALLOW_OWNER,
            enums.Operation.CHECK:                enums.Policy.ALLOW_OWNER,
            enums.Operation.GET:                  enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_ATTRIBUTES:       enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_ATTRIBUTE_LIST:   enums.Policy.ALLOW_OWNER,
            enums.Operation.ADD_ATTRIBUTE:        enums.Policy.ALLOW_OWNER,
            enums.Operation.MODIFY_ATTRIBUTE:     enums.Policy.ALLOW_OWNER,
            enums.Operation.DELETE_ATTRIBUTE:     enums.Policy.ALLOW_OWNER,
            enums.Operation.OBTAIN_LEASE:         enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_USAGE_ALLOCATION: enums.Policy.ALLOW_OWNER,
            enums.Operation.ACTIVATE:             enums.Policy.ALLOW_OWNER,
            enums.Operation.REVOKE:               enums.Policy.ALLOW_OWNER,
            enums.Operation.DESTROY:              enums.Policy.ALLOW_OWNER,
            enums.Operation.ARCHIVE:              enums.Policy.ALLOW_OWNER,
            enums.Operation.RECOVER:              enums.Policy.ALLOW_OWNER
        },
        enums.ObjectType.TEMPLATE: {
            enums.Operation.LOCATE:             enums.Policy.ALLOW_OWNER,
            enums.Operation.GET:                enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_ATTRIBUTES:     enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_ATTRIBUTE_LIST: enums.Policy.ALLOW_OWNER,
            enums.Operation.ADD_ATTRIBUTE:      enums.Policy.ALLOW_OWNER,
            enums.Operation.MODIFY_ATTRIBUTE:   enums.Policy.ALLOW_OWNER,
            enums.Operation.DELETE_ATTRIBUTE:   enums.Policy.ALLOW_OWNER,
            enums.Operation.DESTROY:            enums.Policy.ALLOW_OWNER
        },
        enums.ObjectType.SECRET_DATA: {
            enums.Operation.REKEY:                enums.Policy.ALLOW_OWNER,
            enums.Operation.REKEY_KEY_PAIR:       enums.Policy.ALLOW_OWNER,
            enums.Operation.DERIVE_KEY:           enums.Policy.ALLOW_OWNER,
            enums.Operation.LOCATE:               enums.Policy.ALLOW_OWNER,
            enums.Operation.CHECK:                enums.Policy.ALLOW_OWNER,
            enums.Operation.GET:                  enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_ATTRIBUTES:       enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_ATTRIBUTE_LIST:   enums.Policy.ALLOW_OWNER,
            enums.Operation.ADD_ATTRIBUTE:        enums.Policy.ALLOW_OWNER,
            enums.Operation.MODIFY_ATTRIBUTE:     enums.Policy.ALLOW_OWNER,
            enums.Operation.DELETE_ATTRIBUTE:     enums.Policy.ALLOW_OWNER,
            enums.Operation.OBTAIN_LEASE:         enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_USAGE_ALLOCATION: enums.Policy.ALLOW_OWNER,
            enums.Operation.ACTIVATE:             enums.Policy.ALLOW_OWNER,
            enums.Operation.REVOKE:               enums.Policy.ALLOW_OWNER,
            enums.Operation.DESTROY:              enums.Policy.ALLOW_OWNER,
            enums.Operation.ARCHIVE:              enums.Policy.ALLOW_OWNER,
            enums.Operation.RECOVER:              enums.Policy.ALLOW_OWNER
        },
        enums.ObjectType.OPAQUE_DATA: {
            enums.Operation.REKEY:                enums.Policy.ALLOW_OWNER,
            enums.Operation.REKEY_KEY_PAIR:       enums.Policy.ALLOW_OWNER,
            enums.Operation.DERIVE_KEY:           enums.Policy.ALLOW_OWNER,
            enums.Operation.LOCATE:               enums.Policy.ALLOW_OWNER,
            enums.Operation.CHECK:                enums.Policy.ALLOW_OWNER,
            enums.Operation.GET:                  enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_ATTRIBUTES:       enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_ATTRIBUTE_LIST:   enums.Policy.ALLOW_OWNER,
            enums.Operation.ADD_ATTRIBUTE:        enums.Policy.ALLOW_OWNER,
            enums.Operation.MODIFY_ATTRIBUTE:     enums.Policy.ALLOW_OWNER,
            enums.Operation.DELETE_ATTRIBUTE:     enums.Policy.ALLOW_OWNER,
            enums.Operation.OBTAIN_LEASE:         enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_USAGE_ALLOCATION: enums.Policy.ALLOW_OWNER,
            enums.Operation.ACTIVATE:             enums.Policy.ALLOW_OWNER,
            enums.Operation.REVOKE:               enums.Policy.ALLOW_OWNER,
            enums.Operation.DESTROY:              enums.Policy.ALLOW_OWNER,
            enums.Operation.ARCHIVE:              enums.Policy.ALLOW_OWNER,
            enums.Operation.RECOVER:              enums.Policy.ALLOW_OWNER
        },
        enums.ObjectType.PGP_KEY: {
            enums.Operation.REKEY:                enums.Policy.ALLOW_OWNER,
            enums.Operation.REKEY_KEY_PAIR:       enums.Policy.ALLOW_OWNER,
            enums.Operation.DERIVE_KEY:           enums.Policy.ALLOW_OWNER,
            enums.Operation.LOCATE:               enums.Policy.ALLOW_OWNER,
            enums.Operation.CHECK:                enums.Policy.ALLOW_OWNER,
            enums.Operation.GET:                  enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_ATTRIBUTES:       enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_ATTRIBUTE_LIST:   enums.Policy.ALLOW_OWNER,
            enums.Operation.ADD_ATTRIBUTE:        enums.Policy.ALLOW_OWNER,
            enums.Operation.MODIFY_ATTRIBUTE:     enums.Policy.ALLOW_OWNER,
            enums.Operation.DELETE_ATTRIBUTE:     enums.Policy.ALLOW_OWNER,
            enums.Operation.OBTAIN_LEASE:         enums.Policy.ALLOW_OWNER,
            enums.Operation.GET_USAGE_ALLOCATION: enums.Policy.ALLOW_OWNER,
            enums.Operation.ACTIVATE:             enums.Policy.ALLOW_OWNER,
            enums.Operation.REVOKE:               enums.Policy.ALLOW_OWNER,
            enums.Operation.DESTROY:              enums.Policy.ALLOW_OWNER,
            enums.Operation.ARCHIVE:              enums.Policy.ALLOW_OWNER,
            enums.Operation.RECOVER:              enums.Policy.ALLOW_OWNER
        }
    },
    'public': {
        enums.ObjectType.TEMPLATE: {
            enums.Operation.LOCATE:             enums.Policy.ALLOW_ALL,
            enums.Operation.GET:                enums.Policy.ALLOW_ALL,
            enums.Operation.GET_ATTRIBUTES:     enums.Policy.ALLOW_ALL,
            enums.Operation.GET_ATTRIBUTE_LIST: enums.Policy.ALLOW_ALL,
            enums.Operation.ADD_ATTRIBUTE:      enums.Policy.DISALLOW_ALL,
            enums.Operation.MODIFY_ATTRIBUTE:   enums.Policy.DISALLOW_ALL,
            enums.Operation.DELETE_ATTRIBUTE:   enums.Policy.DISALLOW_ALL,
            enums.Operation.DESTROY:            enums.Policy.DISALLOW_ALL
        }
    }
}
