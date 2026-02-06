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

from kmip.core import enums

def parse_policy(policy):
    result = {}

    for object_type, operation_policies in policy.items():
        processed_operation_policies = {}

        for operation, permission in operation_policies.items():
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

            processed_operation_policies[enum_operation] = enum_policy

        try:
            enum_type = enums.ObjectType[object_type]
        except Exception:
            raise ValueError(
                "'{0}' is not a valid ObjectType value.".format(
                    object_type
                )
            )

        result[enum_type] = processed_operation_policies

    return result

def read_policy_from_file(path):
    policy_blob = {}

    with open(path, 'r') as f:
        try:
            policy_blob = json.loads(f.read())
        except Exception as e:
            raise ValueError(
                "Loading the policy file '{}' generated a JSON error: "
                "{}".format(path, e)
            )

    policy_sections = {'groups', 'preset'}
    object_types = set([t.name for t in enums.ObjectType])
    result = {}

    for name, object_policy in policy_blob.items():
        if len(object_policy.keys()) == 0:
            continue

        # Use subset checking to determine what type of policy we have
        sections = set([s for s in object_policy.keys()])
        if sections <= policy_sections:
            parsed_policies = dict()

            default_policy = object_policy.get('preset')
            if default_policy:
                parsed_policies['preset'] = parse_policy(default_policy)

            group_policies = object_policy.get('groups')
            if group_policies:
                parsed_group_policies = dict()
                for group_name, group_policy in group_policies.items():
                    parsed_group_policies[group_name] = parse_policy(
                        group_policy
                    )
                parsed_policies['groups'] = parsed_group_policies

            result[name] = parsed_policies
        elif sections <= object_types:
            policy = parse_policy(object_policy)
            result[name] = {'preset': policy}
        else:
            invalid_sections = sections - policy_sections - object_types
            raise ValueError(
                "Policy '{}' contains an invalid section named: "
                "{}".format(name, invalid_sections.pop())
            )

    return result

policies = {
    'default': {
        'preset': {
            enums.ObjectType.CERTIFICATE: {
                enums.Operation.LOCATE:             enums.Policy.ALLOW_ALL,
                enums.Operation.CHECK:              enums.Policy.ALLOW_ALL,
                enums.Operation.GET:                enums.Policy.ALLOW_ALL,
                enums.Operation.GET_ATTRIBUTES:     enums.Policy.ALLOW_ALL,
                enums.Operation.GET_ATTRIBUTE_LIST: enums.Policy.ALLOW_ALL,
                enums.Operation.ADD_ATTRIBUTE:      enums.Policy.ALLOW_OWNER,
                enums.Operation.MODIFY_ATTRIBUTE:   enums.Policy.ALLOW_OWNER,
                enums.Operation.DELETE_ATTRIBUTE:   enums.Policy.ALLOW_OWNER,
                enums.Operation.SET_ATTRIBUTE:      enums.Policy.ALLOW_OWNER,
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
                enums.Operation.SET_ATTRIBUTE:        enums.Policy.ALLOW_OWNER,
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
                enums.Operation.SET_ATTRIBUTE:        enums.Policy.ALLOW_OWNER,
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
                enums.Operation.SET_ATTRIBUTE:        enums.Policy.ALLOW_OWNER,
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
                enums.Operation.SET_ATTRIBUTE:        enums.Policy.ALLOW_OWNER,
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
                enums.Operation.SET_ATTRIBUTE:      enums.Policy.ALLOW_OWNER,
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
                enums.Operation.SET_ATTRIBUTE:        enums.Policy.ALLOW_OWNER,
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
                enums.Operation.SET_ATTRIBUTE:        enums.Policy.ALLOW_OWNER,
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
                enums.Operation.SET_ATTRIBUTE:        enums.Policy.ALLOW_OWNER,
                enums.Operation.OBTAIN_LEASE:         enums.Policy.ALLOW_OWNER,
                enums.Operation.GET_USAGE_ALLOCATION: enums.Policy.ALLOW_OWNER,
                enums.Operation.ACTIVATE:             enums.Policy.ALLOW_OWNER,
                enums.Operation.REVOKE:               enums.Policy.ALLOW_OWNER,
                enums.Operation.DESTROY:              enums.Policy.ALLOW_OWNER,
                enums.Operation.ARCHIVE:              enums.Policy.ALLOW_OWNER,
                enums.Operation.RECOVER:              enums.Policy.ALLOW_OWNER
            }
        }
    },
    'public': {
        'preset': {
            enums.ObjectType.TEMPLATE: {
                enums.Operation.LOCATE:             enums.Policy.ALLOW_ALL,
                enums.Operation.GET:                enums.Policy.ALLOW_ALL,
                enums.Operation.GET_ATTRIBUTES:     enums.Policy.ALLOW_ALL,
                enums.Operation.GET_ATTRIBUTE_LIST: enums.Policy.ALLOW_ALL,
                enums.Operation.ADD_ATTRIBUTE:      enums.Policy.DISALLOW_ALL,
                enums.Operation.MODIFY_ATTRIBUTE:   enums.Policy.DISALLOW_ALL,
                enums.Operation.DELETE_ATTRIBUTE:   enums.Policy.DISALLOW_ALL,
                enums.Operation.SET_ATTRIBUTE:      enums.Policy.DISALLOW_ALL,
                enums.Operation.DESTROY:            enums.Policy.DISALLOW_ALL
            }
        }
    }
}
