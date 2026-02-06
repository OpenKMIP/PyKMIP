# Copyright (c) 2015 The Johns Hopkins University/Applied Physics Laboratory
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

import mock
import testtools

from kmip.core import attributes as attr
from kmip.core import enums
from kmip.core import objects as obj

from kmip.core.factories import attributes
from kmip.core.messages import contents
from kmip.core.messages import payloads
from kmip.core.messages.contents import Operation
from kmip.core.messages.contents import ResultMessage
from kmip.core.messages.contents import ResultReason
from kmip.core.messages.contents import ResultStatus
from kmip.core.messages.messages import ResponseBatchItem
from kmip.core.messages.messages import ResponseMessage

from kmip.services import results
from kmip.services.kmip_client import KMIPProxy

from kmip.pie import factory
from kmip.pie import objects
from kmip.pie.client import ProxyKmipClient
from kmip.pie.exceptions import ClientConnectionFailure
from kmip.pie.exceptions import ClientConnectionNotOpen
from kmip.pie.exceptions import KmipOperationFailure


class TestProxyKmipClientExtended(testtools.TestCase):
    def setUp(self):
        super(TestProxyKmipClientExtended, self).setUp()
        self.attribute_factory = attributes.AttributeFactory()
        self.object_factory = factory.ObjectFactory()
        self._kmip_proxy_patcher = mock.patch(
            'kmip.pie.client.KMIPProxy',
            mock.MagicMock(spec_set=KMIPProxy)
        )
        self.addCleanup(self._kmip_proxy_patcher.stop)
        self._kmip_proxy_class = self._kmip_proxy_patcher.start()
        self.proxy = mock.MagicMock(spec_set=KMIPProxy)
        self._kmip_proxy_class.return_value = self.proxy

    def _open_client(self):
        client = ProxyKmipClient()
        client.open()
        return client

    def _build_failure_result(self):
        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "Test failure message"
        result = results.OperationResult(
            contents.ResultStatus(status),
            contents.ResultReason(reason),
            contents.ResultMessage(message)
        )
        error_msg = str(KmipOperationFailure(status, reason, message))
        return result, error_msg

    def _build_failure_dict(self):
        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "Test failure message"
        result = {
            "result_status": status,
            "result_reason": reason,
            "result_message": message
        }
        error_msg = str(KmipOperationFailure(status, reason, message))
        return result, error_msg

    def _build_failure_exception(self):
        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "Test failure message"
        exc = KmipOperationFailure(status, reason, message)
        return exc, str(exc)

    def _build_core_attribute(self, name, value):
        return self.attribute_factory.create_attribute(name, value)

    def _build_symmetric_key(self, name="Symmetric Key", masks=None,
                             app_specific_info=None):
        return objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (b'\x00' * 16),
            masks=masks,
            name=name,
            app_specific_info=app_specific_info
        )

    def _assert_operation_success(self, op_name, variant):
        case = OPERATION_CASES[op_name]
        config = case[variant](self)
        client = self._open_client()
        proxy_method = case["proxy_method"]
        getattr(client.proxy, proxy_method).return_value = config["result"]
        result = getattr(client, op_name)(*config["args"], **config["kwargs"])
        self.assertEqual(config["expected"], result)

    def _assert_operation_invalid(self, op_name):
        case = OPERATION_CASES[op_name]
        config = case["invalid"](self)
        client = self._open_client()
        exc = config.get("exc", TypeError)
        self.assertRaises(
            exc,
            getattr(client, op_name),
            *config["args"],
            **config["kwargs"]
        )

    def _assert_operation_closed(self, op_name):
        case = OPERATION_CASES[op_name]
        config = case["minimal"](self)
        client = ProxyKmipClient()
        self.assertRaises(
            ClientConnectionNotOpen,
            getattr(client, op_name),
            *config["args"],
            **config["kwargs"]
        )

    def _assert_operation_failure(self, op_name):
        case = OPERATION_CASES[op_name]
        config = case["minimal"](self)
        client = self._open_client()
        if case["category"] == "payload_response":
            exc, error_msg = self._build_failure_exception()
            client.proxy.send_request_payload.side_effect = exc
            self.assertRaisesRegex(
                KmipOperationFailure,
                error_msg,
                getattr(client, op_name),
                *config["args"],
                **config["kwargs"]
            )
            return

        if case["category"] == "dict_result":
            result, error_msg = self._build_failure_dict()
        else:
            result, error_msg = self._build_failure_result()

        proxy_method = case["proxy_method"]
        getattr(client.proxy, proxy_method).return_value = result
        self.assertRaisesRegex(
            KmipOperationFailure,
            error_msg,
            getattr(client, op_name),
            *config["args"],
            **config["kwargs"]
        )

    def _assert_operation_none_response(self, op_name):
        case = OPERATION_CASES[op_name]
        config = case["minimal"](self)
        client = self._open_client()
        proxy_method = case["proxy_method"]
        getattr(client.proxy, proxy_method).return_value = None
        self.assertRaises(
            AttributeError,
            getattr(client, op_name),
            *config["args"],
            **config["kwargs"]
        )

    def test_open_already_open(self):
        client = ProxyKmipClient()
        client.open()
        self.assertRaises(ClientConnectionFailure, client.open)

    def test_close_already_closed(self):
        client = ProxyKmipClient()
        client.close()
        client.proxy.close.assert_not_called()

    def test_context_manager_exception_in_body(self):
        client = ProxyKmipClient()
        with self.assertRaises(ValueError):
            with client:
                raise ValueError("boom")
        self.assertFalse(client._is_open)
        client.proxy.close.assert_called_once_with()

    def test_context_manager_nested(self):
        with ProxyKmipClient() as outer:
            self.assertTrue(outer._is_open)
            with ProxyKmipClient() as inner:
                self.assertTrue(inner._is_open)
            self.assertFalse(inner._is_open)
            self.assertTrue(outer._is_open)
        self.assertFalse(outer._is_open)

    def test_locate_by_name(self):
        attribute = self._build_core_attribute("Name", "locate-name")
        result = results.LocateResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuids=["uid-name"]
        )
        client = self._open_client()
        client.proxy.locate.return_value = result
        uuids = client.locate(attributes=[attribute])
        self.assertEqual(["uid-name"], uuids)

    def test_locate_by_algorithm(self):
        attribute = self._build_core_attribute(
            "Cryptographic Algorithm",
            enums.CryptographicAlgorithm.AES
        )
        result = results.LocateResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuids=["uid-alg"]
        )
        client = self._open_client()
        client.proxy.locate.return_value = result
        uuids = client.locate(attributes=[attribute])
        self.assertEqual(["uid-alg"], uuids)

    def test_locate_by_state(self):
        attribute = self._build_core_attribute("State", enums.State.ACTIVE)
        result = results.LocateResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuids=["uid-state"]
        )
        client = self._open_client()
        client.proxy.locate.return_value = result
        uuids = client.locate(attributes=[attribute])
        self.assertEqual(["uid-state"], uuids)

    def test_locate_by_object_type(self):
        attribute = self._build_core_attribute(
            "Object Type",
            enums.ObjectType.SYMMETRIC_KEY
        )
        result = results.LocateResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuids=["uid-type"]
        )
        client = self._open_client()
        client.proxy.locate.return_value = result
        uuids = client.locate(attributes=[attribute])
        self.assertEqual(["uid-type"], uuids)

    def test_locate_with_offset_and_maximum_items(self):
        attributes_list = [
            self._build_core_attribute("Name", "locate-offset"),
            self._build_core_attribute(
                "Object Type",
                enums.ObjectType.SYMMETRIC_KEY
            )
        ]
        result = results.LocateResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuids=["uid-offset"]
        )
        client = self._open_client()
        client.proxy.locate.return_value = result
        uuids = client.locate(
            maximum_items=10,
            offset_items=5,
            storage_status_mask=1,
            object_group_member=enums.ObjectGroupMember.GROUP_MEMBER_FRESH,
            attributes=attributes_list
        )
        self.assertEqual(["uid-offset"], uuids)

    def test_locate_empty_results(self):
        result = results.LocateResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuids=[]
        )
        client = self._open_client()
        client.proxy.locate.return_value = result
        uuids = client.locate()
        self.assertEqual([], uuids)

    def test_locate_multiple_filters(self):
        attributes_list = [
            self._build_core_attribute("Name", "locate-multi"),
            self._build_core_attribute(
                "Object Type",
                enums.ObjectType.SYMMETRIC_KEY
            ),
            self._build_core_attribute(
                "Cryptographic Algorithm",
                enums.CryptographicAlgorithm.AES
            )
        ]
        result = results.LocateResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuids=["uid-multi"]
        )
        client = self._open_client()
        client.proxy.locate.return_value = result
        uuids = client.locate(attributes=attributes_list)
        self.assertEqual(["uid-multi"], uuids)

    def test_operations_with_kmip_1_0(self):
        client = self._open_client()
        client.kmip_version = enums.KMIPVersion.KMIP_1_0
        self.assertEqual(enums.KMIPVersion.KMIP_1_0, client.proxy.kmip_version)
        client.proxy.activate.return_value = results.ActivateResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS)
        )
        client.activate("uid")

    def test_operations_with_kmip_1_2(self):
        client = self._open_client()
        client.kmip_version = enums.KMIPVersion.KMIP_1_2
        self.assertEqual(enums.KMIPVersion.KMIP_1_2, client.proxy.kmip_version)
        client.proxy.activate.return_value = results.ActivateResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS)
        )
        client.activate("uid")

    def test_operations_with_kmip_2_0(self):
        client = self._open_client()
        client.kmip_version = enums.KMIPVersion.KMIP_2_0
        self.assertEqual(enums.KMIPVersion.KMIP_2_0, client.proxy.kmip_version)
        client.proxy.activate.return_value = results.ActivateResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS)
        )
        client.activate("uid")


class TestProxyKmipClientBatchOps(testtools.TestCase):
    def setUp(self):
        super(TestProxyKmipClientBatchOps, self).setUp()
        self.proxy = KMIPProxy()

    def test_batch_items_processing(self):
        batch_item = ResponseBatchItem(
            operation=Operation(enums.Operation.CREATE_KEY_PAIR),
            response_payload=payloads.CreateKeyPairResponsePayload()
        )
        response = ResponseMessage(batch_items=[batch_item, batch_item])
        results_list = self.proxy._process_batch_items(response)

        self.assertIsInstance(results_list, list)
        self.assertEqual(2, len(results_list))
        for result in results_list:
            self.assertIsInstance(result, results.CreateKeyPairResult)

    def test_batch_with_mixed_results(self):
        success_item = ResponseBatchItem(
            operation=Operation(enums.Operation.CREATE_KEY_PAIR),
            result_status=ResultStatus(enums.ResultStatus.SUCCESS),
            response_payload=payloads.CreateKeyPairResponsePayload()
        )
        failure_item = ResponseBatchItem(
            result_status=ResultStatus(enums.ResultStatus.OPERATION_FAILED),
            result_reason=ResultReason(enums.ResultReason.INVALID_MESSAGE),
            result_message=ResultMessage("failure")
        )
        response = ResponseMessage(batch_items=[success_item, failure_item])
        results_list = self.proxy._process_batch_items(response)

        self.assertEqual(2, len(results_list))
        self.assertIsInstance(results_list[0], results.CreateKeyPairResult)
        self.assertIsInstance(results_list[1], results.OperationResult)


def _register_full_case(self):
    managed_object = self._build_symmetric_key(
        name="sym-full",
        masks=[enums.CryptographicUsageMask.ENCRYPT],
        app_specific_info=[
            {
                "application_namespace": "ns",
                "application_data": "data"
            }
        ]
    )
    managed_object.operation_policy_name = "policy"
    managed_object.names.append("alias")
    return {
        "args": (managed_object,),
        "kwargs": {},
        "result": results.RegisterResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuid="uid-register-full"
        ),
        "expected": "uid-register-full"
    }


def _register_min_case(self):
    managed_object = self._build_symmetric_key()
    return {
        "args": (managed_object,),
        "kwargs": {},
        "result": results.RegisterResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuid="uid-register-min"
        ),
        "expected": "uid-register-min"
    }


def _get_full_case(self):
    pie_secret = self._build_symmetric_key(name="sym-get-full")
    core_secret = self.object_factory.convert(pie_secret)
    spec = {
        "wrapping_method": enums.WrappingMethod.ENCRYPT,
        "encryption_key_information": {
            "unique_identifier": "1",
            "cryptographic_parameters": {
                "cryptographic_algorithm": enums.CryptographicAlgorithm.AES
            }
        },
        "mac_signature_key_information": {
            "unique_identifier": "2",
            "cryptographic_parameters": {
                "padding_method": enums.PaddingMethod.PKCS5
            }
        },
        "attribute_names": [
            "Cryptographic Algorithm",
            "Cryptographic Length"
        ],
        "encoding_option": enums.EncodingOption.NO_ENCODING
    }
    return {
        "args": ("uid-get-full",),
        "kwargs": {"key_wrapping_specification": spec},
        "result": results.GetResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuid=attr.PublicKeyUniqueIdentifier("uid-get-full"),
            secret=core_secret
        ),
        "expected": pie_secret
    }


def _get_min_case(self):
    pie_secret = self._build_symmetric_key(name="sym-get-min")
    core_secret = self.object_factory.convert(pie_secret)
    return {
        "args": ("uid-get-min",),
        "kwargs": {},
        "result": results.GetResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuid=attr.PublicKeyUniqueIdentifier("uid-get-min"),
            secret=core_secret
        ),
        "expected": pie_secret
    }


def _get_attributes_full_case(self):
    attribute_names = ["Name", "Object Type"]
    attributes_list = [
        self._build_core_attribute("Name", "test"),
        self._build_core_attribute(
            "Object Type",
            enums.ObjectType.SYMMETRIC_KEY
        )
    ]
    return {
        "args": ("uid-attrs-full", attribute_names),
        "kwargs": {},
        "result": results.GetAttributesResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuid="uid-attrs-full",
            attributes=attributes_list
        ),
        "expected": ("uid-attrs-full", attributes_list)
    }


def _get_attributes_min_case(self):
    attributes_list = []
    return {
        "args": (),
        "kwargs": {},
        "result": results.GetAttributesResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuid="uid-attrs-min",
            attributes=attributes_list
        ),
        "expected": ("uid-attrs-min", attributes_list)
    }


def _get_attribute_list_full_case(self):
    names = ["Object Type", "Name"]
    return {
        "args": ("uid-attr-list-full",),
        "kwargs": {},
        "result": results.GetAttributeListResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uid="uid-attr-list-full",
            names=names
        ),
        "expected": sorted(names)
    }


def _get_attribute_list_min_case(self):
    names = ["b", "a"]
    return {
        "args": (),
        "kwargs": {},
        "result": results.GetAttributeListResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uid="uid-attr-list-min",
            names=names
        ),
        "expected": sorted(names)
    }


def _delete_attribute_full_case(self):
    attribute = self._build_core_attribute("State", enums.State.ACTIVE)
    current_attribute = obj.CurrentAttribute(attribute)
    attribute_reference = obj.AttributeReference("vendor", "State")
    return {
        "args": (),
        "kwargs": {
            "unique_identifier": "uid-del-full",
            "attribute_name": "State",
            "attribute_index": 0,
            "current_attribute": current_attribute,
            "attribute_reference": attribute_reference
        },
        "result": payloads.DeleteAttributeResponsePayload(
            unique_identifier="uid-del-full",
            attribute=attribute
        ),
        "expected": ("uid-del-full", attribute)
    }


def _delete_attribute_min_case(self):
    attribute = self._build_core_attribute("State", enums.State.ACTIVE)
    return {
        "args": (),
        "kwargs": {
            "unique_identifier": "uid-del-min",
            "attribute_name": "State"
        },
        "result": payloads.DeleteAttributeResponsePayload(
            unique_identifier="uid-del-min",
            attribute=attribute
        ),
        "expected": ("uid-del-min", attribute)
    }


def _modify_attribute_full_case(self):
    attribute = self._build_core_attribute("State", enums.State.ACTIVE)
    current_attribute = obj.CurrentAttribute(attribute)
    new_attribute = obj.NewAttribute(attribute=attribute)
    return {
        "args": (),
        "kwargs": {
            "unique_identifier": "uid-mod-full",
            "attribute": attribute,
            "current_attribute": current_attribute,
            "new_attribute": new_attribute
        },
        "result": payloads.ModifyAttributeResponsePayload(
            unique_identifier="uid-mod-full",
            attribute=attribute
        ),
        "expected": ("uid-mod-full", attribute)
    }


def _modify_attribute_min_case(self):
    attribute = self._build_core_attribute("State", enums.State.ACTIVE)
    return {
        "args": (),
        "kwargs": {
            "unique_identifier": "uid-mod-min",
            "attribute": attribute
        },
        "result": payloads.ModifyAttributeResponsePayload(
            unique_identifier="uid-mod-min",
            attribute=attribute
        ),
        "expected": ("uid-mod-min", attribute)
    }


def _set_attribute_full_case(self):
    return {
        "args": (),
        "kwargs": {
            "unique_identifier": "uid-set-full",
            "attribute_name": "Sensitive",
            "attribute_value": True
        },
        "result": payloads.SetAttributeResponsePayload(
            unique_identifier="uid-set-full"
        ),
        "expected": "uid-set-full"
    }


def _set_attribute_min_case(self):
    return {
        "args": (),
        "kwargs": {
            "unique_identifier": "uid-set-min",
            "attribute_name": "State",
            "attribute_value": enums.State.ACTIVE
        },
        "result": payloads.SetAttributeResponsePayload(
            unique_identifier="uid-set-min"
        ),
        "expected": "uid-set-min"
    }


def _locate_full_case(self):
    attributes_list = [
        self._build_core_attribute("Name", "locate-full"),
        self._build_core_attribute(
            "Object Type",
            enums.ObjectType.SYMMETRIC_KEY
        )
    ]
    return {
        "args": (),
        "kwargs": {
            "maximum_items": 10,
            "offset_items": 2,
            "storage_status_mask": 1,
            "object_group_member": enums.ObjectGroupMember.GROUP_MEMBER_FRESH,
            "attributes": attributes_list
        },
        "result": results.LocateResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuids=["uid-locate-full", "uid-locate-full-2"]
        ),
        "expected": ["uid-locate-full", "uid-locate-full-2"]
    }


def _locate_min_case(self):
    return {
        "args": (),
        "kwargs": {},
        "result": results.LocateResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuids=["uid-locate-min"]
        ),
        "expected": ["uid-locate-min"]
    }


OPERATION_CASES = {
    "create": {
        "proxy_method": "create",
        "category": "result_object",
        "full": lambda self: {
            "args": (enums.CryptographicAlgorithm.AES, 256),
            "kwargs": {
                "operation_policy_name": "policy",
                "name": "sym-full",
                "cryptographic_usage_mask": [
                    enums.CryptographicUsageMask.MAC_GENERATE
                ]
            },
            "result": results.CreateResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS),
                uuid="uid-create-full"
            ),
            "expected": "uid-create-full"
        },
        "minimal": lambda self: {
            "args": (enums.CryptographicAlgorithm.AES, 128),
            "kwargs": {},
            "result": results.CreateResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS),
                uuid="uid-create-min"
            ),
            "expected": "uid-create-min"
        },
        "invalid": lambda self: {
            "args": ("invalid", 128),
            "kwargs": {},
            "exc": TypeError
        }
    },
    "create_key_pair": {
        "proxy_method": "create_key_pair",
        "category": "result_object",
        "full": lambda self: {
            "args": (enums.CryptographicAlgorithm.RSA, 2048),
            "kwargs": {
                "operation_policy_name": "policy",
                "public_name": "pub",
                "public_usage_mask": [
                    enums.CryptographicUsageMask.VERIFY
                ],
                "private_name": "priv",
                "private_usage_mask": [
                    enums.CryptographicUsageMask.SIGN
                ]
            },
            "result": results.CreateKeyPairResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS),
                public_key_uuid="pub",
                private_key_uuid="priv"
            ),
            "expected": ("pub", "priv")
        },
        "minimal": lambda self: {
            "args": (enums.CryptographicAlgorithm.RSA, 1024),
            "kwargs": {},
            "result": results.CreateKeyPairResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS),
                public_key_uuid="pub-min",
                private_key_uuid="priv-min"
            ),
            "expected": ("pub-min", "priv-min")
        },
        "invalid": lambda self: {
            "args": ("invalid", 1024),
            "kwargs": {},
            "exc": TypeError
        }
    },
    "register": {
        "proxy_method": "register",
        "category": "result_object",
        "full": _register_full_case,
        "minimal": _register_min_case,
        "invalid": lambda self: {
            "args": ("invalid",),
            "kwargs": {},
            "exc": TypeError
        }
    },
    "get": {
        "proxy_method": "get",
        "category": "result_object",
        "full": _get_full_case,
        "minimal": _get_min_case,
        "invalid": lambda self: {
            "args": (123,),
            "kwargs": {},
            "exc": TypeError
        }
    },
    "destroy": {
        "proxy_method": "destroy",
        "category": "result_object",
        "full": lambda self: {
            "args": ("uid-destroy-full",),
            "kwargs": {},
            "result": results.DestroyResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS)
            ),
            "expected": None
        },
        "minimal": lambda self: {
            "args": (),
            "kwargs": {},
            "result": results.DestroyResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS)
            ),
            "expected": None
        },
        "invalid": lambda self: {
            "args": (123,),
            "kwargs": {},
            "exc": TypeError
        }
    },
    "locate": {
        "proxy_method": "locate",
        "category": "result_object",
        "full": _locate_full_case,
        "minimal": _locate_min_case,
        "invalid": lambda self: {
            "args": ("invalid",),
            "kwargs": {},
            "exc": TypeError
        }
    },
    "activate": {
        "proxy_method": "activate",
        "category": "result_object",
        "full": lambda self: {
            "args": ("uid-activate-full",),
            "kwargs": {},
            "result": results.ActivateResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS)
            ),
            "expected": None
        },
        "minimal": lambda self: {
            "args": (),
            "kwargs": {},
            "result": results.ActivateResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS)
            ),
            "expected": None
        },
        "invalid": lambda self: {
            "args": (123,),
            "kwargs": {},
            "exc": TypeError
        }
    },
    "revoke": {
        "proxy_method": "revoke",
        "category": "result_object",
        "full": lambda self: {
            "args": (enums.RevocationReasonCode.CESSATION_OF_OPERATION,
                     "uid-revoke-full"),
            "kwargs": {
                "revocation_message": "message",
                "compromise_occurrence_date": 1234
            },
            "result": results.RevokeResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS)
            ),
            "expected": None
        },
        "minimal": lambda self: {
            "args": (enums.RevocationReasonCode.CESSATION_OF_OPERATION,),
            "kwargs": {},
            "result": results.RevokeResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS)
            ),
            "expected": None
        },
        "invalid": lambda self: {
            "args": ("invalid",),
            "kwargs": {},
            "exc": TypeError
        }
    },
    "encrypt": {
        "proxy_method": "encrypt",
        "category": "dict_result",
        "full": lambda self: {
            "args": (b"data-full",),
            "kwargs": {
                "uid": "uid-enc-full",
                "cryptographic_parameters": {
                    "block_cipher_mode": enums.BlockCipherMode.CBC,
                    "padding_method": enums.PaddingMethod.PKCS5,
                    "cryptographic_algorithm":
                        enums.CryptographicAlgorithm.AES
                },
                "iv_counter_nonce": b"iv-full"
            },
            "result": {
                "result_status": enums.ResultStatus.SUCCESS,
                "data": b"enc-full",
                "iv_counter_nonce": b"iv-full"
            },
            "expected": (b"enc-full", b"iv-full")
        },
        "minimal": lambda self: {
            "args": (b"data-min",),
            "kwargs": {},
            "result": {
                "result_status": enums.ResultStatus.SUCCESS,
                "data": b"enc-min",
                "iv_counter_nonce": None
            },
            "expected": (b"enc-min", None)
        },
        "invalid": lambda self: {
            "args": ("invalid",),
            "kwargs": {},
            "exc": TypeError
        }
    },
    "decrypt": {
        "proxy_method": "decrypt",
        "category": "dict_result",
        "full": lambda self: {
            "args": (b"data-full",),
            "kwargs": {
                "uid": "uid-dec-full",
                "cryptographic_parameters": {
                    "block_cipher_mode": enums.BlockCipherMode.CBC,
                    "padding_method": enums.PaddingMethod.PKCS5,
                    "cryptographic_algorithm":
                        enums.CryptographicAlgorithm.AES
                },
                "iv_counter_nonce": b"iv-full"
            },
            "result": {
                "result_status": enums.ResultStatus.SUCCESS,
                "data": b"dec-full"
            },
            "expected": b"dec-full"
        },
        "minimal": lambda self: {
            "args": (b"data-min",),
            "kwargs": {},
            "result": {
                "result_status": enums.ResultStatus.SUCCESS,
                "data": b"dec-min"
            },
            "expected": b"dec-min"
        },
        "invalid": lambda self: {
            "args": ("invalid",),
            "kwargs": {},
            "exc": TypeError
        }
    },
    "sign": {
        "proxy_method": "sign",
        "category": "dict_result",
        "full": lambda self: {
            "args": (b"data-full",),
            "kwargs": {
                "uid": "uid-sign-full",
                "cryptographic_parameters": {
                    "padding_method": enums.PaddingMethod.PKCS1v15,
                    "cryptographic_algorithm":
                        enums.CryptographicAlgorithm.RSA,
                    "hashing_algorithm": enums.HashingAlgorithm.SHA_256
                }
            },
            "result": {
                "result_status": enums.ResultStatus.SUCCESS,
                "signature": b"sig-full"
            },
            "expected": b"sig-full"
        },
        "minimal": lambda self: {
            "args": (b"data-min",),
            "kwargs": {},
            "result": {
                "result_status": enums.ResultStatus.SUCCESS,
                "signature": b"sig-min"
            },
            "expected": b"sig-min"
        },
        "invalid": lambda self: {
            "args": ("invalid",),
            "kwargs": {},
            "exc": TypeError
        }
    },
    "signature_verify": {
        "proxy_method": "signature_verify",
        "category": "dict_result",
        "full": lambda self: {
            "args": (b"message-full", b"signature-full"),
            "kwargs": {
                "uid": "uid-verify-full",
                "cryptographic_parameters": {
                    "padding_method": enums.PaddingMethod.PKCS1v15,
                    "cryptographic_algorithm":
                        enums.CryptographicAlgorithm.RSA,
                    "hashing_algorithm": enums.HashingAlgorithm.SHA_256
                }
            },
            "result": {
                "result_status": enums.ResultStatus.SUCCESS,
                "validity_indicator": enums.ValidityIndicator.VALID
            },
            "expected": enums.ValidityIndicator.VALID
        },
        "minimal": lambda self: {
            "args": (b"message-min", b"signature-min"),
            "kwargs": {},
            "result": {
                "result_status": enums.ResultStatus.SUCCESS,
                "validity_indicator": enums.ValidityIndicator.INVALID
            },
            "expected": enums.ValidityIndicator.INVALID
        },
        "invalid": lambda self: {
            "args": ("invalid", b"signature"),
            "kwargs": {},
            "exc": TypeError
        }
    },
    "mac": {
        "proxy_method": "mac",
        "category": "result_object",
        "full": lambda self: {
            "args": (b"data-full", "uid-mac-full",
                     enums.CryptographicAlgorithm.HMAC_SHA256),
            "kwargs": {},
            "result": results.MACResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS),
                uuid=attr.UniqueIdentifier("uid-mac-full"),
                mac_data=obj.MACData(b"mac-full")
            ),
            "expected": ("uid-mac-full", b"mac-full")
        },
        "minimal": lambda self: {
            "args": (b"data-min",),
            "kwargs": {},
            "result": results.MACResult(
                contents.ResultStatus(enums.ResultStatus.SUCCESS),
                uuid=attr.UniqueIdentifier("uid-mac-min"),
                mac_data=obj.MACData(b"mac-min")
            ),
            "expected": ("uid-mac-min", b"mac-min")
        },
        "invalid": lambda self: {
            "args": ("invalid",),
            "kwargs": {},
            "exc": TypeError
        }
    },
    "derive_key": {
        "proxy_method": "derive_key",
        "category": "dict_result",
        "full": lambda self: {
            "args": (
                enums.ObjectType.SYMMETRIC_KEY,
                ["id1", "id2"],
                enums.DerivationMethod.ENCRYPT,
                {
                    "cryptographic_parameters": {
                        "block_cipher_mode": enums.BlockCipherMode.CBC,
                        "padding_method": enums.PaddingMethod.PKCS1v15,
                        "cryptographic_algorithm":
                            enums.CryptographicAlgorithm.AES
                    },
                    "initialization_vector": b"iv",
                    "derivation_data": b"data",
                    "salt": b"salt",
                    "iteration_count": 10
                }
            ),
            "kwargs": {
                "cryptographic_length": 128,
                "cryptographic_algorithm":
                    enums.CryptographicAlgorithm.AES,
                "cryptographic_usage_mask": [
                    enums.CryptographicUsageMask.DERIVE_KEY
                ]
            },
            "result": {
                "result_status": enums.ResultStatus.SUCCESS,
                "unique_identifier": "uid-derive-full"
            },
            "expected": "uid-derive-full"
        },
        "minimal": lambda self: {
            "args": (
                enums.ObjectType.SYMMETRIC_KEY,
                ["id1"],
                enums.DerivationMethod.ENCRYPT,
                {}
            ),
            "kwargs": {},
            "result": {
                "result_status": enums.ResultStatus.SUCCESS,
                "unique_identifier": "uid-derive-min"
            },
            "expected": "uid-derive-min"
        },
        "invalid": lambda self: {
            "args": ("invalid", ["id1"],
                     enums.DerivationMethod.ENCRYPT, {}),
            "kwargs": {},
            "exc": TypeError
        }
    },
    "get_attributes": {
        "proxy_method": "get_attributes",
        "category": "result_object",
        "full": _get_attributes_full_case,
        "minimal": _get_attributes_min_case,
        "invalid": lambda self: {
            "args": (None, [1]),
            "kwargs": {},
            "exc": TypeError
        }
    },
    "get_attribute_list": {
        "proxy_method": "get_attribute_list",
        "category": "result_object",
        "full": _get_attribute_list_full_case,
        "minimal": _get_attribute_list_min_case,
        "invalid": lambda self: {
            "args": (123,),
            "kwargs": {},
            "exc": TypeError
        }
    },
    "delete_attribute": {
        "proxy_method": "send_request_payload",
        "category": "payload_response",
        "full": _delete_attribute_full_case,
        "minimal": _delete_attribute_min_case,
        "invalid": lambda self: {
            "args": (),
            "kwargs": {"unique_identifier": 123, "attribute_name": "State"},
            "exc": TypeError
        }
    },
    "modify_attribute": {
        "proxy_method": "send_request_payload",
        "category": "payload_response",
        "full": _modify_attribute_full_case,
        "minimal": _modify_attribute_min_case,
        "invalid": lambda self: {
            "args": (),
            "kwargs": {
                "unique_identifier": "uid-mod",
                "attribute": "invalid"
            },
            "exc": TypeError
        }
    },
    "set_attribute": {
        "proxy_method": "send_request_payload",
        "category": "payload_response",
        "full": _set_attribute_full_case,
        "minimal": _set_attribute_min_case,
        "invalid": lambda self: {
            "args": (),
            "kwargs": {
                "unique_identifier": "uid-set",
                "attribute_name": "Cryptographic Length",
                "attribute_value": "invalid"
            },
            "exc": TypeError
        }
    }
}


# Generate repetitive operation tests from the OPERATION_CASES map.

def _make_success_test(op_name):
    def test(self):
        self._assert_operation_success(op_name, "full")
    test.__name__ = "test_{}_success".format(op_name)
    return test


def _make_minimal_test(op_name):
    def test(self):
        self._assert_operation_success(op_name, "minimal")
    test.__name__ = "test_{}_with_minimal_params".format(op_name)
    return test


def _make_invalid_test(op_name):
    def test(self):
        self._assert_operation_invalid(op_name)
    test.__name__ = "test_{}_invalid_param_types".format(op_name)
    return test


def _make_closed_test(op_name):
    def test(self):
        self._assert_operation_closed(op_name)
    test.__name__ = "test_{}_on_closed_connection".format(op_name)
    return test


def _make_failure_test(op_name):
    def test(self):
        self._assert_operation_failure(op_name)
    test.__name__ = "test_{}_on_operation_failure".format(op_name)
    return test


def _make_none_response_test(op_name):
    def test(self):
        self._assert_operation_none_response(op_name)
    test.__name__ = "test_{}_with_none_response".format(op_name)
    return test


for _op_name in OPERATION_CASES:
    setattr(
        TestProxyKmipClientExtended,
        "test_{}_success".format(_op_name),
        _make_success_test(_op_name)
    )
    setattr(
        TestProxyKmipClientExtended,
        "test_{}_with_minimal_params".format(_op_name),
        _make_minimal_test(_op_name)
    )
    setattr(
        TestProxyKmipClientExtended,
        "test_{}_invalid_param_types".format(_op_name),
        _make_invalid_test(_op_name)
    )
    setattr(
        TestProxyKmipClientExtended,
        "test_{}_on_closed_connection".format(_op_name),
        _make_closed_test(_op_name)
    )
    setattr(
        TestProxyKmipClientExtended,
        "test_{}_on_operation_failure".format(_op_name),
        _make_failure_test(_op_name)
    )
    setattr(
        TestProxyKmipClientExtended,
        "test_{}_with_none_response".format(_op_name),
        _make_none_response_test(_op_name)
    )
