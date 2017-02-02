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


class OperationResult(object):

    def __init__(self,
                 result_status,
                 result_reason=None,
                 result_message=None):
        self.result_status = result_status

        if result_reason is not None:
            self.result_reason = result_reason
        else:
            self.result_reason = None

        if result_message is not None:
            self.result_message = result_message
        else:
            self.result_message = None


class CreateResult(OperationResult):

    def __init__(self,
                 result_status,
                 result_reason=None,
                 result_message=None,
                 object_type=None,
                 uuid=None,
                 template_attribute=None):
        super(CreateResult, self).__init__(
            result_status, result_reason, result_message)
        if object_type is not None:
            self.object_type = object_type
        else:
            self.object_type = None

        if uuid is not None:
            self.uuid = uuid
        else:
            self.uuid = None

        if template_attribute is not None:
            self.template_attribute = template_attribute
        else:
            self.template_attribute = None


class CreateKeyPairResult(OperationResult):

    def __init__(self,
                 result_status,
                 result_reason=None,
                 result_message=None,
                 private_key_uuid=None,
                 public_key_uuid=None,
                 private_key_template_attribute=None,
                 public_key_template_attribute=None):
        super(CreateKeyPairResult, self).__init__(
            result_status, result_reason, result_message)
        self.private_key_uuid = private_key_uuid
        self.public_key_uuid = public_key_uuid
        self.private_key_template_attribute = private_key_template_attribute
        self.public_key_template_attribute = public_key_template_attribute


class ActivateResult(OperationResult):

    def __init__(self,
                 result_status,
                 result_reason=None,
                 result_message=None,
                 uuid=None):
        super(ActivateResult, self).__init__(
            result_status, result_reason, result_message)

        if uuid is not None:
            self.uuid = uuid
        else:
            self.uuid = None


class RegisterResult(OperationResult):

    def __init__(self,
                 result_status,
                 result_reason=None,
                 result_message=None,
                 uuid=None,
                 template_attribute=None):
        super(RegisterResult, self).__init__(
            result_status, result_reason, result_message)
        if uuid is not None:
            self.uuid = uuid
        else:
            self.uuid = None

        if template_attribute is not None:
            self.template_attribute = template_attribute
        else:
            self.template_attribute = None


class RekeyKeyPairResult(CreateKeyPairResult):

    def __init__(self,
                 result_status,
                 result_reason=None,
                 result_message=None,
                 private_key_uuid=None,
                 public_key_uuid=None,
                 private_key_template_attribute=None,
                 public_key_template_attribute=None):
        super(RekeyKeyPairResult, self).__init__(
            result_status, result_reason, result_message, private_key_uuid,
            public_key_uuid, private_key_template_attribute,
            public_key_template_attribute)


class GetResult(OperationResult):

    def __init__(self,
                 result_status,
                 result_reason=None,
                 result_message=None,
                 object_type=None,
                 uuid=None,
                 secret=None):
        super(GetResult, self).__init__(
            result_status, result_reason, result_message)
        if object_type is not None:
            self.object_type = object_type
        else:
            self.object_type = None

        if uuid is not None:
            self.uuid = uuid
        else:
            self.uuid = None

        if secret is not None:
            self.secret = secret
        else:
            self.secret = None


class GetAttributesResult(OperationResult):

    def __init__(
            self,
            result_status,
            result_reason=None,
            result_message=None,
            uuid=None,
            attributes=None
    ):
        super(GetAttributesResult, self).__init__(
            result_status,
            result_reason,
            result_message
        )
        self.uuid = uuid
        self.attributes = attributes


class GetAttributeListResult(OperationResult):

    def __init__(
            self,
            result_status,
            result_reason=None,
            result_message=None,
            uid=None,
            names=None):
        super(GetAttributeListResult, self).__init__(
            result_status, result_reason, result_message)
        self.uid = uid
        self.names = names


class DestroyResult(OperationResult):

    def __init__(self,
                 result_status,
                 result_reason=None,
                 result_message=None,
                 uuid=None):
        super(DestroyResult, self).__init__(
            result_status, result_reason, result_message)
        if uuid is not None:
            self.uuid = uuid
        else:
            self.uuid = None


class LocateResult(OperationResult):

    def __init__(self,
                 result_status,
                 result_reason=None,
                 result_message=None,
                 uuids=None):
        super(LocateResult, self).__init__(
            result_status, result_reason, result_message)
        self.uuids = uuids


class QueryResult(OperationResult):
    """
    A container for the results of a Query operation.

    Attributes:
        result_status: The status of the Query operation (e.g., success or
            failure).
        result_reason: The reason for the operation status.
        result_message: Extra information pertaining to the status reason.
        operations: A list of Operations supported by the server.
        object_types: A list of Object Types supported by the server.
        vendor_identification:
        server_information:
        application_namespaces: A list of namespaces supported by the server.
        extension_information: A list of extensions supported by the server.
    """

    def __init__(self,
                 result_status,
                 result_reason=None,
                 result_message=None,
                 operations=None,
                 object_types=None,
                 vendor_identification=None,
                 server_information=None,
                 application_namespaces=None,
                 extension_information=None):
        super(QueryResult, self).__init__(
            result_status, result_reason, result_message)

        if operations is None:
            self.operations = list()
        else:
            self.operations = operations

        if object_types is None:
            self.object_types = list()
        else:
            self.object_types = object_types

        self.vendor_identification = vendor_identification
        self.server_information = server_information

        if application_namespaces is None:
            self.application_namespaces = list()
        else:
            self.application_namespaces = application_namespaces

        if extension_information is None:
            self.extension_information = list()
        else:
            self.extension_information = extension_information


class DiscoverVersionsResult(OperationResult):

    def __init__(self,
                 result_status,
                 result_reason=None,
                 result_message=None,
                 protocol_versions=None):
        super(DiscoverVersionsResult, self).__init__(
            result_status, result_reason, result_message)
        self.protocol_versions = protocol_versions


class RevokeResult(OperationResult):

    def __init__(self,
                 result_status,
                 result_reason=None,
                 result_message=None,
                 unique_identifier=None):
        super(RevokeResult, self).__init__(
            result_status, result_reason, result_message)
        self.unique_identifier = unique_identifier


class MACResult(OperationResult):

    def __init__(self,
                 result_status,
                 result_reason=None,
                 result_message=None,
                 uuid=None,
                 mac_data=None):
        super(MACResult, self).__init__(
            result_status,
            result_reason,
            result_message
        )
        self.uuid = uuid
        self.mac_data = mac_data
