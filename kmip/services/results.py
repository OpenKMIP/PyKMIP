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
        super(self.__class__, self).__init__(result_status,
                                             result_reason,
                                             result_message)
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


class RegisterResult(OperationResult):

    def __init__(self,
                 result_status,
                 result_reason=None,
                 result_message=None,
                 uuid=None,
                 template_attribute=None):
        super(self.__class__, self).__init__(result_status,
                                             result_reason,
                                             result_message)
        if uuid is not None:
            self.uuid = uuid
        else:
            self.uuid = None

        if template_attribute is not None:
            self.template_attribute = template_attribute
        else:
            self.template_attribute = None


class GetResult(OperationResult):

    def __init__(self,
                 result_status,
                 result_reason=None,
                 result_message=None,
                 object_type=None,
                 uuid=None,
                 secret=None):
        super(self.__class__, self).__init__(result_status,
                                             result_reason,
                                             result_message)
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


class DestroyResult(OperationResult):

    def __init__(self,
                 result_status,
                 result_reason=None,
                 result_message=None,
                 uuid=None):
        super(self.__class__, self).__init__(result_status,
                                             result_reason,
                                             result_message)
        if uuid is not None:
            self.uuid = uuid
        else:
            self.uuid = None
