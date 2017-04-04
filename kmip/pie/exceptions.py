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


class ClientConnectionFailure(Exception):
    """
    An exception raised for errors with the client socket connection.
    """
    pass


class ClientConnectionNotOpen(Exception):
    """
    An exception raised when operations are issued to a closed connection.
    """
    def __init__(self):
        """
        Construct the closed client connection error message.
        """
        super(ClientConnectionNotOpen, self).__init__(
            "client connection not open")


class KmipOperationFailure(Exception):
    """
    An exception raised upon the failure of a KMIP appliance operation.
    """
    def __init__(self, status, reason, message):
        """
        Construct the error message and attributes for the KMIP operation
        failure.

        Args:
            status: a ResultStatus enumeration
            reason: a ResultReason enumeration
            message: a string providing additional error information
        """
        msg = "{0}: {1} - {2}".format(status.name, reason.name, message)
        super(KmipOperationFailure, self).__init__(msg)
        self.status = status
        self.reason = reason
        self.message = message
