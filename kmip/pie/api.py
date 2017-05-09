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

import abc
import six


@six.add_metaclass(abc.ABCMeta)
class KmipClient:
    """
    A simplified KMIP client interface for conducting KMIP operations.

    The KmipClient provides a simple external interface for various KMIP
    operations and composes the bulk of the PyKMIP Pie API.
    """

    UNIQUE_IDENTIFIER = "uid"
    NAME = "name"
    OBJECT_TYPE = "object_type"
    CRYPTOGRAPHIC_ALGORITHM = "cryptographic_algorithm"
    CRYPTOGRAPHIC_LENGTH = "cryptographic_length"
    CRYPTOGRAPHIC_PARAMETERS = "cryptographic_parameters"
    CRYPTOGRAPHIC_DOMAIN_PARAMETERS = "cryptographic_domain_parameters"
    CERTIFICATE_TYPE = "certificate_type"
    CERTIFICATE_LENGTH = "certificate_length"
    X509_CERTIFICATE_IDENTIFIER = "x509_certificate_identifier"
    X509_CERTIFICATE_SUBJECT = "x509_certificate_subject"
    X509_CERTIFICATE_ISSUER = "x509_certificate_issuer"
    CERTIFICATE_IDENTIFIER = "certificate_identifier"
    CERTIFICATE_SUBJECT = "certificate_subject"
    CERTIFICATE_ISSUER = "certificate_issuer"
    DIGITAL_SIGNATURE_ALGORITHM = "digital_signature_algorithm"
    DIGEST = "digest"
    OPERATION_POLICY_NAME = "operation_policy_name"
    CRYPTOGRAPHIC_USAGE_MASK = "cryptographic_usage_mask"
    LEASE_TIME = "lease_time"
    USAGE_LIMITS = "usage_limits"
    STATE = "state"
    INITIAL_DATE = "initial_date"
    ACTIVATION_DATE = "activation_date"
    PROCESS_START_DATE = "process_start_date"
    PROTECT_STOP_DATE = "protect_stop_date"
    DEACTIVATION_DATE = "deactivation_date"
    DESTROY_DATE = "destroy_date"
    COMPROMISE_OCCURRENCE_DATE = "compromise_occurrence_date"
    COMPROMISE_DATE = "compromise_date"
    REVOCATION_REASON = "revocation_reason"
    ARCHIVE_DATE = "archive_date"
    OBJECT_GROUP = "object_group"
    FRESH = "fresh"
    LINK = "link"
    APPLICATION_SPECIFIC_INFORMATION = "application_specific_information"
    CONTACT_INFORMATION = "contact_information"
    LAST_CHANGE_DATE = "last_change_date"
    CUSTOM_ATTRIBUTE = "custom_attribute"
    ALTERNATIVE_NAME = "alternative_name"
    KEY_VALUE_PRESENT = "key_value_present"
    KEY_VALUE_LOCATION = "key_value_location"
    ORIGINAL_CREATION_DATE = "original_creation_date"

    @abc.abstractmethod
    def create(self, algorithm, length):
        """
        Create a symmetric key on a KMIP appliance.

        Args:
            algorithm (CryptographicAlgorithm): An enumeration defining the
                algorithm to use to generate the symmetric key.
            length (int): The length in bits for the symmetric key.
        """
        pass

    @abc.abstractmethod
    def create_key_pair(self, algorithm, length):
        """
        Create an asymmetric key pair on a KMIP appliance.

        Args:
            algorithm (CryptographicAlgorithm): An enumeration defining the
                algorithm to use to generate the key pair.
            length (int): The length in bits for the key pair.
        """
        pass

    @abc.abstractmethod
    def register(self, managed_object):
        """
        Register a managed object with a KMIP appliance.

        Args:
            managed_object (ManagedObject): A managed object to register. An
                instantiatable subclass of ManagedObject from the Pie API.
        """
        pass

    @abc.abstractmethod
    def locate(self, maximum_items, storage_status_mask, object_group_member,
               attributes):
        """
        Search for managed objects with a KMIP appliance.

        Args:
            maximum_items (integer): Maximum number of object identifiers the
                server MAY return.
            storage_status_mask (integer): A bit mask that indicates whether
                on-line or archived objects are to be searched.
            object_group_member (ObjectGroupMember): An enumeration that
                indicates the object group member type.
            attributes (list): Attributes the are REQUIRED to match those in a
                candidate object.

        """
        pass

    @abc.abstractmethod
    def get(self, uid):
        """
        Get a managed object from a KMIP appliance.

        Args:
            uid (string): The unique ID of the managed object to retrieve.
        """
        pass

    @abc.abstractmethod
    def get_attribute_list(self, uid):
        """
        Get a list of attribute names for a managed object on a KMIP appliance.

        Args:
            uid (string): The unique ID of the managed object whose attribute
                names should be retrieved.
        """
        pass

    @abc.abstractmethod
    def activate(self, uid):
        """
        Activate a managed object stored by a KMIP appliance.

        Args:
            uid (string): The unique ID of the managed object to activate.
        """
        pass

    @abc.abstractmethod
    def revoke(self, revocation_reason, uid, revocation_message,
               compromise_occurrence_date):
        """
        Revoke a managed object stored by a KMIP appliance.

        Args:
            revocation_reason (RevocationReasonCode): An enumeration indicating
                the revocation reason.
            uid (string): The unique ID of the managed object to revoke.
                Optional, defaults to None.
            revocation_message (string): A message regarding the revocation.
                Optional, defaults to None.
            compromise_occurrence_date (int): A integer which will be converted
                to the Datetime when the managed object was firstly believed to
                be compromised. Optional, defaults to None.
        """
        pass

    @abc.abstractmethod
    def destroy(self, uid):
        """
        Destroy a managed object stored by a KMIP appliance.

        Args:
            uid (string): The unique ID of the managed object to destroy.
        """
        pass

    @abc.abstractmethod
    def mac(self, data, uid, algorithm):
        """
        Get the message authentication code for data.

        Args:
            data (string): The data to be MACed.
            uid (string): The unique ID of the managed object that is the key
                to use for the MAC operation.
            algorithm (CryptographicAlgorithm): An enumeration defining the
                algorithm to use to generate the MAC.
        """
        pass
