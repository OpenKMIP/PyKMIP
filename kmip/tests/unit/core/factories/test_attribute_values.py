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

import testtools

from kmip.core import attributes
from kmip.core import enums
from kmip.core import primitives

from kmip.core.factories import attribute_values


class TestAttributeValueFactory(testtools.TestCase):

    def setUp(self):
        super(TestAttributeValueFactory, self).setUp()
        self.factory = attribute_values.AttributeValueFactory()

    def tearDown(self):
        super(TestAttributeValueFactory, self).tearDown()

    def test_create_unique_identifier(self):
        """
        Test that a UniqueIdentifier attribute can be created.
        """
        self.skip('')

    def test_create_name(self):
        """
        Test that a Name attribute can be created.
        """
        attr_type = enums.AttributeType.NAME
        name = self.factory.create_attribute_value(attr_type, "foo")
        self.assertIsInstance(name, attributes.Name)
        self.assertEqual("foo", name.name_value.value)
        self.assertEqual(enums.Tags.NAME, name.tag)

    def test_create_object_type(self):
        """
        Test that an empty ObjectType attribute can be created.
        """
        object_type = self.factory.create_attribute_value(
            enums.AttributeType.OBJECT_TYPE,
            None
        )
        self.assertIsInstance(object_type, attributes.ObjectType)
        self.assertEqual(None, object_type.value)

    def test_create_object_type_with_value(self):
        """
        Test that an ObjectType attribute can be created with a custom value.
        """
        object_type = self.factory.create_attribute_value(
            enums.AttributeType.OBJECT_TYPE,
            enums.ObjectType.SYMMETRIC_KEY
        )
        self.assertIsInstance(object_type, attributes.ObjectType)
        self.assertEqual(enums.ObjectType.SYMMETRIC_KEY, object_type.value)

    def test_create_cryptographic_algorithm(self):
        """
        Test that a CryptographicAlgorithm attribute can be created.
        """
        self.skip('')

    def test_create_cryptographic_length(self):
        """
        Test that a CryptographicLength attribute can be created.
        """
        self.skip('')

    def test_create_cryptographic_parameters(self):
        """
        Test that a CryptographicParameters attribute can be created.
        """
        value = {
            'block_cipher_mode': enums.BlockCipherMode.NIST_KEY_WRAP,
            'padding_method': enums.PaddingMethod.ANSI_X9_23,
            'key_role_type': enums.KeyRoleType.KEK,
            'hashing_algorithm': enums.HashingAlgorithm.SHA_512,
            'digital_signature_algorithm':
                enums.DigitalSignatureAlgorithm.ECDSA_WITH_SHA512,
            'cryptographic_algorithm':
                enums.CryptographicAlgorithm.HMAC_SHA512}
        params = self.factory.create_attribute_value(
            enums.AttributeType.CRYPTOGRAPHIC_PARAMETERS, value)

        # TODO (peter-hamilton): Update assertEquals after structure changes
        self.assertIsInstance(params, attributes.CryptographicParameters)
        self.assertEqual(
            attributes.CryptographicParameters.BlockCipherMode(
                enums.BlockCipherMode.NIST_KEY_WRAP),
            params.block_cipher_mode)
        self.assertEqual(
            attributes.CryptographicParameters.PaddingMethod(
                enums.PaddingMethod.ANSI_X9_23),
            params.padding_method)
        self.assertEqual(
            attributes.CryptographicParameters.KeyRoleType(
                enums.KeyRoleType.KEK),
            params.key_role_type)
        self.assertEqual(
            attributes.HashingAlgorithm(enums.HashingAlgorithm.SHA_512),
            params.hashing_algorithm)
        self.assertEqual(
            attributes.CryptographicParameters.DigitalSignatureAlgorithm(
                enums.DigitalSignatureAlgorithm.ECDSA_WITH_SHA512),
            params.digital_signature_algorithm)
        self.assertEqual(
            attributes.CryptographicAlgorithm(
                enums.CryptographicAlgorithm.HMAC_SHA512),
            params.cryptographic_algorithm)

    def test_create_cryptographic_domain_parameters(self):
        """
        Test that a CryptographicDomainParameters attribute can be created.
        """
        kwargs = {'name': enums.AttributeType.CRYPTOGRAPHIC_DOMAIN_PARAMETERS,
                  'value': None}
        self.assertRaises(
            NotImplementedError, self.factory.create_attribute_value, **kwargs)

    def test_create_certificate_type(self):
        """
        Test that a CertificateType attribute can be created.
        """
        kwargs = {'name': enums.AttributeType.CERTIFICATE_TYPE,
                  'value': None}
        self.assertRaises(
            NotImplementedError, self.factory.create_attribute_value, **kwargs)

    def test_create_certificate_length(self):
        """
        Test that a CertificateLength attribute can be created.
        """
        length = self.factory.create_attribute_value(
            enums.AttributeType.CERTIFICATE_LENGTH, 0)
        self.assertIsInstance(length, primitives.Integer)
        self.assertEqual(0, length.value)
        self.assertEqual(enums.Tags.CERTIFICATE_LENGTH, length.tag)

    def test_create_x509_certificate_identifier(self):
        """
        Test that an X509CertificateIdentifier attribute can be created.
        """
        kwargs = {'name': enums.AttributeType.X_509_CERTIFICATE_IDENTIFIER,
                  'value': None}
        self.assertRaises(
            NotImplementedError, self.factory.create_attribute_value, **kwargs)

    def test_create_x509_certificate_subject(self):
        """
        Test that an X509CertificateSubject attribute can be created.
        """
        kwargs = {'name': enums.AttributeType.X_509_CERTIFICATE_SUBJECT,
                  'value': None}
        self.assertRaises(
            NotImplementedError, self.factory.create_attribute_value, **kwargs)

    def test_create_x509_certificate_issuer(self):
        """
        Test that an X509CertificateIssuer attribute can be created.
        """
        kwargs = {'name': enums.AttributeType.X_509_CERTIFICATE_ISSUER,
                  'value': None}
        self.assertRaises(
            NotImplementedError, self.factory.create_attribute_value, **kwargs)

    def test_create_certificate_identifier(self):
        """
        Test that a CertificateIdentifier attribute can be created.
        """
        kwargs = {'name': enums.AttributeType.CERTIFICATE_IDENTIFIER,
                  'value': None}
        self.assertRaises(
            NotImplementedError, self.factory.create_attribute_value, **kwargs)

    def test_create_certificate_subject(self):
        """
        Test that a CertificateSubject attribute can be created.
        """
        kwargs = {'name': enums.AttributeType.CERTIFICATE_SUBJECT,
                  'value': None}
        self.assertRaises(
            NotImplementedError, self.factory.create_attribute_value, **kwargs)

    def test_create_certificate_issuer(self):
        """
        Test that a CertificateIssuer attribute can be created.
        """
        kwargs = {'name': enums.AttributeType.CERTIFICATE_ISSUER,
                  'value': None}
        self.assertRaises(
            NotImplementedError, self.factory.create_attribute_value, **kwargs)

    def test_create_digital_signature_algorithm(self):
        """
        Test that a DigitalSignatureAlgorithm attribute can be created.
        """
        kwargs = {'name': enums.AttributeType.DIGITAL_SIGNATURE_ALGORITHM,
                  'value': None}
        self.assertRaises(
            NotImplementedError, self.factory.create_attribute_value, **kwargs)

    def test_create_digest(self):
        """
        Test that a Digest attribute can be created.
        """
        digest = self.factory.create_attribute_value(
            enums.AttributeType.DIGEST, None)
        self.assertIsInstance(digest, attributes.Digest)

    def test_create_operation_policy_name(self):
        """
        Test that an OperationPolicyName attribute can be created.
        """
        attribute = self.factory.create_attribute_value(
            enums.AttributeType.OPERATION_POLICY_NAME, 'test')
        self.assertIsInstance(attribute, attributes.OperationPolicyName)
        self.assertEqual('test', attribute.value)

    def test_create_cryptographic_usage_mask(self):
        """
        Test that a CryptographicUsageMask attribute can be created.
        """
        self.skip('')

    def test_create_lease_time(self):
        """
        Test that a LeaseTime attribute can be created.
        """
        lease = self.factory.create_attribute_value(
            enums.AttributeType.LEASE_TIME, 0)
        self.assertIsInstance(lease, primitives.Interval)
        self.assertEqual(0, lease.value)
        self.assertEqual(enums.Tags.LEASE_TIME, lease.tag)

    def test_create_usage_limits(self):
        """
        Test that a UsageLimits attribute can be created.
        """
        kwargs = {'name': enums.AttributeType.USAGE_LIMITS,
                  'value': None}
        self.assertRaises(
            NotImplementedError, self.factory.create_attribute_value, **kwargs)

    def test_create_state(self):
        """
        Test that a State attribute can be created.
        """
        state = self.factory.create_attribute_value(
            enums.AttributeType.STATE,
            enums.State.ACTIVE
        )
        self.assertIsInstance(state, attributes.State)
        self.assertEqual(enums.State.ACTIVE, state.value)

    def test_create_initial_date(self):
        """
        Test that an InitialDate attribute can be created.
        """
        date = self.factory.create_attribute_value(
            enums.AttributeType.INITIAL_DATE, 0)
        self.assertIsInstance(date, primitives.DateTime)
        self.assertEqual(0, date.value)
        self.assertEqual(enums.Tags.INITIAL_DATE, date.tag)

    def test_create_activation_date(self):
        """
        Test that an ActivationDate attribute can be created.
        """
        date = self.factory.create_attribute_value(
            enums.AttributeType.ACTIVATION_DATE, 0)
        self.assertIsInstance(date, primitives.DateTime)
        self.assertEqual(0, date.value)
        self.assertEqual(enums.Tags.ACTIVATION_DATE, date.tag)

    def test_create_process_start_date(self):
        """
        Test that a ProcessStartDate attribute can be created.
        """
        date = self.factory.create_attribute_value(
            enums.AttributeType.PROCESS_START_DATE, 0)
        self.assertIsInstance(date, primitives.DateTime)
        self.assertEqual(0, date.value)
        self.assertEqual(enums.Tags.PROCESS_START_DATE, date.tag)

    def test_create_protect_stop_date(self):
        """
        Test that a ProtectStopDate attribute can be created.
        """
        date = self.factory.create_attribute_value(
            enums.AttributeType.PROTECT_STOP_DATE, 0)
        self.assertIsInstance(date, primitives.DateTime)
        self.assertEqual(0, date.value)
        self.assertEqual(enums.Tags.PROTECT_STOP_DATE, date.tag)

    def test_create_deactivation_date(self):
        """
        Test that a DeactivationDate attribute can be created.
        """
        date = self.factory.create_attribute_value(
            enums.AttributeType.DEACTIVATION_DATE, 0)
        self.assertIsInstance(date, primitives.DateTime)
        self.assertEqual(0, date.value)
        self.assertEqual(enums.Tags.DEACTIVATION_DATE, date.tag)

    def test_create_destroy_date(self):
        """
        Test that a DestroyDate attribute can be created.
        """
        date = self.factory.create_attribute_value(
            enums.AttributeType.DESTROY_DATE, 0)
        self.assertIsInstance(date, primitives.DateTime)
        self.assertEqual(0, date.value)
        self.assertEqual(enums.Tags.DESTROY_DATE, date.tag)

    def test_create_compromise_occurance_date(self):
        """
        Test that a CompromiseOccurrenceDate attribute can be created.
        """
        date = self.factory.create_attribute_value(
            enums.AttributeType.COMPROMISE_OCCURRENCE_DATE, 0)
        self.assertIsInstance(date, primitives.DateTime)
        self.assertEqual(0, date.value)
        self.assertEqual(enums.Tags.COMPROMISE_OCCURRENCE_DATE, date.tag)

    def test_create_compromise_date(self):
        """
        Test that a CompromiseDate attribute can be created.
        """
        date = self.factory.create_attribute_value(
            enums.AttributeType.COMPROMISE_DATE, 0)
        self.assertIsInstance(date, primitives.DateTime)
        self.assertEqual(0, date.value)
        self.assertEqual(enums.Tags.COMPROMISE_DATE, date.tag)

    def test_create_revocation_reason(self):
        """
        Test that a RevocationReason attribute can be created.
        """
        kwargs = {'name': enums.AttributeType.REVOCATION_REASON,
                  'value': None}
        self.assertRaises(
            NotImplementedError, self.factory.create_attribute_value, **kwargs)

    def test_create_archive_date(self):
        """
        Test that an ArchiveDate attribute can be created.
        """
        date = self.factory.create_attribute_value(
            enums.AttributeType.ARCHIVE_DATE, 0)
        self.assertIsInstance(date, primitives.DateTime)
        self.assertEqual(0, date.value)
        self.assertEqual(enums.Tags.ARCHIVE_DATE, date.tag)

    def test_create_object_group(self):
        """
        Test that an ObjectGroup attribute can be created.
        """
        self.skip('')

    def test_create_fresh(self):
        """
        Test that a Fresh attribute can be created.
        """
        fresh = self.factory.create_attribute_value(
            enums.AttributeType.FRESH, True)
        self.assertIsInstance(fresh, primitives.Boolean)
        self.assertEqual(True, fresh.value)
        self.assertEqual(enums.Tags.FRESH, fresh.tag)

    def test_create_link(self):
        """
        Test that a Link attribute can be created.
        """
        kwargs = {'name': enums.AttributeType.LINK,
                  'value': None}
        self.assertRaises(
            NotImplementedError, self.factory.create_attribute_value, **kwargs)

    def test_create_application_specific_information(self):
        """
        Test that an ApplicationSpecificInformation attribute can be created.
        """
        self.skip('')

    def test_create_contact_information(self):
        """
        Test that a ContactInformation attribute can be created.
        """
        self.skip('')

    def test_create_last_change_date(self):
        """
        Test that an LastChangeDate attribute can be created.
        """
        date = self.factory.create_attribute_value(
            enums.AttributeType.LAST_CHANGE_DATE, 0)
        self.assertIsInstance(date, primitives.DateTime)
        self.assertEqual(0, date.value)
        self.assertEqual(enums.Tags.LAST_CHANGE_DATE, date.tag)

    def test_create_custom_attribute(self):
        """
        Test that a CustomAttribute can be created.
        """
        custom = self.factory.create_attribute_value(
            enums.AttributeType.CUSTOM_ATTRIBUTE, None)
        self.assertIsInstance(custom, attributes.CustomAttribute)
