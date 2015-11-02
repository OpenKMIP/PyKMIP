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

from testtools import TestCase

from kmip.core.attributes import ApplicationData
from kmip.core.attributes import ApplicationNamespace
from kmip.core.attributes import CertificateType
from kmip.core.attributes import CryptographicParameters
from kmip.core.attributes import DigestValue
from kmip.core.attributes import HashingAlgorithm
from kmip.core.attributes import Name
from kmip.core.attributes import OperationPolicyName
from kmip.core.attributes import Tags

from kmip.core.factories.attribute_values import AttributeValueFactory

from kmip.core.enums import AttributeType
from kmip.core.enums import BlockCipherMode
from kmip.core.enums import CertificateTypeEnum
from kmip.core.enums import HashingAlgorithm as HashingAlgorithmEnum
from kmip.core.enums import KeyRoleType
from kmip.core.enums import PaddingMethod
from kmip.core.enums import NameType

from kmip.core.utils import BytearrayStream


class TestNameValue(TestCase):

    def setUp(self):
        super(TestNameValue, self).setUp()
        self.stream = BytearrayStream()

    def tearDown(self):
        super(TestNameValue, self).tearDown()

    def test_write_no_padding(self):
        self.skip('Not implemented')

    def test_write_with_padding(self):
        self.skip('Not implemented')

    def test_read_no_padding(self):
        self.skip('Not implemented')

    def test_read_with_padding(self):
        self.skip('Not implemented')


class TestName(TestCase):

    def setUp(self):
        super(TestName, self).setUp()
        self.stream = BytearrayStream()
        self.badFormatName = 8675309
        self.stringName1 = 'Jenny'
        self.enumNameType = NameType.UNINTERPRETED_TEXT_STRING

    def tearDown(self):
        super(TestName, self).tearDown()

    def test_bad_name_value_format(self):
        """
         Test that an error is raised in for an incorrectly formatted name
         value
        """
        name_obj = Name()
        name_obj.name_value = self.badFormatName
        name_obj.name_type = self.enumNameType

        self.assertRaises(TypeError, name_obj.validate)

    def test_bad_name_type_format(self):
        """
         Test that an error is raised for an incorrectly formatted name type
        """
        name_obj = Name()
        name_obj.name_value = self.stringName1
        name_obj.name_type = self.badFormatName

        self.assertRaises(TypeError, name_obj.validate)

    def test_name_create_string_input(self):
        """
         Test the creation of object names with an enum value for the name type
        """
        name_obj = Name.create(self.stringName1, self.enumNameType)
        self.assertIsInstance(name_obj.name_value, Name.NameValue)
        self.assertEqual(self.stringName1, name_obj.name_value.value)

    def test_name_create_bad_input(self):
        """
         Test the creation of object names with a bad value input
        """
        name_value = self.badFormatName
        name_type = self.enumNameType

        self.assertRaises(TypeError, Name.create, *(name_value, name_type))

    def test_name_create_bad_type_input(self):
        """
         Test the creation of object names with a bad value input
        """
        self.assertRaises(TypeError, Name.create, *(self.stringName1,
                                                    self.badFormatName))


class TestOperationPolicyName(TestCase):

    def setUp(self):
        super(TestOperationPolicyName, self).setUp()

    def tearDown(self):
        super(TestOperationPolicyName, self).tearDown()

    def _test_operation_policy_name(self, value):
        opn = OperationPolicyName(value)

        if value is None:
            value = ''

        msg = "expected {0}, received {1}".format(value, opn.value)
        self.assertEqual(value, opn.value, msg)

    def test_operation_policy_name(self):
        self._test_operation_policy_name('test')

    def test_operation_policy_name_on_none(self):
        self._test_operation_policy_name(None)


class TestHashingAlgorithm(TestCase):
    """
    A test suite for the HashingAlgorithm class.

    Since HashingAlgorithm is a simple wrapper for the Enumeration primitive,
    only a few tests pertaining to construction are needed.
    """

    def setUp(self):
        super(TestHashingAlgorithm, self).setUp()

    def tearDown(self):
        super(TestHashingAlgorithm, self).tearDown()

    def _test_init(self, value):
        if (isinstance(value, HashingAlgorithmEnum)) or (value is None):
            hashing_algorithm = HashingAlgorithm(value)

            msg = "expected {0}, observed {1}".format(
                value, hashing_algorithm.value)
            self.assertEqual(value, hashing_algorithm.value, msg)
        else:
            self.assertRaises(TypeError, HashingAlgorithm, value)

    def test_init_with_none(self):
        """
        Test that a HashingAlgorithm object can be constructed with no
        specified value.
        """
        self._test_init(None)

    def test_init_with_valid(self):
        """
        Test that a HashingAlgorithm object can be constructed with a valid
        HashingAlgorithm enumeration value.
        """
        self._test_init(HashingAlgorithmEnum.MD5)

    def test_init_with_invalid(self):
        """
        Test that a TypeError exception is raised when a non HashingAlgorithm
        enumeration value is used to construct a HashingAlgorithm object.
        """
        self._test_init("invalid")


# TODO (peter-hamilton) Replace with generic Enumeration subclass test suite.
class TestCertificateType(TestCase):
    """
    A test suite for the CertificateType class.

    Since CertificateType is a simple wrapper for the Enumeration primitive,
    only a few tests pertaining to construction are needed.
    """

    def setUp(self):
        super(TestCertificateType, self).setUp()

    def tearDown(self):
        super(TestCertificateType, self).tearDown()

    def _test_init(self, value):
        if (isinstance(value, CertificateTypeEnum)) or (value is None):
            if value is None:
                certificate_type = CertificateType()
                value = CertificateTypeEnum.X_509
            else:
                certificate_type = CertificateType(value)

            msg = "expected {0}, observed {1}".format(
                value, certificate_type.value)
            self.assertEqual(value, certificate_type.value, msg)
        else:
            self.assertRaises(TypeError, CertificateType, value)

    def test_init_with_none(self):
        """
        Test that a CertificateType object can be constructed with no specified
        value.
        """
        self._test_init(None)

    def test_init_with_valid(self):
        """
        Test that a CertificateType object can be constructed with valid byte
        data.
        """
        self._test_init(CertificateTypeEnum.PGP)


class TestDigestValue(TestCase):
    """
    A test suite for the DigestValue class.

    Since DigestValue is a simple wrapper for the ByteString primitive, only
    a few tests pertaining to construction are needed.
    """

    def setUp(self):
        super(TestDigestValue, self).setUp()

    def tearDown(self):
        super(TestDigestValue, self).tearDown()

    def _test_init(self, value):
        if (isinstance(value, bytes)) or (value is None):
            digest_value = DigestValue(value)

            if value is None:
                value = bytes()

            msg = "expected {0}, observed {1}".format(
                value, digest_value.value)
            self.assertEqual(value, digest_value.value, msg)
        else:
            self.assertRaises(TypeError, DigestValue, value)

    def test_init_with_none(self):
        """
        Test that a DigestValue object can be constructed with no specified
        value.
        """
        self._test_init(None)

    def test_init_with_valid(self):
        """
        Test that a DigestValue object can be constructed with valid byte data.
        """
        self._test_init(b'\x00\x01\x02\x03')


class TestApplicationNamespace(TestCase):
    """
    A test suite for the ApplicationNamespace class.

    Since ApplicationNamespace is a simple wrapper for the TextString
    primitive, only a few tests pertaining to construction are needed.
    """

    def setUp(self):
        super(TestApplicationNamespace, self).setUp()

    def tearDown(self):
        super(TestApplicationNamespace, self).tearDown()

    def _test_init(self, value):
        if (isinstance(value, str)) or (value is None):
            application_namespace = ApplicationNamespace(value)

            if value is None:
                value = ''

            msg = "expected {0}, observed {1}".format(
                value, application_namespace.value)
            self.assertEqual(value, application_namespace.value, msg)
        else:
            self.assertRaises(TypeError, ApplicationNamespace, value)

    def test_init_with_none(self):
        """
        Test that an ApplicationNamespace object can be constructed with no
        specified value.
        """
        self._test_init(None)

    def test_init_with_valid(self):
        """
        Test that an ApplicationNamespace object can be constructed with a
        valid, string-type value.
        """
        self._test_init("valid")

    def test_init_with_invalid(self):
        """
        Test that a TypeError exception is raised when a non-string value is
        used to construct an ApplicationNamespace object.
        """
        self._test_init(0)


class TestApplicationData(TestCase):
    """
    A test suite for the ApplicationData class.

    Since ApplicationData is a simple wrapper for the TextString primitive,
    only a few tests pertaining to construction are needed.
    """

    def setUp(self):
        super(TestApplicationData, self).setUp()

    def tearDown(self):
        super(TestApplicationData, self).tearDown()

    def _test_init(self, value):
        if (isinstance(value, str)) or (value is None):
            application_data = ApplicationData(value)

            if value is None:
                value = ''

            msg = "expected {0}, observed {1}".format(
                value, application_data.value)
            self.assertEqual(value, application_data.value, msg)
        else:
            self.assertRaises(TypeError, ApplicationData, value)

    def test_init_with_none(self):
        """
        Test that an ApplicationData object can be constructed with no
        specified value.
        """
        self._test_init(None)

    def test_init_with_valid(self):
        """
        Test that an ApplicationData object can be constructed with a
        valid, string-type value.
        """
        self._test_init("valid")

    def test_init_with_invalid(self):
        """
        Test that a TypeError exception is raised when a non-string value is
        used to construct an ApplicationData object.
        """
        self._test_init(0)


class TestCryptographicParameters(TestCase):
    """
    A test suite for the CryptographicParameters class
    """

    def setUp(self):
        super(TestCryptographicParameters, self).setUp()

        self.factory = AttributeValueFactory()

        self.cp = self.factory.create_attribute_value(
            AttributeType.CRYPTOGRAPHIC_PARAMETERS,
            {'block_cipher_mode': BlockCipherMode.CBC,
             'padding_method': PaddingMethod.PKCS5,
             'hashing_algorithm': HashingAlgorithmEnum.SHA_1,
             'key_role_type': KeyRoleType.BDK})

        self.cp_none = self.factory.create_attribute_value(
            AttributeType.CRYPTOGRAPHIC_PARAMETERS, {})

        # Symmetric key object with Cryptographic Parameters
        # Byte stream edited to add Key Role Type parameter
        # Based on the KMIP Spec 1.1 Test Cases document
        # 11.1 page 255 on the pdf version
        self.key_req_with_crypt_params = BytearrayStream((
            b'\x42\x00\x2B\x01\x00\x00\x00\x40'
            b'\x42\x00\x11\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x5F\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x38\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x83\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        ))

    def teardown(self):
        super(TestDigestValue, self).tearDown()

    def test_write_crypto_params(self):
        ostream = BytearrayStream()
        self.cp.write(ostream)
        self.assertEqual(self.key_req_with_crypt_params, ostream)

    def test_read_crypto_params(self):
        CryptographicParameters.read(self.cp, self.key_req_with_crypt_params)

        self.assertEqual(Tags.BLOCK_CIPHER_MODE.value,
                         self.cp.block_cipher_mode.tag.value)
        self.assertEqual(BlockCipherMode.CBC.value,
                         self.cp.block_cipher_mode.value.value)

        self.assertEqual(Tags.PADDING_METHOD.value,
                         self.cp.padding_method.tag.value)
        self.assertEqual(PaddingMethod.PKCS5.value,
                         self.cp.padding_method.value.value)

        self.assertEqual(Tags.KEY_ROLE_TYPE.value,
                         self.cp.key_role_type.tag.value)
        self.assertEqual(KeyRoleType.BDK.value,
                         self.cp.key_role_type.value.value)

        self.assertEqual(Tags.HASHING_ALGORITHM.value,
                         self.cp.hashing_algorithm.tag.value)
        self.assertEqual(HashingAlgorithmEnum.SHA_1.value,
                         self.cp.hashing_algorithm.value.value)
