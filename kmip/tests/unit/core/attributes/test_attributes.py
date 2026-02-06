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

from kmip.core.attributes import CertificateType
from kmip.core.attributes import CryptographicParameters
from kmip.core.attributes import DerivationParameters
from kmip.core.attributes import DigestValue
from kmip.core.attributes import HashingAlgorithm
from kmip.core.attributes import Name
from kmip.core.attributes import OperationPolicyName

from kmip.core import enums
from kmip.core.enums import HashingAlgorithm as HashingAlgorithmEnum
from kmip.core.enums import NameType

from kmip.core.utils import BytearrayStream

class TestNameValue(TestCase):

    def setUp(self):
        super(TestNameValue, self).setUp()
        self.stream = BytearrayStream()
        self.stringName1 = 'Jenny'
        self.stringName2 = 'Johnny'

    def tearDown(self):
        super(TestNameValue, self).tearDown()

    def test_write_no_padding(self):
        self.skipTest('Not implemented')

    def test_write_with_padding(self):
        self.skipTest('Not implemented')

    def test_read_no_padding(self):
        self.skipTest('Not implemented')

    def test_read_with_padding(self):
        self.skipTest('Not implemented')

    def test__eq(self):
        name_val = Name.NameValue(self.stringName1)
        same_name_val = Name.NameValue(self.stringName1)
        other_name_val = Name.NameValue(self.stringName2)

        self.assertTrue(name_val == same_name_val)
        self.assertFalse(name_val == other_name_val)
        self.assertFalse(name_val == 'invalid')

    def test__ne(self):
        name_val = Name.NameValue(self.stringName1)
        other_name_val = Name.NameValue(self.stringName2)

        self.assertTrue(name_val != other_name_val)
        self.assertTrue(name_val != 'invalid')

    def test__str(self):
        name_val = Name.NameValue(self.stringName1)
        repr_name = "NameValue(value='{0}')".format(self.stringName1)

        self.assertEqual(self.stringName1, str(name_val))
        self.assertEqual(repr_name, repr(name_val))

class TestNameType(TestCase):

    def setUp(self):
        super(TestNameType, self).setUp()
        self.stream = BytearrayStream()
        self.enum_uri = NameType.URI
        self.enum_txt = NameType.UNINTERPRETED_TEXT_STRING

    def tearDown(self):
        super(TestNameType, self).tearDown()

    def test_write_no_padding(self):
        self.skipTest('Not implemented')

    def test_write_with_padding(self):
        self.skipTest('Not implemented')

    def test_read_no_padding(self):
        self.skipTest('Not implemented')

    def test_read_with_padding(self):
        self.skipTest('Not implemented')

    def test__eq(self):
        type_uri = Name.NameType(self.enum_uri)
        same_type = Name.NameType(self.enum_uri)
        type_txt = Name.NameType(self.enum_txt)

        self.assertTrue(type_uri == same_type)
        self.assertFalse(type_uri == type_txt)
        self.assertFalse(type_uri == 'invalid')

    def test__ne(self):
        type_uri = Name.NameType(self.enum_uri)
        same_type = Name.NameType(self.enum_uri)
        type_txt = Name.NameType(self.enum_txt)

        self.assertFalse(type_uri != same_type)
        self.assertTrue(type_uri != type_txt)
        self.assertTrue(type_uri != 'invalid')

    def test__str(self):
        type_uri = Name.NameType(self.enum_uri)
        str_uri = "{0}".format(self.enum_uri)
        repr_uri = "NameType(value=<{0}: {1}>)".format(
                self.enum_uri,
                self.enum_uri.value)

        self.assertEqual(str_uri, str(type_uri))
        self.assertEqual(repr_uri, repr(type_uri))

class TestName(TestCase):

    def setUp(self):
        super(TestName, self).setUp()
        self.stream = BytearrayStream()
        self.badFormatName = 8675309
        self.stringName1 = 'Jenny'
        self.stringName2 = 'Johnny'
        self.enumNameType = NameType.UNINTERPRETED_TEXT_STRING
        self.enumNameTypeUri = NameType.URI

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

    def test__eq(self):
        name_obj = Name.create(self.stringName1, self.enumNameType)
        same_name = Name.create(self.stringName1, self.enumNameType)
        other_name = Name.create(self.stringName2, self.enumNameType)
        other_type = Name.create(self.stringName1, self.enumNameTypeUri)

        self.assertTrue(name_obj == same_name)
        self.assertFalse(name_obj == other_name)
        self.assertFalse(name_obj == other_type)
        self.assertFalse(name_obj == 'invalid')

    def test__ne(self):
        name_obj = Name.create(self.stringName1, self.enumNameType)
        same_name = Name.create(self.stringName1, self.enumNameType)
        other_name = Name.create(self.stringName2, self.enumNameType)
        other_type = Name.create(self.stringName1, self.enumNameTypeUri)

        self.assertFalse(name_obj != same_name)
        self.assertNotEqual(name_obj, other_name)
        self.assertNotEqual(name_obj, other_type)

    def test__str(self):
        name_obj = Name.create(self.stringName1, self.enumNameType)
        repr_name = (
                "Name(type=NameType(value="
                "<NameType.UNINTERPRETED_TEXT_STRING: {0}>),"
                "value=NameValue(value='{1}'))"
                ).format(self.enumNameType.value, self.stringName1)

        self.assertEqual(self.stringName1, str(name_obj))
        self.assertEqual(repr_name, repr(name_obj))

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
        if (isinstance(value, enums.CertificateType)) or (value is None):
            if value is None:
                certificate_type = CertificateType()
                value = enums.CertificateType.X_509
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
        self._test_init(enums.CertificateType.PGP)

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

class TestCryptographicParameters(TestCase):
    """
    Test suite for the CryptographicParameters struct.
    """

    def setUp(self):
        super(TestCryptographicParameters, self).setUp()

        # Encoding obtained in part from the KMIP 1.1 testing document,
        # Section 11.1. The rest of the encoding for KMIP 1.2+ features was
        # built by hand; later KMIP testing documents do not include the
        # encoding, so a manual construction is necessary.
        #
        # This encoding matches the following set of values:
        # Block Cipher Mode - CBC
        # Padding Method - PKCS5
        # Hashing Algorithm - SHA-1
        # Key Role Type - KEK
        # Digital Signature Algorithm - SHA-256 with RSA
        # Cryptographic Algorithm - AES
        # Random IV - True
        # IV Length - 96
        # Tag Length - 128
        # Fixed Field Length - 32
        # Invocation Field Length - 64
        # Counter Length - 0
        # Initial Counter Value - 1

        self.full_encoding = BytearrayStream(
            b'\x42\x00\x2B\x01\x00\x00\x00\xD0'
            b'\x42\x00\x11\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x5F\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x38\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x83\x05\x00\x00\x00\x04\x00\x00\x00\x0B\x00\x00\x00\x00'
            b'\x42\x00\xAE\x05\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xC5\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01'
            b'\x42\x00\xCD\x02\x00\x00\x00\x04\x00\x00\x00\x60\x00\x00\x00\x00'
            b'\x42\x00\xCE\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
            b'\x42\x00\xCF\x02\x00\x00\x00\x04\x00\x00\x00\x20\x00\x00\x00\x00'
            b'\x42\x00\xD2\x02\x00\x00\x00\x04\x00\x00\x00\x40\x00\x00\x00\x00'
            b'\x42\x00\xD0\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xD1\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # Adapted from the full encoding above. This encoding matches the
        # following set of values:
        # Block Cipher Mode - CBC
        # Padding Method - PKCS5
        # Hashing Algorithm - SHA-1
        # Key Role Type - KEK
        # Digital Signature Algorithm - SHA-256 with RSA
        # Cryptographic Algorithm - AES
        # Tag Length - 128
        # Initial Counter Value - 1

        self.partial_encoding = BytearrayStream(
            b'\x42\x00\x2B\x01\x00\x00\x00\x80'
            b'\x42\x00\x11\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x5F\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x38\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x83\x05\x00\x00\x00\x04\x00\x00\x00\x0B\x00\x00\x00\x00'
            b'\x42\x00\xAE\x05\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xCE\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
            b'\x42\x00\xD1\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        self.empty_encoding = BytearrayStream(
            b'\x42\x00\x2B\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestCryptographicParameters, self).tearDown()

    def test_init(self):
        """
        Test that a CryptographicParameters struct can be constructed with
        no arguments.
        """
        cryptographic_parameters = CryptographicParameters()

        self.assertEqual(None, cryptographic_parameters.block_cipher_mode)
        self.assertEqual(None, cryptographic_parameters.padding_method)
        self.assertEqual(None, cryptographic_parameters.hashing_algorithm)
        self.assertEqual(None, cryptographic_parameters.key_role_type)
        self.assertEqual(
            None,
            cryptographic_parameters.digital_signature_algorithm
        )
        self.assertEqual(
            None,
            cryptographic_parameters.cryptographic_algorithm
        )
        self.assertEqual(None, cryptographic_parameters.random_iv)
        self.assertEqual(None, cryptographic_parameters.iv_length)
        self.assertEqual(None, cryptographic_parameters.tag_length)
        self.assertEqual(None, cryptographic_parameters.fixed_field_length)
        self.assertEqual(
            None,
            cryptographic_parameters.invocation_field_length
        )
        self.assertEqual(None, cryptographic_parameters.counter_length)
        self.assertEqual(None, cryptographic_parameters.initial_counter_value)

    def test_init_with_args(self):
        """
        Test that a CryptographicParameters struct can be constructed with
        valid values.
        """
        cryptographic_parameters = CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CTR,
            padding_method=enums.PaddingMethod.NONE,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256,
            key_role_type=enums.KeyRoleType.BDK,
            digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
            SHA1_WITH_RSA_ENCRYPTION,
            cryptographic_algorithm=enums.CryptographicAlgorithm.TRIPLE_DES,
            random_iv=False,
            iv_length=128,
            tag_length=256,
            fixed_field_length=48,
            invocation_field_length=60,
            counter_length=20,
            initial_counter_value=2
        )

        self.assertEqual(
            enums.BlockCipherMode.CTR,
            cryptographic_parameters.block_cipher_mode
        )
        self.assertEqual(
            enums.PaddingMethod.NONE,
            cryptographic_parameters.padding_method
        )
        self.assertEqual(
            enums.HashingAlgorithm.SHA_256,
            cryptographic_parameters.hashing_algorithm
        )
        self.assertEqual(
            enums.KeyRoleType.BDK,
            cryptographic_parameters.key_role_type
        )
        self.assertEqual(
            enums.DigitalSignatureAlgorithm.SHA1_WITH_RSA_ENCRYPTION,
            cryptographic_parameters.digital_signature_algorithm
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.TRIPLE_DES,
            cryptographic_parameters.cryptographic_algorithm
        )
        self.assertEqual(False, cryptographic_parameters.random_iv)
        self.assertEqual(128, cryptographic_parameters.iv_length)
        self.assertEqual(256, cryptographic_parameters.tag_length)
        self.assertEqual(48, cryptographic_parameters.fixed_field_length)
        self.assertEqual(60, cryptographic_parameters.invocation_field_length)
        self.assertEqual(20, cryptographic_parameters.counter_length)
        self.assertEqual(2, cryptographic_parameters.initial_counter_value)

    def test_invalid_block_cipher_mode(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the block cipher mode of a CryptographicParameters struct.
        """
        cryptographic_parameters = CryptographicParameters()
        args = (cryptographic_parameters, 'block_cipher_mode', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "block cipher mode must be a BlockCipherMode enumeration",
            setattr,
            *args
        )

    def test_invalid_padding_method(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the padding method of a CryptographicParameters struct.
        """
        cryptographic_parameters = CryptographicParameters()
        args = (cryptographic_parameters, 'padding_method', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "padding method must be a PaddingMethod enumeration",
            setattr,
            *args
        )

    def test_invalid_hashing_algorithm(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the hashing algorithm of a CryptographicParameters struct.
        """
        cryptographic_parameters = CryptographicParameters()
        args = (cryptographic_parameters, 'hashing_algorithm', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "hashing algorithm must be a HashingAlgorithm enumeration",
            setattr,
            *args
        )

    def test_invalid_key_role_type(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the key role type of a CryptographicParameters struct.
        """
        cryptographic_parameters = CryptographicParameters()
        args = (cryptographic_parameters, 'key_role_type', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "key role type must be a KeyRoleType enumeration",
            setattr,
            *args
        )

    def test_invalid_digital_signature_algorithm(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the digital signature algorithm of a CryptographicParameters struct.
        """
        cryptographic_parameters = CryptographicParameters()
        args = (
            cryptographic_parameters,
            'digital_signature_algorithm',
            'invalid'
        )
        self.assertRaisesRegex(
            TypeError,
            "digital signature algorithm must be a "
            "DigitalSignatureAlgorithm enumeration",
            setattr,
            *args
        )

    def test_invalid_cryptographic_algorithm(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the cryptographic algorithm of a CryptographicParameters struct.
        """
        cryptographic_parameters = CryptographicParameters()
        args = (cryptographic_parameters, 'cryptographic_algorithm', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "cryptographic algorithm must be a CryptographicAlgorithm "
            "enumeration",
            setattr,
            *args
        )

    def test_invalid_cryptographic_algorithm_enum_type(self):
        """
        Test that a TypeError is raised when an enum of the wrong type is
        used for the cryptographic algorithm.
        """
        cryptographic_parameters = CryptographicParameters()
        args = (
            cryptographic_parameters,
            'cryptographic_algorithm',
            enums.ObjectType.SYMMETRIC_KEY
        )
        self.assertRaisesRegex(
            TypeError,
            "cryptographic algorithm must be a CryptographicAlgorithm "
            "enumeration",
            setattr,
            *args
        )

    def test_invalid_cryptographic_algorithm_int(self):
        """
        Test that a TypeError is raised when an integer is used for the
        cryptographic algorithm.
        """
        cryptographic_parameters = CryptographicParameters()
        args = (cryptographic_parameters, 'cryptographic_algorithm', 1)
        self.assertRaisesRegex(
            TypeError,
            "cryptographic algorithm must be a CryptographicAlgorithm "
            "enumeration",
            setattr,
            *args
        )

    def test_invalid_random_iv(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the random IV of a CryptographicParameters struct.
        """
        cryptographic_parameters = CryptographicParameters()
        args = (cryptographic_parameters, 'random_iv', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "random iv must be a boolean",
            setattr,
            *args
        )

    def test_invalid_iv_length(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the IV length of a CryptographicParameters struct.
        """
        cryptographic_parameters = CryptographicParameters()
        args = (cryptographic_parameters, 'iv_length', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "iv length must be an integer",
            setattr,
            *args
        )

    def test_invalid_tag_length(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the tag length of a CryptographicParameters struct.
        """
        cryptographic_parameters = CryptographicParameters()
        args = (cryptographic_parameters, 'tag_length', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "tag length must be an integer",
            setattr,
            *args
        )

    def test_invalid_fixed_field_length(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the fixed field length of a CryptographicParameters struct.
        """
        cryptographic_parameters = CryptographicParameters()
        args = (cryptographic_parameters, 'fixed_field_length', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "fixed field length must be an integer",
            setattr,
            *args
        )

    def test_invalid_invocation_field_length(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the invocation field length of a CryptographicParameters struct.
        """
        cryptographic_parameters = CryptographicParameters()
        args = (cryptographic_parameters, 'invocation_field_length', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "invocation field length must be an integer",
            setattr,
            *args
        )

    def test_invalid_counter_length(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the counter length of a CryptographicParameters struct.
        """
        cryptographic_parameters = CryptographicParameters()
        args = (cryptographic_parameters, 'counter_length', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "counter length must be an integer",
            setattr,
            *args
        )

    def test_invalid_initial_counter_value(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the counter value of a CryptographicParameters struct.
        """
        cryptographic_parameters = CryptographicParameters()
        args = (cryptographic_parameters, 'initial_counter_value', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "initial counter value must be an integer",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a CryptographicParameters struct can be read from a data
        stream.
        """
        cryptographic_parameters = CryptographicParameters()

        self.assertEqual(None, cryptographic_parameters.block_cipher_mode)
        self.assertEqual(None, cryptographic_parameters.padding_method)
        self.assertEqual(None, cryptographic_parameters.hashing_algorithm)
        self.assertEqual(None, cryptographic_parameters.key_role_type)
        self.assertEqual(
            None,
            cryptographic_parameters.digital_signature_algorithm
        )
        self.assertEqual(
            None,
            cryptographic_parameters.cryptographic_algorithm
        )
        self.assertEqual(None, cryptographic_parameters.random_iv)
        self.assertEqual(None, cryptographic_parameters.iv_length)
        self.assertEqual(None, cryptographic_parameters.tag_length)
        self.assertEqual(None, cryptographic_parameters.fixed_field_length)
        self.assertEqual(
            None,
            cryptographic_parameters.invocation_field_length
        )
        self.assertEqual(None, cryptographic_parameters.counter_length)
        self.assertEqual(None, cryptographic_parameters.initial_counter_value)

        cryptographic_parameters.read(self.full_encoding)

        self.assertEqual(
            enums.BlockCipherMode.CBC,
            cryptographic_parameters.block_cipher_mode
        )
        self.assertEqual(
            enums.PaddingMethod.PKCS5,
            cryptographic_parameters.padding_method
        )
        self.assertEqual(
            enums.HashingAlgorithm.SHA_1,
            cryptographic_parameters.hashing_algorithm
        )
        self.assertEqual(
            enums.KeyRoleType.KEK,
            cryptographic_parameters.key_role_type
        )
        self.assertEqual(
            enums.DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION,
            cryptographic_parameters.digital_signature_algorithm
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            cryptographic_parameters.cryptographic_algorithm
        )
        self.assertEqual(True, cryptographic_parameters.random_iv)
        self.assertEqual(96, cryptographic_parameters.iv_length)
        self.assertEqual(128, cryptographic_parameters.tag_length)
        self.assertEqual(32, cryptographic_parameters.fixed_field_length)
        self.assertEqual(64, cryptographic_parameters.invocation_field_length)
        self.assertEqual(0, cryptographic_parameters.counter_length)
        self.assertEqual(1, cryptographic_parameters.initial_counter_value)

    def test_read_partial(self):
        """
        Test that a CryptographicParameters struct can be read from a partial
        data stream.
        """
        cryptographic_parameters = CryptographicParameters()

        self.assertEqual(None, cryptographic_parameters.block_cipher_mode)
        self.assertEqual(None, cryptographic_parameters.padding_method)
        self.assertEqual(None, cryptographic_parameters.hashing_algorithm)
        self.assertEqual(None, cryptographic_parameters.key_role_type)
        self.assertEqual(
            None,
            cryptographic_parameters.digital_signature_algorithm
        )
        self.assertEqual(
            None,
            cryptographic_parameters.cryptographic_algorithm
        )
        self.assertEqual(None, cryptographic_parameters.random_iv)
        self.assertEqual(None, cryptographic_parameters.iv_length)
        self.assertEqual(None, cryptographic_parameters.tag_length)
        self.assertEqual(None, cryptographic_parameters.fixed_field_length)
        self.assertEqual(
            None,
            cryptographic_parameters.invocation_field_length
        )
        self.assertEqual(None, cryptographic_parameters.counter_length)
        self.assertEqual(None, cryptographic_parameters.initial_counter_value)

        cryptographic_parameters.read(self.partial_encoding)

        self.assertEqual(
            enums.BlockCipherMode.CBC,
            cryptographic_parameters.block_cipher_mode
        )
        self.assertEqual(
            enums.PaddingMethod.PKCS5,
            cryptographic_parameters.padding_method
        )
        self.assertEqual(
            enums.HashingAlgorithm.SHA_1,
            cryptographic_parameters.hashing_algorithm
        )
        self.assertEqual(
            enums.KeyRoleType.KEK,
            cryptographic_parameters.key_role_type
        )
        self.assertEqual(
            enums.DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION,
            cryptographic_parameters.digital_signature_algorithm
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            cryptographic_parameters.cryptographic_algorithm
        )
        self.assertEqual(None, cryptographic_parameters.random_iv)
        self.assertEqual(None, cryptographic_parameters.iv_length)
        self.assertEqual(128, cryptographic_parameters.tag_length)
        self.assertEqual(None, cryptographic_parameters.fixed_field_length)
        self.assertEqual(
            None,
            cryptographic_parameters.invocation_field_length
        )
        self.assertEqual(None, cryptographic_parameters.counter_length)
        self.assertEqual(1, cryptographic_parameters.initial_counter_value)

    def test_read_empty(self):
        """
        Test that a CryptographicParameters struct can be read from an empty
        data stream.
        """
        cryptographic_parameters = CryptographicParameters()

        self.assertEqual(None, cryptographic_parameters.block_cipher_mode)
        self.assertEqual(None, cryptographic_parameters.padding_method)
        self.assertEqual(None, cryptographic_parameters.hashing_algorithm)
        self.assertEqual(None, cryptographic_parameters.key_role_type)
        self.assertEqual(
            None,
            cryptographic_parameters.digital_signature_algorithm
        )
        self.assertEqual(
            None,
            cryptographic_parameters.cryptographic_algorithm
        )
        self.assertEqual(None, cryptographic_parameters.random_iv)
        self.assertEqual(None, cryptographic_parameters.iv_length)
        self.assertEqual(None, cryptographic_parameters.tag_length)
        self.assertEqual(None, cryptographic_parameters.fixed_field_length)
        self.assertEqual(
            None,
            cryptographic_parameters.invocation_field_length
        )
        self.assertEqual(None, cryptographic_parameters.counter_length)
        self.assertEqual(None, cryptographic_parameters.initial_counter_value)

        cryptographic_parameters.read(self.empty_encoding)

        self.assertEqual(None, cryptographic_parameters.block_cipher_mode)
        self.assertEqual(None, cryptographic_parameters.padding_method)
        self.assertEqual(None, cryptographic_parameters.hashing_algorithm)
        self.assertEqual(None, cryptographic_parameters.key_role_type)
        self.assertEqual(
            None,
            cryptographic_parameters.digital_signature_algorithm
        )
        self.assertEqual(
            None,
            cryptographic_parameters.cryptographic_algorithm
        )
        self.assertEqual(None, cryptographic_parameters.random_iv)
        self.assertEqual(None, cryptographic_parameters.iv_length)
        self.assertEqual(None, cryptographic_parameters.tag_length)
        self.assertEqual(None, cryptographic_parameters.fixed_field_length)
        self.assertEqual(
            None,
            cryptographic_parameters.invocation_field_length
        )
        self.assertEqual(None, cryptographic_parameters.counter_length)
        self.assertEqual(None, cryptographic_parameters.initial_counter_value)

    def test_write(self):
        """
        Test that a CryptographicParameters struct can be written to a data
        stream.
        """
        cryptographic_parameters = CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            hashing_algorithm=enums.HashingAlgorithm.SHA_1,
            key_role_type=enums.KeyRoleType.KEK,
            digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
            SHA256_WITH_RSA_ENCRYPTION,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            random_iv=True,
            iv_length=96,
            tag_length=128,
            fixed_field_length=32,
            invocation_field_length=64,
            counter_length=0,
            initial_counter_value=1
        )
        stream = BytearrayStream()
        cryptographic_parameters.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_partial(self):
        """
        Test that a partially defined CryptographicParameters struct can be
        written to a data stream.
        """
        cryptographic_parameters = CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            hashing_algorithm=enums.HashingAlgorithm.SHA_1,
            key_role_type=enums.KeyRoleType.KEK,
            digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
            SHA256_WITH_RSA_ENCRYPTION,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            tag_length=128,
            initial_counter_value=1
        )
        stream = BytearrayStream()
        cryptographic_parameters.write(stream)

        self.assertEqual(len(self.partial_encoding), len(stream))
        self.assertEqual(str(self.partial_encoding), str(stream))

    def test_write_empty(self):
        """
        Test that an empty CryptographicParameters struct can be written to a
        data stream.
        """
        cryptographic_parameters = CryptographicParameters()
        stream = BytearrayStream()
        cryptographic_parameters.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        CryptographicParameters structs with the same data.
        """
        a = CryptographicParameters()
        b = CryptographicParameters()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            hashing_algorithm=enums.HashingAlgorithm.SHA_1,
            key_role_type=enums.KeyRoleType.KEK,
            digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
            SHA256_WITH_RSA_ENCRYPTION,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            random_iv=True,
            iv_length=96,
            tag_length=128,
            fixed_field_length=32,
            invocation_field_length=64,
            counter_length=0,
            initial_counter_value=1
        )
        b = CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            hashing_algorithm=enums.HashingAlgorithm.SHA_1,
            key_role_type=enums.KeyRoleType.KEK,
            digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
            SHA256_WITH_RSA_ENCRYPTION,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            random_iv=True,
            iv_length=96,
            tag_length=128,
            fixed_field_length=32,
            invocation_field_length=64,
            counter_length=0,
            initial_counter_value=1
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_block_cipher_mode(self):
        """
        Test that the equality operator returns False when comparing two
        CryptographicParameters structs with different block cipher modes.
        """
        a = CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC
        )
        b = CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.GCM
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_padding_method(self):
        """
        Test that the equality operator returns False when comparing two
        CryptographicParameters structs with different padding methods.
        """
        a = CryptographicParameters(padding_method=enums.PaddingMethod.NONE)
        b = CryptographicParameters(padding_method=enums.PaddingMethod.PKCS5)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_hashing_algorithm(self):
        """
        Test that the equality operator returns False when comparing two
        CryptographicParameters structs with different hashing algorithms.
        """
        a = CryptographicParameters(
            hashing_algorithm=enums.HashingAlgorithm.MD5
        )
        b = CryptographicParameters(
            hashing_algorithm=enums.HashingAlgorithm.SHA_256
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_key_role_type(self):
        """
        Test that the equality operator returns False when comparing two
        CryptographicParameters structs with different key role types.
        """
        a = CryptographicParameters(key_role_type=enums.KeyRoleType.BDK)
        b = CryptographicParameters(key_role_type=enums.KeyRoleType.KEK)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_digital_signature_algorithm(self):
        """
        Test that the equality operator returns False when comparing two
        CryptographicParameters structs with different digital signature
        algorithms.
        """
        a = CryptographicParameters(
            digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
            DSA_WITH_SHA1
        )
        b = CryptographicParameters(
            digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
            ECDSA_WITH_SHA1
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_cryptographic_algorithm(self):
        """
        Test that the equality operator returns False when comparing two
        CryptographicParameters structs with different cryptographic
        algorithms.
        """
        a = CryptographicParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES
        )
        b = CryptographicParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.DES
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_random_iv(self):
        """
        Test that the equality operator returns False when comparing two
        CryptographicParameters structs with different random IVs.
        """
        a = CryptographicParameters(random_iv=True)
        b = CryptographicParameters(random_iv=False)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_iv_length(self):
        """
        Test that the equality operator returns False when comparing two
        CryptographicParameters structs with different IV lengths.
        """
        a = CryptographicParameters(iv_length=96)
        b = CryptographicParameters(iv_length=128)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_tag_length(self):
        """
        Test that the equality operator returns False when comparing two
        CryptographicParameters structs with different tag lengths.
        """
        a = CryptographicParameters(tag_length=128)
        b = CryptographicParameters(tag_length=256)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_fixed_field_length(self):
        """
        Test that the equality operator returns False when comparing two
        CryptographicParameters structs with different fixed field lengths.
        """
        a = CryptographicParameters(fixed_field_length=32)
        b = CryptographicParameters(fixed_field_length=40)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_invocation_field_length(self):
        """
        Test that the equality operator returns False when comparing two
        CryptographicParameters structs with different invocation field
        lengths.
        """
        a = CryptographicParameters(invocation_field_length=64)
        b = CryptographicParameters(invocation_field_length=80)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_counter_length(self):
        """
        Test that the equality operator returns False when comparing two
        CryptographicParameters structs with different counter lengths.
        """
        a = CryptographicParameters(counter_length=0)
        b = CryptographicParameters(counter_length=32)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_initial_counter_value(self):
        """
        Test that the equality operator returns False when comparing two
        CryptographicParameters structs with different counter values.
        """
        a = CryptographicParameters(initial_counter_value=0)
        b = CryptographicParameters(initial_counter_value=1)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        CryptographicParameters structs with different types.
        """
        a = CryptographicParameters()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        CryptographicParameters structs with the same data.
        """
        a = CryptographicParameters()
        b = CryptographicParameters()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            hashing_algorithm=enums.HashingAlgorithm.SHA_1,
            key_role_type=enums.KeyRoleType.KEK,
            digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
            SHA256_WITH_RSA_ENCRYPTION,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            random_iv=True,
            iv_length=96,
            tag_length=128,
            fixed_field_length=32,
            invocation_field_length=64,
            counter_length=0,
            initial_counter_value=1
        )
        b = CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            hashing_algorithm=enums.HashingAlgorithm.SHA_1,
            key_role_type=enums.KeyRoleType.KEK,
            digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
            SHA256_WITH_RSA_ENCRYPTION,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            random_iv=True,
            iv_length=96,
            tag_length=128,
            fixed_field_length=32,
            invocation_field_length=64,
            counter_length=0,
            initial_counter_value=1
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_block_cipher_mode(self):
        """
        Test that the inequality operator returns True when comparing two
        CryptographicParameters structs with different block cipher modes.
        """
        a = CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC
        )
        b = CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.GCM
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_padding_method(self):
        """
        Test that the inequality operator returns True when comparing two
        CryptographicParameters structs with different padding methods.
        """
        a = CryptographicParameters(padding_method=enums.PaddingMethod.NONE)
        b = CryptographicParameters(padding_method=enums.PaddingMethod.PKCS5)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_hashing_algorithm(self):
        """
        Test that the inequality operator returns True when comparing two
        CryptographicParameters structs with different hashing algorithms.
        """
        a = CryptographicParameters(
            hashing_algorithm=enums.HashingAlgorithm.MD5
        )
        b = CryptographicParameters(
            hashing_algorithm=enums.HashingAlgorithm.SHA_256
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_key_role_type(self):
        """
        Test that the inequality operator returns True when comparing two
        CryptographicParameters structs with different key role types.
        """
        a = CryptographicParameters(key_role_type=enums.KeyRoleType.BDK)
        b = CryptographicParameters(key_role_type=enums.KeyRoleType.KEK)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_digital_signature_algorithm(self):
        """
        Test that the inequality operator returns True when comparing two
        CryptographicParameters structs with different digital signature
        algorithms.
        """
        a = CryptographicParameters(
            digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
            DSA_WITH_SHA1
        )
        b = CryptographicParameters(
            digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
            ECDSA_WITH_SHA1
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_cryptographic_algorithm(self):
        """
        Test that the inequality operator returns True when comparing two
        CryptographicParameters structs with different cryptographic
        algorithms.
        """
        a = CryptographicParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES
        )
        b = CryptographicParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.DES
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_random_iv(self):
        """
        Test that the inequality operator returns True when comparing two
        CryptographicParameters structs with different random IVs.
        """
        a = CryptographicParameters(random_iv=True)
        b = CryptographicParameters(random_iv=False)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_iv_length(self):
        """
        Test that the inequality operator returns True when comparing two
        CryptographicParameters structs with different IV lengths.
        """
        a = CryptographicParameters(iv_length=96)
        b = CryptographicParameters(iv_length=128)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_tag_length(self):
        """
        Test that the inequality operator returns True when comparing two
        CryptographicParameters structs with different tag lengths.
        """
        a = CryptographicParameters(tag_length=128)
        b = CryptographicParameters(tag_length=256)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_fixed_field_length(self):
        """
        Test that the inequality operator returns True when comparing two
        CryptographicParameters structs with different fixed field lengths.
        """
        a = CryptographicParameters(fixed_field_length=32)
        b = CryptographicParameters(fixed_field_length=40)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_invocation_field_length(self):
        """
        Test that the inequality operator returns True when comparing two
        CryptographicParameters structs with different invocation field
        lengths.
        """
        a = CryptographicParameters(invocation_field_length=64)
        b = CryptographicParameters(invocation_field_length=80)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_counter_length(self):
        """
        Test that the inequality operator returns True when comparing two
        CryptographicParameters structs with different counter lengths.
        """
        a = CryptographicParameters(counter_length=0)
        b = CryptographicParameters(counter_length=32)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_initial_counter_value(self):
        """
        Test that the inequality operator returns True when comparing two
        CryptographicParameters structs with different counter values.
        """
        a = CryptographicParameters(initial_counter_value=0)
        b = CryptographicParameters(initial_counter_value=1)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        CryptographicParameters structs with different types.
        """
        a = CryptographicParameters()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a CryptographicParameters struct.
        """
        cryptographic_parameters = CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            hashing_algorithm=enums.HashingAlgorithm.SHA_1,
            key_role_type=enums.KeyRoleType.KEK,
            digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
            SHA256_WITH_RSA_ENCRYPTION,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            random_iv=True,
            iv_length=96,
            tag_length=128,
            fixed_field_length=32,
            invocation_field_length=64,
            counter_length=0,
            initial_counter_value=1
        )

        expected = (
            "CryptographicParameters("
            "block_cipher_mode=BlockCipherMode.CBC, "
            "padding_method=PaddingMethod.PKCS5, "
            "hashing_algorithm=HashingAlgorithm.SHA_1, "
            "key_role_type=KeyRoleType.KEK, "
            "digital_signature_algorithm="
            "DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION, "
            "cryptographic_algorithm=CryptographicAlgorithm.AES, "
            "random_iv=True, "
            "iv_length=96, "
            "tag_length=128, "
            "fixed_field_length=32, "
            "invocation_field_length=64, "
            "counter_length=0, "
            "initial_counter_value=1)"
        )
        observed = repr(cryptographic_parameters)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a GetAttributeList response payload.
        """
        cryptographic_parameters = CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            hashing_algorithm=enums.HashingAlgorithm.SHA_1,
            key_role_type=enums.KeyRoleType.KEK,
            digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
            SHA256_WITH_RSA_ENCRYPTION,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            random_iv=True,
            iv_length=96,
            tag_length=128,
            fixed_field_length=32,
            invocation_field_length=64,
            counter_length=0,
            initial_counter_value=1
        )

        expected = str({
            'block_cipher_mode': enums.BlockCipherMode.CBC,
            'padding_method': enums.PaddingMethod.PKCS5,
            'hashing_algorithm': enums.HashingAlgorithm.SHA_1,
            'key_role_type': enums.KeyRoleType.KEK,
            'digital_signature_algorithm':
                enums.DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION,
            'cryptographic_algorithm': enums.CryptographicAlgorithm.AES,
            'random_iv': True,
            'iv_length': 96,
            'tag_length': 128,
            'fixed_field_length': 32,
            'invocation_field_length': 64,
            'counter_length': 0,
            'initial_counter_value': 1
        })
        observed = str(cryptographic_parameters)

        self.assertEqual(expected, observed)

class TestDerivationParameters(TestCase):
    """
    Test suite for the DerivationParameters struct.
    """

    def setUp(self):
        super(TestDerivationParameters, self).setUp()

        # Encoding obtained in part from the KMIP 1.1 testing document,
        # Section 11.1. The rest of the encoding for KMIP 1.2+ features was
        # built by hand; later KMIP testing documents do not include the
        # encoding, so a manual construction is necessary.
        #
        # This encoding matches the following set of values:
        # Cryptographic Parameters
        #     Block Cipher Mode - CBC
        #     Padding Method - PKCS5
        #     Hashing Algorithm - SHA-1
        #     Key Role Type - KEK
        #     Digital Signature Algorithm - SHA-256 with RSA
        #     Cryptographic Algorithm - AES
        #     Random IV - True
        #     IV Length - 96
        #     Tag Length - 128
        #     Fixed Field Length - 32
        #     Invocation Field Length - 64
        #     Counter Length - 0
        #     Initial Counter Value - 1
        # Initialization Vector - 0x39487432492834A3
        # Derivation Data - 0xFAD98B6ACA6D87DD
        # Salt - 0x8F99212AA15435CD
        # Iteration Count - 10000

        self.full_encoding = BytearrayStream(
            b'\x42\x00\x32\x01\x00\x00\x01\x18'
            b'\x42\x00\x2B\x01\x00\x00\x00\xD0'
            b'\x42\x00\x11\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x5F\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x38\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x83\x05\x00\x00\x00\x04\x00\x00\x00\x0B\x00\x00\x00\x00'
            b'\x42\x00\xAE\x05\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xC5\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01'
            b'\x42\x00\xCD\x02\x00\x00\x00\x04\x00\x00\x00\x60\x00\x00\x00\x00'
            b'\x42\x00\xCE\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
            b'\x42\x00\xCF\x02\x00\x00\x00\x04\x00\x00\x00\x20\x00\x00\x00\x00'
            b'\x42\x00\xD2\x02\x00\x00\x00\x04\x00\x00\x00\x40\x00\x00\x00\x00'
            b'\x42\x00\xD0\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xD1\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x3A\x08\x00\x00\x00\x08\x39\x48\x74\x32\x49\x28\x34\xA3'
            b'\x42\x00\x30\x08\x00\x00\x00\x08\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            b'\x42\x00\x84\x08\x00\x00\x00\x08\x8F\x99\x21\x2A\xA1\x54\x35\xCD'
            b'\x42\x00\x3C\x02\x00\x00\x00\x04\x00\x00\x27\x10\x00\x00\x00\x00'
        )

        # Adapted from the full encoding above. This encoding matches the
        # following set of values:
        # Initialization Vector - 0x39487432492834A3
        # Derivation Data - 0xFAD98B6ACA6D87DD

        self.partial_encoding = BytearrayStream(
            b'\x42\x00\x32\x01\x00\x00\x00\x20'
            b'\x42\x00\x3A\x08\x00\x00\x00\x08\x39\x48\x74\x32\x49\x28\x34\xA3'
            b'\x42\x00\x30\x08\x00\x00\x00\x08\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
        )

        self.empty_encoding = BytearrayStream(
            b'\x42\x00\x32\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestDerivationParameters, self).tearDown()

    def test_init(self):
        """
        Test that a DerivationParameters struct can be constructed with
        no arguments.
        """
        derivation_parameters = DerivationParameters()

        self.assertEqual(None, derivation_parameters.cryptographic_parameters)
        self.assertEqual(None, derivation_parameters.initialization_vector)
        self.assertEqual(None, derivation_parameters.derivation_data)
        self.assertEqual(None, derivation_parameters.salt)
        self.assertEqual(None, derivation_parameters.iteration_count)

    def test_init_with_args(self):
        """
        Test that a DerivationParameters struct can be constructed with
        valid values.
        """
        cryptographic_parameters = CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CTR,
            padding_method=enums.PaddingMethod.NONE,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256,
            key_role_type=enums.KeyRoleType.BDK,
            digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
            SHA1_WITH_RSA_ENCRYPTION,
            cryptographic_algorithm=enums.CryptographicAlgorithm.TRIPLE_DES,
            random_iv=False,
            iv_length=128,
            tag_length=256,
            fixed_field_length=48,
            invocation_field_length=60,
            counter_length=20,
            initial_counter_value=2
        )
        derivation_parameters = DerivationParameters(
            cryptographic_parameters=cryptographic_parameters,
            initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
            derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD',
            salt=b'\x8F\x99\x21\x2A\xA1\x54\x35\xCD',
            iteration_count=10000
        )

        self.assertIsInstance(
            derivation_parameters.cryptographic_parameters,
            CryptographicParameters
        )
        parameters = derivation_parameters.cryptographic_parameters
        self.assertEqual(
            enums.BlockCipherMode.CTR,
            parameters.block_cipher_mode
        )
        self.assertEqual(
            enums.PaddingMethod.NONE,
            parameters.padding_method
        )
        self.assertEqual(
            enums.HashingAlgorithm.SHA_256,
            parameters.hashing_algorithm
        )
        self.assertEqual(
            enums.KeyRoleType.BDK,
            parameters.key_role_type
        )
        self.assertEqual(
            enums.DigitalSignatureAlgorithm.SHA1_WITH_RSA_ENCRYPTION,
            parameters.digital_signature_algorithm
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.TRIPLE_DES,
            parameters.cryptographic_algorithm
        )
        self.assertEqual(False, parameters.random_iv)
        self.assertEqual(128, parameters.iv_length)
        self.assertEqual(256, parameters.tag_length)
        self.assertEqual(48, parameters.fixed_field_length)
        self.assertEqual(60, parameters.invocation_field_length)
        self.assertEqual(20, parameters.counter_length)
        self.assertEqual(2, parameters.initial_counter_value)

        self.assertEqual(
            (
                b'\x39\x48\x74\x32\x49\x28\x34\xA3'
            ),
            derivation_parameters.initialization_vector
        )
        self.assertEqual(
            (
                b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            ),
            derivation_parameters.derivation_data
        )
        self.assertEqual(
            (
                b'\x8F\x99\x21\x2A\xA1\x54\x35\xCD'
            ),
            derivation_parameters.salt
        )
        self.assertEqual(10000, derivation_parameters.iteration_count)

    def test_invalid_cryptographic_parameters(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the cryptographic parameters of a DerivationParameters struct.
        """
        kwargs = {'cryptographic_parameters': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "cryptographic parameters must be a CryptographicParameters "
            "struct",
            DerivationParameters,
            **kwargs
        )

        derivation_parameters = DerivationParameters()
        args = (derivation_parameters, 'cryptographic_parameters', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "cryptographic parameters must be a CryptographicParameters "
            "struct",
            setattr,
            *args
        )

    def test_invalid_initialization_vector(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the initialization vector of a DerivationParameters struct.
        """
        derivation_parameters = DerivationParameters()
        args = (derivation_parameters, 'initialization_vector', 0)
        self.assertRaisesRegex(
            TypeError,
            "initialization vector must be bytes",
            setattr,
            *args
        )

    def test_invalid_derivation_data(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the derivation data of a DerivationParameters struct.
        """
        derivation_parameters = DerivationParameters()
        args = (derivation_parameters, 'derivation_data', 0)
        self.assertRaisesRegex(
            TypeError,
            "derivation data must be bytes",
            setattr,
            *args
        )

    def test_invalid_salt(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the salt of a DerivationParameters struct.
        """
        derivation_parameters = DerivationParameters()
        args = (derivation_parameters, 'salt', 0)
        self.assertRaisesRegex(
            TypeError,
            "salt must be bytes",
            setattr,
            *args
        )

    def test_invalid_iteration_count(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the iteration count of a DerivationParameters struct.
        """
        derivation_parameters = DerivationParameters()
        args = (derivation_parameters, 'iteration_count', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "iteration count must be an integer",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a DerivationParameters struct can be read from a data
        stream.
        """
        derivation_parameters = DerivationParameters()

        self.assertEqual(None, derivation_parameters.cryptographic_parameters)
        self.assertEqual(None, derivation_parameters.initialization_vector)
        self.assertEqual(None, derivation_parameters.derivation_data)
        self.assertEqual(None, derivation_parameters.salt)
        self.assertEqual(None, derivation_parameters.iteration_count)

        derivation_parameters.read(self.full_encoding)

        self.assertIsInstance(
            derivation_parameters.cryptographic_parameters,
            CryptographicParameters
        )
        cryptographic_parameters = \
            derivation_parameters.cryptographic_parameters
        self.assertEqual(
            enums.BlockCipherMode.CBC,
            cryptographic_parameters.block_cipher_mode
        )
        self.assertEqual(
            enums.PaddingMethod.PKCS5,
            cryptographic_parameters.padding_method
        )
        self.assertEqual(
            enums.HashingAlgorithm.SHA_1,
            cryptographic_parameters.hashing_algorithm
        )
        self.assertEqual(
            enums.KeyRoleType.KEK,
            cryptographic_parameters.key_role_type
        )
        self.assertEqual(
            enums.DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION,
            cryptographic_parameters.digital_signature_algorithm
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            cryptographic_parameters.cryptographic_algorithm
        )
        self.assertEqual(True, cryptographic_parameters.random_iv)
        self.assertEqual(96, cryptographic_parameters.iv_length)
        self.assertEqual(128, cryptographic_parameters.tag_length)
        self.assertEqual(32, cryptographic_parameters.fixed_field_length)
        self.assertEqual(64, cryptographic_parameters.invocation_field_length)
        self.assertEqual(0, cryptographic_parameters.counter_length)
        self.assertEqual(1, cryptographic_parameters.initial_counter_value)

        self.assertEqual(
            (
                b'\x39\x48\x74\x32\x49\x28\x34\xA3'
            ),
            derivation_parameters.initialization_vector
        )
        self.assertEqual(
            (
                b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            ),
            derivation_parameters.derivation_data
        )
        self.assertEqual(
            (
                b'\x8F\x99\x21\x2A\xA1\x54\x35\xCD'
            ),
            derivation_parameters.salt
        )
        self.assertEqual(10000, derivation_parameters.iteration_count)

    def test_read_partial(self):
        """
        Test that a DerivationParameters struct can be read from a partial
        data stream.
        """
        derivation_parameters = DerivationParameters()

        self.assertEqual(None, derivation_parameters.cryptographic_parameters)
        self.assertEqual(None, derivation_parameters.initialization_vector)
        self.assertEqual(None, derivation_parameters.derivation_data)
        self.assertEqual(None, derivation_parameters.salt)
        self.assertEqual(None, derivation_parameters.iteration_count)

        derivation_parameters.read(self.partial_encoding)

        self.assertEqual(None, derivation_parameters.cryptographic_parameters)
        self.assertEqual(
            (
                b'\x39\x48\x74\x32\x49\x28\x34\xA3'
            ),
            derivation_parameters.initialization_vector
        )
        self.assertEqual(
            (
                b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            ),
            derivation_parameters.derivation_data
        )
        self.assertEqual(None, derivation_parameters.salt)
        self.assertEqual(None, derivation_parameters.iteration_count)

    def test_read_empty(self):
        """
        Test that a DerivationParameters struct can be read from an empty
        data stream.
        """
        derivation_parameters = DerivationParameters()

        self.assertEqual(None, derivation_parameters.cryptographic_parameters)
        self.assertEqual(None, derivation_parameters.initialization_vector)
        self.assertEqual(None, derivation_parameters.derivation_data)
        self.assertEqual(None, derivation_parameters.salt)
        self.assertEqual(None, derivation_parameters.iteration_count)

        derivation_parameters.read(self.empty_encoding)

        self.assertEqual(None, derivation_parameters.cryptographic_parameters)
        self.assertEqual(None, derivation_parameters.initialization_vector)
        self.assertEqual(None, derivation_parameters.derivation_data)
        self.assertEqual(None, derivation_parameters.salt)
        self.assertEqual(None, derivation_parameters.iteration_count)

    def test_write(self):
        """
        Test that a DerivationParameters struct can be written to a data
        stream.
        """
        cryptographic_parameters = CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            hashing_algorithm=enums.HashingAlgorithm.SHA_1,
            key_role_type=enums.KeyRoleType.KEK,
            digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
            SHA256_WITH_RSA_ENCRYPTION,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            random_iv=True,
            iv_length=96,
            tag_length=128,
            fixed_field_length=32,
            invocation_field_length=64,
            counter_length=0,
            initial_counter_value=1
        )
        derivation_parameters = DerivationParameters(
            cryptographic_parameters=cryptographic_parameters,
            initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
            derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD',
            salt=b'\x8F\x99\x21\x2A\xA1\x54\x35\xCD',
            iteration_count=10000
        )
        stream = BytearrayStream()
        derivation_parameters.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_partial(self):
        """
        Test that a partially defined DerivationParameters struct can be
        written to a data stream.
        """
        derivation_parameters = DerivationParameters(
            initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
            derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD',
        )
        stream = BytearrayStream()
        derivation_parameters.write(stream)

        self.assertEqual(len(self.partial_encoding), len(stream))
        self.assertEqual(str(self.partial_encoding), str(stream))

    def test_write_empty(self):
        """
        Test that an empty DerivationParameters struct can be written to a
        data stream.
        """
        derivation_parameters = DerivationParameters()
        stream = BytearrayStream()
        derivation_parameters.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        DerivationParameters structs with the same data.
        """
        a = DerivationParameters()
        b = DerivationParameters()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = DerivationParameters(
            cryptographic_parameters=CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC,
                padding_method=enums.PaddingMethod.PKCS5,
                hashing_algorithm=enums.HashingAlgorithm.SHA_1,
                key_role_type=enums.KeyRoleType.KEK,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA256_WITH_RSA_ENCRYPTION,
                cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                random_iv=True,
                iv_length=96,
                tag_length=128,
                fixed_field_length=32,
                invocation_field_length=64,
                counter_length=0,
                initial_counter_value=1
            ),
            initialization_vector=b'\x01\x02\x03\x04\x05\x06\x07\x08',
            derivation_data=b'\x11\x22\x33\x44\x55\x66\x77\x88',
            salt=b'\x12\x34\x56\x78\x9A\xBC\xDE\xF0',
            iteration_count=1000
        )
        b = DerivationParameters(
            cryptographic_parameters=CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC,
                padding_method=enums.PaddingMethod.PKCS5,
                hashing_algorithm=enums.HashingAlgorithm.SHA_1,
                key_role_type=enums.KeyRoleType.KEK,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA256_WITH_RSA_ENCRYPTION,
                cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                random_iv=True,
                iv_length=96,
                tag_length=128,
                fixed_field_length=32,
                invocation_field_length=64,
                counter_length=0,
                initial_counter_value=1
            ),
            initialization_vector=b'\x01\x02\x03\x04\x05\x06\x07\x08',
            derivation_data=b'\x11\x22\x33\x44\x55\x66\x77\x88',
            salt=b'\x12\x34\x56\x78\x9A\xBC\xDE\xF0',
            iteration_count=1000
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_cryptographic_parameters(self):
        """
        Test that the equality operator returns False when comparing two
        DerivationParameters structs with different cryptographic parameters.
        """
        a = DerivationParameters(
            cryptographic_parameters=CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC
            )
        )
        b = DerivationParameters(
            cryptographic_parameters=CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.GCM
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_initialization_vector(self):
        """
        Test that the equality operator returns False when comparing two
        DerivationParameters structs with different initialization vectors.
        """
        a = DerivationParameters(initialization_vector=b'\x01')
        b = DerivationParameters(initialization_vector=b'\x02')

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_derivation_data(self):
        """
        Test that the equality operator returns False when comparing two
        DerivationParameters structs with different derivation data.
        """
        a = DerivationParameters(derivation_data=b'\x01')
        b = DerivationParameters(derivation_data=b'\x02')

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_salt(self):
        """
        Test that the equality operator returns False when comparing two
        DerivationParameters structs with different salts.
        """
        a = DerivationParameters(salt=b'\x01')
        b = DerivationParameters(salt=b'\x02')

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_iteration_count(self):
        """
        Test that the equality operator returns False when comparing two
        DerivationParameters structs with different iteration counts.
        """
        a = DerivationParameters(iteration_count=1)
        b = DerivationParameters(iteration_count=2)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        DerivationParameters structs with different types.
        """
        a = DerivationParameters()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        DerivationParameters structs with the same data.
        """
        a = DerivationParameters()
        b = DerivationParameters()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = DerivationParameters(
            cryptographic_parameters=CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC,
                padding_method=enums.PaddingMethod.PKCS5,
                hashing_algorithm=enums.HashingAlgorithm.SHA_1,
                key_role_type=enums.KeyRoleType.KEK,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA256_WITH_RSA_ENCRYPTION,
                cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                random_iv=True,
                iv_length=96,
                tag_length=128,
                fixed_field_length=32,
                invocation_field_length=64,
                counter_length=0,
                initial_counter_value=1
            ),
            initialization_vector=b'\x01\x02\x03\x04\x05\x06\x07\x08',
            derivation_data=b'\x11\x22\x33\x44\x55\x66\x77\x88',
            salt=b'\x12\x34\x56\x78\x9A\xBC\xDE\xF0',
            iteration_count=1000
        )
        b = DerivationParameters(
            cryptographic_parameters=CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC,
                padding_method=enums.PaddingMethod.PKCS5,
                hashing_algorithm=enums.HashingAlgorithm.SHA_1,
                key_role_type=enums.KeyRoleType.KEK,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA256_WITH_RSA_ENCRYPTION,
                cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                random_iv=True,
                iv_length=96,
                tag_length=128,
                fixed_field_length=32,
                invocation_field_length=64,
                counter_length=0,
                initial_counter_value=1
            ),
            initialization_vector=b'\x01\x02\x03\x04\x05\x06\x07\x08',
            derivation_data=b'\x11\x22\x33\x44\x55\x66\x77\x88',
            salt=b'\x12\x34\x56\x78\x9A\xBC\xDE\xF0',
            iteration_count=1000
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_cryptographic_parameters(self):
        """
        Test that the inequality operator returns True when comparing two
        DerivationParameters structs with different cryptographic parameters.
        """
        a = DerivationParameters(
            cryptographic_parameters=CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC
            )
        )
        b = DerivationParameters(
            cryptographic_parameters=CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.GCM
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_initialization_vectors(self):
        """
        Test that the inequality operator returns True when comparing two
        DerivationParameters structs with different initialization vectors.
        """
        a = DerivationParameters(initialization_vector=b'\x01')
        b = DerivationParameters(initialization_vector=b'\x02')

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_derivation_data(self):
        """
        Test that the inequality operator returns True when comparing two
        DerivationParameters structs with different derivation data.
        """
        a = DerivationParameters(derivation_data=b'\x01')
        b = DerivationParameters(derivation_data=b'\x02')

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_salt(self):
        """
        Test that the inequality operator returns True when comparing two
        DerivationParameters structs with different salts.
        """
        a = DerivationParameters(salt=b'\x01')
        b = DerivationParameters(salt=b'\x02')

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_iteration_counts(self):
        """
        Test that the inequality operator returns True when comparing two
        DerivationParameters structs with different iteration counts.
        """
        a = DerivationParameters(iteration_count=1)
        b = DerivationParameters(iteration_count=2)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        DerivationParameters structs with different types.
        """
        a = DerivationParameters()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a DerivationParameters struct.
        """
        derivation_parameters = DerivationParameters(
            cryptographic_parameters=CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC,
                padding_method=enums.PaddingMethod.PKCS5,
                hashing_algorithm=enums.HashingAlgorithm.SHA_1,
                key_role_type=enums.KeyRoleType.KEK,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA256_WITH_RSA_ENCRYPTION,
                cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                random_iv=True,
                iv_length=96,
                tag_length=128,
                fixed_field_length=32,
                invocation_field_length=64,
                counter_length=0,
                initial_counter_value=1
            ),
            initialization_vector=b'\x01\x02\x03\x04\x05\x06\x07\x08',
            derivation_data=b'\x11\x22\x33\x44\x55\x66\x77\x88',
            salt=b'\x12\x34\x56\x78\x9A\xBC\xDE\xF0',
            iteration_count=10000
        )

        expected = (
            "DerivationParameters("
            "cryptographic_parameters=CryptographicParameters("
            "block_cipher_mode=BlockCipherMode.CBC, "
            "padding_method=PaddingMethod.PKCS5, "
            "hashing_algorithm=HashingAlgorithm.SHA_1, "
            "key_role_type=KeyRoleType.KEK, "
            "digital_signature_algorithm="
            "DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION, "
            "cryptographic_algorithm=CryptographicAlgorithm.AES, "
            "random_iv=True, "
            "iv_length=96, "
            "tag_length=128, "
            "fixed_field_length=32, "
            "invocation_field_length=64, "
            "counter_length=0, "
            "initial_counter_value=1), "
            "initialization_vector=" + str(
                b'\x01\x02\x03\x04\x05\x06\x07\x08'
            ) + ", "
            "derivation_data=" + str(
                b'\x11\x22\x33\x44\x55\x66\x77\x88'
            ) + ", "
            "salt=" + str(b'\x12\x34\x56\x78\x9A\xBC\xDE\xF0') + ", "
            "iteration_count=10000)"
        )
        observed = repr(derivation_parameters)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a DerivationParameters struct.
        """
        cryptographic_parameters = CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            hashing_algorithm=enums.HashingAlgorithm.SHA_1,
            key_role_type=enums.KeyRoleType.KEK,
            digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
            SHA256_WITH_RSA_ENCRYPTION,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            random_iv=True,
            iv_length=96,
            tag_length=128,
            fixed_field_length=32,
            invocation_field_length=64,
            counter_length=0,
            initial_counter_value=1
        )
        derivation_parameters = DerivationParameters(
            cryptographic_parameters=cryptographic_parameters,
            initialization_vector=b'\x01\x02\x03\x04\x05\x06\x07\x08',
            derivation_data=b'\x11\x22\x33\x44\x55\x66\x77\x88',
            salt=b'\x12\x34\x56\x78\x9A\xBC\xDE\xF0',
            iteration_count=10000
        )

        expected = str({
            'cryptographic_parameters': cryptographic_parameters,
            'initialization_vector': b'\x01\x02\x03\x04\x05\x06\x07\x08',
            'derivation_data': b'\x11\x22\x33\x44\x55\x66\x77\x88',
            'salt': b'\x12\x34\x56\x78\x9A\xBC\xDE\xF0',
            'iteration_count': 10000
        })
        observed = str(derivation_parameters)

        self.assertEqual(expected, observed)
