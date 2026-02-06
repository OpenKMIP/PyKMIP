# Copyright (c) 2026 The Johns Hopkins University/Applied Physics Laboratory
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

import os

import testtools

from cryptography import exceptions as crypto_exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import keywrap

from kmip.core import enums
from kmip.core import exceptions
from kmip.services.server import crypto


class TestCryptographyEngineExtended(testtools.TestCase):

    _rsa_2048_private = None
    _rsa_2048_public = None
    _rsa_4096_private = None
    _rsa_4096_public = None

    def setUp(self):
        super(TestCryptographyEngineExtended, self).setUp()
        self.engine = crypto.CryptographyEngine()

        self.aes_128 = os.urandom(16)
        self.aes_192 = os.urandom(24)
        self.aes_256 = os.urandom(32)
        self.tdes_128 = os.urandom(16)
        self.tdes_192 = os.urandom(24)
        self.blowfish_128 = os.urandom(16)
        self.blowfish_192 = os.urandom(24)
        self.blowfish_256 = os.urandom(32)
        self.camellia_128 = os.urandom(16)
        self.camellia_192 = os.urandom(24)
        self.camellia_256 = os.urandom(32)

        self.iv_16 = os.urandom(16)
        self.iv_12 = os.urandom(12)

        self._ensure_rsa_keys()

    def tearDown(self):
        super(TestCryptographyEngineExtended, self).tearDown()

    @classmethod
    def _serialize_rsa_keypair(cls, private_key):
        private_bytes = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.PKCS1
        )
        return private_bytes, public_bytes

    def _ensure_rsa_keys(self):
        if self.__class__._rsa_2048_private is None:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            private_bytes, public_bytes = self._serialize_rsa_keypair(
                private_key
            )
            self.__class__._rsa_2048_private = private_bytes
            self.__class__._rsa_2048_public = public_bytes

        if self.__class__._rsa_4096_private is None:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            private_bytes, public_bytes = self._serialize_rsa_keypair(
                private_key
            )
            self.__class__._rsa_4096_private = private_bytes
            self.__class__._rsa_4096_public = public_bytes

        self.rsa_2048_private = self.__class__._rsa_2048_private
        self.rsa_2048_public = self.__class__._rsa_2048_public
        self.rsa_4096_private = self.__class__._rsa_4096_private
        self.rsa_4096_public = self.__class__._rsa_4096_public

    def _load_public_key(self, public_bytes):
        return serialization.load_der_public_key(
            public_bytes,
            backend=default_backend()
        )

    def test_create_symmetric_key_aes_128(self):
        """Test AES-128 symmetric key generation."""
        key = self.engine.create_symmetric_key(
            enums.CryptographicAlgorithm.AES,
            128
        )
        self.assertEqual(16, len(key.get('value')))

    def test_create_symmetric_key_aes_192(self):
        """Test AES-192 symmetric key generation."""
        key = self.engine.create_symmetric_key(
            enums.CryptographicAlgorithm.AES,
            192
        )
        self.assertEqual(24, len(key.get('value')))

    def test_create_symmetric_key_aes_256(self):
        """Test AES-256 symmetric key generation."""
        key = self.engine.create_symmetric_key(
            enums.CryptographicAlgorithm.AES,
            256
        )
        self.assertEqual(32, len(key.get('value')))

    def test_create_symmetric_key_3des_128(self):
        """Test 3DES 128-bit symmetric key generation."""
        key = self.engine.create_symmetric_key(
            enums.CryptographicAlgorithm.TRIPLE_DES,
            128
        )
        self.assertEqual(16, len(key.get('value')))

    def test_create_symmetric_key_3des_192(self):
        """Test 3DES 192-bit symmetric key generation."""
        key = self.engine.create_symmetric_key(
            enums.CryptographicAlgorithm.TRIPLE_DES,
            192
        )
        self.assertEqual(24, len(key.get('value')))

    def test_create_symmetric_key_blowfish_various_lengths(self):
        """Test Blowfish key generation for multiple lengths."""
        for length in [128, 192, 256]:
            with self.subTest(length=length):
                key = self.engine.create_symmetric_key(
                    enums.CryptographicAlgorithm.BLOWFISH,
                    length
                )
                self.assertEqual(length // 8, len(key.get('value')))

    def _assert_camellia_length(self, length):
        key = self.engine.create_symmetric_key(
            enums.CryptographicAlgorithm.CAMELLIA,
            length
        )
        self.assertEqual(length // 8, len(key.get('value')))

    def test_create_symmetric_key_camellia_128(self):
        """Test Camellia 128-bit symmetric key generation."""
        self._assert_camellia_length(128)

    def test_create_symmetric_key_camellia_192(self):
        """Test Camellia 192-bit symmetric key generation."""
        self._assert_camellia_length(192)

    def test_create_symmetric_key_camellia_256(self):
        """Test Camellia 256-bit symmetric key generation."""
        self._assert_camellia_length(256)

    def test_create_symmetric_key_unsupported_algorithm(self):
        """Test unsupported symmetric algorithm raises InvalidField."""
        self.assertRaises(
            exceptions.InvalidField,
            self.engine.create_symmetric_key,
            enums.CryptographicAlgorithm.RSA,
            128
        )

    def test_create_symmetric_key_invalid_length(self):
        """Test invalid symmetric key length raises InvalidField."""
        self.assertRaises(
            exceptions.InvalidField,
            self.engine.create_symmetric_key,
            enums.CryptographicAlgorithm.AES,
            127
        )

    def test_create_asymmetric_key_pair_rsa_2048(self):
        """Test RSA 2048 key pair generation."""
        public_key, private_key = self.engine.create_asymmetric_key_pair(
            enums.CryptographicAlgorithm.RSA,
            2048
        )
        private = serialization.load_der_private_key(
            private_key.get('value'),
            password=None,
            backend=default_backend()
        )
        self.assertEqual(2048, private.key_size)
        public = self._load_public_key(public_key.get('value'))
        self.assertEqual(2048, public.key_size)

    def test_create_asymmetric_key_pair_rsa_4096(self):
        """Test RSA 4096 key pair generation."""
        public_key, private_key = self.engine.create_asymmetric_key_pair(
            enums.CryptographicAlgorithm.RSA,
            4096
        )
        private = serialization.load_der_private_key(
            private_key.get('value'),
            password=None,
            backend=default_backend()
        )
        self.assertEqual(4096, private.key_size)
        public = self._load_public_key(public_key.get('value'))
        self.assertEqual(4096, public.key_size)

    def test_create_asymmetric_key_pair_invalid_algorithm(self):
        """Test invalid algorithm for asymmetric keys raises InvalidField."""
        self.assertRaises(
            exceptions.InvalidField,
            self.engine.create_asymmetric_key_pair,
            enums.CryptographicAlgorithm.AES,
            2048
        )

    def test_create_asymmetric_key_pair_invalid_length(self):
        """Test invalid RSA key length raises CryptographicFailure."""
        self.assertRaises(
            exceptions.CryptographicFailure,
            self.engine.create_asymmetric_key_pair,
            enums.CryptographicAlgorithm.RSA,
            0
        )

    def test_encrypt_aes_cbc_pkcs5_padding(self):
        """Test AES-CBC encryption with PKCS5 padding."""
        plain_text = b'kmip-plain-text'
        result = self.engine.encrypt(
            encryption_algorithm=enums.CryptographicAlgorithm.AES,
            encryption_key=self.aes_128,
            plain_text=plain_text,
            cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5
        )
        self.assertIn('cipher_text', result)
        self.assertIn('iv_nonce', result)

    def test_encrypt_aes_gcm_with_aad(self):
        """Test AES-GCM encryption with additional authenticated data."""
        plain_text = b'kmip-gcm-plain-text'
        aad = b'kmip-aad'
        result = self.engine.encrypt(
            encryption_algorithm=enums.CryptographicAlgorithm.AES,
            encryption_key=self.aes_256,
            plain_text=plain_text,
            cipher_mode=enums.BlockCipherMode.GCM,
            iv_nonce=self.iv_12,
            auth_additional_data=aad,
            auth_tag_length=16
        )
        self.assertIn('cipher_text', result)
        self.assertIn('auth_tag', result)

    def test_encrypt_aes_ctr_mode(self):
        """Test AES-CTR encryption."""
        plain_text = b'kmip-ctr-plain-text'
        result = self.engine.encrypt(
            encryption_algorithm=enums.CryptographicAlgorithm.AES,
            encryption_key=self.aes_128,
            plain_text=plain_text,
            cipher_mode=enums.BlockCipherMode.CTR,
            iv_nonce=self.iv_16
        )
        self.assertIn('cipher_text', result)

    def test_decrypt_aes_cbc_pkcs5_padding(self):
        """Test AES-CBC decryption with PKCS5 padding."""
        plain_text = b'kmip-cbc-plain-text'
        enc = self.engine.encrypt(
            encryption_algorithm=enums.CryptographicAlgorithm.AES,
            encryption_key=self.aes_128,
            plain_text=plain_text,
            cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            iv_nonce=self.iv_16
        )
        dec = self.engine.decrypt(
            decryption_algorithm=enums.CryptographicAlgorithm.AES,
            decryption_key=self.aes_128,
            cipher_text=enc.get('cipher_text'),
            cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            iv_nonce=self.iv_16
        )
        self.assertEqual(plain_text, dec)

    def test_decrypt_aes_gcm_with_aad(self):
        """Test AES-GCM decryption with additional authenticated data."""
        plain_text = b'kmip-gcm-plain-text'
        aad = b'kmip-aad'
        enc = self.engine.encrypt(
            encryption_algorithm=enums.CryptographicAlgorithm.AES,
            encryption_key=self.aes_256,
            plain_text=plain_text,
            cipher_mode=enums.BlockCipherMode.GCM,
            iv_nonce=self.iv_12,
            auth_additional_data=aad,
            auth_tag_length=16
        )
        dec = self.engine.decrypt(
            decryption_algorithm=enums.CryptographicAlgorithm.AES,
            decryption_key=self.aes_256,
            cipher_text=enc.get('cipher_text'),
            cipher_mode=enums.BlockCipherMode.GCM,
            iv_nonce=self.iv_12,
            auth_additional_data=aad,
            auth_tag=enc.get('auth_tag')
        )
        self.assertEqual(plain_text, dec)

    def test_decrypt_wrong_key(self):
        """Test AES-GCM decryption with wrong key raises InvalidTag."""
        plain_text = b'kmip-gcm-plain-text'
        aad = b'kmip-aad'
        enc = self.engine.encrypt(
            encryption_algorithm=enums.CryptographicAlgorithm.AES,
            encryption_key=self.aes_256,
            plain_text=plain_text,
            cipher_mode=enums.BlockCipherMode.GCM,
            iv_nonce=self.iv_12,
            auth_additional_data=aad,
            auth_tag_length=16
        )
        self.assertRaises(
            crypto_exceptions.InvalidTag,
            self.engine.decrypt,
            enums.CryptographicAlgorithm.AES,
            self.aes_128,
            enc.get('cipher_text'),
            cipher_mode=enums.BlockCipherMode.GCM,
            iv_nonce=self.iv_12,
            auth_additional_data=aad,
            auth_tag=enc.get('auth_tag')
        )

    def test_decrypt_corrupted_ciphertext(self):
        """Test AES-GCM decryption fails with corrupted ciphertext."""
        plain_text = b'kmip-gcm-plain-text'
        aad = b'kmip-aad'
        enc = self.engine.encrypt(
            encryption_algorithm=enums.CryptographicAlgorithm.AES,
            encryption_key=self.aes_256,
            plain_text=plain_text,
            cipher_mode=enums.BlockCipherMode.GCM,
            iv_nonce=self.iv_12,
            auth_additional_data=aad,
            auth_tag_length=16
        )
        cipher_text = bytearray(enc.get('cipher_text'))
        cipher_text[0] ^= 0xFF
        self.assertRaises(
            crypto_exceptions.InvalidTag,
            self.engine.decrypt,
            enums.CryptographicAlgorithm.AES,
            self.aes_256,
            bytes(cipher_text),
            cipher_mode=enums.BlockCipherMode.GCM,
            iv_nonce=self.iv_12,
            auth_additional_data=aad,
            auth_tag=enc.get('auth_tag')
        )

    def test_encrypt_decrypt_roundtrip_aes_128_cbc(self):
        """Test AES-128 CBC roundtrip encryption/decryption."""
        plain_text = b'kmip-roundtrip-plain-text'
        enc = self.engine.encrypt(
            encryption_algorithm=enums.CryptographicAlgorithm.AES,
            encryption_key=self.aes_128,
            plain_text=plain_text,
            cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            iv_nonce=self.iv_16
        )
        dec = self.engine.decrypt(
            decryption_algorithm=enums.CryptographicAlgorithm.AES,
            decryption_key=self.aes_128,
            cipher_text=enc.get('cipher_text'),
            cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            iv_nonce=self.iv_16
        )
        self.assertEqual(plain_text, dec)

    def test_encrypt_decrypt_roundtrip_aes_256_gcm(self):
        """Test AES-256 GCM roundtrip encryption/decryption."""
        plain_text = b'kmip-roundtrip-gcm'
        aad = b'kmip-aad'
        enc = self.engine.encrypt(
            encryption_algorithm=enums.CryptographicAlgorithm.AES,
            encryption_key=self.aes_256,
            plain_text=plain_text,
            cipher_mode=enums.BlockCipherMode.GCM,
            iv_nonce=self.iv_12,
            auth_additional_data=aad,
            auth_tag_length=16
        )
        dec = self.engine.decrypt(
            decryption_algorithm=enums.CryptographicAlgorithm.AES,
            decryption_key=self.aes_256,
            cipher_text=enc.get('cipher_text'),
            cipher_mode=enums.BlockCipherMode.GCM,
            iv_nonce=self.iv_12,
            auth_additional_data=aad,
            auth_tag=enc.get('auth_tag')
        )
        self.assertEqual(plain_text, dec)

    def test_sign_rsa_pkcs1v15_sha256(self):
        """Test RSA PKCS#1 v1.5 signing with SHA-256."""
        data = b'kmip-sign-data'
        signature = self.engine.sign(
            digital_signature_algorithm=None,
            crypto_alg=enums.CryptographicAlgorithm.RSA,
            hash_algorithm=enums.HashingAlgorithm.SHA_256,
            padding=enums.PaddingMethod.PKCS1v15,
            signing_key=self.rsa_2048_private,
            data=data
        )
        public_key = self._load_public_key(self.rsa_2048_public)
        public_key.verify(
            signature,
            data,
            asym_padding.PKCS1v15(),
            hashes.SHA256()
        )

    def test_sign_rsa_pss_sha256(self):
        """Test RSA PSS signing with SHA-256."""
        data = b'kmip-sign-data'
        signature = self.engine.sign(
            digital_signature_algorithm=None,
            crypto_alg=enums.CryptographicAlgorithm.RSA,
            hash_algorithm=enums.HashingAlgorithm.SHA_256,
            padding=enums.PaddingMethod.PSS,
            signing_key=self.rsa_2048_private,
            data=data
        )
        public_key = self._load_public_key(self.rsa_2048_public)
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def test_sign_rsa_pss_sha512(self):
        """Test RSA PSS signing with SHA-512."""
        data = b'kmip-sign-data'
        signature = self.engine.sign(
            digital_signature_algorithm=None,
            crypto_alg=enums.CryptographicAlgorithm.RSA,
            hash_algorithm=enums.HashingAlgorithm.SHA_512,
            padding=enums.PaddingMethod.PSS,
            signing_key=self.rsa_2048_private,
            data=data
        )
        public_key = self._load_public_key(self.rsa_2048_public)
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA512()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )

    def test_verify_signature_valid(self):
        """Test signature verification returns True for valid signatures."""
        data = b'kmip-verify-data'
        signature = self.engine.sign(
            digital_signature_algorithm=None,
            crypto_alg=enums.CryptographicAlgorithm.RSA,
            hash_algorithm=enums.HashingAlgorithm.SHA_256,
            padding=enums.PaddingMethod.PKCS1v15,
            signing_key=self.rsa_2048_private,
            data=data
        )
        result = self.engine.verify_signature(
            signing_key=self.rsa_2048_public,
            message=data,
            signature=signature,
            padding_method=enums.PaddingMethod.PKCS1v15,
            signing_algorithm=enums.CryptographicAlgorithm.RSA,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256
        )
        self.assertTrue(result)

    def test_verify_signature_invalid(self):
        """Test signature verification returns False for invalid signatures."""
        data = b'kmip-verify-data'
        signature = self.engine.sign(
            digital_signature_algorithm=None,
            crypto_alg=enums.CryptographicAlgorithm.RSA,
            hash_algorithm=enums.HashingAlgorithm.SHA_256,
            padding=enums.PaddingMethod.PKCS1v15,
            signing_key=self.rsa_2048_private,
            data=data
        )
        signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])
        result = self.engine.verify_signature(
            signing_key=self.rsa_2048_public,
            message=data,
            signature=signature,
            padding_method=enums.PaddingMethod.PKCS1v15,
            signing_algorithm=enums.CryptographicAlgorithm.RSA,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256
        )
        self.assertFalse(result)

    def test_verify_signature_wrong_key(self):
        """Test signature verification returns False with wrong key."""
        data = b'kmip-verify-data'
        signature = self.engine.sign(
            digital_signature_algorithm=None,
            crypto_alg=enums.CryptographicAlgorithm.RSA,
            hash_algorithm=enums.HashingAlgorithm.SHA_256,
            padding=enums.PaddingMethod.PKCS1v15,
            signing_key=self.rsa_2048_private,
            data=data
        )
        result = self.engine.verify_signature(
            signing_key=self.rsa_4096_public,
            message=data,
            signature=signature,
            padding_method=enums.PaddingMethod.PKCS1v15,
            signing_algorithm=enums.CryptographicAlgorithm.RSA,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256
        )
        self.assertFalse(result)

    def test_sign_verify_roundtrip(self):
        """Test sign/verify roundtrip with RSA."""
        data = b'kmip-sign-verify'
        signature = self.engine.sign(
            digital_signature_algorithm=
                enums.DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION,
            crypto_alg=None,
            hash_algorithm=None,
            padding=enums.PaddingMethod.PKCS1v15,
            signing_key=self.rsa_2048_private,
            data=data
        )
        result = self.engine.verify_signature(
            signing_key=self.rsa_2048_public,
            message=data,
            signature=signature,
            padding_method=enums.PaddingMethod.PKCS1v15,
            digital_signature_algorithm=
                enums.DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION
        )
        self.assertTrue(result)

    def test_mac_hmac_sha256(self):
        """Test HMAC-SHA256 MAC generation."""
        data = b'kmip-mac-data'
        key = os.urandom(32)
        mac = self.engine.mac(
            enums.CryptographicAlgorithm.HMAC_SHA256,
            key,
            data
        )
        h = crypto_hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        expected = h.finalize()
        self.assertEqual(expected, mac)

    def test_mac_hmac_sha512(self):
        """Test HMAC-SHA512 MAC generation."""
        data = b'kmip-mac-data'
        key = os.urandom(64)
        mac = self.engine.mac(
            enums.CryptographicAlgorithm.HMAC_SHA512,
            key,
            data
        )
        h = crypto_hmac.HMAC(key, hashes.SHA512(), backend=default_backend())
        h.update(data)
        expected = h.finalize()
        self.assertEqual(expected, mac)

    def test_mac_invalid_algorithm(self):
        """Test MAC rejects unsupported algorithm."""
        self.assertRaises(
            exceptions.InvalidField,
            self.engine.mac,
            enums.CryptographicAlgorithm.RSA,
            os.urandom(16),
            b'data'
        )

    def test_mac_verify_roundtrip(self):
        """Test HMAC roundtrip verification."""
        data = b'kmip-mac-data'
        key = os.urandom(32)
        mac = self.engine.mac(
            enums.CryptographicAlgorithm.HMAC_SHA256,
            key,
            data
        )
        verifier = crypto_hmac.HMAC(
            key,
            hashes.SHA256(),
            backend=default_backend()
        )
        verifier.update(data)
        verifier.verify(mac)

    def test_derive_key_pbkdf2_hmac_sha256(self):
        """Test PBKDF2 key derivation using HMAC-SHA256."""
        derived = self.engine.derive_key(
            derivation_method=enums.DerivationMethod.PBKDF2,
            derivation_length=32,
            key_material=self.aes_256,
            hash_algorithm=enums.HashingAlgorithm.SHA_256,
            salt=b'kmip-salt',
            iteration_count=1000
        )
        self.assertEqual(32, len(derived))

    def test_derive_key_hmac(self):
        """Test HMAC-based key derivation."""
        derived = self.engine.derive_key(
            derivation_method=enums.DerivationMethod.HMAC,
            derivation_length=32,
            derivation_data=b'kmip-info',
            key_material=self.aes_256,
            hash_algorithm=enums.HashingAlgorithm.SHA_256
        )
        self.assertEqual(32, len(derived))

    def test_derive_key_encrypt(self):
        """Test encryption-based key derivation."""
        derivation_data = b'kmip-derive-data'
        encrypted = self.engine.derive_key(
            derivation_method=enums.DerivationMethod.ENCRYPT,
            derivation_length=16,
            derivation_data=derivation_data,
            key_material=self.aes_128,
            encryption_algorithm=enums.CryptographicAlgorithm.AES,
            cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            iv_nonce=self.iv_16
        )
        expected = self.engine.encrypt(
            encryption_algorithm=enums.CryptographicAlgorithm.AES,
            encryption_key=self.aes_128,
            plain_text=derivation_data,
            cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            iv_nonce=self.iv_16
        ).get('cipher_text')
        self.assertEqual(expected, encrypted)

    def test_derive_key_nist_800_108c(self):
        """Test NIST 800-108 counter mode derivation."""
        derived = self.engine.derive_key(
            derivation_method=enums.DerivationMethod.NIST800_108_C,
            derivation_length=32,
            derivation_data=b'kmip-context',
            key_material=self.aes_256,
            hash_algorithm=enums.HashingAlgorithm.SHA_256
        )
        self.assertEqual(32, len(derived))

    def test_derive_key_missing_parameters(self):
        """Test key derivation errors for missing parameters."""
        self.assertRaises(
            exceptions.InvalidField,
            self.engine.derive_key,
            enums.DerivationMethod.HMAC,
            16,
            derivation_data=b'kmip',
            key_material=self.aes_128,
            hash_algorithm=None
        )
        self.assertRaises(
            exceptions.InvalidField,
            self.engine.derive_key,
            enums.DerivationMethod.PBKDF2,
            16,
            key_material=self.aes_128,
            hash_algorithm=enums.HashingAlgorithm.SHA_256
        )

    def test_derive_key_invalid_method(self):
        """Test invalid key derivation method raises InvalidField."""
        self.assertRaises(
            exceptions.InvalidField,
            self.engine.derive_key,
            enums.DerivationMethod.ASYMMETRIC_KEY,
            16,
            key_material=self.aes_128,
            hash_algorithm=enums.HashingAlgorithm.SHA_256
        )

    def test_wrap_key_aes_key_wrap(self):
        """Test AES key wrap produces expected output."""
        key_material = os.urandom(16)
        wrapping_key = os.urandom(16)
        wrapped = self.engine.wrap_key(
            key_material=key_material,
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            key_wrap_algorithm=enums.BlockCipherMode.NIST_KEY_WRAP,
            encryption_key=wrapping_key
        )
        expected = keywrap.aes_key_wrap(
            wrapping_key,
            key_material,
            backend=default_backend()
        )
        self.assertEqual(expected, wrapped)

    def test_unwrap_key_aes_key_wrap(self):
        """Test AES key wrap can be unwrapped to original key material."""
        key_material = os.urandom(16)
        wrapping_key = os.urandom(16)
        wrapped = self.engine.wrap_key(
            key_material=key_material,
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            key_wrap_algorithm=enums.BlockCipherMode.NIST_KEY_WRAP,
            encryption_key=wrapping_key
        )
        unwrapped = keywrap.aes_key_unwrap(
            wrapping_key,
            wrapped,
            backend=default_backend()
        )
        self.assertEqual(key_material, unwrapped)

    def test_wrap_unwrap_roundtrip(self):
        """Test wrap/unwrap roundtrip for larger key material."""
        key_material = os.urandom(32)
        wrapping_key = os.urandom(32)
        wrapped = self.engine.wrap_key(
            key_material=key_material,
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            key_wrap_algorithm=enums.BlockCipherMode.NIST_KEY_WRAP,
            encryption_key=wrapping_key
        )
        unwrapped = keywrap.aes_key_unwrap(
            wrapping_key,
            wrapped,
            backend=default_backend()
        )
        self.assertEqual(key_material, unwrapped)
