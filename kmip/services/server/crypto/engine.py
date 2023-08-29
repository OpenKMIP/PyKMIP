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

import logging
import os

from cryptography import exceptions as errors
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac, cmac
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as \
    asymmetric_padding
from cryptography.hazmat.primitives import ciphers, keywrap
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.kdf import hkdf
from cryptography.hazmat.primitives.kdf import kbkdf
from cryptography.hazmat.primitives.kdf import pbkdf2

from kmip.core import enums
from kmip.core import exceptions
from kmip.services.server.crypto import api


class CryptographyEngine(api.CryptographicEngine):
    """
    A cryptographic engine that uses pyca/cryptography to generate
    cryptographic objects and conduct cryptographic operations.
    """

    def __init__(self):
        """
        Construct a CryptographyEngine.
        """
        self.logger = logging.getLogger('kmip.server.engine.cryptography')

        # The IDEA algorithm is supported by cryptography but may not be
        # supported by certain backends, like OpenSSL.
        self._symmetric_key_algorithms = {
            enums.CryptographicAlgorithm.TRIPLE_DES: algorithms.TripleDES,
            enums.CryptographicAlgorithm.AES:        algorithms.AES,
            enums.CryptographicAlgorithm.BLOWFISH:   algorithms.Blowfish,
            enums.CryptographicAlgorithm.CAMELLIA:   algorithms.Camellia,
            enums.CryptographicAlgorithm.CAST5:      algorithms.CAST5,
            enums.CryptographicAlgorithm.IDEA:       algorithms.IDEA,
            enums.CryptographicAlgorithm.RC4:        algorithms.ARC4
        }
        self._asymmetric_key_algorithms = {
            enums.CryptographicAlgorithm.RSA: self._create_rsa_key_pair
        }
        self._hash_algorithms = {
            enums.CryptographicAlgorithm.HMAC_SHA1: hashes.SHA1,
            enums.CryptographicAlgorithm.HMAC_SHA224: hashes.SHA224,
            enums.CryptographicAlgorithm.HMAC_SHA256: hashes.SHA256,
            enums.CryptographicAlgorithm.HMAC_SHA384: hashes.SHA384,
            enums.CryptographicAlgorithm.HMAC_SHA512: hashes.SHA512,
            enums.CryptographicAlgorithm.HMAC_MD5: hashes.MD5
        }

        # TODO(peter-hamilton): Consider merging above hash dict and this one
        self._encryption_hash_algorithms = {
            enums.HashingAlgorithm.MD5:     hashes.MD5,
            enums.HashingAlgorithm.SHA_1:   hashes.SHA1,
            enums.HashingAlgorithm.SHA_224: hashes.SHA224,
            enums.HashingAlgorithm.SHA_256: hashes.SHA256,
            enums.HashingAlgorithm.SHA_384: hashes.SHA384,
            enums.HashingAlgorithm.SHA_512: hashes.SHA512
        }

        self._modes = {
            enums.BlockCipherMode.CBC: modes.CBC,
            enums.BlockCipherMode.ECB: modes.ECB,
            enums.BlockCipherMode.OFB: modes.OFB,
            enums.BlockCipherMode.CFB: modes.CFB,
            enums.BlockCipherMode.CTR: modes.CTR,
            enums.BlockCipherMode.GCM: modes.GCM
        }
        self._asymmetric_padding_methods = {
             enums.PaddingMethod.OAEP:     asymmetric_padding.OAEP,
             enums.PaddingMethod.PKCS1v15: asymmetric_padding.PKCS1v15,
             enums.PaddingMethod.PSS:      asymmetric_padding.PSS
        }
        self._symmetric_padding_methods = {
            enums.PaddingMethod.ANSI_X923: symmetric_padding.ANSIX923,
            enums.PaddingMethod.PKCS5:     symmetric_padding.PKCS7
        }
        self._no_mode_needed = [
            enums.CryptographicAlgorithm.RC4
        ]
        self._no_padding_needed = [
            enums.BlockCipherMode.CTR,
            enums.BlockCipherMode.OFB,
            enums.BlockCipherMode.CFB,
            enums.BlockCipherMode.GCM
        ]

        self._digital_signature_algorithms = {
            enums.DigitalSignatureAlgorithm.MD5_WITH_RSA_ENCRYPTION:
                (hashes.MD5, enums.CryptographicAlgorithm.RSA),
            enums.DigitalSignatureAlgorithm.SHA1_WITH_RSA_ENCRYPTION:
                (hashes.SHA1, enums.CryptographicAlgorithm.RSA),
            enums.DigitalSignatureAlgorithm.SHA224_WITH_RSA_ENCRYPTION:
                (hashes.SHA224, enums.CryptographicAlgorithm.RSA),
            enums.DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION:
                (hashes.SHA256, enums.CryptographicAlgorithm.RSA),
            enums.DigitalSignatureAlgorithm.SHA384_WITH_RSA_ENCRYPTION:
                (hashes.SHA384, enums.CryptographicAlgorithm.RSA),
            enums.DigitalSignatureAlgorithm.SHA512_WITH_RSA_ENCRYPTION:
                (hashes.SHA512, enums.CryptographicAlgorithm.RSA)
        }

    def create_symmetric_key(self, algorithm, length):
        """
        Create a symmetric key.

        Args:
            algorithm(CryptographicAlgorithm): An enumeration specifying the
                algorithm for which the created key will be compliant.
            length(int): The length of the key to be created. This value must
                be compliant with the constraints of the provided algorithm.

        Returns:
            dict: A dictionary containing the key data, with the following
                key/value fields:
                * value - the bytes of the key
                * format - a KeyFormatType enumeration for the bytes format

        Raises:
            InvalidField: Raised when the algorithm is unsupported or the
                length is incompatible with the algorithm.
            CryptographicFailure: Raised when the key generation process
                fails.

        Example:
            >>> engine = CryptographyEngine()
            >>> key = engine.create_symmetric_key(
            ...     CryptographicAlgorithm.AES, 256)
        """
        if algorithm not in self._symmetric_key_algorithms.keys():
            raise exceptions.InvalidField(
                "The cryptographic algorithm {0} is not a supported symmetric "
                "key algorithm.".format(algorithm)
            )

        cryptography_algorithm = self._symmetric_key_algorithms.get(algorithm)

        if length not in cryptography_algorithm.key_sizes:
            raise exceptions.InvalidField(
                "The cryptographic length ({0}) is not valid for "
                "the cryptographic algorithm ({1}).".format(
                    length, algorithm.name
                )
            )

        self.logger.info(
            "Generating a {0} symmetric key with length: {1}".format(
                algorithm.name, length
            )
        )

        key_bytes = os.urandom(length // 8)
        try:
            cryptography_algorithm(key_bytes)
        except Exception as e:
            self.logger.exception(e)
            raise exceptions.CryptographicFailure(
                "Invalid bytes for the provided cryptographic algorithm.")

        return {'value': key_bytes, 'format': enums.KeyFormatType.RAW}

    def create_asymmetric_key_pair(self, algorithm, length):
        """
        Create an asymmetric key pair.

        Args:
            algorithm(CryptographicAlgorithm): An enumeration specifying the
                algorithm for which the created keys will be compliant.
            length(int): The length of the keys to be created. This value must
                be compliant with the constraints of the provided algorithm.

        Returns:
            dict: A dictionary containing the public key data, with at least
                the following key/value fields:
                * value - the bytes of the key
                * format - a KeyFormatType enumeration for the bytes format
            dict: A dictionary containing the private key data, identical in
                structure to the one above.

        Raises:
            InvalidField: Raised when the algorithm is unsupported or the
                length is incompatible with the algorithm.
            CryptographicFailure: Raised when the key generation process
                fails.

        Example:
            >>> engine = CryptographyEngine()
            >>> key = engine.create_asymmetric_key(
            ...     CryptographicAlgorithm.RSA, 2048)
        """
        if algorithm not in self._asymmetric_key_algorithms.keys():
            raise exceptions.InvalidField(
                "The cryptographic algorithm ({0}) is not a supported "
                "asymmetric key algorithm.".format(algorithm)
            )

        engine_method = self._asymmetric_key_algorithms.get(algorithm)
        return engine_method(length)

    def mac(self, algorithm, key, data):
        """
        Generate message authentication code.

        Args:
            algorithm(CryptographicAlgorithm): An enumeration specifying the
                algorithm for which the MAC operation will use.
            key(bytes): secret key used in the MAC operation
            data(bytes): The data to be MACed.

        Returns:
            bytes: The MACed data

        Raises:
            InvalidField: Raised when the algorithm is unsupported or the
                length is incompatible with the algorithm.
            CryptographicFailure: Raised when the key generation process
                fails.

        Example:
            >>> engine = CryptographyEngine()
            >>> mac_data = engine.mac(
            ...     CryptographicAlgorithm.HMAC-SHA256, b'\x01\x02\x03\x04',
            ...     b'\x05\x06\x07\x08')
        """

        mac_data = None

        if algorithm in self._hash_algorithms.keys():
            self.logger.info(
                "Generating a hash-based message authentication code using "
                "{0}".format(algorithm.name)
            )
            hash_algorithm = self._hash_algorithms.get(algorithm)
            try:
                h = hmac.HMAC(key, hash_algorithm(), backend=default_backend())
                h.update(data)
                mac_data = h.finalize()
            except Exception as e:
                self.logger.exception(e)
                raise exceptions.CryptographicFailure(
                    "An error occurred while computing an HMAC. "
                    "See the server log for more information."
                )
        elif algorithm in self._symmetric_key_algorithms.keys():
            self.logger.info(
                "Generating a cipher-based message authentication code using "
                "{0}".format(algorithm.name)
            )
            cipher_algorithm = self._symmetric_key_algorithms.get(algorithm)
            try:
                # ARC4 and other non-block cipher algorithm will raise TypeError
                c = cmac.CMAC(cipher_algorithm(key), backend=default_backend())
                c.update(data)
                mac_data = c.finalize()
            except Exception:
                raise exceptions.CryptographicFailure(
                    "An error occurred while computing a CMAC. "
                    "See the server log for more information."
                )
        else:
            raise exceptions.InvalidField(
                "The cryptographic algorithm ({0}) is not a supported "
                "for a MAC operation.".format(algorithm)
            )
        return mac_data

    def encrypt(self,
                encryption_algorithm,
                encryption_key,
                plain_text,
                cipher_mode=None,
                padding_method=None,
                iv_nonce=None,
                auth_additional_data=None,
                auth_tag_length=None,
                hashing_algorithm=None):
        """
        Encrypt data using symmetric or asymmetric encryption.

        Args:
            encryption_algorithm (CryptographicAlgorithm): An enumeration
                specifying the encryption algorithm to use for encryption.
            encryption_key (bytes): The bytes of the encryption key to use for
                encryption.
            plain_text (bytes): The bytes to be encrypted.
            cipher_mode (BlockCipherMode): An enumeration specifying the
                block cipher mode to use with the encryption algorithm.
                Required in the general case. Optional if the encryption
                algorithm is RC4 (aka ARC4). If optional, defaults to None.
            padding_method (PaddingMethod): An enumeration specifying the
                padding method to use on the data before encryption. Required
                if the cipher mode is for block ciphers (e.g., CBC, ECB).
                Optional otherwise, defaults to None.
            iv_nonce (bytes): The IV/nonce value to use to initialize the mode
                of the encryption algorithm. Optional, defaults to None. If
                required and not provided, it will be autogenerated and
                returned with the cipher text.
            auth_additional_data (bytes): Any additional data to be
                authenticated via the Authenticated Encryption Tag.
                Optional, defaults to None.
            auth_tag_length (int): The length of the authentication tag in
                bytes. This parameter SHALL be provided when the Block
                Cipher Mode is GCM.
            hashing_algorithm (HashingAlgorithm): An enumeration specifying
                the hashing algorithm to use with the encryption algorithm,
                if needed. Required for OAEP-based asymmetric encryption.
                Optional, defaults to None.

        Returns:
            dict: A dictionary containing the encrypted data, with at least
                the following key/value fields:
                * cipher_text - the bytes of the encrypted data
                * iv_nonce - the bytes of the IV/counter/nonce used if it
                    was needed by the encryption scheme and if it was
                    automatically generated for the encryption
                * auth_tag - the bytes of the authentication tag used in GCM or
                    CCM mode

        Raises:
            InvalidField: Raised when the algorithm is unsupported or the
                length is incompatible with the algorithm.
            CryptographicFailure: Raised when the key generation process
                fails.

        Example:
            >>> engine = CryptographyEngine()
            >>> result = engine.encrypt(
            ...     encryption_algorithm=CryptographicAlgorithm.AES,
            ...     encryption_key=(
            ...         b'\xF3\x96\xE7\x1C\xCF\xCD\xEC\x1F'
            ...         b'\xFC\xE2\x8E\xA6\xF8\x74\x28\xB0'
            ...     ),
            ...     plain_text=(
            ...         b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ...         b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ...     ),
            ...     cipher_mode=BlockCipherMode.CBC,
            ...     padding_method=PaddingMethod.ANSI_X923,
            ... )
            >>> result.get('cipher_text')
            b'\x18[\xb9y\x1bL\xd1\x8f\x9a\xa0e\x02b\xa3=c'
            >>> result.iv_counter_nonce
            b'8qA\x05\xc4\x86\x03\xd9=\xef\xdf\xb8ke\x9a\xa2'
        """
        if encryption_algorithm is None:
            raise exceptions.InvalidField("Encryption algorithm is required.")

        if encryption_algorithm == enums.CryptographicAlgorithm.RSA:
            return self._encrypt_asymmetric(
                encryption_algorithm,
                encryption_key,
                plain_text,
                padding_method,
                hashing_algorithm=hashing_algorithm
            )
        else:
            return self._encrypt_symmetric(
                encryption_algorithm,
                encryption_key,
                plain_text,
                cipher_mode=cipher_mode,
                padding_method=padding_method,
                iv_nonce=iv_nonce,
                auth_additional_data=auth_additional_data,
                auth_tag_length=auth_tag_length
            )

    def _encrypt_symmetric(
            self,
            encryption_algorithm,
            encryption_key,
            plain_text,
            cipher_mode=None,
            padding_method=None,
            iv_nonce=None,
            auth_additional_data=None,
            auth_tag_length=None):
        """
        Encrypt data using symmetric encryption.

        Args:
            encryption_algorithm (CryptographicAlgorithm): An enumeration
                specifying the symmetric encryption algorithm to use for
                encryption.
            encryption_key (bytes): The bytes of the symmetric key to use for
                encryption.
            plain_text (bytes): The bytes to be encrypted.
            cipher_mode (BlockCipherMode): An enumeration specifying the
                block cipher mode to use with the encryption algorithm.
                Required in the general case. Optional if the encryption
                algorithm is RC4 (aka ARC4). If optional, defaults to None.
            padding_method (PaddingMethod): An enumeration specifying the
                padding method to use on the data before encryption. Required
                if the cipher mode is for block ciphers (e.g., CBC, ECB).
                Optional otherwise, defaults to None.
            iv_nonce (bytes): The IV/nonce value to use to initialize the mode
                of the encryption algorithm. Optional, defaults to None. If
                required and not provided, it will be autogenerated and
                returned with the cipher text.
            auth_additional_data (bytes): Any additional data to be
                authenticated via the Authenticated Encryption Tag.
                Optional, defaults to None.
            auth_tag_length (int): The length of the authentication tag in
                bytes. This parameter SHALL be provided when the Block Cipher
                Mode is GCM.

        Returns:
            dict: A dictionary containing the encrypted data, with at least
                the following key/value fields:
                * cipher_text - the bytes of the encrypted data
                * iv_nonce - the bytes of the IV/counter/nonce used if it
                    was needed by the encryption scheme and if it was
                    automatically generated for the encryption
                * auth_tag - the bytes of the authentication tag used in
                    GCM mode

        Raises:
            InvalidField: Raised when the algorithm is unsupported or the
                encryption key is incompatible with the algorithm.
            CryptographicFailure: Raised when the key generation process
                fails.
        """

        # Set up the algorithm
        algorithm = self._symmetric_key_algorithms.get(
            encryption_algorithm,
            None
        )
        if algorithm is None:
            raise exceptions.InvalidField(
                "Encryption algorithm '{0}' is not a supported symmetric "
                "encryption algorithm.".format(encryption_algorithm)
            )
        try:
            algorithm = algorithm(encryption_key)
        except Exception as e:
            self.logger.exception(e)
            raise exceptions.CryptographicFailure(
                "Invalid key bytes for the specified encryption algorithm."
            )

        is_gcm_mode = cipher_mode == enums.BlockCipherMode.GCM
        if not is_gcm_mode and auth_additional_data is not None:
            raise exceptions.InvalidField(
                'Authenticated encryption additional data is supported '
                'in GCM mode only.'
            )
        if is_gcm_mode and auth_tag_length is None:
            raise exceptions.InvalidField(
                'Authenticated encryption tag length must be provided '
                'in GCM mode only.'
            )

        # Set up the cipher mode if needed
        return_iv_nonce = False
        if encryption_algorithm == enums.CryptographicAlgorithm.RC4:
            mode = None
        else:
            if cipher_mode is None:
                raise exceptions.InvalidField("Cipher mode is required.")
            mode = self._modes.get(cipher_mode, None)
            if mode is None:
                raise exceptions.InvalidField(
                    "Cipher mode '{0}' is not a supported mode.".format(
                        cipher_mode
                    )
                )
            if hasattr(mode, 'initialization_vector') or \
                    hasattr(mode, 'nonce'):
                if iv_nonce is None:
                    iv_nonce = os.urandom(algorithm.block_size // 8)
                    return_iv_nonce = True
                if is_gcm_mode:
                    mode = mode(iv_nonce, None, min_tag_length=auth_tag_length)
                else:
                    mode = mode(iv_nonce)
            else:
                mode = mode()

        # Pad the plain text if needed (separate methods for testing purposes)
        if cipher_mode in [
                enums.BlockCipherMode.CBC,
                enums.BlockCipherMode.ECB
        ]:
            plain_text = self._handle_symmetric_padding(
                self._symmetric_key_algorithms.get(encryption_algorithm),
                plain_text,
                padding_method
            )

        # Encrypt the plain text
        cipher = ciphers.Cipher(algorithm, mode, backend=default_backend())
        encryptor = cipher.encryptor()
        if auth_additional_data is not None:
            encryptor.authenticate_additional_data(auth_additional_data)
        cipher_text = encryptor.update(plain_text) + encryptor.finalize()

        result = {'cipher_text': cipher_text}
        if return_iv_nonce:
            result['iv_nonce'] = iv_nonce
        if is_gcm_mode:
            result['auth_tag'] = encryptor.tag[:auth_tag_length]
        return result

    def _encrypt_asymmetric(self,
                            encryption_algorithm,
                            encryption_key,
                            plain_text,
                            padding_method,
                            hashing_algorithm=None):
        """
        Encrypt data using asymmetric encryption.

        Args:
            encryption_algorithm (CryptographicAlgorithm): An enumeration
                specifying the asymmetric encryption algorithm to use for
                encryption. Required.
            encryption_key (bytes): The bytes of the public key to use for
                encryption. Required.
            plain_text (bytes): The bytes to be encrypted. Required.
            padding_method (PaddingMethod): An enumeration specifying the
                padding method to use with the asymmetric encryption
                algorithm. Required.
            hashing_algorithm (HashingAlgorithm): An enumeration specifying
                the hashing algorithm to use with the encryption padding
                method. Required, if the padding method is OAEP. Optional
                otherwise, defaults to None.

        Returns:
            dict: A dictionary containing the encrypted data, with at least
                the following key/value field:
                * cipher_text - the bytes of the encrypted data

        Raises:
            InvalidField: Raised when the algorithm is unsupported or the
                length is incompatible with the algorithm.
            CryptographicFailure: Raised when the key generation process
                fails.
        """
        if encryption_algorithm == enums.CryptographicAlgorithm.RSA:
            if padding_method == enums.PaddingMethod.OAEP:
                hash_algorithm = self._encryption_hash_algorithms.get(
                    hashing_algorithm
                )
                if hash_algorithm is None:
                    raise exceptions.InvalidField(
                        "The hashing algorithm '{0}' is not supported for "
                        "asymmetric encryption.".format(hashing_algorithm)
                    )

                padding_method = asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(
                        algorithm=hash_algorithm()
                    ),
                    algorithm=hash_algorithm(),
                    label=None
                )
            elif padding_method == enums.PaddingMethod.PKCS1v15:
                padding_method = asymmetric_padding.PKCS1v15()
            else:
                raise exceptions.InvalidField(
                    "The padding method '{0}' is not supported for asymmetric "
                    "encryption.".format(padding_method)
                )

            backend = default_backend()

            try:
                public_key = backend.load_der_public_key(encryption_key)
            except Exception:
                try:
                    public_key = backend.load_pem_public_key(encryption_key)
                except Exception:
                    raise exceptions.CryptographicFailure(
                        "The public key bytes could not be loaded."
                    )
            cipher_text = public_key.encrypt(
                plain_text,
                padding_method
            )
            return {'cipher_text': cipher_text}
        else:
            raise exceptions.InvalidField(
                "The cryptographic algorithm '{0}' is not supported for "
                "asymmetric encryption.".format(encryption_algorithm)
            )

    def _handle_symmetric_padding(self,
                                  algorithm,
                                  plain_text,
                                  padding_method,
                                  undo_padding=False):
        # KMIP 1.3 test TC-STREAM-ENC-2-13.xml demonstrates a case
        # where an encrypt call for 3DES-ECB does not use padding if
        # the plaintext fits the blocksize of the algorithm. This does
        # not appear to be documented explicitly in the KMIP spec. It
        # also makes failures during unpadding after decryption
        # impossible to differentiate from cipher text/key mismatches.
        # For now, ALWAYS apply padding regardless of plain text length.
        if padding_method in self._symmetric_padding_methods.keys():
            padding_method = self._symmetric_padding_methods.get(
                padding_method
            )
            if undo_padding:
                padder = padding_method(algorithm.block_size).unpadder()
            else:
                padder = padding_method(algorithm.block_size).padder()
            plain_text = padder.update(plain_text)
            plain_text += padder.finalize()
        else:
            if padding_method is None:
                raise exceptions.InvalidField(
                    "Padding method is required."
                )
            else:
                raise exceptions.InvalidField(
                    "Padding method '{0}' is not supported.".format(
                        padding_method
                    )
                )
        return plain_text

    def decrypt(self,
                decryption_algorithm,
                decryption_key,
                cipher_text,
                cipher_mode=None,
                padding_method=None,
                iv_nonce=None,
                auth_additional_data=None,
                auth_tag=None,
                hashing_algorithm=None):
        """
        Decrypt data using symmetric decryption.

        Args:
            decryption_algorithm (CryptographicAlgorithm): An enumeration
                specifying the symmetric decryption algorithm to use for
                decryption.
            decryption_key (bytes): The bytes of the symmetric key to use for
                decryption.
            cipher_text (bytes): The bytes to be decrypted.
            cipher_mode (BlockCipherMode): An enumeration specifying the
                block cipher mode to use with the decryption algorithm.
                Required in the general case. Optional if the decryption
                algorithm is RC4 (aka ARC4). If optional, defaults to None.
            padding_method (PaddingMethod): An enumeration specifying the
                padding method to use on the data after decryption. Required
                if the cipher mode is for block ciphers (e.g., CBC, ECB).
                Optional otherwise, defaults to None.
            iv_nonce (bytes): The IV/nonce value to use to initialize the mode
                of the decryption algorithm. Optional, defaults to None.
            auth_additional_data (bytes): Any additional data to be
                authenticated via the Authenticated Encryption Tag.
                Added in KMIP 1.4.
            auth_tag (bytes): Specifies the tag that will be needed to
                authenticate the decrypted data. Only returned on completion
                of the encryption of the last of the plaintext by an
                authenticated encryption cipher. Optional, defaults to None.
                Added in KMIP 1.4.
            hashing_algorithm (HashingAlgorithm): An enumeration specifying
                the hashing algorithm to use with the decryption algorithm,
                if needed. Required for OAEP-based asymmetric decryption.
                Optional, defaults to None.

        Returns:
            bytes: the bytes of the decrypted data

        Raises:
            InvalidField: Raised when the algorithm is unsupported or the
                length is incompatible with the algorithm.
            CryptographicFailure: Raised when the key generation process
                fails.

        Example:
            >>> engine = CryptographyEngine()
            >>> result = engine.decrypt(
            ...     decryption_algorithm=CryptographicAlgorithm.AES,
            ...     decryption_key=(
            ...         b'\xF3\x96\xE7\x1C\xCF\xCD\xEC\x1F'
            ...         b'\xFC\xE2\x8E\xA6\xF8\x74\x28\xB0'
            ...     ),
            ...     cipher_text=(
            ...         b'\x18\x5B\xB9\x79\x1B\x4C\xD1\x8F'
            ...         b'\x9A\xA0\x65\x02\x62\xA3\x3D\x63'
            ...     ),
            ...     cipher_mode=BlockCipherMode.CBC,
            ...     padding_method=PaddingMethod.ANSI_X923,
            ...     iv_nonce=(
            ...         b'\x38\x71\x41\x05\xC4\x86\x03\xD9'
            ...         b'\x3D\xEF\xDF\xB8\x6B\x65\x9A\xA2'
            ...     )
            ... )
            >>> result
            b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f'
        """
        if decryption_algorithm is None:
            raise exceptions.InvalidField("Decryption algorithm is required.")

        if decryption_algorithm == enums.CryptographicAlgorithm.RSA:
            return self._decrypt_asymmetric(
                decryption_algorithm,
                decryption_key,
                cipher_text,
                padding_method,
                hashing_algorithm=hashing_algorithm
            )
        else:
            return self._decrypt_symmetric(
                decryption_algorithm,
                decryption_key,
                cipher_text,
                cipher_mode=cipher_mode,
                padding_method=padding_method,
                iv_nonce=iv_nonce,
                auth_additional_data=auth_additional_data,
                auth_tag=auth_tag
            )

    def _decrypt_symmetric(
            self,
            decryption_algorithm,
            decryption_key,
            cipher_text,
            cipher_mode=None,
            padding_method=None,
            iv_nonce=None,
            auth_additional_data=None,
            auth_tag=None):
        """
        Decrypt data using symmetric decryption.

        Args:
            decryption_algorithm (CryptographicAlgorithm): An enumeration
                specifying the symmetric decryption algorithm to use for
                decryption.
            decryption_key (bytes): The bytes of the symmetric key to use for
                decryption.
            cipher_text (bytes): The bytes to be decrypted.
            cipher_mode (BlockCipherMode): An enumeration specifying the
                block cipher mode to use with the decryption algorithm.
                Required in the general case. Optional if the decryption
                algorithm is RC4 (aka ARC4). If optional, defaults to None.
            padding_method (PaddingMethod): An enumeration specifying the
                padding method to use on the data after decryption. Required
                if the cipher mode is for block ciphers (e.g., CBC, ECB).
                Optional otherwise, defaults to None.
            iv_nonce (bytes): The IV/nonce value to use to initialize the mode
                of the decryption algorithm. Optional, defaults to None.
            auth_additional_data (bytes): Any additional data to be
                authenticated via the Authenticated Encryption Tag.
                Added in KMIP 1.4.
            auth_tag (bytes): Specifies the tag that will be needed to
                authenticate the decrypted data. Only returned on completion
                of the encryption of the last of the plaintext by an
                authenticated encryption cipher. Optional, defaults to None.
                Added in KMIP 1.4.

        Returns:
            bytes: the bytes of the decrypted data

        Raises:
            InvalidField: Raised when the algorithm is unsupported or the
                length is incompatible with the algorithm.
            CryptographicFailure: Raised when the key generation process
                fails.
        """
        # Set up the algorithm
        algorithm = self._symmetric_key_algorithms.get(
            decryption_algorithm,
            None
        )
        if algorithm is None:
            raise exceptions.InvalidField(
                "Decryption algorithm '{0}' is not a supported symmetric "
                "decryption algorithm.".format(decryption_algorithm)
            )
        try:
            algorithm = algorithm(decryption_key)
        except Exception as e:
            self.logger.exception(e)
            raise exceptions.CryptographicFailure(
                "Invalid key bytes for the specified decryption algorithm."
            )

        is_gcm_mode = cipher_mode == enums.BlockCipherMode.GCM
        if auth_additional_data is not None and not is_gcm_mode:
            raise exceptions.InvalidField(
                'Additional data is supported in GCM mode only.'
            )
        if is_gcm_mode and auth_tag is None:
            raise exceptions.InvalidField(
                'Authenticated tag must be provided in GCM mode.'
            )

        # Set up the cipher mode if needed
        if decryption_algorithm == enums.CryptographicAlgorithm.RC4:
            mode = None
        else:
            if cipher_mode is None:
                raise exceptions.InvalidField("Cipher mode is required.")
            mode = self._modes.get(cipher_mode, None)
            if mode is None:
                raise exceptions.InvalidField(
                    "Cipher mode '{0}' is not a supported mode.".format(
                        cipher_mode
                    )
                )
            if hasattr(mode, 'initialization_vector') or \
                    hasattr(mode, 'nonce'):
                if iv_nonce is None:
                    raise exceptions.InvalidField(
                        "IV/nonce is required."
                    )
                if is_gcm_mode:
                    mode = mode(
                        iv_nonce,
                        tag=auth_tag,
                        min_tag_length=len(auth_tag)
                    )
                else:
                    mode = mode(iv_nonce)
            else:
                mode = mode()

        # Decrypt the plain text
        cipher = ciphers.Cipher(algorithm, mode, backend=default_backend())
        decryptor = cipher.decryptor()
        if auth_additional_data is not None:
            decryptor.authenticate_additional_data(auth_additional_data)
        plain_text = decryptor.update(cipher_text) + decryptor.finalize()

        # Unpad the plain text if needed (separate methods for testing
        # purposes)
        if cipher_mode in [
                enums.BlockCipherMode.CBC,
                enums.BlockCipherMode.ECB
        ]:
            plain_text = self._handle_symmetric_padding(
                self._symmetric_key_algorithms.get(decryption_algorithm),
                plain_text,
                padding_method,
                undo_padding=True
            )

        return plain_text

    def _decrypt_asymmetric(
            self,
            decryption_algorithm,
            decryption_key,
            cipher_text,
            padding_method,
            hashing_algorithm=None):
        """
        Decrypt data using asymmetric decryption.

        Args:
            decryption_algorithm (CryptographicAlgorithm): An enumeration
                specifying the asymmetric decryption algorithm to use for
                decryption. Required.
            decryption_key (bytes): The bytes of the private key to use for
                decryption. Required.
            cipher_text (bytes): The bytes to be decrypted. Required.
            padding_method (PaddingMethod): An enumeration specifying the
                padding method to use with the asymmetric decryption
                algorithm. Required.
            hashing_algorithm (HashingAlgorithm): An enumeration specifying
                the hashing algorithm to use with the decryption padding
                method. Required, if the padding method is OAEP. Optional
                otherwise, defaults to None.

        Returns:
            dict: A dictionary containing the decrypted data, with at least
                the following key/value field:
                * plain_text - the bytes of the decrypted data

        Raises:
            InvalidField: Raised when the algorithm is unsupported or the
                length is incompatible with the algorithm.
            CryptographicFailure: Raised when the key generation process
                fails.
        """
        if decryption_algorithm == enums.CryptographicAlgorithm.RSA:
            if padding_method == enums.PaddingMethod.OAEP:
                hash_algorithm = self._encryption_hash_algorithms.get(
                    hashing_algorithm
                )
                if hash_algorithm is None:
                    raise exceptions.InvalidField(
                        "The hashing algorithm '{0}' is not supported for "
                        "asymmetric decryption.".format(hashing_algorithm)
                    )

                padding_method = asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(
                        algorithm=hash_algorithm()
                    ),
                    algorithm=hash_algorithm(),
                    label=None
                )
            elif padding_method == enums.PaddingMethod.PKCS1v15:
                padding_method = asymmetric_padding.PKCS1v15()
            else:
                raise exceptions.InvalidField(
                    "The padding method '{0}' is not supported for asymmetric "
                    "decryption.".format(padding_method)
                )

            try:
                private_key = serialization.load_der_private_key(
                    decryption_key,
                    password=None,
                    backend=default_backend()
                )
            except Exception:
                try:
                    private_key = serialization.load_pem_private_key(
                        decryption_key,
                        password=None,
                        backend=default_backend()
                    )
                except Exception:
                    raise exceptions.CryptographicFailure(
                        "The private key bytes could not be loaded."
                    )
            plain_text = private_key.decrypt(
                cipher_text,
                padding_method
            )
            return plain_text
        else:
            raise exceptions.InvalidField(
                "The cryptographic algorithm '{0}' is not supported for "
                "asymmetric decryption.".format(decryption_algorithm)
            )

    def _create_rsa_key_pair(self, length, public_exponent=65537):
        """
        Create an RSA key pair.

        Args:
            length(int): The length of the keys to be created. This value must
                be compliant with the constraints of the provided algorithm.
            public_exponent(int): The value of the public exponent needed to
                generate the keys. Usually a small Fermat prime number.
                Optional, defaults to 65537.

        Returns:
            dict: A dictionary containing the public key data, with the
                following key/value fields:
                * value - the bytes of the key
                * format - a KeyFormatType enumeration for the bytes format
                * public_exponent - the public exponent integer
            dict: A dictionary containing the private key data, identical in
                structure to the one above.

        Raises:
            CryptographicFailure: Raised when the key generation process
                fails.
        """
        self.logger.info(
            "Generating an RSA key pair with length: {0}, and "
            "public_exponent: {1}".format(
                length, public_exponent
            )
        )
        try:
            private_key = rsa.generate_private_key(
                public_exponent=public_exponent,
                key_size=length,
                backend=default_backend())
            public_key = private_key.public_key()

            private_bytes = private_key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())
            public_bytes = public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.PKCS1)
        except Exception as e:
            self.logger.exception(e)
            raise exceptions.CryptographicFailure(
                "An error occurred while generating the RSA key pair. "
                "See the server log for more information."
            )

        public_key = {
            'value': public_bytes,
            'format': enums.KeyFormatType.PKCS_1,
            'public_exponent': public_exponent
        }
        private_key = {
            'value': private_bytes,
            'format': enums.KeyFormatType.PKCS_8,
            'public_exponent': public_exponent
        }

        return public_key, private_key

    def derive_key(self,
                   derivation_method,
                   derivation_length,
                   derivation_data=None,
                   key_material=None,
                   hash_algorithm=None,
                   salt=None,
                   iteration_count=None,
                   encryption_algorithm=None,
                   cipher_mode=None,
                   padding_method=None,
                   iv_nonce=None):
        """
        Derive key data using a variety of key derivation functions.

        Args:
            derivation_method (DerivationMethod): An enumeration specifying
                the key derivation method to use. Required.
            derivation_length (int): An integer specifying the size of the
                derived key data in bytes. Required.
            derivation_data (bytes): The non-cryptographic bytes to be used
                in the key derivation process (e.g., the data to be encrypted,
                hashed, HMACed). Required in the general case. Optional if the
                derivation method is Hash and the key material is provided.
                Optional, defaults to None.
            key_material (bytes): The bytes of the key material to use for
                key derivation. Required in the general case. Optional if
                the derivation_method is HASH and derivation_data is provided.
                Optional, defaults to None.
            hash_algorithm (HashingAlgorithm): An enumeration specifying the
                hashing algorithm to use with the key derivation method.
                Required in the general case, optional if the derivation
                method specifies encryption. Optional, defaults to None.
            salt (bytes): Bytes representing a randomly generated salt.
                Required if the derivation method is PBKDF2. Optional,
                defaults to None.
            iteration_count (int): An integer representing the number of
                iterations to use when deriving key material. Required if
                the derivation method is PBKDF2. Optional, defaults to None.
            encryption_algorithm (CryptographicAlgorithm): An enumeration
                specifying the symmetric encryption algorithm to use for
                encryption-based key derivation. Required if the derivation
                method specifies encryption. Optional, defaults to None.
            cipher_mode (BlockCipherMode): An enumeration specifying the
                block cipher mode to use with the encryption algorithm.
                Required in in the general case if the derivation method
                specifies encryption and the encryption algorithm is
                specified. Optional if the encryption algorithm is RC4 (aka
                ARC4). Optional, defaults to None.
            padding_method (PaddingMethod): An enumeration specifying the
                padding method to use on the data before encryption. Required
                in in the general case if the derivation method specifies
                encryption and the encryption algorithm is specified. Required
                if the cipher mode is for block ciphers (e.g., CBC, ECB).
                Optional otherwise, defaults to None.
            iv_nonce (bytes): The IV/nonce value to use to initialize the mode
                of the encryption algorithm. Required in the general case if
                the derivation method specifies encryption and the encryption
                algorithm is specified. Optional, defaults to None. If
                required and not provided, it will be autogenerated.

        Returns:
            bytes: the bytes of the derived data

        Raises:
            InvalidField: Raised when cryptographic data and/or settings are
                unsupported or incompatible with the derivation method.

        Example:
            >>> engine = CryptographyEngine()
            >>> result = engine.derive_key(
            ...     derivation_method=enums.DerivationMethod.HASH,
            ...     derivation_length=16,
            ...     derivation_data=b'abc',
            ...     hash_algorithm=enums.HashingAlgorithm.MD5
            ... )
            >>> result
            b'\x90\x01P\x98<\xd2O\xb0\xd6\x96?}(\xe1\x7fr'
        """
        if derivation_method == enums.DerivationMethod.ENCRYPT:
            result = self.encrypt(
                encryption_algorithm=encryption_algorithm,
                encryption_key=key_material,
                plain_text=derivation_data,
                cipher_mode=cipher_mode,
                padding_method=padding_method,
                iv_nonce=iv_nonce
            )
            return result.get('cipher_text')
        else:
            # Handle key derivation functions that use hash algorithms

            # Set up the hashing algorithm
            if hash_algorithm is None:
                raise exceptions.InvalidField("Hash algorithm is required.")
            hashing_algorithm = self._encryption_hash_algorithms.get(
                hash_algorithm,
                None
            )
            if hashing_algorithm is None:
                raise exceptions.InvalidField(
                    "Hash algorithm '{0}' is not a supported hashing "
                    "algorithm.".format(hash_algorithm)
                )

            if derivation_method == enums.DerivationMethod.HMAC:
                df = hkdf.HKDF(
                    algorithm=hashing_algorithm(),
                    length=derivation_length,
                    salt=salt,
                    info=derivation_data,
                    backend=default_backend()
                )
                derived_data = df.derive(key_material)
                return derived_data
            elif derivation_method == enums.DerivationMethod.HASH:
                if None not in [derivation_data, key_material]:
                    raise exceptions.InvalidField(
                        "For hash-based key derivation, specify only "
                        "derivation data or key material, not both."
                    )
                elif derivation_data is not None:
                    hashing_data = derivation_data
                elif key_material is not None:
                    hashing_data = key_material
                else:
                    raise exceptions.InvalidField(
                        "For hash-based key derivation, derivation data or "
                        "key material must be specified."
                    )

                df = hashes.Hash(
                    algorithm=hashing_algorithm(),
                    backend=default_backend()
                )
                df.update(hashing_data)
                derived_data = df.finalize()
                return derived_data
            elif derivation_method == enums.DerivationMethod.PBKDF2:
                if salt is None:
                    raise exceptions.InvalidField(
                        "For PBKDF2 key derivation, salt must be specified."
                    )
                if iteration_count is None:
                    raise exceptions.InvalidField(
                        "For PBKDF2 key derivation, iteration count must be "
                        "specified."
                    )

                df = pbkdf2.PBKDF2HMAC(
                    algorithm=hashing_algorithm(),
                    length=derivation_length,
                    salt=salt,
                    iterations=iteration_count,
                    backend=default_backend()
                )
                derived_data = df.derive(key_material)
                return derived_data
            elif derivation_method == enums.DerivationMethod.NIST800_108_C:
                df = kbkdf.KBKDFHMAC(
                    algorithm=hashing_algorithm(),
                    mode=kbkdf.Mode.CounterMode,
                    length=derivation_length,
                    rlen=4,
                    llen=None,
                    location=kbkdf.CounterLocation.BeforeFixed,
                    label=None,
                    context=None,
                    fixed=derivation_data,
                    backend=default_backend()
                )
                derived_data = df.derive(key_material)
                return derived_data
            else:
                raise exceptions.InvalidField(
                    "Derivation method '{0}' is not a supported key "
                    "derivation method.".format(derivation_method)
                )

    def wrap_key(self,
                 key_material,
                 wrapping_method,
                 key_wrap_algorithm,
                 encryption_key):
        """
        Args:
            key_material (bytes): The bytes of the key to wrap. Required.
            wrapping_method (WrappingMethod): A WrappingMethod enumeration
                specifying what wrapping technique to use to wrap the key
                material. Required.
            key_wrap_algorithm (BlockCipherMode): A BlockCipherMode
                enumeration specifying the key wrapping algorithm to use to
                wrap the key material. Required.
            encryption_key (bytes): The bytes of the encryption key to use
                to encrypt the key material. Required.

        Returns:
            bytes: the bytes of the wrapped key

        Raises:
            CryptographicFailure: Raised when an error occurs during key
                wrapping.
            InvalidField: Raised when an unsupported wrapping or encryption
                algorithm is specified.

        Example:
            >>> engine = CryptographyEngine()
            >>> result = engine.wrap_key(
            ...     key_material=(
            ...         b'\x00\x11\x22\x33\x44\x55\x66\x77'
            ...         b'\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
            ...     )
            ...     wrapping_method=enums.WrappingMethod.ENCRYPT,
            ...     key_wrap_algorithm=enums.BlockCipherMode.NIST_KEY_WRAP,
            ...     encryption_key=(
            ...         b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ...         b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ...     )
            ... )
            >>> result
            b'\x1f\xa6\x8b\n\x81\x12\xb4G\xae\xf3K\xd8\xfbZ{\x82\x9d>\x86#q
            \xd2\xcf\xe5'
        """
        if wrapping_method == enums.WrappingMethod.ENCRYPT:
            if key_wrap_algorithm == enums.BlockCipherMode.NIST_KEY_WRAP:
                try:
                    wrapped_key = keywrap.aes_key_wrap(
                        encryption_key,
                        key_material,
                        default_backend()
                    )
                    return wrapped_key
                except Exception as e:
                    raise exceptions.CryptographicFailure(str(e))
            else:
                raise exceptions.InvalidField(
                    "Encryption algorithm '{0}' is not a supported key "
                    "wrapping algorithm.".format(key_wrap_algorithm)
                )
        else:
            raise exceptions.InvalidField(
                "Wrapping method '{0}' is not a supported key wrapping "
                "method.".format(wrapping_method)
            )

    def _create_RSA_private_key(self,
                                bytes):
        """
        Instantiates an RSA key from bytes.

        Args:
            bytes (byte string): Bytes of RSA private key.
        Returns:
            private_key
                (cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
                RSA private key created from key bytes.
        """

        try:
            private_key = serialization.load_pem_private_key(
                bytes,
                password=None,
                backend=default_backend()
            )
            return private_key
        except Exception:
            private_key = serialization.load_der_private_key(
                bytes,
                password=None,
                backend=default_backend()
            )
            return private_key

    def sign(self,
             digital_signature_algorithm,
             crypto_alg,
             hash_algorithm,
             padding,
             signing_key,
             data):
        """
        Args:
            digital_signature_algorithm (DigitalSignatureAlgorithm): An
                enumeration specifying the asymmetric cryptographic algorithm
                and hashing algorithm to use for the signature operation. Can
                be None if cryptographic_algorithm and hash_algorithm are set.
            crypto_alg (CryptographicAlgorithm): An enumeration
                specifying the asymmetric cryptographic algorithm to use for
                the signature operation. Can be None if
                digital_signature_algorithm is set.
            hash_algorithm (HashingAlgorithm): An enumeration specifying the
                hash algorithm to use for the signature operation. Can be None
                if digital_signature_algorithm is set.
            padding (PaddingMethod): An enumeration specifying the asymmetric
                padding method to use for the signature operation.
            signing_key (bytes): The bytes of the private key to use for the
                signature operation.
            data (bytes): The data to be signed.

        Returns:
            signature (bytes): the bytes of the signature data

        Raises:
            CryptographicFailure: Raised when an error occurs during signature
                creation.
            InvalidField: Raised when an unsupported hashing or cryptographic
                algorithm is specified.
        """

        if digital_signature_algorithm:
            (hash_alg, crypto_alg) = self._digital_signature_algorithms.get(
                                         digital_signature_algorithm,
                                         (None, None)
            )

        elif crypto_alg and hash_algorithm:
            hash_alg = self._encryption_hash_algorithms.get(
                hash_algorithm, None
            )
        else:
            raise exceptions.InvalidField(
                'For signing, either a digital signature algorithm or a hash'
                ' algorithm and a cryptographic algorithm must be specified.'
            )

        if crypto_alg == enums.CryptographicAlgorithm.RSA:
            try:
                key = self._create_RSA_private_key(signing_key)
            except Exception:
                raise exceptions.InvalidField('Unable to deserialize key '
                                              'bytes, unknown format.')
        else:
            raise exceptions.InvalidField(
                'For signing, an RSA key must be used.'
            )

        if padding:
            padding_method = self._asymmetric_padding_methods.get(
                padding, None
            )
        else:
            raise exceptions.InvalidField(
                'For signing, a padding method must be specified.'
            )

        if padding == enums.PaddingMethod.PSS:
            signature = key.sign(
                data,
                asymmetric_padding.PSS(
                    mgf=asymmetric_padding.MGF1(hash_alg()),
                    salt_length=asymmetric_padding.PSS.MAX_LENGTH
                ),
                hash_alg()
            )
        elif padding == enums.PaddingMethod.PKCS1v15:
            signature = key.sign(
                data,
                padding_method(),
                hash_alg()
            )
        else:
            raise exceptions.InvalidField(
                "Padding method '{0}' is not a supported signature "
                "padding method.".format(padding)
            )
        return signature

    def verify_signature(self,
                         signing_key,
                         message,
                         signature,
                         padding_method,
                         signing_algorithm=None,
                         hashing_algorithm=None,
                         digital_signature_algorithm=None):
        """
        Verify a message signature.

        Args:
            signing_key (bytes): The bytes of the signing key to use for
                signature verification. Required.
            message (bytes): The bytes of the message that corresponds with
                the signature. Required.
            signature (bytes): The bytes of the signature to be verified.
                Required.
            padding_method (PaddingMethod): An enumeration specifying the
                padding method to use during signature verification. Required.
            signing_algorithm (CryptographicAlgorithm): An enumeration
            specifying the cryptographic algorithm to use for signature
            verification. Only RSA is supported. Optional, must match the
                algorithm specified by the digital signature algorithm if both
                are provided. Defaults to None.
            hashing_algorithm (HashingAlgorithm): An enumeration specifying
                the hashing algorithm to use with the cryptographic algortihm,
                if needed. Optional, must match the algorithm specified by the
                digital signature algorithm if both are provided. Defaults to
                None.
            digital_signature_algorithm (DigitalSignatureAlgorithm): An
                enumeration specifying both the cryptographic and hashing
                algorithms to use for signature verification. Optional, must
                match the cryptographic and hashing algorithms if both are
                provided. Defaults to None.

        Returns:
            boolean: the result of signature verification, True for valid
                signatures, False for invalid signatures

        Raises:
            InvalidField: Raised when various settings or values are invalid.
            CryptographicFailure: Raised when the signing key bytes cannot be
                loaded, or when the signature verification process fails
                unexpectedly.
        """
        backend = default_backend()

        hash_algorithm = None
        dsa_hash_algorithm = None
        dsa_signing_algorithm = None

        if hashing_algorithm:
            hash_algorithm = self._encryption_hash_algorithms.get(
                hashing_algorithm
            )
        if digital_signature_algorithm:
            algorithm_pair = self._digital_signature_algorithms.get(
                digital_signature_algorithm
            )
            if algorithm_pair:
                dsa_hash_algorithm = algorithm_pair[0]
                dsa_signing_algorithm = algorithm_pair[1]

        if dsa_hash_algorithm and dsa_signing_algorithm:
            if hash_algorithm and (hash_algorithm != dsa_hash_algorithm):
                raise exceptions.InvalidField(
                    "The hashing algorithm does not match the digital "
                    "signature algorithm."
                )
            if (signing_algorithm and
                    (signing_algorithm != dsa_signing_algorithm)):
                raise exceptions.InvalidField(
                    "The signing algorithm does not match the digital "
                    "signature algorithm."
                )

            signing_algorithm = dsa_signing_algorithm
            hash_algorithm = dsa_hash_algorithm

        if signing_algorithm == enums.CryptographicAlgorithm.RSA:
            if padding_method == enums.PaddingMethod.PSS:
                if hash_algorithm:
                    padding = asymmetric_padding.PSS(
                        mgf=asymmetric_padding.MGF1(hash_algorithm()),
                        salt_length=asymmetric_padding.PSS.MAX_LENGTH
                    )
                else:
                    raise exceptions.InvalidField(
                        "A hashing algorithm must be specified for PSS "
                        "padding."
                    )
            elif padding_method == enums.PaddingMethod.PKCS1v15:
                padding = asymmetric_padding.PKCS1v15()
            else:
                raise exceptions.InvalidField(
                    "The padding method '{0}' is not supported for signature "
                    "verification.".format(padding_method)
                )

            try:
                public_key = backend.load_der_public_key(signing_key)
            except Exception:
                try:
                    public_key = backend.load_pem_public_key(signing_key)
                except Exception:
                    raise exceptions.CryptographicFailure(
                        "The signing key bytes could not be loaded."
                    )

            try:
                public_key.verify(
                    signature,
                    message,
                    padding,
                    hash_algorithm()
                )
                return True
            except errors.InvalidSignature:
                return False
            except Exception:
                raise exceptions.CryptographicFailure(
                    "The signature verification process failed."
                )
        else:
            raise exceptions.InvalidField(
                "The signing algorithm '{0}' is not supported for "
                "signature verification.".format(signing_algorithm)
            )
