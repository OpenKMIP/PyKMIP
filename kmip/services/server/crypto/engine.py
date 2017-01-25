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

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac, cmac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import algorithms

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

        self._symmetric_key_algorithms = {
            enums.CryptographicAlgorithm.TRIPLE_DES: algorithms.TripleDES,
            enums.CryptographicAlgorithm.AES: algorithms.AES,
            enums.CryptographicAlgorithm.BLOWFISH: algorithms.Blowfish,
            enums.CryptographicAlgorithm.CAMELLIA: algorithms.Camellia,
            enums.CryptographicAlgorithm.CAST5: algorithms.CAST5,
            enums.CryptographicAlgorithm.IDEA: algorithms.IDEA,
            enums.CryptographicAlgorithm.RC4: algorithms.ARC4
        }
        self._asymetric_key_algorithms = {
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
        if algorithm not in self._asymetric_key_algorithms.keys():
            raise exceptions.InvalidField(
                "The cryptographic algorithm ({0}) is not a supported "
                "asymmetric key algorithm.".format(algorithm)
            )

        engine_method = self._asymetric_key_algorithms.get(algorithm)
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
            ...     CryptographicAlgorithm.HMAC-SHA256, b'\x01\x02\x03\x04')
        """

        mac_data = None

        if algorithm in self._hash_algorithms.keys():
            self.logger.info(
                "Generating hash-based Message authentication codes using {0}".
                format(algorithm.name)
            )
            hash_algorithm = self._hash_algorithms.get(algorithm)
            try:
                h = hmac.HMAC(key, hash_algorithm(), backend=default_backend())
                h.update(data)
                mac_data = h.finalize()
            except Exception as e:
                self.logger.exception(e)
                raise exceptions.CryptographicFailure(
                    "An error occurred while doing HMAC operation. "
                    "See the server log for more information."
                )
        elif algorithm in self._symmetric_key_algorithms.keys():
            self.logger.info(
                "Generating cipher-based Message authentication codes using "
                "{0}".format(algorithm.name)
            )
            cipher_algorithm = self._symmetric_key_algorithms.get(algorithm)
            try:
                c = cmac.CMAC(cipher_algorithm(key), backend=default_backend())
                c.update(data)
                mac_data = c.finalize()
            except Exception as e:
                raise exceptions.CryptographicFailure(
                    "An error occurred while doing CMAC operation. "
                    "See the server log for more information."
                )
        else:
            raise exceptions.InvalidField(
                "The cryptographic algorithm ({0}) is not a supported "
                "for MAC operation.".format(algorithm)
            )
        return mac_data

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
