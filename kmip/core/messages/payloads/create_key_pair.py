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

from kmip.core import enums
from kmip.core import exceptions
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils
from kmip.core.messages.payloads import base

class CreateKeyPairRequestPayload(base.RequestPayload):
    """
    A request payload for the CreateKeyPair operation.

    Attributes:
        common_template_attribute: A group of attributes to set on the new
            public and private keys.
        private_key_template_attribute: A group of attributes to set on the new
            private key.
        public_key_template_attribute: A group of attributes to set on the new
            public key.
        common_protection_storage_masks: A ProtectionStorageMasks structure
            containing the storage masks permissible for both new public and
            private keys. Added in KMIP 2.0.
        private_protection_storage_masks: A ProtectionStorageMasks structure
            containing the storage masks permissible for the new private key.
            Added in KMIP 2.0.
        public_protection_storage_masks: A ProtectionStorageMasks structure
            containing the storage masks permissible for the new public key.
            Added in KMIP 2.0.
    """

    def __init__(self,
                 common_template_attribute=None,
                 private_key_template_attribute=None,
                 public_key_template_attribute=None,
                 common_protection_storage_masks=None,
                 private_protection_storage_masks=None,
                 public_protection_storage_masks=None):
        """
        Construct a CreateKeyPair request payload structure.

        Args:
            common_template_attribute (TemplateAttribute): A TemplateAttribute
                structure with the CommonTemplateAttribute tag containing a set
                of attributes to set on the new public and private keys.
                Optional, defaults to None.
            private_key_template_attribute (TemplateAttribute): A
                TemplateAttribute structure with the
                PrivateKeyTemplateAttribute tag containing a set of attributes
                to set on the new private key. Optional, defaults to None.
            public_key_template_attribute (TemplateAttribute): A
                TemplateAttribute structure with the PublicKeyTemplateAttribute
                tag containing a set of attributes to set on the new public
                key. Optional, defaults to None.
            common_protection_storage_masks (structure): A
                ProtectionStorageMasks structure containing the storage masks
                permissible for both new public and private keys. Added in KMIP
                2.0. Optional, defaults to None.
            private_protection_storage_masks (structure): A
                ProtectionStorageMasks structure containing the storage masks
                permissible for the new private key. Added in KMIP 2.0.
                Optional, defaults to None.
            public_protection_storage_masks (structure): A
                ProtectionStorageMasks structure containing the storage masks
                permissible for the new public key. Added in KMIP 2.0.
                Optional, defaults to None.
        """
        super(CreateKeyPairRequestPayload, self).__init__()

        self._common_template_attribute = None
        self._private_key_template_attribute = None
        self._public_key_template_attribute = None
        self._common_protection_storage_masks = None
        self._private_protection_storage_masks = None
        self._public_protection_storage_masks = None

        self.common_template_attribute = common_template_attribute
        self.private_key_template_attribute = private_key_template_attribute
        self.public_key_template_attribute = public_key_template_attribute
        self.common_protection_storage_masks = common_protection_storage_masks
        self.private_protection_storage_masks = \
            private_protection_storage_masks
        self.public_protection_storage_masks = public_protection_storage_masks

    @property
    def common_template_attribute(self):
        return self._common_template_attribute

    @common_template_attribute.setter
    def common_template_attribute(self, value):
        if value is None:
            self._common_template_attribute = None
        elif isinstance(value, objects.TemplateAttribute):
            if value.tag == enums.Tags.COMMON_TEMPLATE_ATTRIBUTE:
                self._common_template_attribute = value
            else:
                raise TypeError(
                    "Common template attribute must be a TemplateAttribute "
                    "structure with a CommonTemplateAttribute tag."
                )
        else:
            raise TypeError(
                "Common template attribute must be a TemplateAttribute "
                "structure."
            )

    @property
    def private_key_template_attribute(self):
        return self._private_key_template_attribute

    @private_key_template_attribute.setter
    def private_key_template_attribute(self, value):
        if value is None:
            self._private_key_template_attribute = None
        elif isinstance(value, objects.TemplateAttribute):
            if value.tag == enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE:
                self._private_key_template_attribute = value
            else:
                raise TypeError(
                    "Private key template attribute must be a "
                    "TemplateAttribute structure with a "
                    "PrivateKeyTemplateAttribute tag."
                )
        else:
            raise TypeError(
                "Private key template attribute must be a TemplateAttribute "
                "structure."
            )

    @property
    def public_key_template_attribute(self):
        return self._public_key_template_attribute

    @public_key_template_attribute.setter
    def public_key_template_attribute(self, value):
        if value is None:
            self._public_key_template_attribute = None
        elif isinstance(value, objects.TemplateAttribute):
            if value.tag == enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE:
                self._public_key_template_attribute = value
            else:
                raise TypeError(
                    "Public key template attribute must be a "
                    "TemplateAttribute structure with a "
                    "PublicKeyTemplateAttribute tag."
                )
        else:
            raise TypeError(
                "Public key template attribute must be a TemplateAttribute "
                "structure."
            )

    @property
    def common_protection_storage_masks(self):
        return self._common_protection_storage_masks

    @common_protection_storage_masks.setter
    def common_protection_storage_masks(self, value):
        if value is None:
            self._common_protection_storage_masks = None
        elif isinstance(value, objects.ProtectionStorageMasks):
            if value.tag == enums.Tags.COMMON_PROTECTION_STORAGE_MASKS:
                self._common_protection_storage_masks = value
            else:
                raise TypeError(
                    "The common protection storage masks must be a "
                    "ProtectionStorageMasks structure with a "
                    "CommonProtectionStorageMasks tag."
                )
        else:
            raise TypeError(
                "The common protection storage masks must be a "
                "ProtectionStorageMasks structure."
            )

    @property
    def private_protection_storage_masks(self):
        return self._private_protection_storage_masks

    @private_protection_storage_masks.setter
    def private_protection_storage_masks(self, value):
        if value is None:
            self._private_protection_storage_masks = None
        elif isinstance(value, objects.ProtectionStorageMasks):
            if value.tag == enums.Tags.PRIVATE_PROTECTION_STORAGE_MASKS:
                self._private_protection_storage_masks = value
            else:
                raise TypeError(
                    "The private protection storage masks must be a "
                    "ProtectionStorageMasks structure with a "
                    "PrivateProtectionStorageMasks tag."
                )
        else:
            raise TypeError(
                "The private protection storage masks must be a "
                "ProtectionStorageMasks structure."
            )

    @property
    def public_protection_storage_masks(self):
        return self._public_protection_storage_masks

    @public_protection_storage_masks.setter
    def public_protection_storage_masks(self, value):
        if value is None:
            self._public_protection_storage_masks = None
        elif isinstance(value, objects.ProtectionStorageMasks):
            if value.tag == enums.Tags.PUBLIC_PROTECTION_STORAGE_MASKS:
                self._public_protection_storage_masks = value
            else:
                raise TypeError(
                    "The public protection storage masks must be a "
                    "ProtectionStorageMasks structure with a "
                    "PublicProtectionStorageMasks tag."
                )
        else:
            raise TypeError(
                "The public protection storage masks must be a "
                "ProtectionStorageMasks structure."
            )

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the CreateKeyPair request payload and decode it
        into its constituent parts.

        Args:
            input_buffer (stream): A data buffer containing encoded object
                data, supporting a read method.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(CreateKeyPairRequestPayload, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self.is_tag_next(
                    enums.Tags.COMMON_TEMPLATE_ATTRIBUTE,
                    local_buffer
            ):
                self._common_template_attribute = objects.TemplateAttribute(
                    tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
                )
                self._common_template_attribute.read(
                    local_buffer,
                    kmip_version=kmip_version
                )
        else:
            if self.is_tag_next(enums.Tags.COMMON_ATTRIBUTES, local_buffer):
                attributes = objects.Attributes(
                    tag=enums.Tags.COMMON_ATTRIBUTES
                )
                attributes.read(local_buffer, kmip_version=kmip_version)
                self._common_template_attribute = \
                    objects.convert_attributes_to_template_attribute(
                        attributes
                    )

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self.is_tag_next(
                    enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
                    local_buffer
            ):
                self._private_key_template_attribute = \
                    objects.TemplateAttribute(
                        tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
                    )
                self._private_key_template_attribute.read(
                    local_buffer,
                    kmip_version=kmip_version
                )
        else:
            if self.is_tag_next(
                    enums.Tags.PRIVATE_KEY_ATTRIBUTES,
                    local_buffer
            ):
                attributes = objects.Attributes(
                    tag=enums.Tags.PRIVATE_KEY_ATTRIBUTES
                )
                attributes.read(local_buffer, kmip_version=kmip_version)
                self._private_key_template_attribute = \
                    objects.convert_attributes_to_template_attribute(
                        attributes
                    )

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self.is_tag_next(
                    enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE,
                    local_buffer
            ):
                self._public_key_template_attribute = \
                    objects.TemplateAttribute(
                        tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
                    )
                self._public_key_template_attribute.read(
                    local_buffer,
                    kmip_version=kmip_version
                )
        else:
            if self.is_tag_next(
                    enums.Tags.PUBLIC_KEY_ATTRIBUTES,
                    local_buffer
            ):
                attributes = objects.Attributes(
                    tag=enums.Tags.PUBLIC_KEY_ATTRIBUTES
                )
                attributes.read(local_buffer, kmip_version=kmip_version)
                self._public_key_template_attribute = \
                    objects.convert_attributes_to_template_attribute(
                        attributes
                    )

        if kmip_version >= enums.KMIPVersion.KMIP_2_0:
            if self.is_tag_next(
                enums.Tags.COMMON_PROTECTION_STORAGE_MASKS,
                local_buffer
            ):
                storage_masks = objects.ProtectionStorageMasks(
                    tag=enums.Tags.COMMON_PROTECTION_STORAGE_MASKS
                )
                storage_masks.read(local_buffer, kmip_version=kmip_version)
                self._common_protection_storage_masks = storage_masks
            if self.is_tag_next(
                enums.Tags.PRIVATE_PROTECTION_STORAGE_MASKS,
                local_buffer
            ):
                storage_masks = objects.ProtectionStorageMasks(
                    tag=enums.Tags.PRIVATE_PROTECTION_STORAGE_MASKS
                )
                storage_masks.read(local_buffer, kmip_version=kmip_version)
                self._private_protection_storage_masks = storage_masks
            if self.is_tag_next(
                enums.Tags.PUBLIC_PROTECTION_STORAGE_MASKS,
                local_buffer
            ):
                storage_masks = objects.ProtectionStorageMasks(
                    tag=enums.Tags.PUBLIC_PROTECTION_STORAGE_MASKS
                )
                storage_masks.read(local_buffer, kmip_version=kmip_version)
                self._public_protection_storage_masks = storage_masks

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the CreateKeyPair request payload to a buffer.

        Args:
            output_buffer (stream): A data buffer in which to encode object
                data, supporting a write method.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        local_buffer = utils.BytearrayStream()

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self._common_template_attribute is not None:
                self._common_template_attribute.write(
                    local_buffer,
                    kmip_version=kmip_version
                )
        else:
            if self._common_template_attribute is not None:
                attributes = objects.convert_template_attribute_to_attributes(
                    self._common_template_attribute
                )
                attributes.write(local_buffer, kmip_version=kmip_version)

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self._private_key_template_attribute is not None:
                self._private_key_template_attribute.write(
                    local_buffer,
                    kmip_version=kmip_version
                )
        else:
            if self._private_key_template_attribute is not None:
                attributes = objects.convert_template_attribute_to_attributes(
                    self._private_key_template_attribute
                )
                attributes.write(local_buffer, kmip_version=kmip_version)

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self._public_key_template_attribute is not None:
                self._public_key_template_attribute.write(
                    local_buffer,
                    kmip_version=kmip_version
                )
        else:
            if self._public_key_template_attribute is not None:
                attributes = objects.convert_template_attribute_to_attributes(
                    self._public_key_template_attribute
                )
                attributes.write(local_buffer, kmip_version=kmip_version)

        if kmip_version >= enums.KMIPVersion.KMIP_2_0:
            if self._common_protection_storage_masks:
                self._common_protection_storage_masks.write(
                    local_buffer,
                    kmip_version=kmip_version
                )
            if self._private_protection_storage_masks:
                self._private_protection_storage_masks.write(
                    local_buffer,
                    kmip_version=kmip_version
                )
            if self._public_protection_storage_masks:
                self._public_protection_storage_masks.write(
                    local_buffer,
                    kmip_version=kmip_version
                )

        self.length = local_buffer.length()
        super(CreateKeyPairRequestPayload, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __eq__(self, other):
        if isinstance(other, CreateKeyPairRequestPayload):
            if self.common_template_attribute != \
                    other.common_template_attribute:
                return False
            elif self.private_key_template_attribute != \
                    other.private_key_template_attribute:
                return False
            elif self.public_key_template_attribute != \
                    other.public_key_template_attribute:
                return False
            elif self.common_protection_storage_masks != \
                    other.common_protection_storage_masks:
                return False
            elif self.private_protection_storage_masks != \
                    other.private_protection_storage_masks:
                return False
            elif self.public_protection_storage_masks != \
                    other.public_protection_storage_masks:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, CreateKeyPairRequestPayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "common_template_attribute={}".format(
                self.common_template_attribute
            ),
            "private_key_template_attribute={}".format(
                self.private_key_template_attribute
            ),
            "public_key_template_attribute={}".format(
                self.public_key_template_attribute
            ),
            "common_protection_storage_masks={}".format(
                repr(self.common_protection_storage_masks)
            ),
            "private_protection_storage_masks={}".format(
                repr(self.private_protection_storage_masks)
            ),
            "public_protection_storage_masks={}".format(
                repr(self.public_protection_storage_masks)
            )
        ])
        return "CreateKeyPairRequestPayload({})".format(args)

    def __str__(self):
        value = ", ".join(
            [
                '"common_template_attribute": {}'.format(
                    self.common_template_attribute
                ),
                '"private_key_template_attribute": {}'.format(
                    self.private_key_template_attribute
                ),
                '"public_key_template_attribute": {}'.format(
                    self.public_key_template_attribute
                ),
                '"common_protection_storage_masks": {}'.format(
                    str(self.common_protection_storage_masks)
                ),
                '"private_protection_storage_masks": {}'.format(
                    str(self.private_protection_storage_masks)
                ),
                '"public_protection_storage_masks": {}'.format(
                    str(self.public_protection_storage_masks)
                )
            ]
        )
        return '{' + value + '}'

class CreateKeyPairResponsePayload(base.ResponsePayload):
    """
    A response payload for the CreateKeyPair operation.

    Attributes:
        private_key_unique_identifier: The ID of the new private key.
        public_key_unique_identifier: The ID of the new public key.
        private_key_template_attribute: A group of attributes to set on the new
            private key.
        public_key_template_attribute: A group of attributes to set on the new
            public key.
    """

    def __init__(self,
                 private_key_unique_identifier=None,
                 public_key_unique_identifier=None,
                 private_key_template_attribute=None,
                 public_key_template_attribute=None):
        """
        Construct a CreateKeyPair response payload structure.

        Args:
            private_key_unique_identifier (string): A string specifying the
                ID of the new private key. Optional, defaults to None. Required
                for read/write.
            public_key_unique_identifier (string): A string specifying the
                ID of the new public key. Optional, defaults to None. Required
                for read/write.
            private_key_template_attribute (TemplateAttribute): A
                TemplateAttribute structure with the
                PrivateKeyTemplateAttribute tag containing the set of
                attributes that were set on the new private key. Optional,
                defaults to None.
            public_key_template_attribute (TemplateAttribute): A
                TemplateAttribute structure with the PublicKeyTemplateAttribute
                tag containing the set of attributes that were set on the new
                public key. Optional, defaults to None.
        """
        super(CreateKeyPairResponsePayload, self).__init__()

        self._private_key_unique_identifier = None
        self._public_key_unique_identifier = None
        self._private_key_template_attribute = None
        self._public_key_template_attribute = None

        self.private_key_unique_identifier = private_key_unique_identifier
        self.public_key_unique_identifier = public_key_unique_identifier
        self.private_key_template_attribute = private_key_template_attribute
        self.public_key_template_attribute = public_key_template_attribute

    @property
    def private_key_unique_identifier(self):
        if self._private_key_unique_identifier:
            return self._private_key_unique_identifier.value
        else:
            return None

    @private_key_unique_identifier.setter
    def private_key_unique_identifier(self, value):
        if value is None:
            self._private_key_unique_identifier = None
        elif isinstance(value, str):
            self._private_key_unique_identifier = primitives.TextString(
                value=value,
                tag=enums.Tags.PRIVATE_KEY_UNIQUE_IDENTIFIER
            )
        else:
            raise TypeError("Private key unique identifier must be a string.")

    @property
    def public_key_unique_identifier(self):
        if self._public_key_unique_identifier:
            return self._public_key_unique_identifier.value
        else:
            return None

    @public_key_unique_identifier.setter
    def public_key_unique_identifier(self, value):
        if value is None:
            self._public_key_unique_identifier = None
        elif isinstance(value, str):
            self._public_key_unique_identifier = primitives.TextString(
                value=value,
                tag=enums.Tags.PUBLIC_KEY_UNIQUE_IDENTIFIER
            )
        else:
            raise TypeError("Public key unique identifier must be a string.")

    @property
    def private_key_template_attribute(self):
        return self._private_key_template_attribute

    @private_key_template_attribute.setter
    def private_key_template_attribute(self, value):
        if value is None:
            self._private_key_template_attribute = None
        elif isinstance(value, objects.TemplateAttribute):
            if value.tag == enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE:
                self._private_key_template_attribute = value
            else:
                raise TypeError(
                    "Private key template attribute must be a "
                    "TemplateAttribute structure with a "
                    "PrivateKeyTemplateAttribute tag."
                )
        else:
            raise TypeError(
                "Private key template attribute must be a TemplateAttribute "
                "structure."
            )

    @property
    def public_key_template_attribute(self):
        return self._public_key_template_attribute

    @public_key_template_attribute.setter
    def public_key_template_attribute(self, value):
        if value is None:
            self._public_key_template_attribute = None
        elif isinstance(value, objects.TemplateAttribute):
            if value.tag == enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE:
                self._public_key_template_attribute = value
            else:
                raise TypeError(
                    "Public key template attribute must be a "
                    "TemplateAttribute structure with a "
                    "PublicKeyTemplateAttribute tag."
                )
        else:
            raise TypeError(
                "Public key template attribute must be a TemplateAttribute "
                "structure."
            )

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the CreateKeyPair response payload and decode it
        into its constituent parts.

        Args:
            input_buffer (stream): A data buffer containing encoded object
                data, supporting a read method.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            InvalidKmipEncoding: Raised if the private key unique identifier or
                the public key unique identifier is missing from the encoded
                payload.
        """
        super(CreateKeyPairResponsePayload, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

        if self.is_tag_next(
                enums.Tags.PRIVATE_KEY_UNIQUE_IDENTIFIER,
                local_buffer
        ):
            self._private_key_unique_identifier = primitives.TextString(
                tag=enums.Tags.PRIVATE_KEY_UNIQUE_IDENTIFIER
            )
            self._private_key_unique_identifier.read(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidKmipEncoding(
                "The CreateKeyPair response payload encoding is missing the "
                "private key unique identifier."
            )

        if self.is_tag_next(
                enums.Tags.PUBLIC_KEY_UNIQUE_IDENTIFIER,
                local_buffer
        ):
            self._public_key_unique_identifier = primitives.TextString(
                tag=enums.Tags.PUBLIC_KEY_UNIQUE_IDENTIFIER
            )
            self._public_key_unique_identifier.read(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidKmipEncoding(
                "The CreateKeyPair response payload encoding is missing the "
                "public key unique identifier."
            )

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self.is_tag_next(
                    enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
                    local_buffer
            ):
                self._private_key_template_attribute = \
                    objects.TemplateAttribute(
                        tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
                    )
                self._private_key_template_attribute.read(
                    local_buffer,
                    kmip_version=kmip_version
                )

            if self.is_tag_next(
                    enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE,
                    local_buffer
            ):
                self._public_key_template_attribute = \
                    objects.TemplateAttribute(
                        tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
                    )
                self._public_key_template_attribute.read(
                    local_buffer,
                    kmip_version=kmip_version
                )

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the CreateKeyPair response payload to a buffer.

        Args:
            output_buffer (stream): A data buffer in which to encode object
                data, supporting a write method.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            InvalidField: Raised if the private key unique identifier or the
                public key unique identifier is not defined.
        """
        local_buffer = utils.BytearrayStream()

        if self._private_key_unique_identifier:
            self._private_key_unique_identifier.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The CreateKeyPair response payload is missing the private "
                "key unique identifier field."
            )

        if self._public_key_unique_identifier:
            self._public_key_unique_identifier.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The CreateKeyPair response payload is missing the public "
                "key unique identifier field."
            )

        if self._private_key_template_attribute:
            self._private_key_template_attribute.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._public_key_template_attribute:
            self._public_key_template_attribute.write(
                local_buffer,
                kmip_version=kmip_version
            )

        self.length = local_buffer.length()
        super(CreateKeyPairResponsePayload, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __eq__(self, other):
        if isinstance(other, CreateKeyPairResponsePayload):
            if self.private_key_unique_identifier != \
                    other.private_key_unique_identifier:
                return False
            elif self.public_key_unique_identifier != \
                    other.public_key_unique_identifier:
                return False
            elif self.private_key_template_attribute != \
                    other.private_key_template_attribute:
                return False
            elif self.public_key_template_attribute != \
                    other.public_key_template_attribute:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, CreateKeyPairResponsePayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "private_key_unique_identifier='{}'".format(
                self.private_key_unique_identifier
            ),
            "public_key_unique_identifier='{}'".format(
                self.public_key_unique_identifier
            ),
            "private_key_template_attribute={}".format(
                self.private_key_template_attribute
            ),
            "public_key_template_attribute={}".format(
                self.public_key_template_attribute
            )
        ])
        return "CreateKeyPairResponsePayload({})".format(args)

    def __str__(self):
        value = ", ".join(
            [
                '"private_key_unique_identifier": "{}"'.format(
                    self.private_key_unique_identifier
                ),
                '"public_key_unique_identifier": "{}"'.format(
                    self.public_key_unique_identifier
                ),
                '"private_key_template_attribute": {}'.format(
                    self.private_key_template_attribute
                ),
                '"public_key_template_attribute": {}'.format(
                    self.public_key_template_attribute
                )
            ]
        )
        return '{' + value + '}'
