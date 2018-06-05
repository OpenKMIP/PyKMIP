Frequently Asked Questions
==========================

.. contents:: Table of Contents

What algorithms are available for creating symmetric encryption keys? For asymmetric encryption keys (i.e., key pairs)?
-----------------------------------------------------------------------------------------------------------------------
The KMIP specification supports a wide variety of symmetric and asymmetric
key algorithms. Support for these algorithms, including corresponding key
lengths, will vary across different KMIP-compliant devices, so check with
your KMIP vendor or with your appliance documentation to determine which
ones are available.

For a full list of the cryptographic algorithms supported by the KMIP
specification, see :term:`cryptographic_algorithm`. The following algorithms
are supported by the PyKMIP server.

Symmetric Key Algorithms
~~~~~~~~~~~~~~~~~~~~~~~~
* `3DES`_
* `AES`_
* `Blowfish`_
* `Camellia`_
* `CAST5`_
* `IDEA`_
* `RC4`_

Asymmetric Key Algorithms
~~~~~~~~~~~~~~~~~~~~~~~~~
* `RSA`_

How does the PyKMIP server handle client identity and authentication?
---------------------------------------------------------------------
See :ref:`authentication`.

How does the PyKMIP server manage access control for the keys and objects it stores?
------------------------------------------------------------------------------------
See :ref:`access-control`.

What built-in operation policies does the PyKMIP server support?
----------------------------------------------------------------
See :ref:`reserved-policies`.


.. |check| unicode:: U+2713
.. _`3DES`: https://en.wikipedia.org/wiki/Triple_DES
.. _`AES`: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
.. _`Blowfish`: https://en.wikipedia.org/wiki/Blowfish_%28cipher%29
.. _`Camellia`: https://en.wikipedia.org/wiki/Camellia_%28cipher%29
.. _`CAST5`: https://en.wikipedia.org/wiki/CAST-128
.. _`IDEA`: https://en.wikipedia.org/wiki/International_Data_Encryption_Algorithm
.. _`RC4`: https://en.wikipedia.org/wiki/RC4
.. _`RSA`: https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29
.. _`RFC 5280`: https://www.ietf.org/rfc/rfc5280.txt