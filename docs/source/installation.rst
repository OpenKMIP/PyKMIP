Installation
============
You can install PyKMIP via ``pip``:

.. code-block:: console

    $ pip install pykmip

Supported platforms
-------------------
PyKMIP is tested on Python 2.7, 3.4, 3.5, and 3.6 on the following
operating systems:

* Ubuntu 12.04, 14.04, and 16.04

PyKMIP also works on Windows and MacOSX however these platforms are not
officially supported or tested.

Building PyKMIP on Linux
------------------------
You can install PyKMIP from source via ``git``:

.. code-block:: console

    $ git clone https://github.com/openkmip/pykmip.git
    $ python pykmip/setup.py install

If you are on a fresh Linux build, you may also need several additional system
dependencies, including headers for Python, OpenSSL, ``libffi``, and
``libsqlite3``.

Ubuntu
~~~~~~
Replace ``python-dev`` with ``python3-dev`` if you are using Python 3.0+.

.. code-block:: console

    $ sudo apt-get install python-dev libffi-dev libssl-dev libsqlite3-dev
