Development
===========
Development for PyKMIP is open to all contributors. Use the information
provided here to inform your contributions and help the project maintainers
review and accept your work.

Getting Started
---------------
File a new issue on the project `issue tracker`_ on GitHub describing the
work you intend on doing. This is especially recommended for any sizable
contributions, like adding support for a new KMIP operation or adding a new
cryptographic backend for the server. Provide as much information on your
feature request as possible, using information from the KMIP specifications
or existing feature support in PyKMIP where applicable.

The issue number for your new issue should be included at the end of the
commit message of each patch related to that issue.

If you simply want to request a new feature but do not intend on working on
it, file your issue as normal and the project maintainers will triage it for
future work.

.. _writing-code:

Writing Code
------------
New code should be written in its own Git branch, ideally branched from
``HEAD`` on ``master``. If other commits are merged into ``master`` after your
branch was created, be sure to rebase your work on the current state of
``master`` before submitting a pull request to GitHub.

New code should generally follow ``PEP 8`` style guidelines, though there are
exceptions that will be allowed in special cases. Run the ``flake8`` tests to
check your code before submitting a pull request (see :ref:`running-tests`).

.. _writing-docs:

Writing Documentation
---------------------
Like new code, new documentation should be written in its own Git branch.
All PyKMIP documentation is written in `RST`_ format and managed using
``sphinx``. It can be found under ``docs/source``.

If you are interested in contributing to the project documentation, install
the project documentation requirements:

.. code:: console

    $ pip install -r doc-requirements.txt

To build the documentation, navigate into the ``docs`` directory and run:

.. code:: console

    $ make html

This will build the PyKMIP documentation as HTML and place it under the new
``docs/build/html`` directory. View it using your preferred web browser.

Commit Messages
---------------
Commit messages should include a single line title (75 character max) followed
by a blank line and a description of the change, including feature details,
testing and documentation updates, feature limitations, known issues, etc.

The issue number for the issue associated with the commit should be included
at the end of the commit message, if it exists. If the commit is the final one
for a specific issue, use ``Closes #XXX`` or ``Fixes #XXX`` to link the issue
and close it simultaneously. For example, see ths commit for `Issue #312`_:

.. code-block:: console

    Fix bug generating detached instance errors in server tests

    This patch fixes a bug that generates intermittent sqlalchemy
    DetachedInstanceErrors during the KMIP server engine unit test
    execution. Specifically, this fix disables instance expiration on
    commit for the sqlalchemy sessions used throughout the unit tests,
    allowing access to instance attributes even if the instance is
    detached from a session.

    Fixes #312

Bug Fixes
---------
If you have found a bug in PyKMIP, file a new issue and use the title format
``Bug: <brief description here>``. In the body of the issue please provide as
much information as you can, including Python version, PyKMIP version,
operating system version, and any stacktraces or logging information produced
by PyKMIP related to the bug. See `What to put in your bug report`_ for a
breakdown of bug reporting best practices.

If you are working on a bug fix for a bug in ``master``, follow the general
guidelines above for branching and code development (see :ref:`writing-code`).

If you are working on a bug fix for an older version of PyKMIP, your branch
should be based on the latest commit of the repository branch for the version
of PyKMIP the bug applies to (e.g., branch ``release-0.6.0`` for PyKMIP 0.6).
The pull request for your bug fix should also target the version branch in
question. If applicable, it will be pulled forward to newer versions of
PyKMIP, up to and including ``master``.

.. _running-tests:

Running Tests
-------------
PyKMIP uses ``tox`` to manage testing across multiple Python versions. ``tox``
in turn uses ``pytest`` to run individual tests. Test infrastructure currently
supports Python 3.12, 3.13, and 3.14. Additional test environments are
provided for security, style, and documentation checks.

.. note::

    All of the ``tox`` commands discussed in this section should be run from
    the root of the PyKMIP repository, in the same directory as the
    ``tox.ini`` configuration file.

The style checks leverage ``flake8`` and can be run like so:

.. code-block:: console

    $ tox -e pep8

The security checks use ``bandit`` and can be run like so:

.. code-block:: console

    $ tox -e bandit

The documentation checks leverage ``sphinx`` to build the HTML documentation
in a temporary directory, verifying that there are no errors. These checks
can be run like so:

.. code-block:: console

    $ tox -e docs

To run the above checks along with the entire unit test suite, simply run
``tox`` without any arguments:

.. code-block:: console

    $ tox

Unit Tests
~~~~~~~~~~
The unit test suite tests many of the individual components of the PyKMIP code
base, verifying that each component works correctly in isolation. Ideal code
coverage would include the entire code base. To facilitate improving coverage,
test coverage results are included with each Python unit test environment.

To test against a specific Python version (e.g., Python 3.12), run:

.. code-block:: console

    $ tox -e py312

To run an individual test suite method or class, use the ``pytest`` ``-k``
flag to specify the name of the method or class to execute. For example, to
run the ``TestProxyKmipClient`` test suite class under Python 3.12, run:

.. code-block:: console

    $ tox -e py312 -- -k TestProxyKmipClient

For more information on the ``-k`` flag, see the `pytest`_ documentation.

Integration Tests
~~~~~~~~~~~~~~~~~
The integration test suite tests the functionality of the PyKMIP clients
against a KMIP server, verifying that the right response data and status
codes are returned for specific KMIP requests. A KMIP server must already
be running and available over the network for the integration test cases
to pass.

Code base coverage is not a goal of the integration test suite. Code coverage
statistics are therefore not included in the output of the integration tests.
For code coverage, run the unit tests above.

For the Travis CI tests run through GitHub, the KMIP server used for
integration testing is actually an instance of the PyKMIP server, allowing us
to verify the functionality of the clients and server simultaneously.

Any third-party KMIP server can be tested using the integration test suite.
Simply add a section to the client configuration file containing the
connection settings for the server and provide the name of the new section
when invoking the integration tests.

To run the integration test suite, the configuration file section name for
the client settings must be passed to the test suite using the ``--config``
configuration argument. Assuming the section name is ``server_1``, the
following ``tox`` command will set up and execute the integration tests:

.. code-block:: console

    $ tox -r -e integration -- --config server_1

Like the unit tests, use the ``-k`` flag to specify a specific test suite
method or class.

.. code-block:: console

    $ tox -r -e integration -- --config server_1 -k TestProxyKmipClientIntegration

Functional Tests
~~~~~~~~~~~~~~~~
The functional test suite tests capabilities and functionality specific to
the PyKMIP server. While similar in structure to the integration test suite
described above, the functional tests cannot be used with arbitrary
third-party servers and require a very specific environment in which to
operate successfully. Therefore, the functional tests are usually only used
for continuous integration testing via Travis CI.

Like the integration test suite, code base coverage is not a goal of the
functional test suite. For code coverage, run the unit tests above.

The functional tests specifically exercise third-party authentication and
group-based access control features supported by the PyKMIP server. The
third-party authentication system in this case is an instance of `SLUGS`_.
The PyKMIP client/server certificates and server operation policies must
align exactly with the user/group information provided by SLUGS for the
functional tests to pass. For more information, see the Travis CI build
information under ``.travis`` in the PyKMIP repository.

To invoke the functional tests, the configuration file path must be passed
to the test suite using the ``--config-file`` configuration argument. Assuming
the file path is ``/tmp/pykmip/client.conf``, the following ``tox`` command
will set up and execute the functional tests:

.. code-block:: console

    $ tox -r -e functional -- --config-file /tmp/pykmip/client.conf

Like the unit and integration tests, use the ``-k`` flag to specify a specific
test suite method or class.

.. code-block:: console

    $ tox -r -e functional -- --config-file /tmp/pykmip/client.conf -k test_policy_caching

For more information on the testing tools used here, see the following
resources:

* `tox`_
* `flake8`_
* `bandit`_

.. _`issue tracker`: https://github.com/OpenKMIP/PyKMIP/issues
.. _`RST`: http://docutils.sourceforge.net/rst.html
.. _`Issue #312`: https://github.com/OpenKMIP/PyKMIP/issues/312
.. _`What to put in your bug report`: http://www.contribution-guide.org/#what-to-put-in-your-bug-report
.. _`tox`: https://pypi.python.org/pypi/tox
.. _`flake8`: https://pypi.python.org/pypi/flake8
.. _`bandit`: https://pypi.python.org/pypi/bandit
.. _`SLUGS`: https://github.com/OpenKMIP/SLUGS
.. _`pytest`: https://docs.pytest.org/en/latest/usage.html
