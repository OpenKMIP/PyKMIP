Security
========
The PyKMIP development team takes security seriously and will respond promptly
to any reported security issue. Use the information provided here to inform
your security posture.

Reporting a Security Issue
--------------------------
If you discover a new PyKMIP security issue, please follow responsible
disclosure best practices and contact the project maintainers in private over
email to discuss the issue before filing a public GitHub issue. When reporting
a security issue, please include as much detail as possible. This includes:

* a high-level description of the issue
* information on how to cause or reproduce the issue
* any details on specific portions of the project code base related to the issue

Once you have provided this information, you should receive an acknowledgement.
Depending upon the severity of the issue, the project maintainers will respond
to collect additional information and work with you to address the security
issue. If applicable, a new library subrelease will be produced across all
actively supported releases to address and fix the issue.

If the developerment team decides the issue does not warrant the sensitivity
of a security issue, you may file a public GitHub issue on the project
`issue tracker`_.

Known Vulnerabilities
---------------------

The following are known vulnerabilities for older, unsupported versions of PyKMIP.

+---------------------+--------------------------+-------------------+--------------------------+
| CVE                 | Brief Description        | PyKMIP Version(s) | Mitigation               |
+=====================+==========================+===================+==========================+
| `CVE-2018-1000872`_ | Server Denial-of-Service | <=0.7.0           | Upgrade to PyKMIP 0.8.0+ |
+---------------------+--------------------------+-------------------+--------------------------+

.. _`issue tracker`: https://github.com/OpenKMIP/PyKMIP/issues
.. _`CVE-2018-1000872`: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000872