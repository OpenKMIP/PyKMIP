#!/usr/bin/env python
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import re
import setuptools

# Dynamically set __version__
this_dir = os.path.dirname(os.path.realpath(__file__))
version_path = os.path.join(this_dir, "kmip", "version.py")
with open(version_path, 'r') as f:
    m = re.search(
        r"^__version__ = \"(\d+\.\d+\..*)\"$",
        f.read(),
        re.MULTILINE
    )
    __version__ = m.group(1)
readme_path = os.path.join(this_dir, "README.rst")
with open(readme_path, 'r') as f:
    long_description = f.read()

setuptools.setup(
    name='PyKMIP',
    version=__version__,
    description='KMIP library',
    keywords='KMIP',
    author='Peter Hamilton',
    author_email='peter.hamilton@jhuapl.edu',
    url='https://github.com/OpenKMIP/PyKMIP',
    license='Apache License, Version 2.0',
    long_description=long_description,
    long_description_content_type="text/x-rst",
    packages=setuptools.find_packages(exclude=["kmip.tests", "kmip.tests.*"]),
    package_data={'kmip': ['kmipconfig.ini', 'logconfig.ini'],
                  'kmip.demos': ['certs/server.crt', 'certs/server.key']},
    entry_points={
        'console_scripts':[
            'pykmip-server = kmip.services.server.server:main'
        ]
    },
    install_requires=[
        "cryptography",
        "requests",
        "sqlalchemy"
    ],
    python_requires=">= 3.12",
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Operating System :: POSIX",
        "Operating System :: POSIX :: BSD",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
    ],
)
