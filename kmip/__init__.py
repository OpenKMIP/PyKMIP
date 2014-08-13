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

import logging.config
import os
import sys

path = os.path.join(os.path.dirname(__file__), 'logconfig.ini')

if os.path.exists(path):
    logging.config.fileConfig(path)
else:
    minor_version = sys.version_info[1]

    if minor_version == 7:
        config = {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'simpleFormatter': {
                    'format':
                        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                }
            },
            'handlers': {
                'consoleHandler': {
                    'level': 'DEBUG',
                    'class': 'logging.StreamHandler',
                    'formatter': 'simpleFormatter',
                    'stream': sys.stdout
                }
            },
            'loggers': {
                'root': {
                    'level': 'DEBUG',
                    'handlers': ['consoleHandler']
                }
            }
        }

        logging.config.dictConfig(config)
    else:
        logging.basicConfig()

__all__ = ['core', 'demos', 'services']
