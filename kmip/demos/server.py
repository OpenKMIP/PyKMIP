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

import logging
import os
import optparse
import sys

from kmip.services.kmip_server import KMIPServer

FILE_PATH = os.path.dirname(os.path.abspath(__file__))


def run_server(host='127.0.0.1', port=5696,
               cert_file=FILE_PATH + '/../tests/utils/certs/server.crt',
               key_file=FILE_PATH + '/../tests/utils/certs/server.key'):
    logger = logging.getLogger(__name__)

    server = KMIPServer(host, port, cert_file, key_file)

    logger.info('Starting the KMIP server')

    try:
        server.serve()
    except KeyboardInterrupt:
        logger.info('KeyboardInterrupt received while serving')
    except Exception as e:
        logger.info('Exception received while serving: {0}'.format(e))
    finally:
        server.close()

    logger.info('Shutting down KMIP server')


def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]",
                                   description="Run KMIP Server")
    parser.add_option("-n", "--hostname", action="store", default='127.0.0.1',
                      dest="hostname",
                      help="Hostname/IP address of platform running the KMIP "
                      "server (e.g., localhost, 127.0.0.1)")
    parser.add_option("-p", "--port", action="store", default=5696,
                      dest="port", help="Port number for KMIP services")
    parser.add_option("-c", "--cert_file", action="store",
                      default=FILE_PATH + '/../tests/utils/certs/server.crt',
                      dest="cert_file")
    parser.add_option("-k", "--key_file", action="store",
                      default=FILE_PATH + '/../tests/utils/certs/server.key',
                      dest="key_file")
    return parser

if __name__ == '__main__':
    parser = build_cli_parser()

    opts, args = parser.parse_args(sys.argv[1:])

    run_server(opts.hostname, opts.port, opts.cert_file, opts.key_file)
