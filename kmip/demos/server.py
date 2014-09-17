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
import optparse
import os
import sys

from kmip.services.kmip_server import KMIPServer

FILE_PATH = os.path.dirname(os.path.abspath(__file__))


def run_server(host, port, keyfile, certfile, cert_reqs, ssl_version,
               ca_certs, do_handshake_on_connect, suppress_ragged_eofs):
    logger = logging.getLogger(__name__)

    server = KMIPServer(host=host, port=port, certfile=certfile,
                        keyfile=keyfile, cert_reqs=cert_reqs,
                        ssl_version=ssl_version, ca_certs=ca_certs,
                        do_handshake_on_connect=do_handshake_on_connect,
                        suppress_ragged_eofs=suppress_ragged_eofs)

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
    parser.add_option("-n", "--host", action="store", default=None,
                      dest="host",
                      help="Hostname/IP address of platform running the KMIP "
                      "server (e.g., localhost, 127.0.0.1)")
    parser.add_option("-p", "--port", action="store", default=None,
                      dest="port", help="Port number for KMIP services")
    parser.add_option("-c", "--certfile", action="store", default=None,
                      dest="certfile")
    parser.add_option("-k", "--keyfile", action="store", default=None,
                      dest="keyfile")
    parser.add_option("-r", "--cert_reqs", action="store", default=None,
                      dest="cert_reqs")
    parser.add_option("-s", "--ssl_version", action="store", default=None,
                      dest="ssl_version")
    parser.add_option("-a", "--ca_certs", action="store", default=None,
                      dest="ca_certs")
    parser.add_option("-d", "--do_handshake_on_connect", action="store",
                      default=None, dest="do_handshake_on_connect")
    parser.add_option("-e", "--suppress_ragged_eofs", action="store",
                      default=None, dest="suppress_ragged_eofs")
    return parser


if __name__ == '__main__':
    parser = build_cli_parser()

    opts, args = parser.parse_args(sys.argv[1:])

    run_server(host=opts.host,
               port=opts.port,
               certfile=opts.certfile,
               keyfile=opts.keyfile,
               cert_reqs=opts.cert_reqs,
               ssl_version=opts.ssl_version,
               ca_certs=opts.ca_certs,
               do_handshake_on_connect=opts.do_handshake_on_connect,
               suppress_ragged_eofs=opts.suppress_ragged_eofs)
