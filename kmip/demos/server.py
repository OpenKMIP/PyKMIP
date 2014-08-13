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
import sys

from thrift.server import TServer
from thrift.transport import TSocket
from thrift.transport import TTransport

from kmip.core.server import KMIPImpl

from kmip.services.kmip_protocol import KMIPProtocolFactory
from kmip.services.kmip_server import Processor


def run_server(host='127.0.0.1', port=5696):
    logger = logging.getLogger(__name__)

    handler = KMIPImpl()
    processor = Processor(handler)
    transport = TSocket.TServerSocket(host, port)
    tfactory = TTransport.TBufferedTransportFactory()
    pfactory = KMIPProtocolFactory()
    server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)

    logger.info('Starting the KMIP server')

    try:
        server.serve()
    except KeyboardInterrupt:
        logger.info('KeyboardInterrupt received while serving')
    except Exception, e:
        logger.info('Exception received while serving: {0}'.format(e))
    finally:
        transport.close()

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
    return parser

if __name__ == '__main__':
    parser = build_cli_parser()

    opts, args = parser.parse_args(sys.argv[1:])

    run_server(opts.hostname, opts.port)
