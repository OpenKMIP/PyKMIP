#!/usr/bin/env python

# TODO insert license here

from transport.kmip import KMIP
from transport.kmip.ttypes import *

from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer

class KMIPHandler:
  def __init__(self):
    pass

  def create(self):
    print 'create()'

  def register_mo(self):
    print 'register_mo()'

handler = KMIPHandler()
processor = KMIP.Processor(handler)
transport = TSocket.TServerSocket(port=9090)
tfactory = TTransport.TBufferedTransportFactory()
pfactory = TBinaryProtocol.TBinaryProtocolFactory()
server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)

print 'Starting the KMIP server...'
server.serve()
print 'done.'
