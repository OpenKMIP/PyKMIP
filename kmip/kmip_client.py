#!/usr/bin/env python

# TODO insert license here

from transport.kmip import KMIP
from transport.kmip.ttypes import *

from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

try:
    
  transport = TSocket.TSocket('localhost', 9090)
  transport = TTransport.TBufferedTransport(transport)
  protocol = TBinaryProtocol.TBinaryProtocol(transport)
  client = KMIP.Client(protocol)
  transport.open()

  print 'ping-client()'
  client.create()
  print 'register_mo-client()'
  client.register_mo()

  transport.close()

except Thrift.TException, tx:
  print '%s' % (tx.message)
