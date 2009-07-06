# -*- coding: utf-8 -*-

import sys
import socket
import threading
import traceback

EVT_PEER_PROTOCOL_VERIFIED = 1

class Servent:
  PROTOCOL_IDENTIFIER = "peergov_p001"

  def __init__(self, peermanager, ip=None, port=4991, id=None):
    self.manager = peermanager
    self.peers_lock = threading.RLock()
    self.peers={}           # peerid -> ServentConnectionHandler 
    self.serversockets=[]   # just a list of open sockets (for eventual destruction)
    self.id = "%s:%s" % (ip, port)
    self.initSocket(port)

  def __del__(self):
    print ("Destructor called %i %i" % (len(self.serversockets), len(self.peers.keys())))
    for socket in self.serversockets[:]:
      socket.stop()
    for peerid, handler in self.peers.iteritems():
      handler.stop()

  def addPeer(self, addr, handler):
    with self.peers_lock:
      self.peers[str(addr)]=handler
      return str(addr)

  def addServerSocket(self, sockethandler):
    self.serversockets.append(sockethandler)

  def removePeer(self, peerid):
    with self.peers_lock:
      if peerid in self.peers:
        self.peers[peerid]=None

  def removeServerSocket(self, sockethandler):
    self.serversockets.remove(sockethandler)

  def runSocketThread(self, addr):
    print addr
    try:
      s = socket.socket(addr[0], addr[1])
      #s = ssl.wrap_socket(s, server_side = True, cert_reqs = ssl.CERT_NONE)
    except Exception,e:
      print("Failed to initialize server socket at %s." % addr[4][0])
      return
    try:
      s.bind(addr[4][:2]) # use only first two entries of addr tuple for v4 and v6
      s.listen(1)
      st = ServentThread(s, self)
      st.start()
    except Exception, e:
      print("Failed to open server socket at %s." % addr[4][0])
      s.close()
    
  def connectTo(self, server):
    try:
      s = socket.socket(server[0], server[1])
      try:
        #s = ssl.wrap_socket(s, cert_reqs=ssl.CERT_NONE)
        s.connect(server[4][:2])
        sch = ServentConnectionHandler(s, server[4][0], self, isClient=True)
        sch.start()
      except Exception, e:
        print("Failed to initialize socket at %s. %s" % (str(server[4]), str(e)))
        s.close()
    except Exception, e:
      print("Failed to open socket at %s. %s" % (str(server), str(e)))

  def initSocket(self, port):
    try:
      addrs = socket.getaddrinfo(None, port)
      addrv4 = None
      addrv6 = None
      for addr in addrs:
        if not addrv4 and (addr[0]==socket.AF_INET):
          addrv4 = addr
        if not addrv6 and (addr[0]==socket.AF_INET6):
          addrv6 = addr
      if addrv4:
        self.runSocketThread(addrv4)
      if addrv6:
        self.runSocketThread(addrv6)
    except Exception,e:
      print("Failed to identify available address families. Exiting.")
      sys.exit(1)

  def syncAuthorities(self, peerid, authorities):
    self.peers[peerid].syncAuthorities(authorities)

class ServentThread (threading.Thread):
  def __init__(self, socket, servent):
    self.socket = socket
    self.servent = servent
    self.servent.addServerSocket(self)
    self.stopped = False
    threading.Thread.__init__(self)

  def run(self):
    while not self.stopped:
      print("Listening on %s." % str(self.socket.getsockname()))
      try:
        conn, addr = self.socket.accept() #FIXME: this method can block incoming connections until SSL handshake is completed!
        print("Incoming connection from %s." % str(addr))
        sch = ServentConnectionHandler(conn, addr, self.servent)
        sch.start()
      except Exception,e:
        print("Incoming connection failed. %s." % str(e))

  def stop(self):
    self.stopped = True
    print ("Closing socket %s" % str(self.socket))
    self.socket.clear()
    self.socket.close()
    self.servent.removeServerSocket(self)
  
class ServentConnectionHandler(threading.Thread):
  STATE_IDLE      = 0 #we are expecting a command
  STATE_DATABLOCK = 1

  syncingAuthorities_lock = threading.Lock()

  def __init__(self, conn, addr, servent, isClient=False):
    self.conn = conn
    self.addr = addr
    self.servent = servent
    self.peerid = self.servent.addPeer(addr, self)
    self.stopped = False
    self.state = self.STATE_IDLE
    self.protocol_verified = False
    self.isClient = isClient
    threading.Thread.__init__(self)

  def parseMessage(self, data, peerid):
    if self.state == self.STATE_IDLE:
      try:
        words = map(lambda x:x.strip(),data.split())
        if words[0]=="HELO":
          if words[1]==self.servent.PROTOCOL_IDENTIFIER:
            self.protocol_verified = True
            self.conn.send("EHLO "+self.servent.PROTOCOL_IDENTIFIER+"\n")
            return
        elif words[0]=="EHLO":
          if words[1]==self.servent.PROTOCOL_IDENTIFIER:
            self.protocol_verified = True
            self.servent.manager.handleServentEvent(EVT_PEER_PROTOCOL_VERIFIED, self.peerid)
            return
        if not self.protocol_verified:
          print("Protocol mismatch. Terminating connection.")
          self.stop()
          return
        if words[0]=="SYNC":
          if words[1]=="AUTH":
            print "So far so good."
            return
        raise(Exception("Instruction just not recognized."))
      except Exception, e:     
        traceback.print_exc()
        print("Failed to parse incoming data. %s" % str(e))

  def syncAuthorities(self, authorities):
    if self.state == self.STATE_IDLE:
      if self.syncingAuthorities_lock.acquire(False):
        #TODO: release lock when finished syncronization or a bogus message interferes
        self.authorities = authorities[:]
        self.authorities.sort()
        self.authorities_index = 1
        self.conn.send("SYNC AUTH "+self.authorities[0]+"\n")
        
  def run(self):
    if not self.isClient:
      self.conn.send("HELO "+self.servent.PROTOCOL_IDENTIFIER+"\n")
    try:
      while not self.stopped:
        data = self.conn.recv(1024)
        if not data: 
          break
        self.parseMessage(data, self.peerid)  
    except Exception, e:
      print("Incoming connection reset: %s" % str(e))
    self.stop()

  def send(self, data):
    self.conn.send(data)

  def stop(self):
    self.stopped = True
    print ("Closing connection %s" % str(self.conn))
    self.conn.close()
    self.servent.removePeer(self.peerid)

