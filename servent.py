# -*- coding: utf-8 -*-

import sys
import socket
import threading
import traceback
import yaml
from datamanager import *

EVT_PEER_PROTOCOL_VERIFIED = 1
EVT_PEER_AUTHORITIES_SYNCHRONIZED = 2
EVT_PEER_TOPIC_SYNCHRONIZED = 3
EVT_PEER_PROPOSALS_SYNCHRONIZED = 3
EVT_PEER_VOTES_SYNCHRONIZED = 3

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

  def syncAuthorities(self, peerid):
    self.peers[peerid].syncAuthorities()
  def syncTopics(self, peerid, authority):
    self.peers[peerid].syncTopics(authority)

class ServentThread (threading.Thread):
  def __init__(self, socket, servent):
    self.socket = socket
    self.servent = servent
    self.servent.addServerSocket(self)
    self.stopped = False
    threading.Thread.__init__(self)

  def run(self):
    while not self.stopped:
      #print("Listening on %s." % str(self.socket.getsockname()))
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
  
STATE_IDLE = 0
STATE_DATABLOCK = 1

class ServentConnectionHandler(threading.Thread):
  syncingAuthorities_lock = threading.Lock()
  syncingTopics_lock      = threading.Lock()
  syncingProposals_lock   = threading.Lock()
  syncingVotes_lock       = threading.Lock()

  def __init__(self, conn, addr, servent, isClient=False):
    self.conn = conn
    self.addr = addr
    self.servent = servent
    self.peerid = self.servent.addPeer(addr, self)
    self.stopped = False
    self.state = STATE_IDLE
    self.protocol_verified = False
    self.isClient = isClient
    self.authority = None
    self.authorities = None
    self.lastAuthSync = None
    self.lastTopicSync = None
    self.lastProposalSync = None
    self.lastVoteSync = None
    self.datablock = None
    self.dataparms = None
    threading.Thread.__init__(self)

  def parseMessage(self, data, peerid):
    if data:
      lines = data.split("\n")
      for line in lines:
        if line.strip():
          self.parseLine(line, peerid) 

  def parseLine(self, data, peerid):
    print peerid,":",data
    try:
      dataman = self.servent.manager.datamanager  # lol, we need to trim down hierarchies
      if self.state == STATE_DATABLOCK:
        terminating = False
        if data == "DATA FIN":
          try:
            content = yaml.load(self.datablock)
            if content[0]['type']=='topic':
              if not content[0]['path'] in self.authority.topics:
                with self.authority.topics_lock:
                  topic = Topic()
                  topic.data, topic.proposals, topic.votes = content
                  #TODO: validate signatures etc. - create utility methods in data manager!              
                  self.authority.topics[content[0]['path']]=topic
            elif content[0]['type']=='proposal':
              with self.authority.topics_lock:
                topic = self.authority.topics[self.dataparms[0]]
                with topic.proposals_lock:
                  if not topic.getProposalById(content[0]['id']):
                    #TODO: validate signatures etc. - create utility methods in data manager!              
                    topic.proposals.append(content[0])
            elif content[0]['type']=='vote':
              with self.authority.topics_lock:
                topic = self.authority.topics[self.dataparms[0]]
                with topic.votes_lock:
                  #TODO: validate signatures etc. - create utility methods in data manager!              
                  topic.votes[content[0]['id']]=content[0]
            else:
              print content
          except:
            print ("Failed to parse:\n---\n%s\n---" % self.datablock)
            traceback.print_exc()
            sys.exit(1)
          self.state == STATE_IDLE 
        else:
          self.datablock += data+"\n"
        return
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
          self.syncingAuthorities_lock.acquire(False) # non blocking, lock into syncAuth process
          if not self.authorities:
            with dataman.authorities_lock:
              authorities = dataman.authorities.keys()
              authorities.sort()
              self.authorities = authorities
          p1 = self.lastAuthSync and self.authorities.index(self.lastAuthSync) or 0
          if words[2]=="FIN":
            next = self.authorities[p1+1:]
            if next:
              self.conn.send("SYNC AUTH "+next[0]+"\n")
            else:
              self.syncingAuthorities_lock.release()
              self.authorities = None
              if not "ACK" in words:
                self.conn.send("SYNC AUTH FIN ACK\n")
              else:
                self.servent.manager.handleServentEvent(EVT_PEER_AUTHORITIES_SYNCHRONIZED, self.peerid)
            return
          for word in words[2:]:
            if not word in self.authorities:
              dataman.addAuthority(word, trusted = False, interesting = False)
          p2 = self.authorities.index(words[2])
          lack = ""
          for auth in self.authorities[p1+1:p2]: 
            lack += auth+" "
          self.lastAuthSync = words[-1]
          if lack:
            self.conn.send("SYNC AUTH "+lack+"\n")
          else:
            next = self.authorities[p2+1:]
            if next:
              self.conn.send("SYNC AUTH "+next[0]+"\n")
            else:
              self.conn.send("SYNC AUTH FIN\n")
          return
        elif words[1]=="TOPC":
          self.syncingTopics_lock.acquire(False) # non blocking
          if words[2:]:
            authority = None
            nextword  = 2
            if "/" in words[2]:
              authority = dataman.getAuthority(words[2][:words[2].index("/")])
            else:
              authority = dataman.getAuthority(words[2]) #authority fpr
              nextword = 3
            if authority:
              with authority.topics_lock:
                topics = authority.topics.keys()
                topics.sort()
                p1 = self.lastTopicSync and topics.index(self.lastTopicSync) or 0
                if words[nextword]=="FIN":
                  next = topics[p1+1:]
                  if next:
                    self.lastTopicSync = next[0]
                    self.conn.send("SYNC TOPC %s" % (next[0]))
                  else:
                    self.syncingTopics_lock.release()
                    if not "ACK" in words:
                      self.conn.send("SYNC TOPC %s FIN ACK\n" % (authority.fpr))
                    else:
                      self.servent.manager.handleServentEvent(EVT_PEER_TOPIC_SYNCHRONIZED, self.peerid) # do we need this event?
                  return
                for word in words[nextword:]:
                  if not word in topics:
                    self.conn.send("SEND TOPC %s\n" % (word))
                  else:
                    self.syncTopicData(authority, word)
                p2 = topics.index(words[nextword])
                lack = ""
                for topic in topics[p1+1:p2]:
                  lack += topic+" "
                self.lastTopicSync = words[-1]
                if lack:
                  self.conn.send("SYNC TOPC %s\n" % (lack))
                else:
                  next = topics[p2+1:]
                  if next:
                    self.lastTopicSync = next[0]
                    self.conn.send("SYNC TOPC %s\n" % (next[0]))
                  else:
                    self.conn.send("SYNC TOPC %s FIN\n" % (authority.fpr))
                return
        elif words[1]=="PROP":
          self.syncingProposals_lock.acquire(False) # non blocking
          if words[2:]:
            authority = dataman.getAuthority(words[2][:words[2].index("/")])
            if authority:
              with authority.topics_lock:
                topic = authority.topics[words[2]]
                with topic.proposals_lock:
                  proposals = map(lambda x:x['id'], topic.proposals[:])
                  proposals.sort()
                  p1 = self.lastProposalSync and proposals.index(self.lastProposalSync) or 0
                  if words[3] == "FIN":
                    next = proposals[p1+1:]
                    if next:
                      self.lastProposalSync = next[0]
                      self.conn.send("SYNC PROP %s %s\n" % (words[2], next[0]))
                    else:
                      self.syncingProposals_lock.release()
                      if not "ACK" in words:
                        self.conn.send("SYNC PROP %s FIN ACK\n" % (words[2]))
                      else:
                        self.servent.manager.handleServentEvent(EVT_PEER_PROPOSALS_SYNCHRONIZED, self.peerid)
                    return
                  for word in words[3:]:
                    if not word in proposals:
                      self.conn.send("SEND PROP %s %s\n" % (words[2], word))
                  p2 = proposals.index(words[3])
                  lack = ""
                  for proposal in proposals[p1+1:p2]:
                    lack += proposal+" "
                  self.lastProposalSync = words[-1]
                  if lack:
                    self.conn.send("SYNC PROP %s %s\n" % (words[2], lack))
                  else:
                    next = proposals[p2+1:]
                    if next:
                      self.lastProposalSync = next[0]
                      self.conn.send("SYNC PROP %s %s\n" % (words[2], next[0]))
                    else:
                      self.conn.send("SYNC PROP %s FIN\n" % (words[2]))
            return
        elif words[1]=="VOTE":
          self.syncingVotes_lock.acquire(False) # non blocking
          if words[2:]:
            authority = dataman.getAuthority(words[2][:words[2].index("/")])
            if authority:
              with authority.topics_lock:
                topic = authority.topics[words[2]]
                with topic.votes_lock:
                  votes = topic.votes.keys()
                  votes.sort()
                  p1 = self.lastVoteSync and votes.index(self.lastVoteSync) or 0
                  if words[3] == "FIN":
                    next = votes[p1+1:]
                    if next:
                      self.lastVoteSync = next[0]
                      self.conn.send("SYNC VOTE %s %s\n" % (words[2], next[0]))
                    else:
                      self.syncingVotes_lock.release()
                      if not "ACK" in words:
                        self.conn.send("SYNC VOTE %s FIN ACK\n" % (words[2]))
                      else:
                        self.servent.manager.handleServentEvent(EVT_PEER_VOTES_SYNCHRONIZED, self.peerid)
                    return
                  for word in words[3:]:
                    if not word in votes:
                      self.conn.send("SEND VOTE %s %s\n" % (words[2], word))
                  p2 = votes.index(words[3])
                  lack = ""
                  for vote in votes[p1+1:p2]:
                    lack += vote+" "
                  self.lastVoteSync = words[-1]
                  if lack:
                    self.conn.send("SYNC VOTE %s %s\n" % (words[2], lack))
                  else:
                    next = votes[p2+1:]
                    if next:
                      self.lastVoteSync = next[0]
                      self.conn.send("SYNC VOTE %s %s\n" % (words[2], next[0]))
                    else:
                      self.conn.send("SYNC VOTE %s FIN\n" % (words[2]))
            return
      elif words[0]=="SEND":
        if words[1]=="TOPC":
          authority = dataman.getAuthority(words[2][:words[2].index("/")])
          topic   = authority.topics[words[2]]
          self.conn.send("DATA TOPC %s %s\n" % (authority.fpr, words[3])); 
          self.conn.send("%s\n" %yaml.dump([topic.data, topic.proposals, topic.votes])); #sending yaml dumps around is *NOT* smart. They may ontain arbitrary data.
          self.conn.send("DATA FIN\n"); 
          return
        if words[1]=="PROP":
          authority = dataman.getAuthority(words[2][:words[2].index("/")])
          topic     = authority.topics[words[2]]
          proposal  = topic.getProposalById(words[3])
          self.conn.send("DATA PROP %s %s\n" % (words[2], words[3])); 
          self.conn.send("%s\n" %yaml.dump([proposal])); #sending yaml dumps around is *NOT* smart. They may ontain arbitrary data.
          self.conn.send("DATA FIN\n"); 
          return
        if words[1]=="VOTE":
          authority = dataman.getAuthority(words[2][:words[2].index("/")])
          topic     = authority.topics[words[2]]
          vote      = topic.votes[words[3]]
          self.conn.send("DATA VOTE %s %s\n" % (words[2], words[3])); 
          self.conn.send("%s\n" %yaml.dump([vote])); #sending yaml dumps around is *NOT* smart. They may ontain arbitrary data.
          self.conn.send("DATA FIN\n"); 
          return
      elif words[0]=="DATA":
        self.state = STATE_DATABLOCK
        self.datablock = ""
        self.authority = dataman.getAuthority(words[2][:words[2].index("/")])
        self.dataparms = words[2:]
        return
     
      raise(Exception("Instruction just not recognized."))
    except Exception, e:     
      traceback.print_exc()
      print("Failed to parse incoming data. %s" % str(e))

  def syncAuthorities(self):
    if self.syncingAuthorities_lock.acquire(False):
      dataman = self.servent.manager.datamanager  # lol, we need to trim down hierarchies
      with dataman.authorities_lock:
        authorities = dataman.authorities.keys()
        authorities.sort()
        self.authorities = authorities
        self.conn.send("SYNC AUTH %s\n" % (self.authorities[0]))

  def syncTopics(self, authority):
    if authority:
      if self.syncingTopics_lock.acquire(False):
        with authority.topics_lock:
          topics = authority.topics.keys()
          topics.sort()
          if topics:
            self.conn.send("SYNC TOPC %s\n" % (topics[0]))

  def syncTopicData(self, authority, topic):
    if authority:
      with authority.topics_lock:
        topic = authority.topics[topic]
        if self.syncingProposals_lock.acquire(False):
          with topic.proposals_lock:
            proposals = map(lambda x:x['id'], topic.proposals[:])
            proposals.sort()
            if proposals:
              self.conn.send("SYNC PROP %s %s\n" % (topic.data['path'], proposals[0]))
        if self.syncingVotes_lock.acquire(False):
          with topic.votes_lock:
            votes = topic.votes.keys()
            votes.sort()
            if votes:
              self.conn.send("SYNC VOTE %s %s\n" % (topic.data['path'], votes[0]))

  def run(self):
    if not self.isClient:
      self.conn.send("HELO "+self.servent.PROTOCOL_IDENTIFIER+"\n")
    try:
      while not self.stopped:
        data = self.conn.recv(4096)
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

