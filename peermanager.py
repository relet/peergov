# -*- coding: utf-8 -*-

from servent import * #Servent object and lots of EVTs possibly

class PeerManager:
  def __init__(self, argv, datamanager):
    self.datamanager = datamanager
    if len(argv)==0:
      print("No meta-peers found on command line. TODO: look for peers in peer history")
      print("Connectivity is currently disabled.")
      return
    self.servent = Servent(self)
    for peer in argv:
      try:
        hp = peer.split(":") #host:port for ipv4 - what's the common notation for ipv6?
        port = hp[1:2] and int(hp[1]) or 4991
        self.servent.connectTo((2,1,6,'',(hp[0], port))) 
        pass
      except Exception,e:
        print str(e)

  def handleServentEvent(self, event, peerid):
    if event == EVT_PEER_PROTOCOL_VERIFIED:
      with self.datamanager.authorities_lock:
        authorities = self.datamanager.authorities.keys() 
      if authorities:
        self.servent.syncAuthorities(peerid, authorities)
      else:
        print("No authorities?")
    elif event == EVT_PEER_AUTHORITIES_SYNCHRONIZED:
      #TODO: initialize syncing of topics
      pass
        