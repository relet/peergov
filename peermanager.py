# -*- coding: utf-8 -*-

from servent import Servent

class PeerManager:
  def __init__(self, argv):
    if len(argv)==0:
      print("No meta-peers found on command line. TODO: look for peers in peer history")
      print("Connectivity is currently disabled.")
      return
    self.servent = Servent()
    for peer in argv:
      try:
        hp = peer.split(":") #host:port for ipv4 - what's the common notation for ipv6?
        port = hp[1:2] and int(hp[1]) or 4991
        self.servent.connectTo((2,1,6,'',(hp[0], port))) 
        pass
      except Exception,e:
        print str(e)

