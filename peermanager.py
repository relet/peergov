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
      #try to connect to peers
      pass
