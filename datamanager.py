# -*- coding: utf-8 -*-

class DataManager:
  authorities = {} #fpr -> Authority
  peers       = {} #fpr -> Peer
  
  def getAuthority(self, fpr):
    if not fpr in self.authorities:
      self.authorities[fpr]=Authority()
    return self.authorities[fpr]
  
class Authority:
  name        = None
  topics      = {} #topicid -> Topic    
  
class Topic:
  data        = None
  signature   = None
  proposals   = [] #Proposal
  votes       = [] #Vote
  #results = 