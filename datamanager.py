# -*- coding: utf-8 -*-

import SchulzeVoting

class DataManager:

  def __init__(self):
    self.datadir     = "."
    self.authorities = {} #fpr -> Authority
    self.peers       = {} #fpr -> Peer

  def getAuthority(self, fpr):
    if not fpr in self.authorities:
      self.authorities[fpr]=Authority()
    return self.authorities[fpr]

  def getTopicByPath(self, topicpath): 
    dirs = topicpath.split("/") 
    authority = self.getAuthority(dirs[0])
    if authority:
      if topicpath in authority.topics:
        topic = authority.topics[topicpath]
        return authority, topic
    return None, None

class Authority:
  name        = None
  fpr         = None
  topics      = {} #topicid -> Topic    
  
class Topic:
  data        = None
  signature   = None
  proposals   = [] #Proposal
  votes       = [] #Vote
  
  def addVote(self, vote):
    for comp in self.votes[:]:
      if comp['id']==vote['id']:
        self.votes.remove(comp)
    self.votes.append(vote)
