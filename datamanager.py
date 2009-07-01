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
  votes       = {} #user fpr -> vote data struct
  
  def getProposalById(self, id):
    for comp in self.proposals:
      if comp['id']==id:
        return comp
    return None
  
  def addVote(self, vote):
    self.votes[vote['voterid']]=vote
