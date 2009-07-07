# -*- coding: utf-8 -*-

import SchulzeVoting
import threading 
#we're thread safe for reading and writing currently. Or trying to be, if used correctly.

class DataManager:

  def __init__(self):
    self.datadir     = "."
    self.authorities_lock = threading.RLock()
    self.authorities = {} #fpr -> Authority
    self.peers_lock = threading.RLock()
    self.peers       = {} #fpr -> Peer

  def addAuthority(self, fpr, trusted = False, interesting = False):
    with self.authorities_lock:
      if not fpr in self.authorities:
        auth = Authority()
        auth.trusted = trusted
        auth.interesting = interesting
        self.authorities[fpr]=auth
      return self.authorities[fpr]

  def getAuthority(self, fpr):
    with self.authorities_lock:
      return self.authorities[fpr]

  def getTopicByPath(self, topicpath): 
    dirs = topicpath.split("/") 
    with self.authorities_lock:
      authority = self.getAuthority(dirs[0])
      if authority:
        with authority.topics_lock:
          if topicpath in authority.topics:
            topic = authority.topics[topicpath]
            return authority, topic
    return None, None

class Authority:
  name        = None
  fpr         = None
  trusted     = False
  interesting = False
  topics_lock = threading.RLock()
  topics      = {} #topicid -> Topic    
  
class Topic:
  data        = None
  signature   = None
  proposals_lock = threading.RLock()
  proposals   = [] #Proposal
  votes_lock = threading.RLock()
  votes       = {} #user fpr -> vote data struct
  
  def getProposalById(self, id):
    with self.proposals_lock:
      for comp in self.proposals:
        if comp['id']==id:
          return comp
    return None
  
  def addVote(self, vote):
    with self.votes_lock:
      self.votes[vote['voterid']]=vote
