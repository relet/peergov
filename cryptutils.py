#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from hashlib import md5
from datetime import datetime
import pyme.core, pyme.constants.sig
import yaml

class CryptUtilException(Exception): 
  pass 

def getPassphrase(hint, desc, prev_bad):
  print "Passphrase Callback! %s %s %s" % (hint, desc, prev_bad)
  sys.stdout.write("Enter passphrase: ")
  return sys.stdin.readline().strip()
  
c = pyme.core.Context()
c.set_armor(1)
c.set_passphrase_cb(getPassphrase)

def createVote (voter, topicid, authorization, vote):
  c.op_keylist_start(voter, 0)
  votekey = c.op_keylist_next()
  
  if not votekey:
    raise CryptUtilException("Voter key not found.")
  
  voterid = votekey.subkeys[0].fpr
  
  #CONFIRM AGAIN THAT VOTER IS AUTHORIZED TO VOTE ON THIS TOPIC (or this set of topics)
  #   raise CryptUtilException("Voter not authorized to vote on this topic.")
  # c.op_keylist_start('Authority', 0)
  # authkey = c.op_keylist_next()
  #
  # if not authkey:
  #   print ("No such key found.")
  #   sys.exit(1)

  cont = {} #it's a container. I'm running out of descriptive variable names.
  cont['type']    = 'vote'
  cont['path']    = topicid
  cont['voterid'] = voterid
  cont['id']      = md5(cont['path']+cont['voterid']).hexdigest()
  cont['vote']    = vote # a list of proposalids

  voteblob = pyme.core.Data(yaml.dump(cont))

  #export voter key
  keyblob = pyme.core.Data()
  c.op_export(voter, 0, keyblob)

  #sign actual vote with voter key
  votesig = pyme.core.Data()
  c.signers_add(votekey)
  c.op_sign(voteblob, votesig, pyme.constants.sig.mode.CLEAR)
  c.signers_clear()

  data = {}
  data['auth'] = authorization
  keyblob.seek(0,0)
  data['key'] = keyblob.read()
  votesig.seek(0,0)
  data['sig'] = votesig.read()

  return cont, data
