#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from hashlib import md5
from datetime import datetime
import pyme.core, pyme.constants.sig
import yaml

def getPassphrase(hint, desc, prev_bad):
  #print "Passphrase Callback! %s %s %s" % (hint, desc, prev_bad)
  #sys.stdout.write("Enter passphrase: ")
  #return sys.stdin.readline().strip()
  return "123456"
  
c = pyme.core.Context()
c.set_armor(1)
c.set_passphrase_cb(getPassphrase)

c.op_keylist_start('Voter 1', 0)
votekey = c.op_keylist_next()

if not votekey:
  print ("No such key found.")
  sys.exit(1)

voterid = votekey.subkeys[0].fpr
topicid = '82529AF0DBF39AAE02BFA77FE00A9A6E8F5630AB/lunch/20090612/place'

authorization = yaml.dump([voterid, topicid])
authblob      = pyme.core.Data(authorization)

topic = {}
topic['type']    = 'vote'
topic['path']    = topicid
topic['voterid'] = voterid
topic['id']      = md5(topic['path']+topic['voterid']).hexdigest()
topic['vote']    = ['ba9b53659aeef6874b2a7ea0d43ef53b', '04d61148ad85246b2886aaa6468b3a43']

voteblob = pyme.core.Data(yaml.dump(topic))

c.op_keylist_start('Authority', 0)
authkey = c.op_keylist_next()

if not authkey:
  print ("No such key found.")
  sys.exit(1)

#sign legitimation with authority key
authsig = pyme.core.Data()
c.signers_add(authkey)
c.op_sign(authblob, authsig, pyme.constants.sig.mode.CLEAR)
c.signers_clear()

#export voter key
keyblob = pyme.core.Data()
c.op_export('Voter 1', 0, keyblob)

#sign actual vote with voter key
votesig = pyme.core.Data()
c.signers_add(votekey)
#print ("So far, so good.")
c.op_sign(voteblob, votesig, pyme.constants.sig.mode.CLEAR)

data = {}
authsig.seek(0,0)
data['auth'] = authsig.read()
keyblob.seek(0,0)
data['key'] = keyblob.read()
votesig.seek(0,0)
data['sig'] = votesig.read()

print(yaml.dump(data))
