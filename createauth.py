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
topicid = '82529AF0DBF39AAE02BFA77FE00A9A6E8F5630AB/lunch'

authorization = yaml.dump([voterid, topicid])
authblob      = pyme.core.Data(authorization)

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

data = {}
authsig.seek(0,0)
data[topicid] = authsig.read()

print(yaml.dump(data))
