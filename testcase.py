#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import pyme.core, pyme.constants.sig

def getPassphrase(hint, desc, prev_bad):
  return "123456"
  
c = pyme.core.Context()
c.set_armor(1)
c.set_passphrase_cb(getPassphrase)

testdata      = pyme.core.Data("testdata")

c.op_keylist_start('Authority', 0)
authkey = c.op_keylist_next()

if not authkey:
  print ("No such key found.")
  sys.exit(1)

#sign legitimation with authority key
authsig = pyme.core.Data()
c.signers_add(authkey)
c.op_sign(testdata, authsig, pyme.constants.sig.mode.CLEAR)
c.signers_clear()

data = {}
authsig.seek(0,0)
data[topicid] = authsig.read()

print(str(data))
