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

topic = {}
topic['type']='topic'
topic['path']='58BD0CCEB421BFB9BE694135F66EA1A3025BA2BF/lunch/2009-07-16/place'
topic['title']='Where?'
topic['short']='Where should we go for lunch on Thursday, 2009-07-16?'
topic['text']=None
topic['expired']=str(datetime(2009,7,16,13,59))
topic['author']='futterbot'

blob = pyme.core.Data(yaml.dump(topic))

#print ("Fetching authority key")
c.op_keylist_start('Authority', 0)
r = c.op_keylist_next()
#print(r)

if not r:
  print ("No such key found.")
  sys.exit(1)

#print ("Exporting key")
key = pyme.core.Data()
c.op_export('Authority', 0, key)

#print ("Signing data with key %s." % str(r))
sig = pyme.core.Data()
c.signers_add(r)
#print ("So far, so good.")
c.op_sign(blob, sig, pyme.constants.sig.mode.CLEAR)

data = {}
sig.seek(0,0)
data['sig'] = sig.read()
#key.seek(0,0)
#data['key'] = key.read()

print(yaml.dump(data))
