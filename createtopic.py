#!/usr/bin/env python

from hashlib import md5
from datetime import datetime
import pyme.core, pyme.constants.sig
import yaml


c = pyme.core.Context()
c.set_armor(1)

topic = {}
topic['path']='futterbot/lunch/20090612/place'
topic['title']='Where?'
topic['id']=md5(topic['path']+topic['title']).hexdigest()
topic['short']='Where should we go for lunch on Friday, 2009-06-12?'
topic['text']=None
topic['expired']=str(datetime(2009,06,12,23,59))
topic['author']='futterbot'

blob = pyme.core.Data(yaml.dump(topic))

c.op_keylist_start('Peergov', 0)
r = c.op_keylist_next()
c.set_passphrase_cb(lambda x,y,z:'123456')

if not r:
  print ("No such key found.")
  sys.exit(1)

sig = pyme.core.Data()
c.signers_add(r)
c.op_sign(blob, sig, pyme.constants.sig.mode.CLEAR)
sig.seek(0,0)

data = {}
data['sig'] = sig.read()

print yaml.dump(data)
