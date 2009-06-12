# -*- coding: utf-8 -*-
import sys
from pyme import core
from pyme.constants.sig import mode
from pyme.constants import protocol
from pyme.constants.data import encoding
 
def getPassphrase(hint, desc, prev_bad):
  print "Passphrase Callback! %s %s %s" % (hint, desc, prev_bad)
  sys.stdout.write("Enter passphrase: ")
  return sys.stdin.readline().strip()
  
# Set up our input and output buffers.
 
plain = core.Data('This is my message.')
verified = core.Data()
sig = core.Data()
 
# Initialize our context.
 
c = core.Context()
#c.set_engine_info(protocol.OpenPGP, "/usr/bin/gpg", "/home/thomas/code/peergov/keyring/")
c.set_armor(1)#encoding.ARMOR?
c.set_passphrase_cb(getPassphrase)
 
# Set up the recipients.
 
sys.stdout.write("Enter name of signing key: ")
name = sys.stdin.readline().strip()
c.op_keylist_start(name, 0)
r = c.op_keylist_next()
 
# Do the encryption.

if r:
  print ("Key found: %s" % r.uids[0].uid)
else:
  print ("No such key found.")
  sys.exit(1)

#c.op_encrypt([r], 1, plain, cipher)
c.signers_add(r)

c.op_sign(plain, sig, mode.NORMAL)

sig.seek(0,0)
print sig.read()
sig.seek(0,0)

c.op_verify(sig, None, verified)
verified.seek(0,0)
print verified.read()
