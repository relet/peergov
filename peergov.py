# -*- coding: utf-8 -*-

import os, sys
import yaml
import pyme.core
import pyme.constants.sigsum
import Tix
#import servent # we'll do that later
from datamanager import *

authority = "8F5630AB" #read from config file
directory = "./data" #make this path absolute; read from config file

#where do we put this one and all the rest of the crypto context?
def desigsum(sigsum):
  str = "" 
  #for constant in dir(pyme.constants.sigsum):
  if (sigsum & pyme.constants.sigsum.VALID)      : str += "VALID;"
  if (sigsum & pyme.constants.sigsum.GREEN)      : str += "GREEN;"
  if (sigsum & pyme.constants.sigsum.RED)        : str += "RED;"
  if (sigsum & pyme.constants.sigsum.KEY_REVOKED): str += "KEY_REVOKED;"
  if (sigsum & pyme.constants.sigsum.KEY_EXPIRED): str += "KEY_EXPIRED;"
  if (sigsum & pyme.constants.sigsum.SIG_EXPIRED): str += "SIG_EXPIRED;"
  if (sigsum & pyme.constants.sigsum.KEY_MISSING): str += "KEY_MISSING;"
  if (sigsum & pyme.constants.sigsum.CRL_MISSING): str += "CRL_MISSING;"
  if (sigsum & pyme.constants.sigsum.CRL_TOO_OLD): str += "CRL_TOO_OLD;"
  if (sigsum & pyme.constants.sigsum.BAD_POLICY) : str += "BAD_POLICY;"
  if (sigsum & pyme.constants.sigsum.SYS_ERROR)  : str += "SYS_ERROR;"
  return str


class Peergov:

  def loadTopic(self, xdir):
    topicsig = xdir + "/" + ".topic.yaml"
    if os.path.exists(topicsig):
      try:
        yamldata = open(topicsig, "r")
        data = yaml.load(yamldata.read())
        if data:
          sig   = pyme.core.Data(data['sig'])
          topicy = pyme.core.Data()
          if not self.cctx.op_verify(sig, None, topicy):
            sigs = self.cctx.op_verify_result().signatures
            sig = sigs[0] # we don't support multiple. 
            valid = (sig.summary & pyme.constants.sigsum.VALID) > 0
            if valid:
              #TODO: get signature key and name using get_key(fpr)
              sigkey = self.cctx.get_key(sig.fpr, 0)
              topicy.seek(0,0)
              topic = yaml.load(topicy.read())
              auth = self.manager.getAuthority(sig.fpr)
              auth.name = sigkey.uids[0].uid
              to = auth.topics[xdir]=Topic()
              to.data      = topic
              to.signature = data['sig']
            else:
              print ("Signature of %s is not VALID - %s." % (str(xdir), desigsum(sig.summary)))
          else:
            print ("Verification of topic %s failed." % str(xdir))
      except Exception,e:
        print("Failed to parse topic signature. %s" % str(e))
    else:
      print("No topic signature found for %s." % str(xdir)) 
      pass

  def loadData(self, dir, file): #proposals and votes?
    if file==".topic.yaml":
      return
    #if dir in self.topics:
    #  try:
    #    yamldata = open(dir + "/" + file, "r")
    #    data = yaml.load(yamldata.read())
    #    if data:
    #      #verify signature
    #      self.topics[dir][file]=data
    #  except (Exception,e):
    #    print("Failed to parse data. %s" % str(e))
    #else:
    #  print("Skipping data file for topic %s. Not authorized." % str(dir)) 

  def initGui(self):
    self.gui = PeerGui(self.manager)
    self.gui.mainloop()
    
  def __init__(self):
    self.manager = DataManager()
    self.cctx   = pyme.core.Context() #crypto context
  
    if not os.path.exists(directory):
      try: 
        print("Directory %s not found. Creating." % str(directory))
        os.mkdir(directory)
      except:
        print("Failed creating data directory. Aborting.")
        sys.exit(1)
    if not os.path.isdir(directory):
      print("Path %s is not a directory. Aborting." % str(directory))
      sys.exit(1)
    
    for root, dirs, files in os.walk(directory):
      for dir in dirs:
        self.loadTopic(root + "/" + dir)
      for file in files:
        self.loadData(root, file)
    
    self.initGui()

class PeerGui:
  def __init__(self, manager):
    self.manager = manager
    self.frame = Tix.Tk()
    self.wPane = Tix.PanedWindow(self.frame, orientation='horizontal')
    self.wPane1 = self.wPane.add('tree')
    self.wPane2 = self.wPane.add('info')
    self.wTopics = Tix.Tree(self.wPane1)
    self.wTopics['opencmd'] = self.openTree(self.wTopics, None) #lambda dir=None, w=tree: opendir(w, dir)
    self.initTree();
    self.wInfo = Tix.ScrolledText(self.wPane2)
    self.wInfo.text['width']=80
    self.wInfo.text['height']=20
    self.wInfo.text['state'] = 'disabled'
    self.wInfo.pack(expand=1, fill=Tix.BOTH, padx=1, pady=1)
    self.wTopics.pack(expand=1, fill=Tix.BOTH, padx=1, pady=1, side=Tix.LEFT)
    self.wPane.pack(side=Tix.TOP, padx=1, pady=1, fill=Tix.BOTH, expand=1)
    
  def openTree(self, tree, dir):
    print str((self, tree, dir))
  
  def initTree(self):
    for fpr, authority in self.manager.authorities.iteritems():
      self.wTopics.hlist.add(fpr, itemtype=Tix.IMAGETEXT, text=authority.name,image=self.wTopics.tk.call('tix', 'getimage', 'folder'))
      for xdir, topic in authority.topics.iteritems():
        self.wTopics.hlist.add(fpr+xdir, itemtype=Tix.IMAGETEXT, text=topic.data['short'],image=self.wTopics.tk.call('tix', 'getimage', 'folder'))
        #etc. for proposals, votes, ...
      pass
  
  def mainloop(self):
    self.frame.mainloop()

Peergov()
#TODO: initiate some servents, once the data has been loaded
