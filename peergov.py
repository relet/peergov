# -*- coding: utf-8 -*-

import os, sys
import yaml
import pyme.core
import pyme.constants.sigsum
import Tix
#import servent # we'll do that later

authority = "8F5630AB" #read from config file
directory = "./data" #make this path absolute; read from config file

class Peergov:

  def loadTopic(self, dir):
    topicsig = dir + "/" + ".topic.yaml"
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
              topicy.seek(0,0)
              topic = yaml.load(topicy.read())
              self.topics[dir]={}
              self.topics[dir]['public'] = topic
              self.topics[dir]['sig']    = data['sig']
              self.topics[dir]['fpr']    = sig.fpr
            else:
              print ("Signature of %s is not VALID." % str(dir))
          else:
            print ("Verification of topic %s failed." % str(dir))
      except Exception,e:
        print("Failed to parse topic signature. %s" % str(e))
    else:
      print("No topic signature found for %s." % str(dir)) 
      pass

  def loadData(self, dir, file): #proposals and votes?
    if file==".topic.yaml":
      return
    if dir in self.topics:
      try:
        yamldata = open(dir + "/" + file, "r")
        data = yaml.load(yamldata.read())
        if data:
          #verify signature
          self.topics[dir][file]=data
      except Exception,e:
        print("Failed to parse data. %s" % str(e))
    else:
      print("Skipping data file for topic %s. Not authorized." % str(dir)) 

  def initGui(self):
    self.gui = PeerGui()
    self.gui.setTopics(self.topics)
    self.gui.mainloop()

  def __init__(self):
    self.topics = {}
    self.peers  = {}
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
  def __init__(self):
    self.frame = Tix.Tk()
    self.wi_topics = Tix.Tree(self.frame)
    self.wi_topics.pack()
  
  def setTopics(self, topics):
    for topic,data in enumerate(topics):
      #self.wi_topics.
      pass
  
  def mainloop(self):
    self.frame.mainloop()

Peergov()
#TODO: initiate some servents, once the data has been loaded
