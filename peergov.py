# -*- coding: utf-8 -*-

import os, sys
import yaml
import pyme.core
import servent

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
          self.cctx.op_verify(sig, None, topicy)
          topicy.seek(0,0)
          topic = yaml.load(topicy.read())
          self.topics[dir]={}
          self.topics[dir]['public'] = topic
          self.topics[dir]['sig']    = data['sig']
      except Exception,e:
        print("Failed to parse topic signature. %s" % str(e))
    else:
      print("No topic signature found for %s." % str(dir)) 
      pass

  def loadData(self, dir, file):
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
    
    
Peergov()
#TODO: initiate some servents, once the data has been loaded
