# -*- coding: utf-8 -*-

import os, sys
import yaml
import pyme.core
import pyme.constants.sigsum
import wx, wx.html
import SchulzeVoting
#import servent # we'll do that later
from datamanager import *

basedir   = "."
datadir   = basedir+"/data" #make this path absolute; read from config file

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
      #try:
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
              if not topic['type']=='topic': #someone exchanged the files
                return
              auth = self.manager.getAuthority(sig.fpr)
              auth.name = sigkey.uids[0].uid
              auth.fpr = sig.fpr
              to = auth.topics[xdir]=Topic()
              to.data      = topic
              to.signature = data['sig']
            else:
              print ("Signature of %s is not VALID - %s." % (str(xdir), desigsum(sig.summary)))
          else:
            print ("Verification of topic %s failed." % str(xdir))
      #except Exception,e:
      #  print("Failed to parse topic signature. %s" % str(e))
    else:
      #print("No topic signature found for %s" % str(xdir)) 
      pass

  def loadData(self, xdir, file): #proposals and votes?
    if file==".topic.yaml":
      return
    authority, topic = self.manager.getTopicByPath(xdir)
    if authority and topic:
      yamldata = open(xdir + "/" + file, "r")
      data = yaml.load(yamldata.read())
      if data:
        authorized = None
        if 'key' in data and 'auth' in data: #a key is provided. check key authorization
          authsig = pyme.core.Data(data['auth'])
          authy   = pyme.core.Data()
          if self.cctx.op_verify(authsig, None, authy):
            print("Vote %s not authorized." % file)
            return
          sigs = self.cctx.op_verify_result().signatures
          sig  = sigs[0]
          valid = (sig.summary & pyme.constants.sigsum.VALID) > 0
          if not valid:
            print("Authorization for vote %s not VALID (%s)." % (file, desigsum(sig.summary)))
            return
          authy.seek(0,0)
          auth = yaml.load(authy.read())
          xcomp = xdir[len(datadir)+1:]
          if auth[1] != xcomp:
            print auth[1], xcomp
            print("Authorization in %s not valid for topic %s." % (file, xcomp))
            return
          authorized = auth[0]
          try:
            votekey = self.cctx.get_key(auth[0], 0)
          except:
            keydata = pyme.core.Data(data['key'])
            fail = self.cctx.op_import(keydata)
            if not fail:
              result = self.cctx.op_import_result()
              print ("Key import - %i considered, %i imported, %i unchanged." % (result.considered, result.imported, result.unchanged))
            else:
              print ("Failed to import keys.")
        sig   = pyme.core.Data(data['sig'])
        propy = pyme.core.Data()
        if not self.cctx.op_verify(sig, None, propy):
          sigs = self.cctx.op_verify_result().signatures
          sig = sigs[0] # we don't support multiple. 
          key_missing = (sig.summary & pyme.constants.sigsum.KEY_MISSING) > 0
          valid = (sig.summary & pyme.constants.sigsum.VALID) > 0
          if valid:
            if authorized and sig.fpr != authorized:
              print("Authorization in %s not valid for signing user %s." % (file, sig.fpr))
              return
            propy.seek(0,0)
            prop = yaml.load(propy.read())
            if prop['type']=='proposal': 
              topic.proposals.append(prop)
              return
            elif prop['type']=='vote' and authorized: 
              topic.votes.append(prop)
              return
          elif key_missing:
            print("Signing key not available/imported for user %s from file %s." % (sig.fpr,file))
            return
    else:
      print("Skipping data file %s/%s. No authority/topic found." % (xdir, file)) 

  def initGui(self):
    self.gui = PeerGui(self, self.manager)
    self.gui.mainloop()
    
  def __init__(self):
    self.voting = SchulzeVoting.SchulzeVoting()
    self.manager = DataManager()
    self.manager.datadir = datadir
    self.cctx   = pyme.core.Context() #crypto context
  
    if not os.path.exists(datadir):
      try: 
        print("Directory %s not found. Attempting to create." % str(datadir))
        os.mkdir(datadir)
      except:
        print("Failed creating data directory. Aborting.")
        sys.exit(1)
    if not os.path.isdir(datadir):
      print("Path %s is not a directory. Aborting." % str(datadir))
      sys.exit(1)
    
    for root, dirs, files in os.walk(datadir):
      for dir in dirs:
        self.loadTopic(root + "/" + dir)
      for file in files:
        self.loadData(root, file)
    
    self.initGui()

class PeerGui:
  def __init__(self, peergov, manager):
    self.peergov = peergov
    self.manager = manager
    self.app     = wx.PySimpleApp()
    self.frame   = wx.Frame(None, wx.ID_ANY, "Peergov edge", size=(800,600))
    self.panel   = wx.Panel(self.frame, wx.ID_ANY, style=wx.SUNKEN_BORDER)
     
    self.tree = wx.TreeCtrl(self.frame)
    self.tree.Bind(wx.EVT_TREE_SEL_CHANGED, self.OnTreeSelectionChanged, self.tree)
    self.root = self.tree.AddRoot('Authorities')
    self.tree.SetItemHasChildren(self.root)

    self.resetTree(True)
    self.tree.ExpandAll()

    self.text = wx.html.HtmlWindow(self.frame)

    self.list1 = wx.ListCtrl(self.frame)
    self.list2 = wx.ListCtrl(self.frame)
    
    self.list1.Bind(wx.EVT_LIST_ITEM_SELECTED, self.OnProposalSelected, self.list1)
    self.list2.Bind(wx.EVT_LIST_ITEM_SELECTED, self.OnProposalSelected, self.list2)

    box3 = wx.BoxSizer(wx.HORIZONTAL)
    box3.Add(self.list1, 1, wx.EXPAND)
    box3.Add(self.list2, 1, wx.EXPAND)

    box2 = wx.BoxSizer(wx.VERTICAL)
    box2.Add(self.text, 1, wx.EXPAND)
    box2.Add(box3, 1, wx.EXPAND)

    box1 = wx.BoxSizer(wx.HORIZONTAL)
    box1.Add(self.tree, 2, wx.EXPAND)
    box1.Add(box2, 3, wx.EXPAND)

    self.currentTopic = None

    self.frame.SetSizer(box1)
    self.frame.Layout()

    self.frame.Show(True)

  def resetTree(self, collapsed=True):
    self.tree.DeleteChildren(self.root)
    self.initTree(collapsed)

  def initTree(self, collapsed=True):
    for fpr, authority in self.manager.authorities.iteritems():
      if not authority.name:
        continue
      child = self.tree.AppendItem(self.root, authority.name)
      self.tree.SetItemData(child, wx.TreeItemData(authority.fpr))
      self.tree.SetItemHasChildren(child)
      for tid, topic in authority.topics.iteritems():
        parent = child
        if not collapsed:
          dirs = tid[len(datadir)+1:].split("/")[1:]
          for xdir in dirs:
            parent = self.tree.AppendItem(parent, xdir)
            self.tree.SetItemHasChildren(parent)
        tchild = self.tree.AppendItem(parent, topic.data['title'])
        self.tree.SetItemData(tchild, wx.TreeItemData(tid))
  
  def resetRightPanel(self):
    self.text.SetPage("")
    self.list1.DeleteAllItems()
    self.list2.DeleteAllItems()
    pass
    
  def genHTML(self, topic, proposal=None):
    html = u"<p><b>%s</b></p><p>%s</p>" % (topic.data['title'], topic.data['short'])
    html += "<hr />"
    if proposal:
      html += "<p><b>%s</b></p><p>%s</p>" % (proposal['title'], proposal['short'])
    return html
      
    
  def displayTopicInfo(self, tpath):
    authority, topic = self.manager.getTopicByPath(tpath)
    self.currentTopic = topic
    voting = self.peergov.voting
    voting.reset()
    if authority and topic:
      self.text.SetPage(self.genHTML(topic))
      item = wx.ListItem()
      item.SetText("--- Don't care ---")
      item.SetData(-1)
      self.list2.InsertItem(item)
      for i,proposal in enumerate(topic.proposals):
        item = wx.ListItem()
        item.SetText(proposal['title'])
        item.SetData(i)
        self.list1.InsertItem(item)
      for i,vote in enumerate(topic.votes):
        #TODO: eliminate invalid choices from ballot
        voting.addVote(vote['vote'])
      print ("Results for this topic: %s" % (str(voting.getRanks())))
    else:
      self.resetRightPanel()
  
  def OnProposalSelected(self, listevent):
    item  = listevent.GetItem()
    index = item.GetData()
    if index>=0:
      proposal = self.currentTopic.proposals[index]
    else:
      proposal = None
    self.text.SetPage(self.genHTML(self.currentTopic, proposal))
  
  def OnTreeSelectionChanged(self, treeevent):
    item = self.tree.GetSelection()
    parent    = self.tree.GetItemParent(item)
    children  = self.tree.ItemHasChildren(item)
    label     = self.tree.GetItemText(item)
    if parent:
      if parent==self.root:
#        print("Authority: %s" % label)
        self.resetRightPanel()
      elif children:
#        print("Folder: %s" % label)
        self.resetRightPanel()
      else:
#        print("Topic: %s" % label)
        self.displayTopicInfo(self.tree.GetItemData(item).GetData())
    else:
#      print("ROOT: %s" % label)
      self.resetRightPanel()

  def mainloop(self):
    self.app.MainLoop()

Peergov()
#TODO: initiate some servents, once the data has been loaded
