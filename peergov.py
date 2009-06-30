# -*- coding: utf-8 -*-

import os, sys
import yaml
import pyme.core
import pyme.constants.sigsum
import wx, wx.html
import SchulzeVoting
#import servent # we'll do that later
from datamanager import Authority, Topic, DataManager
from cryptutils import createVote

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
  def loadAuth(self, xdir, xfile):
    data = yaml.load(open(xdir+"/"+xfile, "r"))
    for auth in data.keys():
      sig   = pyme.core.Data(data[auth])
      authy = pyme.core.Data()
      if not self.cctx.op_verify(sig, None, authy):
        sigs = self.cctx.op_verify_result().signatures
        sig = sigs[0] # we don't support multiple. 
        valid = (sig.summary & pyme.constants.sigsum.VALID) > 0
        if valid:
          authy.seek(0,0)
          authcontent = yaml.load(authy.read())
          if authcontent[0]==self.user:
            self.authorizations[auth]=data[auth]
          else:
            print("Authorization %s not valid for this user %s." % (xfile, self.user))
        else:
          print ("Signature of authorization %s is not VALID - %s." % (str(xfile), desigsum(sig.summary)))
      else:
        print ("Failed to verify authorization %s" % (str(xfile)))

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
          xcomp = xdir[len(self.datadir)+1:]
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
    
  def ensureDirExists(self, xdir):
    if not os.path.exists(xdir):
      try: 
        print("Directory %s not found. Attempting to create." % str(xdir))
        os.mkdir(xdir)
      except:
        print("Failed creating directory. Aborting.")
        sys.exit(1)
    if not os.path.isdir(xdir):
      print("Path %s is not a directory. Aborting." % str(xdir))
      sys.exit(1)
  
    
  def __init__(self):
    self.config = yaml.load(open(".peergovrc","r").read())
    self.basedir = self.config['basedir']
    self.datadir = self.config['datadir']
    self.authdir = self.config['authdir']
    self.user    = self.config['userfpr']
    self.authorizations = {}
  
    self.voting = SchulzeVoting.SchulzeVoting()
    self.manager = DataManager()
    self.manager.datadir = self.datadir
    self.cctx   = pyme.core.Context() #crypto context
  
    self.ensureDirExists(self.basedir)
    self.ensureDirExists(self.datadir)
    self.ensureDirExists(self.authdir)
    
    for root, dirs, files in os.walk(self.datadir):
      for dir in dirs:
        self.loadTopic(root + "/" + dir)
      for file in files:
        self.loadData(root, file)

    for root, dirs, files in os.walk(self.authdir):
      for file in files:
        self.loadAuth(root, file)

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

    notebook = wx.Notebook(self.frame, wx.ID_ANY)

    panel1 = wx.Panel(notebook)
    self.list1 = wx.ListCtrl(panel1)
    buttonpanel1 = wx.Panel(panel1)
    buttonadd = wx.Button(buttonpanel1, wx.ID_ANY, u"\u2192", style=wx.BU_EXACTFIT)
    buttonadd.Bind(wx.EVT_BUTTON, self.changePreference)
    buttonrem = wx.Button(buttonpanel1, wx.ID_ANY, u"\u2190", style=wx.BU_EXACTFIT)
    buttonrem.Bind(wx.EVT_BUTTON, self.changePreference)
    buttonsizer = wx.BoxSizer(wx.VERTICAL)
    buttonsizer.Add(buttonadd, 1, wx.CENTER)
    buttonsizer.Add(buttonrem, 1, wx.CENTER)
    buttonpanel1.SetSizer(buttonsizer)
    
    list2panel = wx.Panel(panel1)
    
    self.list2 = wx.ListCtrl(list2panel)
    buttonpanel2 = wx.Panel(panel1)
    button2up = wx.Button(buttonpanel2, wx.ID_ANY, u"\u219F", style=wx.BU_EXACTFIT)
    button2up.Bind(wx.EVT_BUTTON, self.changePreference)
    buttonup = wx.Button(buttonpanel2, wx.ID_ANY, u"\u2191", style=wx.BU_EXACTFIT)
    buttonup.Bind(wx.EVT_BUTTON, self.changePreference)
    buttondn = wx.Button(buttonpanel2, wx.ID_ANY, u"\u2193", style=wx.BU_EXACTFIT)
    buttondn.Bind(wx.EVT_BUTTON, self.changePreference)
    button2dn = wx.Button(buttonpanel2, wx.ID_ANY, u"\u21A1", style=wx.BU_EXACTFIT)
    button2dn.Bind(wx.EVT_BUTTON, self.changePreference)
    buttonsizer2 = wx.BoxSizer(wx.VERTICAL)
    buttonsizer2.Add(button2up, 1, wx.CENTER)
    buttonsizer2.Add(buttonup, 1, wx.CENTER)
    buttonsizer2.Add(buttondn, 1, wx.CENTER)
    buttonsizer2.Add(button2dn, 1, wx.CENTER)
    buttonpanel2.SetSizer(buttonsizer2)
    
    self.list1.Bind(wx.EVT_LIST_ITEM_SELECTED, self.OnProposalSelected, self.list1)
    self.list2.Bind(wx.EVT_LIST_ITEM_SELECTED, self.OnProposalSelected, self.list2)

    self.buttonvote = wx.Button(list2panel, wx.ID_ANY, u"Submit vote")
    self.buttonvote.Bind(wx.EVT_BUTTON, self.submitVote)
    
    box4 = wx.BoxSizer(wx.VERTICAL)
    box4.Add(self.list2, 12, wx.EXPAND)
    box4.Add(self.buttonvote, 1, wx.EXPAND)
    list2panel.SetSizer(box4)

    box3 = wx.BoxSizer(wx.HORIZONTAL)
    box3.Add(self.list1, 8, wx.EXPAND)
    box3.Add(buttonpanel1, 1, wx.CENTER)
    box3.Add(list2panel, 8, wx.EXPAND)
    box3.Add(buttonpanel2, 1, wx.CENTER)
    panel1.SetSizer(box3)

    self.results = wx.ListCtrl(notebook) #make this a html or canvas, showing the results in beautiful

    notebook.AddPage(panel1, "Ballot")
    notebook.AddPage(self.results, "Results")
    
    box2 = wx.BoxSizer(wx.VERTICAL)
    box2.Add(self.text, 1, wx.EXPAND)
    box2.Add(notebook, 1, wx.EXPAND)

    box1 = wx.BoxSizer(wx.HORIZONTAL)
    box1.Add(self.tree, 1, wx.EXPAND)
    box1.Add(box2, 2, wx.EXPAND)

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
          dirs = tid[len(self.datadir)+1:].split("/")[1:]
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
    authorized = False
    for path in self.peergov.authorizations.keys():
      if path in tpath:
        authorized = True
    authority, topic = self.manager.getTopicByPath(tpath)
    self.currentTopic = topic
    voting = self.peergov.voting
    voting.reset()
    if authority and topic:
      self.text.SetPage(self.genHTML(topic))
      item = wx.ListItem()
      if authorized:
        item.SetText("--- Any (other) option ---")
        self.buttonvote.Enable(True)
      else:
        item.SetText("NO AUTHORIZATION TO VOTE")
        self.buttonvote.Enable(False)
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
      print ("DEBUG - Results for this topic: %s" % (str(voting.getRanks())))
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

  def listSortBottom(self, i1, i2):
    if i1 == self.sortingItem:
      return 1
    return -1
  def listSortTop(self, i1, i2):
    if i2 == self.sortingItem:
      return 1
    return -1
  def listSortUp(self, i1, i2):
    if (i2 == self.sortingItem) and (i1 == self.sortingItem2):
      return 1
    return -1
  def listSortDown(self, i1, i2):
    if (i1 == self.sortingItem) and (i2 == self.sortingItem2):
      return 1
    return -1
    
  def submitVote(self, event):
    print(str(event))
    # voter = TODO: read from configuration file
    topicid = self.currentTopic
    # authorization = TODO: read from authorization file/folder
    vote = []
    #for item in list2:
    #  proposalId = ???
    #  vote.append(proposalId)
    # createVote(voter, topicid, authorization, vote):

  def changePreference(self, event):
    label = event.GetEventObject().GetLabel()
    if label == u"\u2192": # add
      index = self.list1.GetFirstSelected()
      item  = self.list1.GetItem(index)
      if item != None:
        self.list2.InsertItem(item)
        self.list1.DeleteItem(index)
    elif label == u"\u2190": # remove
      index = self.list2.GetFirstSelected()
      item  = self.list2.GetItem(index)
      if self.list2.GetItemData(index) == -1: # skip the any-item placeholder
        return
      if item != None:
        self.list1.InsertItem(item)
        self.list2.DeleteItem(index)
    elif label == u"\u2191": # up
      index = self.list2.GetFirstSelected()
      #item  = self.list2.GetItem(index)
      self.sortingItem = self.list2.GetItemData(index)
      self.sortingItem2 = self.list2.GetItemData(index-1)
      if index != None:
        self.list2.SortItems(self.listSortUp)
    elif label == u"\u2193": # down
      index = self.list2.GetFirstSelected()
      #item  = self.list2.GetItem(index)
      self.sortingItem = self.list2.GetItemData(index)
      self.sortingItem2 = self.list2.GetItemData(index+1)
      if index != None:
        self.list2.SortItems(self.listSortDown)
    elif label == u"\u219F": # top
      index = self.list2.GetFirstSelected()
      #item  = self.list2.GetItem(index)
      self.sortingItem = self.list2.GetItemData(index)
      if index != None:
        self.list2.SortItems(self.listSortTop)
    elif label == u"\u21A1": # bottom
      index = self.list2.GetFirstSelected()
      #item  = self.list2.GetItem(index)
      self.sortingItem = self.list2.GetItemData(index)
      if index != None:
        self.list2.SortItems(self.listSortBottom)
    

  def mainloop(self):
    self.app.MainLoop()

Peergov()
#TODO: initiate some servents, once the data has been loaded
