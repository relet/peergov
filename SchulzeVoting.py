#!/usr/bin/env python
# Licence: LGPL - by Thomas Hirsch 2009 

class SchulzeVoting:
  def __init__(self):
    self.reset()

  def reset(self):
    self.ballots = []
    self.candidates = []

  def addVote(self, ballot):
    self.ballots.append(ballot)
    for candidate in ballot:
      if not candidate in self.candidates:
        self.candidates.append(candidate)
 
  def getPaths(self): 
    defeats = {}
    paths   = {}
    for c1 in self.candidates:
      for c2 in self.candidates:
        if not c1 in defeats:
          defeats[c1]={}
        if not c1 in paths:
          paths[c1]={}
        defeats[c1][c2] = 0
        paths[c1][c2]   = 0
    for ballot in self.ballots:
      for i, choice in enumerate(ballot):
        for candidate in self.candidates:
          place = ballot.index(candidate)
          if place and place>i:
            defeats[choice][candidate] += 1
    for c1 in self.candidates:
      for c2 in self.candidates:
        if (c1 != c2):
          if defeats[c1][c2]>defeats[c2][c1]:
            paths[c1][c2]=defeats[c1][c2]
    for c1 in self.candidates:
      for c2 in self.candidates:
        if (c1 != c2):
          for c3 in self.candidates:
            if (c1 != c3) and (c2 != c3):
              paths[c2][c3] = max(paths[c2][c3], min(paths[c2][c1], paths[c1][c3]))
    return paths

  def getWinners(self):
    paths = self.getPaths()
    winners = self.candidates[:]
    for c1 in self.candidates:
      for c2 in self.candidates:
        if (c1 != c2):
          if paths[c2][c1]>paths[c1][c2]:
            winners.remove[c1]
    return winners

  def getRanks(self):
    paths = self.getPaths()
    ranks = []
    remaining = self.candidates[:]
    while remaining:
      winners = remaining[:]
      for c1 in remaining:
        for c2 in remaining:
          if (c1 != c2):
            if paths[c2][c1]>paths[c1][c2]:
              if c1 in winners:
                winners.remove(c1)
      ranks.append(winners)
      for winner in winners:
        remaining.remove(winner)
    return ranks

  def countVotes(self):
    return len(self.ballots)


if __name__=="__main__":
  v = SchulzeVoting()

  ballot = ["Correct"]
  v.addVote(ballot)
  print("Tests:")
  print("Single vote, single candidate: "+str(v.getRanks()))
  v.reset()

  ballot.extend(["Second","Third"])
  v.addVote(ballot)
  print("Single vote, three candidates: "+str(v.getRanks()))
  v.reset();

  ballot2 = ["Third","Correct","Second"]
  ballot3 = ["Second","Correct","Third"]

  v.addVote(ballot);
  v.addVote(ballot2);
  v.addVote(ballot3);

  print("Three votes, three candidates: "+str(v.getRanks()))

