#!/usr/bin/env python

# Step 1: Create a new user from the web interface
# Step 2: Do a one-shot (NOT continuous) replication between the existing DB and the new one
# Step 3: Run this script to rename all the user's documents key names to the new ones.

from couchdb import Server
from optparse import OptionParser
import os
import sys
import re

reload(sys)
sys.setdefaultencoding("utf-8")

parser = OptionParser()

parser.add_option("-o", "--newuser", dest = "username", help ="Original username")
parser.add_option("-i", "--olduser", dest = "orig", help ="New username")
parser.add_option("-s", "--server", dest = "server", help ="DB address")
parser.add_option("-t", "--to", dest = "todb", help ="destination DB")
parser.add_option("-f", "--from", dest = "fromdb", help ="source DB")

parser.set_defaults()
options, args = parser.parse_args()

s = Server(args.server)
todb = s[args.todb]
fromdb = s[args.todb]

def copydoc(fromkey) :
    doc = fromdb[fromkey]

    newkey = fromkey.replace(args.orig, args.username)
    doc["_id"] = newkey 

    print fromkey + " => " + newkey 

    del doc["_rev"]
    attachments = {}
    if "_attachments" in doc :
        for akey in doc["_attachments"].keys() :
            attachments[akey] = fromdb.get_attachment(fromkey, akey)
        del doc["_attachments"]
        
    try :
        del todb[newkey]
    except Exception, e :
        pass

    try :
        todb[newkey] = doc 
    except Exception, e :
        print "ERROR: " + str(e)
        return

    for akey, attach in attachments.iteritems() :
        todb.put_attachment(doc, attach, akey)

count = 0
for row in fromdb.view('_all_docs'):
    fromkey = row.id
    if fromkey.strip() != "MICA:accounts:" + args.orig :
        copydoc(fromkey)
        count += 1

print "copied: " + str(count)
