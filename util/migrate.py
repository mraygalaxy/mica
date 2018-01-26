#!/usr/bin/env python

from couchdb import Server
from optparse import OptionParser
import os
import sys
import re
import argparse
from time import sleep
import couchdb

parser = OptionParser()

parser = argparse.ArgumentParser(description='Replicate one server to another.')
parser.add_argument('--source', type=str, required = True, help='Source address')
parser.add_argument('--dest', type=str, required = True, help='Destination address')

args = parser.parse_args()

src = Server(args.source)
dest = Server(args.dest)

count = 0
for dbname in src :
    db = src[dbname]
    if (len(dbname) >= 4 and dbname[:4] == "mica" ) or dbname == "_users" :
        try :
            newdb = dest[dbname]
        except couchdb.http.ResourceNotFound, e :
            dest.create(dbname)
            newdb = dest[dbname]

        security = db.security
        print "Copying " + str(dbname) + " security parameters: " + str(security)
        newdb.security = security
        if db.info()["doc_count"] != newdb.info()["doc_count"] :
            print "Replicating: " + str(dbname)
            src.replicate(args.source + "/" + dbname, args.dest + "/" + dbname, continuous = True) 
        else :
            print "Already replicated: " + str(dbname)
            continue

        while db.info()["doc_count"] > newdb.info()["doc_count"] :
            print "Source count: " + str(db.info()["doc_count"]) + " dest count: " +  str(newdb.info()["doc_count"])
            sleep(5)

        count += 1

print "DBs: " + str(count)
