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
parser.add_argument('--source', type=str, help='Source address')
parser.add_argument('--dest', type=str, help='Destination address')

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

        print "Replicating: " + str(dbname)
        src.replicate(args.source + "/" + dbname, args.dest + "/" + dbname, continuous = True) 
        while db.info()["doc_count"] != newdb.info()["doc_count"] :
            print "Source count: " + str(db.info()["doc_count"]) + " dest count: " +  str(newdb.info()["doc_count"])
            sleep(5)
        count += 1

print "DBs: " + str(count)
