#!/usr/bin/env python
import shelve
import ZODB, ZODB.FileStorage
import transaction
from optparse import OptionParser
import os
import sys
import re

reload(sys)
sys.setdefaultencoding("utf-8")

parser = OptionParser()

parser.add_option("-o", "--output", dest = "out_file", default = False, help ="original shelve database filename")
parser.add_option("-i", "--input", dest = "in_file", default = False, help ="new zodb database filename")

parser.set_defaults()
options, args = parser.parse_args()

if options.in_file == False or options.out_file == False :
    print "Need input and output database filenames"
    exit(1)

db = shelve.open(options.in_file, writeback=True)
zstorage = ZODB.FileStorage.FileStorage(options.out_file)
zdb = ZODB.DB(zstorage)
zconnection = zdb.open()
newdb = zconnection.root()

for key, value in db.iteritems() :
    print "Copying key: " + str(key)
    newdb[key] = value

transaction.commit()
                                        

