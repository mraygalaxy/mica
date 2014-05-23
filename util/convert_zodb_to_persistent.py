#!/usr/bin/env python
import transaction
import ZODB, ZODB.FileStorage
from ZODB.PersistentMapping import PersistentMapping
from ZODB.PersistentList import PersistentList
from optparse import OptionParser
import os
import sys
import re
import codecs


def depth_first_deep_copy(src, dst, key = None) :
    if key is None :
        if isinstance(src, dict) or isinstance(src, PersistentMapping) :
            for key in src.keys() :
                depth_first_deep_copy(src, dst, key)
        elif isinstance(src, list) :
            for item in src :
                if isinstance(item, dict) :
                    newitem = PersistentMapping()
                    depth_first_deep_copy(item, newitem)
                elif isinstance(item, list) :
                    newitem = PersistentList()
                    depth_first_deep_copy(item, newitem)
                else :
                    newitem = item

                dst.append(newitem)
        else :
            print "Unknown type! Ah! " + str(type(src))

    else :
        if isinstance(src[key], dict) :
            dst[key] = PersistentMapping()
            depth_first_deep_copy(src[key], dst[key])
        elif isinstance(src[key], list) :
            dst[key] = PersistentList()
            depth_first_deep_copy(src[key], dst[key])
        else : 
            dst[key] = src[key]

reload(sys)
sys.setdefaultencoding("utf-8")

parser = OptionParser()

parser.add_option("-o", "--output", dest = "out_file", default = False, help ="original zodb database filename")
parser.add_option("-i", "--input", dest = "in_file", default = False, help ="new zodb database filename")

parser.set_defaults()
options, args = parser.parse_args()

if options.in_file == False or options.out_file == False :
    print "Need input and output database filenames"
    exit(1)

instorage = ZODB.FileStorage.FileStorage(options.in_file)
indb = ZODB.DB(instorage)
inconnection = indb.open()
srcdb = inconnection.root()

outstorage = ZODB.FileStorage.FileStorage(options.out_file)
outdb = ZODB.DB(outstorage)
outconnection = outdb.open()
dstdb = outconnection.root()

depth_first_deep_copy(srcdb, dstdb)

def pp(db, fh, tabs = 0) :
    t = ""
    for x in range(0, tabs) :
        t += "    "

    if isinstance(db, PersistentMapping) or isinstance(db, dict) :
        for key, value in db.iteritems() :
            fh.write(t + "{\n")
            fh.write(t + "   \"" + key + "\" : \n")
            pp(value, fh, tabs + 1)
            fh.write(t + "},\n")
    elif isinstance(db, PersistentList) or isinstance(db, list) :
        for item in db :
            fh.write(t + "[\n")
            pp(item, fh, tabs + 1)
            fh.write(t + "],\n")
    else :
        if isinstance(db, unicode) :
            fh.write(t + db.encode("utf-8") + ",\n")
        elif isinstance(db, str) and len(db) > 20 :
            fh.write(t + "string too big..." + ",\n")
        else :
            fh.write(t + str(db) + ",\n")

fh = codecs.open("compare.src", "w", "utf-8")
pp(srcdb, fh)
fh.close()
fh = codecs.open("compare.dst", "w", "utf-8")
pp(dstdb, fh)
fh.close()

transaction.commit()
indb.close()
instorage.close()
outdb.close()
outstorage.close()
                                        

