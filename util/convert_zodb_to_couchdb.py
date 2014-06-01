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
import couchdbkit
from couchdbkit import Server
import simplejson as json

''' These patterns must be ordered by depth.
    Put the deepest patterns first and the
    shortest patters last.

    Probably, I should just sort them, but I'll do that later.
'''

'''
Example commands:
$ cd /tmp
  # first one drops the whole databases
$ cp /home/mrhines/mica-v0.2/databases/family@hinespot.com.db .; ~/convert_zodb_to_couchdb.py -i family@hinespot.com.db -o "https://admin:super_secret_password@localhost:6984" -d
$ cp /home/mrhines/mica-v0.2/databases/admin.db .; ~/convert_zodb_to_couchdb.py -o "https://admin:super_secret_password@localhost:6984" -i admin.db
$ cp /home/mrhines/mica-v0.2/databases/jonathan.db .; ~/convert_zodb_to_couchdb.py -o "https://admin:super_secret_password@localhost:6984" -i jonathan.db
$ cp /home/mrhines/mica-v0.2/accounts.db .; ~/convert_zodb_to_couchdb.py -o "https://admin:super_secret_password@localhost:6984" -i accounts.db


#	    Keep|Throw, Attachment?, Regex members
'''
patterns = [
            (True, 'text/plain', [ 'stories', 1, 'original', 1 ]),
            (True, False, [ 'stories', 1, 'pages', 1 ]),
            (False, False, [ 'stories', 1, 'original', 1 ]),
            (False, False, [ 'stories', 1, 'temp_units' ]),
            (False, False, [ 'stories', 1, 'pages' ]),
            (False, False, [ 'stories', 1, 'units' ]),
            (True, False, [ 'stories', 1, 'original' ]),
            (True, False, [ 'stories', 1, 'final', 1 ]),
            (False, False, [ 'stories', 1, 'final' ]),
            (True, False, [ 'stories', 1]),
            (False, False, [ 'accounts', 1]),
            (True, False, [ 'memorized', 1]),
            (True, False, [ 'story_index', 1]),
            (True, False, [ 'tonechanges', 1]),
            (True, False, [ 'mergegroups', 1 ]),
        ]

'''
patterns = [
            (True, False, [ 'accounts', 1]),
        ]

def make_obj(orig, attach) :
    obj = str(orig)
    if not isinstance(orig, dict) and not isinstance(orig, PersistentMapping) :
	print "WARNING: Non-dict document automatically subclassed: " + str(type(orig))
	obj = { 'value' : obj }
    obj = eval(str(obj))
    if attach :
	obj = { '_attachments' : { 'attach' : { 'content_type' : attach, "data" : str(obj) } } }

    return obj

# sometimes the above individual unique character is wierd, like a newline or an empty space, so strip() and throw out
def depth_first_deep_copy(src, dst, pattern, keep, attach, key = "") :
    delete_me = False
    if isinstance(src, dict) or isinstance(src, PersistentMapping) :
        for tmp_key in src.keys() :
            if tmp_key.strip() == "" :
                continue
            new_key = key + ":" + tmp_key

            if len(re.compile(pattern).findall(new_key)) == 1 :
                if keep :
                    print "Dict Keep: " + new_key 
                    dst[new_key] = make_obj(src[tmp_key], attach)
                else :
                    print "Dict Throw: " + new_key
                del src[tmp_key]
                transaction.commit()
            else :
                #print "No match: " + new_key
                if depth_first_deep_copy(src[tmp_key], dst, pattern, keep, attach, new_key) :
                    #print "Deleting: " + new_key
                    del src[tmp_key]
                    transaction.commit()
    elif isinstance(src, list) or isinstance(src, PersistentList) :
        for idx in range(0, len(src)) :
            new_key = key + ":" + str(idx)
            if len(re.compile(pattern).findall(new_key)) == 1 :
                printed = new_key
                if keep :
                    print "List Keep: " + printed
		    #print "Storing: " + str(src[idx])
                    dst[new_key] = make_obj(src[idx], attach)
                else :
                    print "List Throw: " + printed

                delete_me = True
            else :
                #print new_key
                tmp_delete_me = depth_first_deep_copy(src[idx], dst, pattern, keep, attach, new_key)
                if not delete_me :
                    delete_me = tmp_delete_me

    return delete_me 

reload(sys)
sys.setdefaultencoding("utf-8")

parser = OptionParser()

parser.add_option("-o", "--output", dest = "out_url", default = False, help ="destination couchdb URL string")
parser.add_option("-i", "--input", dest = "in_file", default = False, help ="original database filename")
parser.add_option("-d", "--drop", dest = "drop", action = "store_true", default = False, help = "drop and recreate database")

parser.set_defaults()
options, args = parser.parse_args()

if options.in_file == False or options.out_url == False :
    print "Need database file name and couchdb address"
    exit(1)

instorage = ZODB.FileStorage.FileStorage(options.in_file)
indb = ZODB.DB(instorage)

root = indb.open().root()

s = Server(options.out_url)

if options.drop :
	print "Attempting to drop database first..." 
	try :
	    s.delete_db('mica')
	    print "mica already exists. dropped."
	except couchdbkit.exceptions.ResourceNotFound, e :
	    print "Mica doesn't existing. proceeding."

couch = s.get_or_create_db('mica')

for (keep, attach, pattern) in patterns :
    extended = []
    for group in pattern :
        if group == 1 :
            extended.append("[^:]+")
        else :
            extended.append(group)
    final_pattern = "MICA:" + (":".join(extended)) + "$"
    print "Extended pattern: " + final_pattern
    depth_first_deep_copy(root, couch, final_pattern, keep, attach, "MICA")

indb.close()
instorage.close()
                                        

