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

cwd = re.compile(".*\/").search(os.path.realpath(__file__)).group(0)

''' 
    These patterns must be ordered by depth.
    Put the deepest patterns first and the
    shortest patterns last.

    Probably, I should just sort them, but I'll do that later.
'''

'''
Example commands:
$ cd /tmp
  # first one drops the whole databases
$ cp /home/mrhines/mica-v0.2/databases/family@hinespot.com.db .; ~/convert_zodb_to_couchdb.py -i family@hinespot.com.db -o "https://admin:super_secret_password@localhost:6984" -u family@hinespot.com -d
$ cp /home/mrhines/mica-v0.2/databases/admin.db .; ~/convert_zodb_to_couchdb.py -o "https://admin:super_secret_password@localhost:6984" -i admin.db -u admin -d
$ cp /home/mrhines/mica-v0.2/databases/jonathan.db .; ~/convert_zodb_to_couchdb.py -o "https://admin:super_secret_password@localhost:6984" -i jonathan.db -u jonathan -d
$ cp /home/mrhines/mica-v0.2/accounts.db .; ~/convert_zodb_to_couchdb.py -o "https://admin:super_secret_password@localhost:6984" -i accounts.db -d
'''


'''
patterns = [
# Keep|Throw,   Attachment?,    Regex depth key 0,  1,  2,          3,  4, # 5,    Stop-Index for DB, Views?
  (True,        'text/plain',   [ 'stories',        1, 'original',  1, 'images', 1   ], 1, [cwd + "../views/stories.js", cwd + "../views/groupings.js"]),
  (False,       False,          [ 'stories',        1, 'original',  1, 'images'         ], -1, []),
  (True,        False,          [ 'stories',        1, 'original',  1                   ], 1, []),
  (True,        False,          [ 'stories',        1, 'pages',     1                   ], 1, []),
  (False,       False,          [ 'stories',        1, 'original',  1                   ], -1, []),
  (False,       False,          [ 'stories',        1, 'temp_units'                     ], -1, []),
  (False,       False,          [ 'stories',        1, 'pages'                          ], -1, []),
  (False,       False,          [ 'stories',        1, 'units'                          ], -1, []),
  # This 'original' is for single-page stories. kind of confusing.
  (True,        False,          [ 'stories',        1, 'original'                       ], 1, []),

  # 'final' is expected to be very infrequently accessed and only contains text
  (True,        False,          [ 'stories',        1, 'final'                          ], 1, []),
  (True,        False,          [ 'stories',        1                                   ], 0, [cwd + "../views/groupings.js"]),
  (False,       False,          [ 'accounts',       1                                   ], -1, []),
  (True,        False,          [ 'splits',         1                                   ], 0, [cwd + "../views/groupings.js"]),
  (True,        False,          [ 'memorized',      1                                   ], 0, [cwd + "../views/groupings.js"]),
  (True,        False,          [ 'story_index',    1                                   ], 0, [cwd + "../views/groupings.js"]),
  (True,        False,          [ 'tonechanges',    1                                   ], 0, [cwd + "../views/groupings.js"]),
  (True,        False,          [ 'mergegroups',    1                                   ], 0, [cwd + "../views/groupings.js"]),
]

patterns = [
  (True,        False,          [ 'accounts',       1                                   ], 0, [cwd + "../views/groupings.js"]),
]
'''

patterns = [
  (True,        False,          [ 'splits',         1                                   ], 0, [cwd + "../views/groupings.js"]),
]

def make_obj(orig, attach) :
    obj = str(orig)

    if attach :
        return { '_attachments' : { 'attach' : { 'content_type' : attach, "data" : str(obj) } } }

    if not isinstance(orig, dict) and not isinstance(orig, PersistentMapping) :
        print "WARNING: Non-dict document automatically subclassed: " + str(type(orig))
        obj = { 'value' : obj }

    obj = eval(str(obj))

    if isinstance(obj, str) :
        print "Uh oh. Not good: " + str(obj) + " attach: " + str(attach) + " orig type : " + str(type(orig))
        exit(1)

    return obj

dbs = {}

# sometimes the above individual unique character is wierd, like a newline or an empty space, so strip() and throw out
def depth_first_deep_copy(src, server, pattern, keep, attach, dbidx, key, designed) :
    delete_me = False
    if isinstance(src, dict) or isinstance(src, PersistentMapping) :
        for tmp_key in src.keys() :
            if tmp_key.strip() == "" :
                continue
            new_key = key + ":" + tmp_key

            if len(re.compile(pattern).findall(new_key)) == 1 :
                if keep :
                    db, final_key = get_db(server, new_key, dbidx, designs)
                    print "Dict Keep: " + new_key + ", final_key: " + final_key 
                    db[final_key] = make_obj(src[tmp_key], attach)
                else :
                    print "Dict Throw: " + new_key
                del src[tmp_key]
                transaction.commit()
            else :
                #print "No match: " + new_key
                if depth_first_deep_copy(src[tmp_key], server, pattern, keep, attach, dbidx, new_key, designs) :
                    #print "Deleting: " + new_key
                    del src[tmp_key]
                    transaction.commit()
    elif isinstance(src, list) or isinstance(src, PersistentList) :
        for idx in range(0, len(src)) :
            new_key = key + ":" + str(idx)
            if len(re.compile(pattern).findall(new_key)) == 1 :
                printed = new_key
                if keep :
                    #print "Storing: " + str(src[idx])
                    db, final_key = get_db(server, new_key, dbidx, designs)
                    print "List Keep: " + printed + ", final_key: " + final_key
                    db[final_key] = make_obj(src[idx], attach)
                else :
                    print "List Throw: " + printed

                delete_me = True
            else :
                #print new_key
                tmp_delete_me = depth_first_deep_copy(src[idx], server, pattern, keep, attach, dbidx, new_key, designs)
                if not delete_me :
                    delete_me = tmp_delete_me

    return delete_me 

reload(sys)
sys.setdefaultencoding("utf-8")

parser = OptionParser()

parser.add_option("-o", "--output", dest = "out_url", default = False, help ="destination couchdb URL string")
parser.add_option("-i", "--input", dest = "in_file", default = False, help ="original database filename")
parser.add_option("-d", "--drop", dest = "drop", action = "store_true", default = False, help = "drop and recreate database")
parser.add_option("-u", "--user", dest = "user", default = False, help = "user account name to prefix in front of key")

parser.set_defaults()
options, args = parser.parse_args()

if options.in_file == False or options.out_url == False :
    print "Need database file name and couchdb address"
    exit(1)

instorage = ZODB.FileStorage.FileStorage(options.in_file)
indb = ZODB.DB(instorage)

root = indb.open().root()

s = Server(options.out_url)

def get_db(server, key, dbidx, designs) :
    if options.user :
        dbidx += 2 # offset by two because of "mica$username"
    else :
        dbidx += 1
    unaccept_key = ":".join(key.split(":", dbidx + 1)[:(dbidx + 1)])
    actual_key = unaccept_key.replace(":", "$")
    filtered_key = ""

    for char in actual_key :
        if char in ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', \
            'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', \
            'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', \
            '_', '$', '(', ')', '+', '-', '/'] :
            filtered_key += char

    new_key = key.split(unaccept_key)[1][1:]

    if filtered_key in dbs :
        return dbs[filtered_key], new_key

    if options.drop :
        print "Attempting to drop database " + filtered_key + " first (orig: " + key + "), new: " + new_key + "..." 
        try :
            s.delete_db(filtered_key)
            print filtered_key + " already exists. dropped. (orig: " + key + "), new: " + new_key
        except couchdbkit.exceptions.ResourceNotFound, e :
            print filtered_key + " doesn't exist. proceeding."

    
    db = s.get_or_create_db(filtered_key)

    for f in designs :
        fh = open(f, 'r')
        design = fh.read()
        dj = json.loads(design)
        db[dj["_id"]] = dj
        fh.close()

    dbs[filtered_key] = db

    return db, new_key

start_key = "mica"

if options.user :
    start_key += ":"
    start_key += options.user

for (keep, attach, pattern, dbidx, designs) in patterns :
    extended = []
    for group in pattern :
        if group == 1 :
            extended.append("[^:]+")
        else :
            extended.append(group)
    final_pattern = start_key + ":" + (":".join(extended)) + "$"
    print "Extended pattern: " + final_pattern + ", dbidx: " + str(dbidx)
    depth_first_deep_copy(root, s, final_pattern, keep, attach, dbidx, start_key, designs)

indb.close()
instorage.close()
