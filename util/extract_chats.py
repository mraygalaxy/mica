#!/usr/bin/env python
# coding: utf-8

from re import compile as re_compile, IGNORECASE as re_IGNORECASE, sub as re_sub
import urllib
from copy import deepcopy
from time import time
from urllib2 import quote, unquote
from random import choice
from time import sleep
from json import dumps
from sys import argv

cwd = re_compile(".*\/").search(os_path.realpath(__file__)).group(0)
import sys
sys.path = [cwd, cwd + "../"] + sys.path

from couch_adapter import *
from params import parameters
from common import myquote

lookup_prefix = dict(human = 0, alien = "chat_ime", ime = 1, mode = "read", target_language = "en", source_language = "zh-CHS", lang = "en")
final_prefix = dict(human = 0, alien = "chat_ime", ime = 1, mode = "read", target_language = "en", source_language = "zh-CHS", lang = "en", tzoffset = 18000, peer = "family@hinespot.com")

url = credentials(parameters) 
s = MicaServerCouchDB(url, parameters["admin_user"], parameters["admin_pass"], refresh = True)
db = s["mica"]

nb_pages = 19
msg = 0
start_trans_id=10000000
messages = []

ts = int(time())

times = {"days" : 60*60*24}
times["weeks"] = times["days"] * 7
times["months"] = times["weeks"] * 4
times["years"] = times["days"] * 365
times["decades"] = times["years"] * 10


def urlify(d) :
    params = []
    for k, v in d.iteritems() :
        params.append(str(k) + "=" + str(v))
    return "&".join(params)

pinyinToneMarks = {
    u'a': u'āáǎà', u'e': u'ēéěè', u'i': u'īíǐì',
    u'o': u'ōóǒò', u'u': u'ūúǔù', u'ü': u'ǖǘǚǜ',
    u'A': u'ĀÁǍÀ', u'E': u'ĒÉĚÈ', u'I': u'ĪÍǏÌ',
    u'O': u'ŌÓǑÒ', u'U': u'ŪÚǓÙ', u'Ü': u'ǕǗǙǛ'
}

def flattenChar(char) :
    newchar = char
    for key, val in pinyinToneMarks.iteritems() :
        if char in val :
            newchar = key
            break
    return newchar


for numpage in range(0, nb_pages) :
    doc = db["MICA:family@hinespot.com:stories:chat;weeks;2376;还在分析:pages:" + str(numpage)]
    units = doc["units"]

    curr_src = ""
    curr_sromanization = ""
    curr_timestamp = False
    curr_offset = times[choice(times.keys())]
    for nb_unit in range(0, len(units)) :
        unit = units[nb_unit]
        if "timestamp" in unit :
            if curr_src != "" :
                curr_src = re_sub(r'  +', ' ', curr_src)
                fromwho, text = curr_src.split(" ", 1)
                sfromwho, stext = curr_sromanization.split(" ", 1)
                if text.strip() != "" :
                    to = "family@hinespot.com" if fromwho == "还在分析" else "还在分析"
                    d = deepcopy(lookup_prefix)
                    d.update(dict(msgfrom = fromwho, source = text, msgto = to))
                    for word in stext.strip().split(" ") :
                        curr_word = ""
                        if word == "" :
                            continue
                        for char in word.decode("utf-8") :
                            char = flattenChar(char)
                            curr_word += char.encode("utf-8")
                            d["source"] = curr_word
                            print urlify(d)

                    d = deepcopy(final_prefix)
                    
                    d.update(dict(msgfrom = fromwho, ime1 = text, ts = int(ts * 1000 - curr_offset * 1000 + msg * 5000), start_trans_id=1000000 + msg, msgto = to))
                    print urlify(d)
                    msg += 1
            curr_src = ""
            curr_sromanization = ""
            curr_timestamp = unit["timestamp"]
 
        tmp_src = "".join(unit["source"]).encode("utf-8").strip()
        tmp_sromanization = "".join(unit["sromanization"]).encode("utf-8").strip()
        if tmp_src == "" :
            curr_src += " "
            continue
        if tmp_sromanization == "" :
            curr_sromanization += " "
            continue
        curr_src += tmp_src 
        curr_sromanization += tmp_sromanization + " "
    print "storylist"
