#!/usr/bin/env python
# coding: utf-8

import codecs

fh = codecs.open("cedict_1_0_ts_utf-8_mdbg.txt", "r")

while True :
    line = fh.readline()
    if not line :
        break

    if len(line) > 0 and line[0] != "#" :
        indexes, definition = line.strip().split("/", 1)
        #print "indexes " + indexes + " definition " + definition
        characters, pinyin = indexes.strip().split("[", 1)
        #print "chars " + characters + " pinyin " + pinyin 
        traditional, simplified = characters.strip().split(" ")
        print "simpl: " + simplified + " trad " + traditional + " pinyin " + pinyin + ": " + definition 

fh.close()
