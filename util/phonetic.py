#!/usr/bin/env python

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

tree = ET.ElementTree(file='general-american-dictionary.xml')

root = tree.getroot()

for child in root :
    print child.tag
    if "role" in child.attrib :
        print " " + child.attrib["role"]

    grapheme = child[0]
    print " " + grapheme.tag + " " + grapheme.text
    phoneme = child[1]
    print " " + phoneme.tag + " " + phoneme.text
    break
