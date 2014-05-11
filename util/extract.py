#!/usr/bin/env python
#-*- coding: utf-8 -*-
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.converter import TextConverter
from pdfminer.layout import LAParams
from pdfminer.pdfpage import PDFPage
from cStringIO import StringIO
from fpdf import FPDF
from optparse import OptionParser

import json
import urllib2
import os
import cgi
import sys
# set system encoding to unicode
import sys
import re

reload(sys)
sys.setdefaultencoding("utf-8")

parser = OptionParser()

parser.add_option("-o", "--output", dest = "out_file", default = False, help ="output file name")
parser.add_option("-i", "--input", dest = "in_file", default = False, help ="input file name")

parser.set_defaults()
options, args = parser.parse_args()

if options.in_file == False or options.out_file == False :
    print "Need input and output file"
    exit(1)

rsrcmgr = PDFResourceManager()
fp = file(options.in_file, 'rb')
pagenos = set()

font_size = 9

pdf = FPDF('P','mm','A4')
pdf.add_font('DejaVu','','fireflysung.ttf', uni=True)
pdf.set_font('DejaVu','', font_size)

page_count = 1
for page in PDFPage.get_pages(fp, pagenos, 0, password='', caching=True, check_extractable=True):
    retstr = StringIO()
    device = TextConverter(rsrcmgr, retstr, codec='utf-8', laparams=LAParams())
    interpreter = PDFPageInterpreter(rsrcmgr, device)
    interpreter.process_page(page)

    data = retstr.getvalue()

    retstr.close()
    device.close()

    pdf.add_page()
    pdf.write(14, "PAGE: " + str(page_count))
    pdf.ln(14)

    print("Page input: " + data)
    for line in data.split("\n") : 
        if len(re.compile(r'[a-z]+[a-z]+', flags=re.IGNORECASE).findall(line)) :
            continue
        if len(line.strip()) <= 1 :
            continue
        if len(line.strip().decode("utf-8")) == 3 and line[0] == "(" and line[-1] == ")" :
            matches = re.compile(u'\(.\)', flags=re.IGNORECASE).findall(line.strip())
            print str(matches) + ": " + line
            if len(matches) == 1 :
                continue
        if len(re.compile(r'[0-9]+[0-9]+[0-9]+', flags=re.IGNORECASE).findall(line)) :
            continue
        pdf.write(font_size,line)
        pdf.ln(font_size / 2)
    page_count += 1

pdf.output(options.out_file,'F')
fp.close()
