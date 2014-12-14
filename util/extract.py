#!/usr/bin/env python
#-*- coding: utf-8 -*-
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.converter import PDFPageAggregator
from pdfminer.layout import LAParams, LTPage, LTTextBox, LTText, LTContainer, LTTextLine, LTImage, LTRect, LTCurve
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
import string


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

pdf_punct = ",卜「,\,,\\,,【,\],\[,>,<,】,〈,@,；,&,*,\|,/,-,_,—,,,，,.,。,?,？,:,：,\:,\：,：,\：,\、,\“,\”,~,`,\",\',…,！,!,（,\(,）,\),口,」,了,丫,㊀,。,门,X,卩,乂,一,丁,田,口,匕,《,》,化,*,厂,主,竹,-,人,八,七,，,、,闩,加,。,』,〔,飞,『,才,廿,来,兀,〜,\.,已,I,幺,去,足,上,円,于,丄,又,…,〉".decode("utf-8")

for letter in (string.ascii_lowercase + string.ascii_uppercase) :
    pdf_punct += letter.decode("utf-8")

pdf_expr = r"([" + pdf_punct + "][" + pdf_punct + "]|[\x00-\x7F][\x00-\x7F]|[\x00-\x7F][" + pdf_punct + "]|[" + pdf_punct + "][\x00-\x7F])"
rsrcmgr = PDFResourceManager()
fp = file(options.in_file, 'rb')
pagenos = set()

font_size = 9

pdf = FPDF('P','mm','A4')
pdf.add_font('DejaVu','','fireflysung.ttf', uni=True)
pdf.set_font('DejaVu','', font_size)

page_count = 1
ASCII = ''.join(chr(x) for x in range(128))


def parse_lt_objs (lt_objs, page_number):
    text_content = [] 
    images = []

    if lt_objs :
        if isinstance(lt_objs, LTTextBox) or isinstance(lt_objs, LTText):
            text_content.append(lt_objs.get_text().strip())
        elif isinstance(lt_objs, LTImage):
            images.append(lt_objs.stream.get_data())
        elif isinstance(lt_objs, LTContainer):
            for lt_obj in lt_objs:
                sub_text, sub_images = parse_lt_objs(lt_obj, page_number)
                text_content = text_content + sub_text
                images.append(sub_images)

    return (text_content, images)

device = PDFPageAggregator(rsrcmgr, laparams=LAParams())
interpreter = PDFPageInterpreter(rsrcmgr, device)

def filter_lines(data2) :
    new_page = []

    for line in data2 : 
        if line == "" :
            continue

        for match in re.compile(r'[0-9]+ +[0-9, ]+', flags=re.IGNORECASE).findall(line) :
            line = line.replace(match, match.replace(" ", ""))


        if len(line.strip().decode("utf-8")) == 3 and line[0] == "(" and line[-1] == ")" :
            matches = re.compile(u'\(.\)', flags=re.IGNORECASE).findall(line.strip())
            print str(matches) + ": " + line

            if len(matches) == 1 :
                continue

        line = re.sub(r'( *82303.*$|[0-9][0-9][0-9][0-9][0-9]+ *)', '', line)
        test_all = re.sub(r'([\x00-\x7F]| )+', '', line)

        if test_all == "" :
            continue

        no_numbers = re.sub(r"([0-9]| )+", "", line).decode("utf-8")
        while len(re.compile(pdf_expr).findall(no_numbers)) :
            no_numbers = re.sub(pdf_expr, '', no_numbers)
            continue

        if len(no_numbers) <= 1 :
            continue

        new_page.append(line)

    return new_page

for page in PDFPage.get_pages(fp, pagenos, 0, password='', caching=True, check_extractable=True):
    interpreter.process_page(page)
    layout = device.get_result()

    data2 = []
    images = []
    for obj in layout :
        sub_data, sub_images = parse_lt_objs (obj, page_count)
        data2 += sub_data
        images += sub_images


    print "Page " + str(page_count) + ", images: " + str(len(images))
    print " got return: \n" + "\n".join(data2)

    pdf.add_page()
    pdf.write(14, "PAGE: " + str(page_count))
    pdf.ln(2)

    new_page = data2#filter_lines(data2)

    #print "Page " + str(page_count)
    #print "Result: " + "\n".join(new_page)
    for line in new_page :
        pdf.write(font_size,line)
        pdf.ln(font_size / 2)
    page_count += 1
    if page_count == 3 :
        break

device.close()

pdf.output(options.out_file,'F')
fp.close()
