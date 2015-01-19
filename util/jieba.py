#!/usr/bin/env python 
# coding: utf-8

import sys
import multiprocessing

sys.path = [".", "jieba"] + sys.path

print sys.path

import jieba

cpus = multiprocessing.cpu_count()
print "Testing with " + str(cpus) + " processors."
jieba.initialize(sqlite = True)
jieba.enable_parallel(cpus)
#print " ".join(jieba.cut(u"面对新世纪。"))
#print " ".join(jieba.cut(u"国务院在山东"))
for x in range(0, 1000) :
    print " ".join(jieba.cut(u"面对新世纪，世界各国人民的共同愿望是：继续发展人类以往创造的一切文明成果，克服20世纪困扰着人类的战争和贫困问题，推进和平与发展的崇高事业，创造一个美好的世界。"))
    print " ".join(jieba.cut(u"国务院在山东省济宁市召开全国春季农业生产暨森林草原防火工作会议。国务院总理李克强作出重要批示：“春为岁首，农为行先。当前抓好春季农业生产对于巩固经济稳中向好势头"))
