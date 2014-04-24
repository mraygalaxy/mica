#!/usr/bin/env python
# -*- coding: utf-8 -*-
import mica
import cjklib

from cjklib.dictionary import CEDICT
from cjklib.characterlookup import CharacterLookup

d = CEDICT()
cjk = CharacterLookup('C')

src = """
小明五岁，他有一个哥哥，哥哥是学生。他爸爸妈妈都工作。小明说，他家一共五口人。

今天星期六，我们不上课。小王说，晚上有一个好电影，他和我一起去看，我很高兴。下午六点我去食堂吃饭，六点半去小王的宿舍，七点我们去看电影。

张丽英家有四口人：爸爸，妈妈，姐姐和她。她爸爸是大夫，五十七岁了，身体很好。他工作很忙，星期天常常不休息。妈妈是银行职员，今年五十岁。她姐姐是老师，今年二月结婚了。她不住在爸爸妈妈家。昨天是星期五，下午没有课。我们去她家了。她家在北京饭店旁边。我们到她家的时候，她爸爸妈妈不在家。我们和她一起谈话，听音乐，看电视。五点半张丽英的爸爸妈妈回家了。她姐姐也来了。我们在她家吃饭，晚上八点半我们就回学校了。

教学楼前边的自行车很多。田芳下课后要找自己的自行车。田芳的自行车是新的。张东问她，你的自行车是什么颜色的？田芳说是蓝的。张东说，那辆蓝车是不是你的？田芳说，我的自行车是新的，不是旧的，那辆车不是我的。忽然，田芳看见了自己的自行车，她说，啊，我的自行车在那儿呢，我找到了
"""

def tryce(uni, fail_if_more_than_one = False) :
    count = 0
    results = d.getFor(uni)
    trans = u''
    last = None

    for e in results : 
        if count > 0 and e[2].lower() == last[2].lower() : 
#           print "Duplicate CEDICT pinyin!"
           count -= 1
        count += 1
        last = e

#    print uni + " has " + str(count) + " results: " + str(fail_if_more_than_one)

    if fail_if_more_than_one and count > 1 :
        return trans 

    count = 0
    results = d.getFor(uni)
    for e in results : 
        if count > 0 and e[2].lower() == last[2].lower() : 
#           print "Duplicate CEDICT pinyin!"
           count -= 1
        trans = e[2] + ": " + e[3].split("/")[1]
        count += 1
        last = e
        break

    return trans

try :
    ignore_bad = [u'的',u'了']
    parsed = mica.trans(src).strip()
    print "Parsed result: " + parsed
    for group in parsed.split(" ") :
        group = group.strip()
        uni = unicode(group, "UTF-8")
        trans = tryce(uni, True if len(group) == 1 else True)
        if trans == u'' :
#            print "First lookup failed for: " + group + ", trying individual. len: " + str(len(group))
            for char in uni :
                cr = tryce(char, True)
                if cr != u'' :
                    trans += cr
                else :
               #     print "Group failed and single char group failed from CE, trying readings."
                    cr = cjk.getReadingForCharacter(char,'Pinyin')
                    if cr : 
                        if char not in ignore_bad and len(cr) > 1 :
                            print "Warning: " + char + " has too many readings: "
                            for x in cr :
                                print " " + x
                        trans += cr[0]

        if trans == u'' :
            trans = "none."
        print ("Translation: " + uni + ":" + trans).replace("\n","")
except mica.error, e :
    print str(e)
