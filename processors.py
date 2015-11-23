#!/usr/bin/env python
# coding: utf-8

from common import *
from stardict import load_dictionary
from sqlalchemy import MetaData, create_engine, Table, Integer, String, Column, Float, or_
from sqlalchemy.interfaces import PoolListener
from string import ascii_lowercase, ascii_uppercase
from copy import deepcopy
from re import compile as re_compile, IGNORECASE
from unicodedata import normalize, category
from os.path import exists as path_exists
from serializable import *
import codecs

if not mobile :
    import multiprocessing

cwd = re_compile(".*\/").search(os_path.realpath(__file__)).group(0)
import sys
sys.path = [cwd, cwd + "mica/"] + sys.path

import jieba

ictc_available = False

story_format = 2

pinyinToneMarks = {
    u'a': u'āáǎà', u'e': u'ēéěè', u'i': u'īíǐì',
    u'o': u'ōóǒò', u'u': u'ūúǔù', u'ü': u'ǖǘǚǜ',
    u'A': u'ĀÁǍÀ', u'E': u'ĒÉĚÈ', u'I': u'ĪÍǏÌ',
    u'O': u'ŌÓǑÒ', u'U': u'ŪÚǓÙ', u'Ü': u'ǕǗǙǛ'
}

class NotReady(Exception) :
    def __init__(self, msg, e = False):
        Exception.__init__(self)
        self.msg = msg
        self.e = e

    def __str__(self) :
        return self.msg

if not mobile :
    try :
        import mica_ictclas
        ictc_available = False
    except ImportError, e :
        mdebug("Could not import ICTCLAS library. Will fallback to jieba library.")
    except SystemError, e :
        mdebug("Could not import ICTCLAS library. Will fallback to jieba library.")

    try:
        import xml.etree.cElementTree as ET
    except ImportError:
        import xml.etree.ElementTree as ET

#class PinyinListener(PoolListener):
#    def connect(self, dbapi_con, con_record):
#        dbapi_con.execute('PRAGMA mmap_size=20971520')

class MyListener(PoolListener):
    def connect(self, dbapi_con, con_record):
        dbapi_con.execute('PRAGMA journal_mode=OFF')
        dbapi_con.execute('PRAGMA synchronous=OFF')
        #dbapi_con.execute('PRAGMA cache_size=100000')

class Processor(object) :
    def __init__(self, mica, params) :
        self.serial = Serializable(True)
        self.serial.start()
        self.already_romanized = True
        self.params = params
        self.mica = mica
        self.accented_source = False
        self.initialized = False
        self.handle = False

        self.punctuation = {}
        self.punctuation_without_newlines = {}
        self.punctuation[u'\n'] = {}
        self.punctuation['\n'] = {}
        self.punctuation_without_letters = {}

        for c in [u';', u'\"', u'+', u'#', u'^', u'}', u'{', u'=', u'%', u'「', u'【', u']', u'[', u'>', u'<', u'】',u'〈', u'@', u'；', u'&', u'*', u'|', u'/', u'-', u'_', u'—', u',', u'，',u'.',u'。', u'?', u'？', u':', u'：', u'：', u'、', u'“', u'”', u'~', u'`', u'"', u'\'', u'…', u'！', u'!', u'（', u'(', u'）', u')', u'$' ] :
           self.punctuation_without_letters[c] = {} 

        for c in ['\"', '+', '#', '}', '{', '=', '%', ']', '[', '<', '>','@',';', '&', "*', "'|', '^','\\','/', '-', '_', '—', ',', '，','.','。', '?', '？', ':', '：', '、', '“', '”', '~', '`', '"', '\'', '…', '！', '!', '（', '(', '）', ')', '$' ] :
           self.punctuation_without_letters[c] = {} 

        self.punctuation_without_newlines.update(self.punctuation_without_letters)
        self.punctuation.update(self.punctuation_without_letters)

        self.punctuation_numbers = {}

        for num in range(0, 10) :
            self.punctuation_numbers[unicode(str(num))] = {}
            self.punctuation_numbers[str(num)] = {}

        self.punctuation_without_newlines.update(deepcopy(self.punctuation_numbers))
        self.punctuation.update(deepcopy(self.punctuation_numbers))

    def get_chars(self, romanized, limit = 8, preload = False, retest = True) :
        return False

    def get_ipa(self, source) :
        return False
    
    @serial
    def parse_page(self, req, story, groups, page, temp_units = False, progress = False, error = False) :
        if temp_units :
            story["temp_units"] = []
        else :
            if "pages" not in story :
                story['pages'] = {}
            story["pages"][page] = {}
            story["pages"][page]["units"] = []

        if not self.handle :
            self.parse_page_start()

        self.parse_page_groups(req, story, groups, progress, temp_units, page)

    def parse_page_start(self, hint_strinput = False) : 
        self.handle = True

    def parse_page_stop(self) :
        self.handle = False

    def pre_parse_page(self, page_input_unicode) :
        if not self.handle :
            self.handle = True
        return page_input_unicode.encode("utf-8")

    def parse_page_groups(self, req, story, groups, progress, temp_units, page) :
        unigroups = []
        unikeys = []

        for idx in range(0, len(groups)) :
            group = groups[idx]
            assert(isinstance(group, str))

            try :
                uni = unicode(group.strip() if (group != "\n" and group != u'\n') else group, "utf-8")
            except UnicodeDecodeError, e :
                if error :
                    self.mica.store_error(req, story['name'], "Should we toss this group? " + str(group) + ": " + str(e) + " index: " + str(idx))
                raise e

            if not self.all_punct(uni) :
                if self.already_romanized :
                    unikeys.append(uni)
                else :
                    for unichar in uni :
                        if unichar not in unikeys :
                            unikeys.append(unichar)

            unigroups.append(uni)

        tone_keys = self.mica.view_keys(req, "tonechanges", False, source_queries = unikeys) 
        mverbose("Tone keys search returned " + str(len(tone_keys)) + "/" + str(len(unikeys)) + " results.") 

        for idx in range(0, len(unigroups)) :
            self.recursive_translate(req, story, unigroups[idx], temp_units, page, tone_keys)
            if progress :
                progress(req, story, idx, len(groups), page)

    def strip_punct(self, word) :
        new_word = ""
        for char in word :
            if char not in self.punctuation_without_letters :
                new_word += char
        return new_word

    def add_unit(self, trans, uni_source, target, online = False, punctuation = False, timestamp = False, peer = False) :
        unit = {}

        unit["sromanization"] = trans
        unit["source"] = []
        unit["multiple_sromanization"] = []
        unit["multiple_target"] = []
        unit["multiple_correct"] = -1

        for char in uni_source : 
            unit["source"].append(char)
        if trans == u'' :
            unit["trans"] = False
            unit["target"] = []
        else :
            unit["trans"] = True 
            unit["target"] = target 

        unit["online"] = online
        unit["punctuation"] = punctuation

        if timestamp: 
            unit["timestamp"] = timestamp 

        if peer :
            unit["peer"] = peer

        return unit

    def score_and_rank_unit(self, unit, tone_keys) :
        source = "".join(unit["source"])
        total_changes = 0.0
        changes = False
        highest = -1
        highest_percentage = -1.0
        selector = -1
        
        # FIXME: This totally needs to be a view. Fix it soon.
        changes = tone_keys[source] if source in tone_keys else False
        
        if changes :
            total_changes = float(changes["total"])

            for idx in range(0, len(unit["multiple_target"])) :
                percent = self.mica.get_polyphome_percentage(idx, total_changes, changes, unit) 
                if percent :
                    if highest_percentage == -1.0 :
                        highest_percentage = percent
                        highest = idx
                    elif percent > highest_percentage :
                        highest_percentage = percent
                        highest = idx

        if highest != -1 :
            selector = highest
            mverbose("HISTORY Multiple for source: " + source + " defaulting to idx " + str(selector) + " using HISTORY.")
        else :
            longest = -1
            longest_length = -1
            
            for idx in range(0, len(unit["multiple_target"])) :
                comb_targ = " ".join(unit["multiple_target"][idx])
                
                if not comb_targ.count("surname") and not comb_targ.count("variant of") :
                    if longest_length == -1 :
                        longest_length = len(comb_targ)
                        longest = idx
                    elif len(comb_targ) > longest_length :
                        longest_length = len(comb_targ)
                        longest = idx

            selector = longest
            mverbose("LONGEST Multiple for source: " + source + " defaulting to idx " + str(selector))

        if selector != -1 :
            if len(unit["multiple_sromanization"]) :
                unit["sromanization"] = unit["multiple_sromanization"][selector]
            unit["target"] = unit["multiple_target"][selector]
            unit["multiple_correct"] = selector 


    def recursive_translate_start(self, req, story, uni, temp_units, page, tone_keys) :
        if self.all_punct(uni) :
            units = []
            units.append(self.add_unit([uni], uni, [uni], punctuation = True))
        else :
            units = self.recursive_translate_lang(req, story, uni, temp_units, page, tone_keys)
        return units

    def recursive_translate(self, req, story, uni, temp_units, page, tone_keys) :
        found = False
        mverbose("Requested: " + uni)

        units = self.recursive_translate_start(req, story, uni, temp_units, page, tone_keys)
        if len(units) :
            found = True

        for unit in units :
            if len(unit["sromanization"]) == 1 and unit["sromanization"][0] == u'' :
               continue

            self.mica.rehash_correct_polyphome(unit)
            
            mverbose(("Translation: (" + "".join(unit["source"]) + ") " + " ".join(unit["sromanization"]) + ":" + " ".join(unit["target"])).replace("\n",""))
            
        if temp_units :
            story["temp_units"] = story["temp_units"] + units
        else :
            story["pages"][page]["units"] = story["pages"][page]["units"] + units 

        return found

    def online_cross_reference(self, req, story, uni) :
        online_units = False
        if not self.params["mobileinternet"] or self.params["mobileinternet"].connected() != "none" :
            online_units = self.online_cross_reference_lang(req, story, uni)
        return online_units

    def all_punct(self, uni, exclude = []) :
        all = True
        for char in uni :
            if char in exclude or (len(uni) and char not in self.punctuation) :
                all = False
                break
        return all

    def test_dictionaries(self, preload = False, retest = False) :
        if not self.handle :
            self.parse_page_start()

    @serial
    def get_first_translation(self, opaque, source, reading, none_if_not_found = True, debug = False) :
        return self.get_first_translation_lang(opaque, source, reading, none_if_not_found, debug)

class RomanizedSource(Processor) :
    def __init__(self, mica, params) :
        super(RomanizedSource, self).__init__(mica, params)
        self.srcdb = False
        self.structs = {}
        self.matches = {}

    def get_dictionaries(self) :
        flist = deepcopy(self.files)
        del flist["idx_file"]
        flistvalues = flist.values()
        flistvalues.append(self.dbname)
        return flistvalues

    def test_dictionaries(self, preload = False, retest = False) :
        super(RomanizedSource, self).test_dictionaries(preload = preload, retest = retest)
        if not self.srcdb :
            self.srcdb = {}
            db = create_engine('sqlite:///' + self.params["scratch"] + self.dbname, listeners= [MyListener()])
            db.echo = False
            metadata = MetaData(db)
            self.srcdb["conn"] = db.connect()
            self.srcdb["metadata"] = metadata

            self.srcdb["_index_idx"] = Table('_index_idx', metadata,
                Column('idx', Integer, primary_key=True),
                Column('word_str', String),
                Column('word_data_offset', Integer),
                Column('word_data_size', Integer),
            )
            self.srcdb["_index_idx"].create(checkfirst=True)

            self.srcdb["_word_idx"] = Table('_word_idx', metadata,
                Column('word_str', String, primary_key=True),
                Column('idx', String),
            )

            self.srcdb["_word_idx"].create(checkfirst=True)

            full_files = {}
            for name, f in self.files.iteritems() :
                full_files[name] = self.params["scratch"] + f
            self.dictionary = load_dictionary(self.srcdb, full_files)

    def online_cross_reference_lang(self, req, story, all_source) :
        mdebug("Going online...")
        name = story['name']

        minfo("translating source to target....")
        result = self.mica.translate_and_check_array(req, name, [all_source], story["target_language"], story["source_language"])
        mdebug("target translation finished." + str(result))

        if not len(result) or "TranslatedText" not in result[0] :
            return []
        
        mstarget = result[0]["TranslatedText"]

        mdebug("target is: " + str(mstarget))
        mstarget = mstarget.split(" ")

        mdebug("Translation finished.")

        unit = self.add_unit([], [all_source], mstarget)
        unit["online"] = True
        unit["punctuation"] = False 
        unit["match_romanization"] = []
        return [unit]

    def recursive_translate_lang(self, req, story, uni, temp_units, page, tone_keys) :
        units = []

        if uni.count(u"-") :
            parts = uni.split(u"-")
            first = True 
            for part in parts :
                if first :
                    first = False
                else :
                    units.append(self.add_unit([u"-"], u"-", [u"-"], punctuation = True))

                res = self.recursive_translate_start(req, story, part, temp_units, page, tone_keys)
                if len(res) :
                    units = units + res
            return units

        begin_punct = u"" 
        end_punct = [u""]
        actual_word = uni
        word_start = 0
        end_start = 0

        # Is it an ackronym?
        ackronym = True 

        if len(uni) % 2 == 0 :
            for x in range(0, len(uni)) :
                if x % 2 == 0 :
                    if self.all_punct(uni[x]) :
                        ackronym = False
                        break
                else :
                    if not self.all_punct(uni[x]) :
                        ackronym = False
                        break
        else :
            ackronym = False

        if not ackronym :
            if self.all_punct(uni[0]) :
                for x in range(0, len(uni)) :
                    char = uni[x]
                    if self.all_punct(char, exclude = [u"'"]) :
                        begin_punct += char
                    else : 
                        word_start = x
                        break
                actual_word = uni[word_start:]

            if self.all_punct(uni[-1]) :
                actual_word = u""
                for x in range(word_start, len(uni)) :
                    char = uni[x]
                    if self.all_punct(char, exclude = [u"'"]) :
                        break
                    else :
                        actual_word += char

                end_start = len(begin_punct) + len(actual_word)

                for x in range(end_start, len(uni)) :
                    end_punct[0] += uni[x]

        mdebug("Parse result original: " + uni + " begin: *" + begin_punct + "* word " + actual_word + " end: *" + end_punct[0] + "*")

        if begin_punct != u"" :
             units.append(self.add_unit([begin_punct], begin_punct, [begin_punct], punctuation = True))

        uni = actual_word

        try_source = uni 
        # Names sometimes need to avoid being lowercased
        targ = self.get_first_translation_lang(self.handle, uni, False, none_if_not_found = False)

        # Then try lowercasing...
        if not targ :
            try_source = uni.lower()
            targ = self.get_first_translation_lang(self.handle, try_source, False, none_if_not_found = False)

        for combo, replacement in self.matches.iteritems() :
            x = len(combo)
            if not targ and len(uni) > x and uni[-x:] == combo :
                search = uni[:-x]
                if replacement :
                    search += replacement
                try_source = search
                targ = self.get_first_translation_lang(self.handle, try_source, False, none_if_not_found = False)

                # Try lowercase
                if not targ :
                    try_source = search.lower()
                    targ = self.get_first_translation_lang(self.handle, try_source, False, none_if_not_found = False)

                # Try repeating without accented characters
                if not targ and self.accented_source :
                    unsource = ''.join((c for c in normalize('NFD', search) if category(c) != 'Mn'))

                    try_source = unsource 
                    targ = self.get_first_translation_lang(self.handle, try_source, False, none_if_not_found = False)

                    # And again, unaccented lowercase
                    if not targ :
                        try_source = unsource.lower()
                        targ = self.get_first_translation_lang(self.handle, try_source, False, none_if_not_found = False)

                if targ :
                    break

        # Things to do:

        '''
        use a while loop around get_first_translation and retry with different variations:
            - capitalize the first letter
            - lowercase everything
            - remove the word endings or conjugations
        '''

        if targ :
            unit = self.add_unit(uni.split(" "), uni, [targ[0]])

            if len(targ) > 1 :
                for target in targ :
                    unit["multiple_target"].append([target])
                    
                if unit["multiple_correct"] == -1 :
                    self.score_and_rank_unit(unit, tone_keys)

            ipa = self.get_ipa(try_source)
            if ipa :
                unit["ipa_word"] = ipa[0]
                unit["ipa_role"] = ipa[1]
            else :
                unit["ipa_word"] = False
                unit["ipa_role"] = False
            units.append(unit)
        else :
            online_units = self.online_cross_reference(req, story, uni)

            if not online_units or not len(online_units) :
                mwarn("Uh oh. No translation =(. ")
                raise Exception("Can't translate this word. API has no result: " + str(uni))

            for unit in online_units :
                ipa = self.get_ipa(uni)
                if ipa :
                    unit["ipa_word"] = ipa[0]
                    unit["ipa_role"] = ipa[1]
                else :
                    unit["ipa_word"] = False
                    unit["ipa_role"] = False
                units.append(unit)

        for ep in end_punct :
            if ep != u"" :
                 units.append(self.add_unit([ep], ep, [ep], punctuation = True))

        return units

    def get_first_translation_lang(self, opaque, source, reading, none_if_not_found = True, debug = False) :
        result = self.dictionary.get_dict_by_word(source)

        targ = [] 
        if result and len(result) > 0 :

            if len(result) > 1 :
                raise Exception("Why does result have more than 1 array entry? " + str(result))

            for trans in result :
                if 'm' in trans :
                    parts = trans['m'].split('\n')[1:]
                    if len(parts) == 0 :
                        targ.append(trans['m'])
                    elif len(parts) == 1 :
                        targ.append(parts[0])
                    else :
                        kind = False
                        for part in parts :
                            if part in self.structs :
                                kind = part
                            else :
                                if kind :
                                    targ.append(kind + ": " + part)
                                else :
                                    targ.append(part)
                else :
                    raise Exception("No 'm' index in translation: " + str(trans))

            mdebug("Parsing definition complete.")
            return targ 
        else :
            if none_if_not_found :
                return ["No target language translation found."]
            return False 

        return False 

class SpanishToEnglish(RomanizedSource) :
    def __init__(self, mica, params) :
        super(SpanishToEnglish, self).__init__(mica, params)
        self.files = dict(dict_file = "dictd_www.freedict.de_spa-eng.dict", idx_file = "dictd_www.freedict.de_spa-eng.idx", ifo_file = "dictd_www.freedict.de_spa-eng.ifo")
        self.dbname = "span2eng.db"
        self.accented_source = True

        self.matches.update({
                        u"s" : False,
                        u"r" : False,
                        u"a" : False,
                        u"te" : False,
                        u"ta" : False,
                        u"os" : False,
                        u"es" : False,
                        u"on" : False,
                        u"l" : False,
                        u"les" : False,
                        u"do" : u"r",
                        u"o" : u"ar",
                        u"ar" : False,
                        })

class EnglishSource(RomanizedSource) :
    def __init__(self, mica, params) :
        super(EnglishSource, self).__init__(mica, params)

        self.structs.update({
                        "abbr." : True,
                        "adj." : True,
                        "adv." : True,
                        "art." : True,
                        "aux." : True,
                        "conj." : True,
                        "int." : True,
                        "n." : True,
                        "num." : True,
                        "prep." : True,
                        "pron." : True,
                        "v." : True,
                        "vbl." : True,
                        "vi." : True,
                        "vt." : True,
                })

        self.matches.update({
                         u"ing" : False, 
                         u"’s" : False,
                         u"'s" : False,
                         u"s" : False,
                         u"ies" : u"y",
                         u"iest" : u"y",
                         u"ly" : False,
                         u"ied" : u"d",
                         u"er" : False,
                         u"d" : False,
                         u"ed" : False,
                         u"ers" : False,
                         u"’ve" : False,
                         u"'ve" : False,
                         u"’d" : False,
                         u"'d" : False,
                         u"’re" : False,
                         u"'re" : False,
                         u"’ll" : False,
                         u"'ll" : False,
                         #u"’" : False,
                         #u"'" : False,
                })

    # Setup all english sources with phonetic IPA
    @serial
    def test_dictionaries(self, preload = False, retest = False) :
        super(EnglishSource, self).test_dictionaries(preload = preload, retest = retest)

        mdebug("Testing EnglishSource IPA database...")

        db = create_engine('sqlite:///' + self.params["scratch"] + "engipa.db", listeners= [MyListener()])
        db.echo = False
        metadata = MetaData(db)
        conn = db.connect()

        self.srcdb["ipa"] = Table('ipa', metadata,
            Column('word_str', String, primary_key=True),
            Column('ipa_repr', String),
            Column('role', String),
        )

        self.srcdb["ipa"].create(checkfirst=True)

        s = self.srcdb["ipa"].select().limit(1)
        rs = s.execute()
        result = rs.fetchone()

        if result is None :
            orig_ipa = self.params["scratch"] + "general-american-dictionary.xml"
            mdebug("Need to re-generate EnglishSource IPA database from " + orig_ipa)
            tree = ET.ElementTree(file=orig_ipa)
            root = tree.getroot()

            trans = conn.begin()

            exists = {}
            for child in root :
                print child.tag
                if "role" in child.attrib :
                    role = child.attrib["role"]
                else :
                    role = ""

                grapheme = child[0].text.lower().decode("utf-8")
                phoneme = child[1].text.decode("utf-8")

                if grapheme not in exists :
                    exists[grapheme] = True
                    i = self.srcdb["ipa"].insert().values(word_str = grapheme, ipa_repr = phoneme, role = role)
                    conn.execute(i)

            trans.commit()

    @serial
    def get_ipa(self, source) :
        if "ipa" in self.srcdb :
            s = self.srcdb["ipa"].select().where(self.srcdb["ipa"].c.word_str == source)
            rs = s.execute()
            result = rs.fetchone()
            # 0 is the IPA
            # 1 is the 'role', like noun, adjective, etc...
            if result is not None :
                return (result[1], result[2])

        return False

    def get_dictionaries(self) :
        return super(EnglishSource, self).get_dictionaries() + ["engipa.db"]


class EnglishToChineseSimplified(EnglishSource) :
    def __init__(self, mica, params) :
        super(EnglishToChineseSimplified, self).__init__(mica, params)
        #self.files = dict(dict_file = "stardict-quick_eng-zh_CN-2.4.2/quick_eng-zh_CN.dict.dz", idx_file = "stardict-quick_eng-zh_CN-2.4.2/quick_eng-zh_CN.idx", ifo_file = "stardict-quick_eng-zh_CN-2.4.2/quick_eng-zh_CN.ifo")
        #self.files = dict(ifo_file = "stardict-langdao-ec-gb-2.4.2/langdao-ec-gb.ifo", idx_file = "stardict-langdao-ec-gb-2.4.2/langdao-ec-gb.idx", dict_file = "stardict-langdao-ec-gb-2.4.2/langdao-ec-gb.dict.dz")
        self.files = dict(dict_file = "lazyworm-ec.dict", idx_file = "lazyworm-ec.idx", ifo_file = "lazyworm-ec.ifo")
        self.dbname = "eng.db"

class EnglishToSpanish(EnglishSource) :
    def __init__(self, mica, params) :
        super(EnglishToSpanish, self).__init__(mica, params)
        self.files = dict(dict_file = "dictd_www.freedict.de_eng-spa.dict", idx_file = "dictd_www.freedict.de_eng-spa.idx", ifo_file = "dictd_www.freedict.de_eng-spa.ifo")
        self.dbname = "eng2span.db"

class ChineseSimplifiedToEnglish(Processor) :
    def __init__(self, mica, params) :
        super(ChineseSimplifiedToEnglish, self).__init__(mica, params)
        self.already_romanized = False 

        self.punctuation_letters = {}

        for letter in (ascii_lowercase + ascii_uppercase) :
            self.punctuation_letters[letter] = {}
            self.punctuation_letters[letter.decode("utf-8")] = {}

        self.punctuation_without_newlines.update(deepcopy(self.punctuation_letters))
        self.punctuation.update(deepcopy(self.punctuation_letters))

    def get_dictionaries(self) :
        return ["cjklib.db", "cedict.db", "tones.db", "jieba.db", "pinyin.db"]

    @serial
    def test_dictionaries(self, preload = False, retest = False) :
        super(ChineseSimplifiedToEnglish, self).test_dictionaries(preload = preload, retest = retest)

        '''
        cjk, d, hold = self.handle 
        for x in self.getFor(d, u'白鹭'.decode('utf-8')) :
            mdebug(str(x))
        for x in cjk.getReadingForCharacter(u'白','Pinyin') :
            mdebug(str(x))
        '''

        self.tonedb = {}
        db = create_engine('sqlite:///' + self.params["scratch"] + 'tones.db', listeners= [MyListener()])
        db.echo = False
        metadata = MetaData(db)
        self.tonedb["conn"] = db.connect()

        word_column = Column('word', String, primary_key=True)
        tone_column = Column('tone', String)
        self.tonedb["tones"] = Table('tones', metadata, word_column, tone_column)

        self.tonedb["tones"].create(checkfirst=True)

        s = self.tonedb["tones"].select()
        rs = s.execute()
        result = rs.fetchone()

        if result is None :
            if mobile :
                raise NotReady("jieba is not initialized yet.")
            trans = self.tonedb["conn"].begin()
            mdebug("Building tone file")
            dpfh = open(self.params["scratch"] + "chinese.txt")
            for line in dpfh.readlines() :
                k, v = line.split('\t')
                i = self.tonedb["tones"].insert().values(word = k, tone = v)
                self.tonedb["conn"].execute(i)
            dpfh.close()
            trans.commit()

        if not hasattr(self, "imedb") :
            mverbose("imedb still not allocated from test_dictionaries (fixme in a shared thread)")
            self.setup_imedb(preload = preload, retest = retest)

        elif "conn" not in self.imedb :
            self.open_imedb(preload = preload)

    def open_imedb(self, preload = False) :
        if preload :
            db = create_engine('sqlite:///' + self.params["scratch"] + "pinyin.db", listeners= [PinyinListener()])
        else :
            db = create_engine('sqlite:///' + self.params["scratch"] + "pinyin.db")
        db.echo = False
        metadata = MetaData(db)
        conn = db.connect()

        self.imedb = {}

        self.imedb["conn"] = conn

        self.imedb["ime"] = Table('ime', metadata,
            Column('chars', String),
            Column('freq', Float),
            Column('traditional', Integer, index=True),
            Column('wordall', String, index = True),
            Column('wordmerged', String, index = True),
            Column('word0', String, index = True),
            Column('word1', String, index = True),
            Column('word2', String, index = True),
            Column('word3', String, index = True),
        )

    def setup_imedb(self, preload = False, retest = True) :
        self.open_imedb(preload)

        if not retest and not preload:
            return

        self.imedb["ime"].create(checkfirst=True)

        if preload :
            s = self.imedb["ime"].select()
        else :
            s = self.imedb["ime"].select().limit(1)

        rs = s.execute()
        result = rs.fetchone()

        if result is None :
            orig_ime = self.params["scratch"] + "pinyin.txt"
            mdebug("Need to re-generate pinyin IME database from " + orig_ime)
            fh = codecs.open(orig_ime, "r", "utf-8")

            trans = self.imedb["conn"].begin()

            while True :
                line = fh.readline().strip()
                if line == u'':
                    break

                chars, freq, traditional, wordall = line.split(u" ", 3)
                wordmerged = wordall.replace(u" ", u"")
                words = wordall.split(u" ")
                wordlist = [u"", u"", u"", u""]
                for idx in range(0, len(words)) :
                    wordlist[idx] = words[idx]

                i = self.imedb["ime"].insert().values(chars = chars, 
                                                      freq = float(freq),  
                                                      traditional = int(traditional),
                                                      wordall = wordall,
                                                      wordmerged = wordmerged,
                                                      word0 = wordlist[0],
                                                      word1 = wordlist[1],
                                                      word2 = wordlist[2],
                                                      word3 = wordlist[3])
                self.imedb["conn"].execute(i)

            trans.commit()
            fh.close()
        else :
            if preload :
                preload_count = 1
                mdebug("Preloading pinyin ime database into OS buffer cache.")
                while rs.fetchone() is not None :
                    preload_count += 1
                mdebug("Preloaded " + str(preload_count) + " rows.")
            else :
                mverbose("Skipping pinyin ime database preload.")

    @serial
    def get_chars(self, wordall, limit = 8, preload = False, retest = True) :
        if not hasattr(self, "imedb") :
            mdebug("imedb still not allocated from get_chars")
            self.setup_imedb(preload = preload, retest = retest)

        # First see if the original version is in there without spaces:
        assert(isinstance(wordall, unicode))
        merged = wordall.replace(u" ", u"")

        # No reason to limit to 8, here, except that we do not yet have pagination
        # in javascript
        s = self.imedb["ime"].select().where(self.imedb["ime"].c.traditional == 0). \
                                       where(self.imedb["ime"].c.wordmerged == merged). \
                                       limit(limit). \
                                       order_by(self.imedb["ime"].c.freq.desc())
        rs = s.execute()
        results = rs.fetchall()

        if len(results) > 0 :
            mverbose("Win on merged: " + merged)
            return map(list, results)

        # Try original
        s = self.imedb["ime"].select().where(self.imedb["ime"].c.traditional == 0). \
                                       where(self.imedb["ime"].c.wordall == wordall). \
                                       limit(limit). \
                                       order_by(self.imedb["ime"].c.freq.desc())

        rs = s.execute()
        results = rs.fetchall()

        if len(results) > 0 :
            mdebug("Win on all: " + wordall)
            return map(list, results)

        # OK, last try separated:
        words = wordall.split(u" ")
        wordlist = [u"", u"", u"", u""]
        for idx in range(0, len(words)) :
            wordlist[idx] = words[idx]

        s = self.imedb["ime"].select().where(self.imedb["ime"].c.traditional == 0). \
                                       where(self.imedb["ime"].c.word0 == wordlist[0]). \
                                       where(self.imedb["ime"].c.word1 == wordlist[1]). \
                                       where(self.imedb["ime"].c.word2 == wordlist[2]). \
                                       where(self.imedb["ime"].c.word3 == wordlist[3]). \
                                       limit(limit). \
                                       order_by(self.imedb["ime"].c.freq.desc())

        rs = s.execute()
        results = rs.fetchall()

        if len(results) > 0 :
            mdebug("Win on : " + wordall)
            return map(list, results)

        return False 

    def get_pinyin(self, chars=u'你好', splitter=''):
        result = []
        for char in chars:
            key = "%X" % ord(char)
            try:
                s = self.tonedb["tones"].select().where(self.tonedb["tones"].c.word == key)
                rs = s.execute()
                kv = rs.fetchone()
                mdebug("get_pinyin result: " + str(kv))
                word, tone = kv[0], kv[1]
                result.append(tone.split(" ")[0].strip().lower())
            except Exception, e:
                mwarn("There was an exception getting pinyin for this character: " + str(char) + ": " + str(e))
                for line in format_exc().splitlines() :
                    merr(line)
                result.append(char)

        return splitter.join(result)

    def convertPinyinCallback(self, m):
        mverbose("convertPinyinCallback: " + str(m))
        tone=int(m.group(3))%5
        r=m.group(1).replace(u'v', u'ü').replace(u'V', u'Ü')
        # for multple vowels, use first one if it is a/e/o, otherwise use second one
        pos=0
        if len(r)>1 and not r[0] in 'aeoAEO':
            pos=1
        if tone != 0:
            r=r[0:pos]+pinyinToneMarks[r[pos]][tone-1]+r[pos+1:]
        return r+m.group(2)

    def convertTone(self, num_pinyin) :
        num_pinyin = num_pinyin.replace(u"u:", u"ü").replace("u:", u"ü")
        mverbose("convertTone: " + str(num_pinyin))
        result = re_compile(ur'([aeiouüvÜ]{1,3})(n?g?r?)([012345])', flags=IGNORECASE).sub(self.convertPinyinCallback, num_pinyin)
        return result

    def convertPinyin(self, char):
        return self.convertTone(self.get_pinyin(char))

    # Longest-common-subsequence algorithm.
    def lcs(self, a, b):
        lengths = [[0 for j in range(len(b)+1)] for i in range(len(a)+1)]
        # row 0 and column 0 are initialized to 0 already
        for i, x in enumerate(a):
            for j, y in enumerate(b):
                if x == y:
                    lengths[i+1][j+1] = lengths[i][j] + 1
                else:
                    lengths[i+1][j+1] = \
                        max(lengths[i+1][j], lengths[i][j+1])
        # read the substring out from the matrix
        result = [] 
        x, y = len(a), len(b)
        while x != 0 and y != 0:
            if lengths[x][y] == lengths[x-1][y]:
                x -= 1
            elif lengths[x][y] == lengths[x][y-1]:
                y -= 1
            else:
                assert a[x-1] == b[y-1]
                result = [[a[x-1],x-1,y-1]] + result
                x -= 1
                y -= 1
        return result

    def jieba_open(self) :
        jfile = self.params["scratch"] + "jieba.db"

        if not mobile :
            cpus = multiprocessing.cpu_count()
            mverbose("Enabling " + str(cpus) + " jieba CPUs from jieba @ " + jfile)

        if path_exists(jfile) : 
            mverbose("Initializing jieba library from: " + jfile)
            jieba.initialize(sqlite = jfile, check_age = False if mobile else True)

        #if not mobile :
            #jieba.enable_parallel(cpus)

    def jieba_close(self) :
        if jieba.initialized and isinstance(jieba.use_sqlite, dict) and "conn" in jieba.use_sqlite :
            mverbose("Closing jieba library.")
            jieba.use_sqlite["conn"].close()
            jieba.use_sqlite = False
        jieba.initialized = False

    def get_cjk_handle(self, big_enough = True) :
        cjk = None
        d = None
        try :
            from cjklib.dictionary import CEDICT
            from cjklib.characterlookup import CharacterLookup
            from cjklib.dbconnector import getDBConnector
            cjkurl = 'sqlite:///' + self.params["scratch"] + "cjklib.db"
            cedicturl = 'sqlite:///' + self.params["scratch"] + "cedict.db"
            mverbose("Opening CJK from: " + cedicturl + " and " + cjkurl)
            cjk = CharacterLookup('C', dbConnectInst = getDBConnector({'sqlalchemy.url': cjkurl}))
            mverbose("MICA cjklib success!")
            # CEDICT must use a connector, just a url which includes both dictionaries.
            # CEDICT internally references pinyin syllables from the main dictionary or crash.
            d = CEDICT(dbConnectInst = getDBConnector({'sqlalchemy.url': cedicturl, 'attach': [cedicturl, cjkurl]}))
            mverbose("MICA cedict success!")

            if big_enough and not ictc_available and not jieba.initialized :
                self.jieba_open()
                self.jieba_close()

        except Exception, e :
            merr("MICA offline open failed: " + str(e))

        return (cjk, d, False)


    def all_two_chars_or_less(self, hint_strinput) :
        # Check if parsing is necessary
        parts = hint_strinput.split(" ")
        all_two_chars_or_less = True

        for part in parts :
            if len(part) > 2 :
                all_two_chars_or_less = False
                break

        return all_two_chars_or_less

    def parse_page_start(self, hint_strinput = False) : 
        if not self.handle :
            big_enough = not hint_strinput or not self.all_two_chars_or_less(hint_strinput)
            if big_enough and not ictc_available :
                mverbose("Opening jieba......")
                self.jieba_open()

            self.handle = self.get_cjk_handle(big_enough = big_enough)

    def parse_page_stop(self) :
        (cjk, d, hold) = self.handle 
        cjk.db.connection.close()
        d.db.connection.close()
        if not ictc_available :
            self.jieba_close()
        if hasattr(self, "imedb") :
            self.imedb["conn"].close()
            del self.imedb["conn"]

    @serial
    def pre_parse_page(self, page_input_unicode) :

        if not self.handle :
            self.parse_page_start()

        strinput = page_input_unicode.encode("utf-8")

        if self.all_two_chars_or_less(page_input_unicode) :
            return strinput

        try :
            if ictc_available :
                result = mica_ictclas.trans(strinput)
            else :
                if not jieba.initialized :
                    raise NotReady("jieba is not initialized yet.")
                    
                result = " "
                for uresult in jieba.cut(strinput) :
                    result += " " + uresult.encode("utf-8")

            return result

        except Exception, e :
            merr("Failed to cut: " + str(e))
            self.parse_page_stop(self.handle)
            raise e

    def get_first_translation_lang(self, opaque, source, reading, none_if_not_found = True, debug = False, temp_r = False) :
        cjk, d, hold = opaque 
        targ = []
        if hold :
            temp_r = hold 
        else :
            temp_r = self.getFor(d, source)

        if debug :
            mdebug("CJK result: " + str(temp_r))
        for tr in temp_r :
            if debug :
                mdebug("CJK iter result: " + str(tr))
            if not reading or tr[2].lower() == reading.lower() :
                targ.append("" + tr[3])
                if not reading :
                    break
            
        if len(targ) == 0 :
            if none_if_not_found :
                return ["No target language translation found."]
            return False
        
        return targ 

    def online_cross_reference_lang(self, req, story, all_source) :
        if len(all_source) <= 1 : 
            return False

        mdebug("Going online...")
        (cjk, d, hold) = self.handle
        name = story['name']
        ms = []
        targ = []
        trans = []
        source = []
        groups = []
        reversep = []
        pinyin = []

        msg = "source: \n"
        idx = 0
        for char in all_source :
           source.append(char)
           cr = cjk.getReadingForCharacter(char,'Pinyin')
           if not cr or not len(cr) :
               py = self.convertPinyin(char)
           else :
               py = cr[0]
           pinyin.append(py)
           msg += " " + py + "(" + char + "," + str(idx) + ")"
           idx += 1

        mdebug(msg.replace("\n",""))

        mverbose("translating source to target....")
        result = self.mica.translate_and_check_array(req, name, [all_source], story["target_language"], story["source_language"])
        mverbose("target translation finished." + str(result))

        if not len(result) or "TranslatedText" not in result[0] :
            return []
        
        mstarget = result[0]["TranslatedText"]

        mverbose("target is: " + str(mstarget))
        mstarget = mstarget.split(" ")

        mverbose("Translating target pieces back to source")
        result = self.mica.translate_and_check_array(req, name, mstarget, story["source_language"], story["target_language"])
        mverbose("Translation finished. Writing in json.")

        for idx in range(0, len(result)) :
            ms.append((mstarget[idx], result[idx]["TranslatedText"]))

        count = 0
        for idx in range(0, len(ms)) :
           pair = ms[idx]
           targ.append(pair[0])
           for char in pair[1] :
               trans.append(char)
               groups.append((idx,char))
               cr = cjk.getReadingForCharacter(char,'Pinyin')
               if not cr or not len(cr) :
                   py = self.convertPinyin(char)
               else :
                   py = cr[0]
               reversep.append(py)
               count += 1

        matches = self.lcs(source,trans)

        current_source_idx = 0
        current_trans_idx = 0
        current_targ_idx = 0
        units = []

        tmatch = ""
        match_romanization = ""
        for triple in matches :
          char, source_idx, trans_idx = triple
          pchar = self.convertPinyin(char)
          mverbose("orig idx " + str(source_idx) + " trans idx " + str(trans_idx) + " => " + char)
          tmatch += " " + str(pchar) + "(s" + str(source_idx) + ",t" + str(trans_idx) + "," + char + ")"
          match_romanization += pchar + " "

        match_romanization = match_romanization.strip()

        mverbose("matches: \n" + tmatch.replace("\n",""))
          
        for triple in matches :
          char, source_idx, trans_idx = triple
          pchar = self.convertPinyin(char)
          
          if source_idx > current_source_idx :
              # only append if there's something in the source
              new_unit = self.make_unit(source_idx, current_source_idx, trans_idx, current_trans_idx, groups, reversep, targ, source, pinyin)
              new_unit["match_romanization"] = []
              units.append(new_unit) 

          current_source_idx = source_idx
          current_trans_idx = trans_idx

          new_unit = self.make_unit(source_idx + 1, current_source_idx, trans_idx + 1, current_trans_idx, groups, reversep, targ, source, pinyin) 
          new_unit["match_romanization"] = [match_romanization]

          units.append(new_unit)

          current_source_idx += 1
          current_trans_idx += 1

        changes = True 
        passes = 0
        try :
            while changes : 
                mverbose("passing: " + str(passes))
                new_units = []
                idx = 0
                changes = False
                while idx < len(units) :
                    new_unit = deepcopy(units[idx])
                    if new_unit["trans"] :
                        new_target = []
                        for word in new_unit["target"] :
                           word = self.strip_punct(word)
                           if not len(new_target) or self.strip_punct(new_target[-1]) != word :
                               new_target.append(word)
                        new_unit["target"] = new_target
    
                    all_punctuation = True
                    for char in new_unit["source"] :
                        if char not in self.punctuation :
                            all_punctuation = False
                            break
    
                    if all_punctuation :
                        new_unit["trans"] = False
                        new_unit["target"] = ""
                    else :
                        append_units = []
                        for fidx in range(idx + 1, min(idx + 2, len(units))) :
                            unit = units[fidx]
                            if not unit["trans"] :
                               continue
                            all_equal = True
                            for worda in new_unit["target"] :
                                for wordb in unit["target"] :
                                    if self.strip_punct(worda) != self.strip_punct(wordb) :
                                        all_equal = False
                                        break
    
                            if not all_equal :
                                if self.strip_punct(unit["target"][0]) == self.strip_punct(new_unit["target"][-1]) :
                                    all_equal = True
    
                            if all_equal :
                               idx += 1
                               append_units.append(unit)
    
                        if len(append_units) :
                            changes = True
    
                        for unit in append_units :
                            for char in unit["source"] :
                                new_unit["source"].append(char)
                            for pinyin in unit["sromanization"] :
                                new_unit["sromanization"].append(pinyin)
                            for pair in unit["trans"] :
                                if new_unit["trans"] :
                                    new_unit["trans"].append(pair)
                                else :
                                    new_unit["trans"] = [pair]
                            for pinyin in unit["tromanization"] :
                                if "tromanization" in new_unit :
                                    new_unit["tromanization"].append(pinyin)
                                else :
                                    new_unit["tromanization"] = [pinyin]
                            if unit["trans"] :
                                for word in unit["target"] :
                                    word = self.strip_punct(word)
                                    if not len(new_unit["target"]) or self.strip_punct(new_unit["target"][-1]) != word :
                                        new_unit["target"].append(word)
                    new_units.append(new_unit)
                    idx += 1
                units = new_units
                passes += 1
    
            msg = ""
            for unit in new_units :
                all_punctuation = True
                for char in unit["source"] :
                    if char not in self.punctuation :
                        all_punctuation = False
                        break
                #for char in unit["source"] :
                #    msg += " " + char
                for pinyin in unit["sromanization"] :
                    if all_punctuation :
                        msg += pinyin
                    else :
                        msg += " " + pinyin 
                if unit["trans"] :
                    msg += "("
                    #for pair in unit["trans"] :
                    #    msg += " " + pair[1]
                    #for pinyin in unit["tromanization"] :
                    #    msg += " " + pinyin 
                    for word in unit["target"] :
                        msg += word  + " "
                    msg += ") "
        except Exception, e :
            merr("Online Cross Reference Error: " + str(e))
            raise e
        
        mverbose(msg)
        for unit_idx in range(0, len(units)) :
            units[unit_idx]["online"] = True
            units[unit_idx]["punctuation"] = False 

        mverbose("Units: " + str(units))
                          
        return units 

    def make_unit(self, source_idx, current_source_idx, trans_idx, current_trans_idx, groups, reversep, target, source, pinyin) :

      unit = {}
      unit["multiple_sromanization"] = []
      unit["multiple_target"] = []
      unit["multiple_correct"] = -1

      if trans_idx > current_trans_idx :
          unit["trans"] = groups[current_trans_idx:trans_idx]
          unit["tromanization"] = reversep[current_trans_idx:trans_idx]
          t = []
          for group in unit["trans"] :
              t.append(target[group[0]])
          unit["target"] = t 
      else :
          unit["trans"] = False
          unit["target"] = [""]

      if source_idx > current_source_idx :
          unit["source"] = source[current_source_idx:source_idx]
          unit["sromanization"] = pinyin[current_source_idx:source_idx]

      mverbose("Returning unit: " + str(unit))

      return unit

    def getFor(self, d, uni) :
        # Verify that the results coming out of CJK
        # are the same as the result we got by bypassing CJK
        do_test = False

        #mdebug("getFor: " + uni)
        if do_test and not mobile :
            master = d.getFor(uni)
            new_master = []
            for elem in master : 
                new_master.append(elem)

        #mdebug("Attached databases: " + str(d.db.tables))
        s = d.db.tables["CEDICT"].select().where(
                or_(d.db.tables["CEDICT"].c.HeadwordSimplified == uni,
                   d.db.tables["CEDICT"].c.HeadwordTraditional == uni))
        rs = s.execute()
        results = rs.fetchall()

        #mdebug("direct search getFor: " + str(results))

        new_results = []
        for idx in range(0, len(results)) :
            result = []
            for num in range(0, 4) :
                result.append(results[idx][num])
            result[2] = self.convertTone(result[2])
            new_results.append(result)

        if do_test and not mobile and len(new_master) :
            #mdebug(" new len " + str(len(new_master)) + " direct len " + str(len(new_results)))
            assert(len(new_master) == len(new_results))
            for idx in range(0, len(new_results)) :
                #mdebug(" new " + str(new_master[idx][2]) + " direct " + str(new_results[idx][2]))
                assert(new_master[idx][2] == new_results[idx][2])
                 
        return new_results

    def recursive_translate_lang(self, req, story, uni, temp_units, page, tone_keys) :
        units = []

        cjk, d, hold = self.handle
        trans = []
        targ = []
        results = self.getFor(d, uni)
        if results is not None :
            for e in results :
                trans.append(e[2])
                targ.append(e[3])

        if len(trans) == 1 :
            mverbose("Adding single-trans source " + uni + " to unit.")
            unit = self.add_unit(trans[0].split(" "), uni, [targ[0]])
            units.append(unit)
        elif len(trans) == 0 :
            mverbose("No trans for " + uni + " unit, recursing...")
            sub_uni = uni
            uni_size = len(uni)
            if len(sub_uni) > 1 :
                # Recursively figure out if any ordered, subset of the characters
                # in this group of characters can be found
                check_whole = False 

                count_sub_chars = 0
                while True :
                    size = len(sub_uni)
                    if not size :
                        break

                    mverbose("Iterate: " + sub_uni)

                    # The whole group is checked already at the beginning of this
                    # function, including for single characters. Only check the
                    # whole thing if were are recursing on a subset.
                    if check_whole :
                        end = size 
                    else :
                        end = size - 1 

                    try_uni = sub_uni[:end]
                    check_whole = True
                    mverbose("Trying: " +  try_uni)

                    sub_units = self.recursive_translate_start(req, story, try_uni, temp_units, page, tone_keys)

                    mverbose("Sub units: " + str(len(sub_units)))

                    for su in sub_units :
                        count_sub_chars += len(su["source"])

                        mverbose("Sub unit characters: " + str(count_sub_chars) + " size " + str(size) + " source " + str(su["source"]))

                    # Strip off what was matched, according to the leng
                    units += sub_units
                    sub_uni = sub_uni[end:]
                    size = len(sub_uni)
                    mverbose("Found. Next: " + sub_uni)

                assert(count_sub_chars == len(uni))

        elif len(trans) > 1 :
            mverbose("Many trans for " + uni + " unit, choosing...")
                        
            for x in range(0, len(trans)) :
                trans[x] = trans[x].lower() 
            
            pre_readings = []
            
            if len(uni) == 1 :
                readg = cjk.getReadingForCharacter(uni, 'Pinyin')
                for read in readg :
                    read = read.lower()
                    if read not in pre_readings :
                        pre_readings.append(read)

            readings = list(set(trans + pre_readings))
            
            assert(len(readings) > 0)

            if uni not in self.punctuation and uni :
                online_units = self.online_cross_reference(req, story, uni)
                online_len = 0
                
                # If the reverse engineered pinyin cross-referencing yields a different number of original characters
                # than the input from the source, then it's not usable and try the next one
                
                if online_units and len(online_units) :
                    for ou in online_units :
                        online_len += len(ou["source"])
                    if online_len != len(uni) :
                        mwarn("Falling back on unusable cross-reference for input: " + uni + " len: " + str(online_len))
                        online_len = -1
                        
                if not online_units or not len(online_units) or online_len == -1 :
                    temp_r = self.getFor(d, uni)
                    tmp_opaque = (cjk, d, temp_r)
                    targ = self.get_first_translation_lang(tmp_opaque, uni, readings[0])
                    unit = self.add_unit([readings[0]], uni, [targ[0]])
                    for x in readings :
                        targ = self.get_first_translation_lang(tmp_opaque, uni, x, False)
                        if not targ :
                            continue
                        for e in targ :
                            unit["multiple_sromanization"].append([x])
                            unit["multiple_target"].append([e])
                    
                    if unit["multiple_correct"] == -1 :
                        self.score_and_rank_unit(unit, tone_keys)

                    units.append(unit)
                else :
                    for unit in online_units :
                       if len(unit["match_romanization"]) :
                           unit["sromanization"] = unit["match_romanization"]
                       if len(unit["sromanization"]) == 1 and unit["sromanization"][0] == u'' :
                           continue
                       units.append(unit)
            else :
                targ = self.get_first_translation_lang(self.handle, uni, readings[0])
                units.append(self.add_unit(readings[0].split(" "), uni, [targ[0]]))

        return units
