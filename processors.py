#!/usr/bin/env python
# coding: utf-8

from common import *
from stardict import load_dictionary
from sqlalchemy import MetaData, create_engine, Table, Integer, String, Column
from sqlalchemy.interfaces import PoolListener
from string import ascii_lowercase, ascii_uppercase
from copy import deepcopy
from re import compile as re_compile, IGNORECASE
from unicodedata import normalize, category

story_format = 2

pinyinToneMarks = {
    u'a': u'āáǎà', u'e': u'ēéěè', u'i': u'īíǐì',
    u'o': u'ōóǒò', u'u': u'ūúǔù', u'ü': u'ǖǘǚǜ',
    u'A': u'ĀÁǍÀ', u'E': u'ĒÉĚÈ', u'I': u'ĪÍǏÌ',
    u'O': u'ŌÓǑÒ', u'U': u'ŪÚǓÙ', u'Ü': u'ǕǗǙǛ'
}

if not mobile :
    try :
        import mica_ictclas
    except ImportError, e :
        mdebug("Could not import ICTCLAS library. Full translation will not work.")
    except SystemError, e :
        mdebug("Could not import ICTCLAS library. Full translation will not work.")

    try:
        import xml.etree.cElementTree as ET
    except ImportError:
        import xml.etree.ElementTree as ET

class MyListener(PoolListener):
    def connect(self, dbapi_con, con_record):
        dbapi_con.execute('pragma journal_mode=OFF')
        dbapi_con.execute('PRAGMA synchronous=OFF')
        #dbapi_con.execute('PRAGMA cache_size=100000')

class Processor(object) :
    def __init__(self, mica, params) :
        self.already_romanized = True
        self.params = params
        self.mica = mica
        self.accented_source = False

        self.punctuation = {}
        self.punctuation_without_newlines = {}
        self.punctuation[u'\n'] = {}
        self.punctuation['\n'] = {}
        self.punctuation_without_letters = {}

        for c in [u'%' u'「', u'【', u']', u'[', u'>', u'<', u'】',u'〈', u'@', u'；', u'&', u'*', u'|', u'/', u'-', u'_', u'—', u',', u'，',u'.',u'。', u'?', u'？', u':', u'：', u'：', u'、', u'“', u'”', u'~', u'`', u'"', u'\'', u'…', u'！', u'!', u'（', u'(', u'）', u')', u'$' ] :
           self.punctuation_without_letters[c] = {} 

        for c in ['%', ']', '[', '<', '>','@',';', '&', "*', "'|', '^','\\','/', '-', '_', '—', ',', '，','.','。', '?', '？', ':', '：', '、', '“', '”', '~', '`', '"', '\'', '…', '！', '!', '（', '(', '）', ')', '$' ] :
           self.punctuation_without_letters[c] = {} 

        self.punctuation_without_newlines.update(self.punctuation_without_letters)
        self.punctuation.update(self.punctuation_without_letters)

        self.punctuation_numbers = {}

        for num in range(0, 10) :
            self.punctuation_numbers[unicode(str(num))] = {}
            self.punctuation_numbers[str(num)] = {}

        self.punctuation_without_newlines.update(deepcopy(self.punctuation_numbers))
        self.punctuation.update(deepcopy(self.punctuation_numbers))

    def parse_page(self, opaque, req, story, groups, page, temp_units = False, progress = False, error = False) :
        if temp_units :
            story["temp_units"] = []
        else :
            if "pages" not in story :
                story['pages'] = {}
            story["pages"][page] = {}
            story["pages"][page]["units"] = []

        if not opaque :
            handle = self.parse_page_start()
        else :
            handle = opaque

        self.parse_page_groups(req, story, groups, handle, progress, temp_units, page)

        if not opaque :
            self.parse_page_stop(handle)

    def parse_page_start(self) : 
        return True

    def parse_page_stop(self, opaque) :
        return True

    def pre_parse_page(self, opaque, page_input_unicode) :
        return page_input_unicode.encode("utf-8")

    def parse_page_groups(self, req, story, groups, opaque, progress, temp_units, page) :
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
                if not handle :
                    self.parse_page_stop(opaque)
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
            self.recursive_translate(req, story, opaque, unigroups[idx], temp_units, page, tone_keys)
            if progress :
                progress(req, story, idx, len(groups), page)

    def strip_punct(self, word) :
        new_word = ""
        for char in word :
            if char not in self.punctuation_without_letters :
                new_word += char
        return new_word

    def add_unit(self, trans, uni_source, target, online = False, punctuation = False) :
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

    def recursive_translate(self, req, story, opaque, uni, temp_units, page, tone_keys) :
        mverbose("Requested: " + uni)

        if self.all_punct(uni) :
            units = []
            units.append(self.add_unit([uni], uni, [uni], punctuation = True))
        else :
            units = self.recursive_translate_lang(req, story, opaque, uni, temp_units, page, tone_keys)

        for unit in units :
            if len(unit["sromanization"]) == 1 and unit["sromanization"][0] == u'' :
               continue

            self.mica.rehash_correct_polyphome(unit)
            
            mverbose(("Translation: (" + "".join(unit["source"]) + ") " + " ".join(unit["sromanization"]) + ":" + " ".join(unit["target"])).replace("\n",""))
            
        if temp_units :
            story["temp_units"] = story["temp_units"] + units
        else :
            story["pages"][page]["units"] = story["pages"][page]["units"] + units 

    def online_cross_reference(self, req, story, uni, opaque) :
        online_units = False
        if not self.params["mobileinternet"] or self.params["mobileinternet"].connected() != "none" :
            online_units = self.online_cross_reference_lang(req, story, uni, opaque)
        return online_units

    def all_punct(self, uni, exclude = []) :
        all = True
        for char in uni :
            if char in exclude or (len(uni) and char not in self.punctuation) :
                all = False
                break
        return all

def get_cjk_handle(params) :
    cjk = None
    d = None
    try :
        from cjklib.dictionary import CEDICT
        from cjklib.characterlookup import CharacterLookup
        from cjklib.dbconnector import getDBConnector
        cjkurl = 'sqlite:///' + params["scratch"] + "cjklib.db"
        cedicturl = 'sqlite:///' + params["scratch"] + "cedict.db"
        mverbose("Opening CJK from: " + cedicturl + " and " + cjkurl)
        cjk = CharacterLookup('C', dbConnectInst = getDBConnector({'sqlalchemy.url': cjkurl}))
        mverbose("MICA cjklib success!")
        # CEDICT must use a connector, just a url which includes both dictionaries.
        # CEDICT internally references pinyin syllables from the main dictionary or crash.
        d = CEDICT(dbConnectInst = getDBConnector({'sqlalchemy.url': cedicturl, 'attach': [cedicturl, cjkurl]}))
        mverbose("MICA cedict success!")
    except Exception, e :
        merr("MICA offline open failed: " + str(e))

    return (cjk, d)


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

    def test_dictionaries(self, opaque) :
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

    def online_cross_reference_lang(self, req, story, all_source, opaque) :
        mdebug("Going online...")
        #opaque is not yet used for Romanized sources 
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

    def parse_page_start(self) : 
        return False

    def parse_page_stop(self, opaque) :
        d = opaque

    def recursive_translate_lang(self, req, story, opaque, uni, temp_units, page, tone_keys) :
        units = []

        if uni.count(u"-") :
            parts = uni.split(u"-")
            first = True 
            for part in parts :
                if first :
                    first = False
                else :
                    units.append(self.add_unit([u"-"], u"-", [u"-"], punctuation = True))

                res = self.recursive_translate_lang(req, story, opaque, part, temp_units, page, tone_keys)
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
        targ = self.get_first_translation(opaque, uni, False, none_if_not_found = False)

        # Then try lowercasing...
        if not targ :
            try_source = uni.lower()
            targ = self.get_first_translation(opaque, try_source, False, none_if_not_found = False)

        for combo, replacement in self.matches.iteritems() :
            x = len(combo)
            if not targ and len(uni) > x and uni[-x:] == combo :
                search = uni[:-x]
                if replacement :
                    search += replacement
                try_source = search
                targ = self.get_first_translation(opaque, try_source, False, none_if_not_found = False)

                # Try lowercase
                if not targ :
                    try_source = search.lower()
                    targ = self.get_first_translation(opaque, try_source, False, none_if_not_found = False)

                # Try repeating without accented characters
                if not targ and self.accented_source :
                    unsource = ''.join((c for c in normalize('NFD', search) if category(c) != 'Mn'))

                    try_source = unsource 
                    targ = self.get_first_translation(opaque, try_source, False, none_if_not_found = False)

                    # And again, unaccented lowercase
                    if not targ :
                        try_source = unsource.lower()
                        targ = self.get_first_translation(opaque, try_source, False, none_if_not_found = False)

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
            online_units = self.online_cross_reference(req, story, uni, opaque)

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

    def get_ipa(self, source) :
        return False
    
    def get_first_translation(self, opaque, source, reading, none_if_not_found = True, debug = False) :
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
    def test_dictionaries(self, opaque) :
        super(EnglishSource, self).test_dictionaries(opaque)

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
        return ["cjklib.db", "cedict.db", "tones.db"]

    def test_dictionaries(self, opaque) :
        cjk, d = opaque 

        '''
        for x in d.getFor(u'白鹭'.decode('utf-8')) :
            mdebug(str(x))
        for x in cjk.getReadingForCharacter(u'白','Pinyin') :
            mdebug(str(x))
        '''

        self.tonedb = {}
        db = create_engine('sqlite:///' + self.params["scratch"] + 'tones.db', listeners= [MyListener()])
        db.echo = False
        metadata = MetaData(db)
        self.tonedb["conn"] = db.connect()

        self.tonedb["tones"] = Table('tones', metadata,
            Column('word', String, primary_key=True),
            Column('tone', String),
        )

        self.tonedb["tones"].create(checkfirst=True)

        s = self.tonedb["tones"].select()
        rs = s.execute()
        result = rs.fetchone()

        if result is None :
            trans = self.tonedb["conn"].begin()
            mdebug("Building tone file")
            dpfh = open(self.params["scratch"] + "chinese.txt")
            for line in dpfh.readlines() :
                k, v = line.split('\t')
                i = self.tonedb["tones"].insert().values(word = k, tone = v)
                self.tonedb["conn"].execute(i)
            dpfh.close()
            trans.commit()
        #mdebug("Tone test: " + str(self.convertPinyin(u'白')))

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
            except:
                result.append(char)

        return splitter.join(result)

    def convertPinyinCallback(self, m):
        tone=int(m.group(3))%5
        r=m.group(1).replace(u'v', u'ü').replace(u'V', u'Ü')
        # for multple vowels, use first one if it is a/e/o, otherwise use second one
        pos=0
        if len(r)>1 and not r[0] in 'aeoAEO':
            pos=1
        if tone != 0:
            r=r[0:pos]+pinyinToneMarks[r[pos]][tone-1]+r[pos+1:]
        return r+m.group(2)

    def convertPinyin(self, char):
        s = self.get_pinyin(char)
        return re_compile(ur'([aeiouüvÜ]{1,3})(n?g?r?)([012345])', flags=IGNORECASE).sub(self.convertPinyinCallback, s)

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


    def parse_page_start(self) : 
        return get_cjk_handle(self.params)

    def parse_page_stop(self, opaque) :
        (cjk, d) = opaque 
        cjk.db.connection.close()
        d.db.connection.close()

    def pre_parse_page(self, opaque, page_input_unicode) :
        try :
            return mica_ictclas.trans(page_input_unicode.encode("utf-8"))
        except mica_ictclas.error, e :
            self.parse_page_stop(opaque)
            raise e

    def get_first_translation(self, opaque, source, reading, none_if_not_found = True, debug = False) :
        cjk, d = opaque 
        targ = []
        temp_r = d.getFor(source)
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

    def online_cross_reference_lang(self, req, story, all_source, opaque) :
        if len(all_source) <= 1 : 
            return False

        mdebug("Going online...")
        (cjk, d) = opaque 
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
#          mdebug("orig idx " + str(source_idx) + " trans idx " + str(trans_idx) + " => " + char)
          pchar = self.convertPinyin(char)
          tmatch += " " + pchar + "(s" + str(source_idx) + ",t" + str(trans_idx) + "," + char + ")"
          match_romanization += pchar + " "

#        mdebug("matches: \n" + tmatch.replace("\n",""))
          
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
    #            mdebug("passing: " + str(passes))
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
        
#        mdebug(msg)
        for unit_idx in range(0, len(units)) :
            units[unit_idx]["online"] = True
            units[unit_idx]["punctuation"] = False 
                          
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

      return unit

    def recursive_translate_lang(self, req, story, opaque, uni, temp_units, page, tone_keys) :
        units = []

        cjk, d = opaque 
        trans = []
        targ = []
        results = d.getFor(uni)
        if results is not None :
            for e in results :
                trans.append(e[2])
                targ.append(e[3])

        if len(trans) == 1 :
            unit = self.add_unit(trans[0].split(" "), uni, [targ[0]])
            units.append(unit)
        elif len(trans) == 0 :
            if len(uni) > 1 :
                for char in uni :
                    self.recursive_translate(req, story, opaque, char, temp_units, page, tone_keys)

        elif len(trans) > 1 :
                        
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
                online_units = self.online_cross_reference(req, story, uni, opaque)

                if not online_units or not len(online_units) :
                    targ = self.get_first_translation(opaque, uni, readings[0])
                    unit = self.add_unit([readings[0]], uni, [targ[0]])
                    for x in readings :
                        targ = self.get_first_translation(opaque, uni, x, False)
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
                targ = self.get_first_translation(opaque, uni, readings[0])
                units.append(self.add_unit(readings[0].split(" "), uni, [targ[0]]))

        return units
