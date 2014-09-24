#!/usr/bin/env python
# coding: utf-8

# Make this an abstract base class the python way - forgot how

from common import *

import pdb
import string 

'''
All stories up to and including mica version 0.4.x only supported
Chinese and were not generalized to support other languages. Thus,
the story dictionary format had a very chinese-specific layout.

To fix this, these pre v0.5.0 stories are thus assumed to have a 
format of '1', i.e. the first version we started with.
This is detected if the key "format" is not contained within the
document for the respective story in question.

Formats 2 and higher restructure the basic unit structure of a story
to support other languages.

Format 1 => Format 2
========================
spinyin => sromanization
tpinyin => tromanization
multiple_english => multiple_target
english => target

'''

story_format = 2

try :
    import mica_ictclas
except ImportError, e :
    mdebug("Could not import ICTCLAS library. Full translation will not work.")

class Processor(object) :
    def __init__(self, mica, params) :
        self.params = params
        self.mica = mica

        self.punctuation = {}
        self.punctuation_without_newlines = {}
        self.punctuation_letters = {}

        for letter in (string.ascii_lowercase + string.ascii_uppercase) :
            self.punctuation_letters[letter] = {}
            self.punctuation_letters[letter.decode("utf-8")] = {}

        for num in range(0, 10) :
            self.punctuation_letters[(unicode(str(num))] = {}
            self.punctuation_letters[str(num)] = {}
            
        self.punctuation_without_newlines = copy.deepcopy(self.punctuation_letters)

        self.punctuation[u'\n'] = {}
        self.punctuation['\n'] = {}

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

        self.parse_page_groups(req, story, groups, handle, progress)

        if not opaque :
            self.parse_page_stop(handle)

    def parse_page_start(self, story, temp_units = False) : 
        return True

    def parse_page_stop(self, opaque) :
        return True

    def pre_parse_page(self, page_input_unicode) :
        return page_input.encode("utf-8")

    def all_punct(self, uni) :
        all = True
        for char in uni :
            if len(uni) and char not in self.punctuation :
                all = False
                break
        return all

    def parse_page_groups(self, req, story, groups, opaque, progress) :
        unigroups = []
        unikeys = []

        for idx in range(0, len(groups)) :
            group = groups[idx]
            assert(isinstance(group, str))

            try :
                uni = unicode(group.strip() if (group != "\n" and group != u'\n') else group, "utf-8")
            except UnicodeDecodeError, e :
                pdb.set_trace()
                if error :
                    self.mica.store_error(req, story['name'], "Should we toss this group? " + str(group) + ": " + str(e) + " index: " + str(idx))
                if not handle :
                    mdebug("Closing CJK 6")
                    self.parse_page_stop(opaque)
                raise e

            if not self.all_punct(uni) :
                for unichar in uni :
                    if unichar not in unikeys :
                        unikeys.append(unichar)
            unigroups.append(uni)

        tone_keys = self.mica.view_keys(req, "tonechanges", False, source_queries = unikeys) 
        mdebug("Tone keys search returned " + str(len(tone_keys)) + "/" + str(len(unikeys)) + " results.") 

        for idx in range(0, len(unigroups)) :
            self.recursive_translate(req, story, opaque, unigroups[idx], temp_units, page, tone_keys)
            if progress :
                self.progress(req, idx, story, page, len(groups))

    def strip_punct(self, word) :
        new_word = ""
        for char in word :
            if char not in self.punctuation_without_letters :
                new_word += char
        return new_word

    # This is where we stopped: We need to change the database structure here
    # This will require a database upgrade =(
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

    def make_unit(source_idx, current_source_idx, trans_idx, current_trans_idx, groups, reversep, target, source, pinyin) :

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

def get_cjk_handle(cjklib_path, cedict_path) :
    cjk = None
    d = None
    try :
        from cjklib.dictionary import CEDICT
        from cjklib.characterlookup import CharacterLookup
        from cjklib.dbconnector import getDBConnector
        mdebug("Opening CJK from: " + params["cedict"] + " and " + params["cjklib"])
        cjkurl = 'sqlite:///' + params['cjklib']
        cedicturl = 'sqlite:///' + params['cedict']
        cjk = CharacterLookup('C', dbConnectInst = getDBConnector({'sqlalchemy.url': cjkurl}))
        mdebug("MICA cjklib success!")
        # CEDICT must use a connector, just a url which includes both dictionaries.
        # CEDICT internally references pinyin syllables from the main dictionary or crash.
        d = CEDICT(dbConnectInst = getDBConnector({'sqlalchemy.url': cedicturl, 'attach': [cedicturl, cjkurl]}))
        mdebug("MICA cedict success!")
    except Exception, e :
        merr("MICA offline open failed: " + str(e))

    return (cjk, d)

class ChineseSimplified(Processor) :
    def __init__(self, mica, params) :
        super(ChineseSimplified, self).__init__(mica, params)

        self.punctuation_characters = [u'%' u'「', u'【', u']', u'[', u'>', u'<', u'】',u'〈', u'@', u'；', u'&', u'*', u'|', u'/', u'-', u'_', u'—', u',', u'，',u'.',u'。', u'?', u'？', u':', u'：', u'：', u'、', u'“', u'”', u'~', u'`', u'"', u'\'', u'…', u'！', u'!', u'（', u'(', u'）', u')' ]

        self.punctuation_characters += ['%', ']', '[', '<', '>','@',';', '&', "*', "'|', '^','\\','/', '-', '_', '—', ',', '，','.','。', '?', '？', ':', '：', '、', '“', '”', '~', '`', '"', '\'', '…', '！', '!', '（', '(', '）', ')' ]

        self.punctuation_without_newlines.update(self.punctuation_characters)
        self.punctuation.update(self.punctuation_characters)

        self.cjklib_path = params["cjklib"]
        self.cedict_path = params["cedict"]

    def parse_page_start(self) : 
        return get_cjk_handle(self.cjklib_path, self.cedict_path)

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

    def recursive_translate(self, req, story, opaque, uni, temp_units, page, tone_keys) :
        uuid = story['uuid']
        name = story['name']
        units = []
        cjk, d = opaque 
        
        mdebug("Requested: " + uni)

        if self.all_punct(uni) :
            units.append(self.add_unit([uni], uni, [uni], punctuation = True))
        else :
            trans = []
            eng = []

            results = d.getFor(uni)
            if results is not None :
                for e in results :
                    trans.append(e[2])
                    eng.append(e[3])

            if len(trans) == 1 :
                unit = self.add_unit(trans[0].split(" "), uni, [eng[0]])
                units.append(unit)
            elif len(trans) == 0 :
                if len(uni) > 1 :
                    for char in uni :
                        self.recursive_translate(req, story, opaque, char, temp_units, page, tone_keys)
            elif len(trans) > 1 :
                            
                for x in range(0, len(trans)) :
                    trans[x] = trans[x].lower() 
                
                readings = trans
                    
                if len(uni) == 1 :
                    readg = cjk.getReadingForCharacter(uni, 'Pinyin')
                    for read in readg :
                        read = read.lower()
                        if read not in readings :
                            readings.append(read)
                
                readings = list(set(readings))
                
                assert(len(readings) > 0)

                if uni not in punctuation and uni :
                    online_units = False
                    if not params["mobileinternet"] or params["mobileinternet"].connected() != "none" :
                        online_units = self.online_cross_reference(req, uuid, name, story, uni, cjk) if len(uni) > 1 else False

                    if not online_units or not len(online_units) :
                        eng = self.get_first_translation(d, uni, readings[0])
                        unit = self.add_unit([readings[0]], uni, [eng[0]])
                        for x in readings :
                            eng = self.get_first_translation(d, uni, x, False)
                            if not eng :
                                continue
                            for e in eng :
                                unit["multiple_sromanization"].append([x])
                                unit["multiple_target"].append([e])
                        
                        if unit["multiple_correct"] == -1 :
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

                                for idx in range(0, len(unit["multiple_sromanization"])) :
                                    percent = self.get_polyphome_percentage(idx, total_changes, changes, unit) 
                                    if percent :
                                        if highest_percentage == -1.0 :
                                            highest_percentage = percent
                                            highest = idx
                                        elif percent > highest_percentage :
                                            highest_percentage = percent
                                            highest = idx

                            if highest != -1 :
                                selector = highest
                                mdebug("HISTORY Multiple pinyin for source: " + source + " defaulting to idx " + str(selector) + " using HISTORY.")
                            else :
                                longest = -1
                                longest_length = -1
                                
                                for idx in range(0, len(unit["multiple_sromanization"])) :
                                    comb_eng = " ".join(unit["multiple_target"][idx])
                                    
                                    if not comb_eng.count("surname") and not comb_eng.count("variant of") :
                                        if longest_length == -1 :
                                            longest_length = len(comb_eng)
                                            longest = idx
                                        elif len(comb_eng) > longest_length :
                                            longest_length = len(comb_eng)
                                            longest = idx

                                selector = longest
                                mdebug("LONGEST Multiple pinyin for source: " + source + " defaulting to idx " + str(selector))

                            if selector != -1 :
                                unit["sromanization"] = unit["multiple_sromanization"][selector]
                                unit["target"] = unit["multiple_target"][selector]
                                unit["multiple_correct"] = selector 

                        units.append(unit)
                    else :
                        for unit in online_units :
                           if len(unit["match_pinyin"]) :
                               unit["sromanization"] = unit["match_pinyin"]
                           if len(unit["sromanization"]) == 1 and unit["sromanization"][0] == u'' :
                               continue
                           units.append(unit)
                else :
                    eng = self.get_first_translation(d, uni, readings[0])
                    units.append(self.add_unit(readings[0].split(" "), uni, [eng[0]]))
        
        for unit in units :
            if len(unit["sromanization"]) == 1 and unit["sromanization"][0] == u'' :
               continue

            self.rehash_correct_polyphome(unit)
            mdebug(("Translation: (" + "".join(unit["source"]) + ") " + " ".join(unit["sromanization"]) + ":" + " ".join(unit["target"])).replace("\n",""))
            
        if temp_units :
            story["temp_units"] = story["temp_units"] + units
        else :
            story["pages"][page]["units"] = story["pages"][page]["units"] + units
