#!/usr/bin/env python
# coding: utf-8

# Make this an abstract base class the python way - forgot how

from common import *
import pdb

try :
    import mica_ictclas
except ImportError, e :
    mdebug("Could not import ICTCLAS library. Full translation will not work.")

class Processor(object) :
    def __init__(self) :
        pass

    def parse_page_start(self) : 
        return None

    def parse_page_stop(self, opaque) :
        pass

    def pre_parse_page(self, page_input_unicode) :
        return page_input.encode("utf-8")

    def parse_page(self, opaque, ...) :

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
    def __init__(self, params) :
        # call super here
        self.cjklib_path = params["cjklib"]
        self.cedict_path = params["cedict"]

    def parse_page_start(self) : 
        return get_cjk_handle(self.cjklib_path, self.cedict_path)

    def parse_page_stop(self, opaque) :
        (cjk, d) = opaque 
        cjk.db.connection.close()
        d.db.connection.close()

    def pre_parse_page(self, page_input_unicode) :
        try :
            return self.ictclas.trans(page_input.encode("utf-8"))
        except mica_ictclas.error, e :
            processor.parse_page_stop(opaque)
            raise e

    def parse_page(self, opaque, req, story, groups, page, temp_units = False, progress = False, error = False) :

        uuid = story['uuid']
        name = story['name']

        if not opaque :
            (cjk, d) = self.parse_page_start()
        else :
            (cjk, d) = opaque 

        if temp_units :
            story["temp_units"] = []
        else :
            if "pages" not in story :
                story['pages'] = {}
            story["pages"][page] = {}
            story["pages"][page]["units"] = []

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
                    error(req, name, "Should we toss this group? " + str(group) + ": " + str(e) + " index: " + str(idx))
                if not handle :
                    mdebug("Closing CJK 6")
                    cjk.db.connection.close()
                    d.db.connection.close()
                raise e

            if not self.all_punct(uni) :
                for unichar in uni :
                    if unichar not in unikeys :
                        unikeys.append(unichar)
            unigroups.append(uni)

        tone_keys = self.view_keys(req, "tonechanges", False, source_queries = unikeys) 
        mdebug("Tone keys search returned " + str(len(tone_keys)) + "/" + str(len(unikeys)) + " results.") 

        for idx in range(0, len(unigroups)) :
            self.recursive_translate(req, story, cjk, d, unigroups[idx], temp_units, page, tone_keys)
            if progress :
                self.progress(req, idx, story, page, len(groups))

        if not handle :
            mdebug("Closing CJK 7")
            cjk.db.connection.close()
            d.db.connection.close()

