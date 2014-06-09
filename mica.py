#!/usr/bin/env python
# coding: utf-8

from pwd import getpwuid
from sys import path
from time import sleep, time as timest
from threading import Thread, Lock
from copy import deepcopy
from cStringIO import StringIO

import traceback
import os
import re
import shutil
import urllib
import urllib2
import copy
import warnings
import codecs
import uuid as uuid4
import inspect
import hashlib
import errno
import json
import string 
import base64
import __builtin__
import sys

from common import *

import couch_adapter

mdebug("Initial imports complete")

cwd = re.compile(".*\/").search(os.path.realpath(__file__)).group(0)

#Non-python-core
from zope.interface import Interface, Attribute, implements
from twisted.python.components import registerAdapter
from twisted.web.server import Session
from twisted.web.wsgi import WSGIResource
from twisted.internet import reactor, ssl
from twisted.web.static import File
from twisted.web.resource import Resource
from twisted.web.server import Site
from twisted.web import proxy, server
from twisted.python import log
from twisted.python.logfile import DailyLogFile

from webob import Request, Response, exc

#from beaker.middleware import SessionMiddleware

from cjklib.dictionary import CEDICT
from cjklib.characterlookup import CharacterLookup
from cjklib.dbconnector import getDBConnector

try :
    from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
    from pdfminer.converter import PDFPageAggregator
    from pdfminer.layout import LAParams, LTPage, LTTextBox, LTTextLine, LTImage
    from pdfminer.pdfpage import PDFPage

    import mica_ictclas
except ImportError, e :
    mdebug("Could not import ICTCLAS library. Full translation will not work.")
    pass

mdebug("Imports complete.")

pdf_punct = ",卜「,\,,\\,,【,\],\[,>,<,】,〈,@,；,&,*,\|,/,-,_,—,,,，,.,。,?,？,:,：,\:,\：,：,\：,\、,\“,\”,~,`,\",\',…,！,!,（,\(,）,\),口,」,了,丫,㊀,。,门,X,卩,乂,一,丁,田,口,匕,《,》,化,*,厂,主,竹,-,人,八,七,，,、,闩,加,。,』,〔,飞,『,才,廿,来,兀,〜,\.,已,I,幺,去,足,上,円,于,丄,又,…,〉".decode("utf-8")

for letter in (string.ascii_lowercase + string.ascii_uppercase) :
    pdf_punct += letter.decode("utf-8")

pdf_expr = r"([" + pdf_punct + "][" + pdf_punct + "]|[\x00-\x7F][\x00-\x7F]|[\x00-\x7F][" + pdf_punct + "]|[" + pdf_punct + "][\x00-\x7F])"

mdebug("Punctuation complete.")

def parse_lt_objs (lt_objs, page_number):
    text_content = [] 
    images = [] 

    for lt_obj in lt_objs:
        if isinstance(lt_obj, LTTextBox) or isinstance(lt_obj, LTTextLine):
            text_content.append(lt_obj.get_text().strip())
        elif isinstance(lt_obj, LTImage):
            images.append(lt_obj.stream.get_data())
        elif isinstance(lt_obj, LTFigure):
            sub_text, sub_images = parse_lt_objs(lt_obj._objs(), page_number)
            text_content.append(sub_text)
            images.append(sub_images)

    return (text_content, images)

                
def repeat(func, args, kwargs):
    success = False
    while not success :
        ret = func(*args, **kwargs)
        success = True
   
    return [success] + ret 

def filter_lines(data2) :
    new_page = []

    for line in data2 : 
        if line == "" :
            continue

        for match in re.compile(r'[0-9]+ +[0-9, ]+', flags=re.IGNORECASE).findall(line) :
            line = line.replace(match, match.replace(" ", ""))

        temp_line = line.strip().decode("utf-8") if isinstance(line, str) else line.strip()
        if len(temp_line) == 3 and temp_line[0] == "(" and temp_line[-1] == ")" :
            matches = re.compile(u'\(.\)', flags=re.IGNORECASE).findall(temp_line)

            if len(matches) == 1 :
                continue

        line = re.sub(r'( *82303.*$|[0-9][0-9][0-9][0-9][0-9]+ *)', '', line)
        test_all = re.sub(r'([\x00-\x7F]| )+', '', line)

        if test_all == "" :
            continue

        no_numbers = re.sub(r"([0-9]| )+", "", line)
        if isinstance(no_numbers, str) :
            no_numbers = no_numbers.decode("utf-8")
        while len(re.compile(pdf_expr).findall(no_numbers)) :
            no_numbers = re.sub(pdf_expr, '', no_numbers)
            continue

        if len(no_numbers) <= 1 :
            continue

        new_page.append(line)

    return new_page

def itemhelp(pairs) :
    story = pairs[1]
    total_memorized = story["total_memorized"] if "total_memorized" in story else 0
    total_unique = story["total_unique"] if "total_unique" in story else 0
    pr = int((float(total_memorized) / float(total_unique)) * 100) if total_unique else 0
    story["pr"] = str(pr)
    reviewed = not ("reviewed" not in story or not story["reviewed"])
    return pr

bins = dir(__builtin__)

cd = {}
def get_pinyin(chars=u'你好', splitter=''):
    result = []
    for char in chars:
        key = "%X" % ord(char)
        try:
            result.append(cd[key].split(" ")[0].strip().lower())
        except:
            result.append(char)

    return splitter.join(result)

pinyinToneMarks = {
    u'a': u'āáǎà', u'e': u'ēéěè', u'i': u'īíǐì',
    u'o': u'ōóǒò', u'u': u'ūúǔù', u'ü': u'ǖǘǚǜ',
    u'A': u'ĀÁǍÀ', u'E': u'ĒÉĚÈ', u'I': u'ĪÍǏÌ',
    u'O': u'ŌÓǑÒ', u'U': u'ŪÚǓÙ', u'Ü': u'ǕǗǙǛ'
}

def convertPinyinCallback(m):
    tone=int(m.group(3))%5
    r=m.group(1).replace(u'v', u'ü').replace(u'V', u'Ü')
    # for multple vowels, use first one if it is a/e/o, otherwise use second one
    pos=0
    if len(r)>1 and not r[0] in 'aeoAEO':
        pos=1
    if tone != 0:
        r=r[0:pos]+pinyinToneMarks[r[pos]][tone-1]+r[pos+1:]
    return r+m.group(2)

def convertPinyin(s):
    return re.compile(ur'([aeiouüvÜ]{1,3})(n?g?r?)([012345])', flags=re.IGNORECASE).sub(convertPinyinCallback, s)

def lcs(a, b):
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

mdebug("Setting up prefixes.")

username = getpwuid(os.getuid())[0]
relative_prefix_suffix = "serve"
relative_prefix = "/" + relative_prefix_suffix

def prefix(uri) :
    result = re.compile("[^/]*\:\/\/([^/]*)(\/(.*))*").search(uri)
    address = result.group(1)
    path = result.group(3)
    if path is None :
        path = ""
    return (address, path)

class ArgumentOutOfRangeException(Exception):
    def __init__(self, message):
        self.message = message.replace('ArgumentOutOfRangeException: ', '')
        super(ArgumentOutOfRangeException, self).__init__(self.message)


class TranslateApiException(Exception):
    def __init__(self, message, *args):
        self.message = message.replace('TranslateApiException: ', '')
        super(TranslateApiException, self).__init__(self.message, *args)


class Translator(object):
    """Implements AJAX API for the Microsoft Translator service

    :param app_id: A string containing the Bing AppID. (Deprecated)
    """

    def __init__(self, client_id, client_secret,
            scope="http://api.microsofttranslator.com",
            grant_type="client_credentials", app_id=None, debug=False):
        """


        :param client_id: The client ID that you specified when you registered
                          your application with Azure DataMarket.
        :param client_secret: The client secret value that you obtained when
                              you registered your application with Azure
                              DataMarket.
        :param scope: Defaults to http://api.microsofttranslator.com
        ;param grant_type: Defaults to "client_credentials"
        :param app_id: Deprecated
        :param debug: If true, the logging level will be set to debug

        .. versionchanged: 0.4
            Bing AppID mechanism is deprecated and is no longer supported.
            See: http://msdn.microsoft.com/en-us/library/hh454950
        """
        if app_id is not None:
            warnings.warn("""app_id is deprected since v0.4.
            See: http://msdn.microsoft.com/en-us/library/hh454950
            """, DeprecationWarning, stacklevel=2)

        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.grant_type = grant_type
        self.access_token = None
        self.debug = debug
        self.logger = logging.getLogger("microsofttranslator")
        if self.debug:
            self.logger.setLevel(level=logging.DEBUG)

    def get_access_token(self):
        """Bing AppID mechanism is deprecated and is no longer supported.
        As mentioned above, you must obtain an access token to use the
        Microsoft Translator API. The access token is more secure, OAuth
        standard compliant, and more flexible. Users who are using Bing AppID
        are strongly recommended to get an access token as soon as possible.

        .. note::
            The value of access token can be used for subsequent calls to the
            Microsoft Translator API. The access token expires after 10
            minutes. It is always better to check elapsed time between time at
            which token issued and current time. If elapsed time exceeds 10
            minute time period renew access token by following obtaining
            access token procedure.

        :return: The access token to be used with subsequent requests
        """
        args = urllib.urlencode({
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': self.scope,
            'grant_type': self.grant_type
        })
        
        try :
            response = json.loads(urllib.urlopen(
                'https://datamarket.accesscontrol.windows.net/v2/OAuth2-13', args
            ).read())
        except IOError, e :
            raise TranslateApiException(
                response.get('error_description', 'Failed to authenticate with translation service'),
                response.get('error', str(e))
            )
        

        self.logger.debug(response)

        if "error" in response:
            raise TranslateApiException(
                response.get('error_description', 'No Error Description'),
                response.get('error', 'Unknown Error')
            )
        return response['access_token']

    def call(self, url, params):
        """Calls the given url with the params urlencoded
        """
        if not self.access_token:
            self.access_token = self.get_access_token()

        request = urllib2.Request(
            "%s?%s" % (url, urllib.urlencode(params)),
            headers={'Authorization': 'Bearer %s' % self.access_token}
        )
        response = urllib2.urlopen(request).read()
        rv =  json.loads(response.decode("utf-8-sig"))

        if isinstance(rv, basestring) and \
                rv.startswith("ArgumentOutOfRangeException"):
            raise ArgumentOutOfRangeException(rv)

        if isinstance(rv, basestring) and \
                rv.startswith("TranslateApiException"):
            raise TranslateApiException(rv)

        return rv

    def translate(self, text, to_lang, from_lang=None,
            content_type='text/plain', category='general'):
        """Translates a text string from one language to another.

        :param text: A string representing the text to translate.
        :param to_lang: A string representing the language code to
            translate the text into.
        :param from_lang: A string representing the language code of the
            translation text. If left None the response will include the
            result of language auto-detection. (Default: None)
        :param content_type: The format of the text being translated.
            The supported formats are "text/plain" and "text/html". Any HTML
            needs to be well-formed.
        :param category: The category of the text to translate. The only
            supported category is "general".
        """
        params = {
            'text': text.encode('utf8'),
            'to': to_lang,
            'contentType': content_type,
            'category': category,
            }
        if from_lang is not None:
            params['from'] = from_lang
        return self.call(
            "http://api.microsofttranslator.com/V2/Ajax.svc/Translate",
            params)

    def translate_array(self, texts, to_lang, from_lang=None, **options):
        """Translates an array of text strings from one language to another.

        :param texts: A list containing texts for translation.
        :param to_lang: A string representing the language code to 
            translate the text into.
        :param from_lang: A string representing the language code of the 
            translation text. If left None the response will include the 
            result of language auto-detection. (Default: None)
        :param options: A TranslateOptions element containing the values below. 
            They are all optional and default to the most common settings.

                Category: A string containing the category (domain) of the 
                    translation. Defaults to "general".
                ContentType: The format of the text being translated. The 
                    supported formats are "text/plain" and "text/html". Any 
                    HTML needs to be well-formed.
                Uri: A string containing the content location of this 
                    translation.
                User: A string used to track the originator of the submission.
                State: User state to help correlate request and response. The 
                    same contents will be returned in the response.
        """
        options = {
            'Category': u"general",
            'Contenttype': u"text/plain",
            'Uri': u'',
            'User': u'default',
            'State': u''
            }.update(options)
        params = {
            'texts': json.dumps(texts),
            'to': to_lang,
            'options': json.dumps(options),
            }
        if from_lang is not None:
            params['from'] = from_lang

        return self.call(
                "http://api.microsofttranslator.com/V2/Ajax.svc/TranslateArray",
                params)

class Params(object) :
    def __init__(self, environ, session):
        self.pid = "none"
        self.http = Request(environ)  
        self.action = self.http.path[1:] if len(self.http.path) > 0 else None
        if self.action is None or self.action == "":
            self.action = "index"

        self.session = session
        #self.session = environ['beaker.session']
        
        if 'connected' not in self.session.value :
            self.session.value['connected'] = False
            if 'cloud_name' in self.session.value :
                del self.session.value['cloud_name']
                
        self.session.save()
        self.unparsed_uri = self.http.url
        self.uri = self.http.path
        self.active = None 
        self.active_obj = None 
        self.skip_show = False

        minfo("Request: " + self.unparsed_uri + " action: " + self.action)

def make_unit(source_idx, current_source_idx, trans_idx, current_trans_idx, groups, reversep, eng, source, pinyin, match_pinyin) :
  unit = {}

  if trans_idx > current_trans_idx :
          unit["trans"] = groups[current_trans_idx:trans_idx]
          unit["tpinyin"] = reversep[current_trans_idx:trans_idx]
          english = []
          for group in unit["trans"] :
              english.append(eng[group[0]])
          unit["english"] = english
  else :
          unit["trans"] = False
          unit["english"] = [""]

  if source_idx > current_source_idx :
          unit["source"] = source[current_source_idx:source_idx]
          unit["spinyin"] = pinyin[current_source_idx:source_idx]

  unit["match_pinyin"] = match_pinyin
  unit["multiple_spinyin"] = []
  unit["multiple_english"] = []
  unit["multiple_correct"] = -1
  return unit

mdebug("Additional punctuation.")
punctuation = [u'「', u'【', u']', u'[', u'>', u'<', u'】',u'〈', u'@', u'；', u'&', u'*', u'|', u'/', u'-', u'_', u'—', u',', u'，',u'.',u'。', u'?', u'？', u':', u'：', u'：', u'、', u'“', u'”', u'~', u'`', u'"', u'\'', u'…', u'！', u'!', u'（', u'(', u'）', u')' ]
punctuation += [']', '[', '<', '>','@',';', '&', "*', "'|', '^','\\','/', '-', '_', '—', ',', '，','.','。', '?', '？', ':', '：', '、', '“', '”', '~', '`', '"', '\'', '…', '！', '!', '（', '(', '）', ')' ]

punctuation_without_letters = copy.deepcopy(punctuation)

for letter in (string.ascii_lowercase + string.ascii_uppercase) :
    punctuation.append(letter)
    punctuation.append(letter.decode("utf-8"))

for num in range(0, 10) :
    punctuation.append(unicode(str(num)))
    punctuation.append(str(num))
    
punctuation_without_newlines = copy.deepcopy(punctuation)
punctuation.append(u'\n')
punctuation.append('\n')

temp_punct = {}
temp_punct_without = {}

for p in punctuation :
    temp_punct[p] = {}

for p in punctuation_without_newlines :
    temp_punct_without[p] = {}
    
punctuation = temp_punct
punctuation_without_newlines = temp_punct_without

def strip_punct(word) :
    new_word = ""
    for char in word :
        if char not in punctuation_without_letters :
            new_word += char
    return new_word

spinner = "<img src='MSTRAP/spinner.gif' width='15px'/>&nbsp;"

class MICA(object):
    def verify_db(self) :
        if not self.db : 
            mdebug("Database not set. Requesting object.")
            self.db = self.cs[self.dbname]

    def acct(self, name) :
        self.verify_db()
        return "MICA:accounts:" + name

    def story(self, req, key) :
        self.verify_db()
        ret = "MICA:" + req.session.value['username'] + ":stories:" + key
        #mdebug("Returning: " + ret)
        return ret 

    def index(self, req, key) :
        self.verify_db()
        return "MICA:" + req.session.value['username'] + ":story_index:" + key 
    
    def merge(self, req, key) :
        self.verify_db()
        return "MICA:" + req.session.value['username'] + ":mergegroups:" + key 
    
    def splits(self, req, key) :
        self.verify_db()
        return "MICA:" + req.session.value['username'] + ":splits:" + key 
    
    def tones(self, req, key) :
        self.verify_db()
        return "MICA:" + req.session.value['username'] + ":tonechanges:" + key 
    
    def memorized(self, req, key):
        self.verify_db()
        return "MICA:" + req.session.value['username'] + ":memorized:" + key 

    
    def __init__(self, client_id, client_secret, couch_url_or_local_db, couch_dbname, cjklocation, db_adapter):
        self.mutex = Lock()
        self.transmutex = Lock()
        self.heromsg = "<div class='span 1 hero-unit' style='padding: 5px'>"
        self.pid = "none"
        self.couch_url_or_local_db = couch_url_or_local_db
        self.cs = db_adapter(couch_url_or_local_db)
        self.dbname = couch_dbname
        
        self.cjklocation = cjklocation

        self.first_request = {}

        self.client = Translator(client_id, client_secret)

        self.menu = [ 
             ("home" , ("/home", "<i class='glyphicon glyphicon-home'></i>&nbsp;Review")), 
             ("edit" , ("/edit", "<i class='glyphicon glyphicon-pencil'></i>&nbsp;Edit")), 
             ("read" , ("/read", "<i class='glyphicon glyphicon-book'></i>&nbsp;Read")), 
        ]
        
        # Replacements must be in this order
        
        self.replacement_keys = [ 
                                    "BOOTNAV", 
                                    "BOOTNEWACCOUNTADMIN",
                                    "BOOTCLOUDNAME", 
                                    "BOOTCLOUDS", 
                                    "BOOTAVAILABLECLOUDS", 
                                    "BOOTBODY", 
                                    "BOOTSHOWPOPOVER",
                                    "BOOTSPINNER", 
                                    "BOOTDEST", 
                                    "BOOTACTIVE", 
                                    "BOOTOBJECTNAME", 
                                    "BOOTSTRAP", 
                                    "MSTRAP",
                                    "BOOTUSERHOLD",
                                    "BOOTREMEMBER",
                                ]


        self.db = False 
        try :
            self.verify_db()
            mdebug("Checking for initial account existence")
            account_exists = self.db.doc_exist(self.acct('admin'))
            if not account_exists:
                # default installations use 'admin' password of 'password'
                self.db[self.acct('admin')] = {
                        'password' : '5f4dcc3b5aa765d61d8327deb882cf99',
                        'roles' : [ 'admin', 'normal' ],
                    } 
        except TypeError, e :
            mwarn("Account documents don't exist yet. Probably they are being replicated." + str(e))
        except couch_adapter.ResourceNotFound, e :
            mwarn("Account document @ " + self.acct('admin') + " not found: " + str(e))
        except Exception, e :
            mwarn("Database (" + str(couch_url_or_local_db) + ") not available yet: " + str(e))

        #pushapps(cwd + "/views", self.db)
            
    def __call__(self, environ, start_response):
        # Hack to make WebOb work with Twisted
        setattr(environ['wsgi.input'], "readline", environ['wsgi.input']._wrapped.readline)

        req = Params(environ, start_response.im_self.request.session)
        req.dest = ""#prefix(req.unparsed_uri)
        req.zdbacctconnection = False
        req.zdb = False
        
        try:
            resp = self.common(req)
        except exc.HTTPTemporaryRedirect, e :
            resp = e
            resp.location = req.dest + resp.location# + req.active
        except exc.HTTPException, e:
            resp = e
        except Exception, e :
#            exc_type, exc_value, exc_traceback = sys.exc_info()
            resp = "<h4>Exception:</h4>"
            for line in traceback.format_exc().splitlines() :
                resp += "<br>" + line

        r = None

        try :
            if isinstance(resp, str) or isinstance(resp, unicode):
                r = Response(resp)(environ, start_response)
            else :
                r = resp(environ, start_response)
        except Exception, e :
            merr("RESPONSE MICA ********Exception:")
            for line in traceback.format_exc().splitlines() :
                merr("RESPONSE MICA ********" + line)

        return r
    
    def sidestart(self, req, name, username, story, reviewed) :
        rname = name.replace(".txt","").replace("\n","").replace("_", " ")
        sideout = ""
        sideout += "\n<tr>"
        sideout += "<td style='font-size: x-small; width: 100px'>" 
        sideout += "<a title='Download Original' href=\"BOOTDEST/stories?type=original&uuid="
        sideout += story["uuid"]
        sideout += "\">"
        sideout += rname
        sideout += "</a>"
        
        nb_pages = self.nb_pages(req, name)
            
        if nb_pages and (reviewed or story["translated"]) :
            pr = story["pr"]
            sideout += "<br/><div class='progress progress-success progress-striped'><div class='progress-bar' style='width: "
            sideout += pr + "%;'> (" + pr + "%)</div>"
            
        sideout += "</td>"
        if nb_pages and reviewed :
            sideout += "<td><a title='Download Pinyin' class='btn-default btn-xs' href=\"BOOTDEST/stories?type=pinyin&uuid=" + story["uuid"]+ "\">"
            sideout += "<i class='glyphicon glyphicon-download-alt'></i></a></td>"
    
        return sideout

    def template(self, template_prefix) :
        contents_fh = open(cwd + relative_prefix + "/" + template_prefix + "_template.html", "r")
        contents = contents_fh.read()
        contents_fh.close()
        return contents

    def bootstrap(self, req, body, now = False, pretend_disconnected = False, nodecode = False) :

        if isinstance(body, str) and not nodecode :
            body = body.decode("utf-8")

        navcontents = ""
        newaccountadmin = ""
        cloudcontents = "None Available"
        availablecontents = "None Available"
        popoveractivate = "$('#connectpop').popover('show');"
        if now :
            contents = body
        else :
            contents = self.template("head")
            
            navactive = req.action
            if navactive == 'home' or navactive == 'index' :
                navactive = 'home'
            for (key, value) in self.menu :
                if key in ["home", "read", "edit"] and not req.session.value['connected'] :
                    continue

                navcontents += "<li"
                if navactive == key :
                    navcontents += " class='active'"
                navcontents += "><a href=\"BOOTDEST" + value[0] + "\">" + value[1] + "</a></li>\n"
        
            if req.session.value['connected'] and not pretend_disconnected :
                user = self.db[self.acct(req.session.value['username'])]
                if 'admin' in user['roles'] :
                    newaccountadmin += """
                            <h5>&nbsp;<input type="checkbox" name="isadmin"/>&nbsp;Admin?</h5>
                    """
                if req.action == "edit" :
                    navcontents += """
                                 <li class='dropdown'>
                                 <a class='dropdown-toggle' data-toggle='dropdown' href='#'>
                                 <i class='glyphicon glyphicon-random'></i>&nbsp;Re-Group
                                 <b class='caret'></b>
                                 </a>
                                 <ul class='dropdown-menu'>
                                 """
                    uuid = 'bad_uuid';
                    navcontents += "<li><a href='#' onclick=\"process_edits('"
                    if "current_story" in req.session.value :
                        uuid = req.session.value["current_story"]
                    navcontents += uuid
                    navcontents += "', 'split', false)\"><i class='glyphicon glyphicon-resize-full'></i>&nbsp;Split Word Apart</a></li>"
                    navcontents += "<li><a href='#' onclick=\"process_edits('"
                    navcontents += uuid
                    navcontents += "','merge', false)\"><i class='glyphicon glyphicon-resize-small'></i>&nbsp;Merge Characters</a></li>"
                    navcontents += "</ul>"
                    navcontents += "</li>"
                if req.action != "help" :
                    navcontents += """
                                <li><a onclick='process_instant()' href='#'><i class='glyphicon glyphicon-share'></i>&nbsp;Instant</a></li>
                                <li class='dropdown'>
                                 <a class='dropdown-toggle' data-toggle='dropdown' href='#'>
                                 <i class='glyphicon glyphicon-eye-open'></i>&nbsp;View
                                 <b class='caret'></b>
                                 </a>
                                <ul class='dropdown-menu'>
                                """
                    navcontents += "<li id='textButton' "
                    if "view_mode" in req.session.value :
                         if req.session.value["view_mode"] == "text" :
                             navcontents += " class='active'"
                    navcontents += "><a href='#'><i class='glyphicon glyphicon-font'></i>&nbsp;Text Only</a></li>"
                    navcontents += "<li id='sideButton' "
                    if "view_mode" in req.session.value :
                         if req.session.value["view_mode"] == "both" :
                             navcontents += " class='active'"
                    navcontents += "><a href='#'><i class='glyphicon glyphicon-th-list'></i>&nbsp;Side-By-Side</a></li>"
                    navcontents += "<li id='imageButton' "
                    if "view_mode" in req.session.value :
                         if req.session.value["view_mode"] == "images" :
                             navcontents += " class='active'"
                    navcontents += "><a href='#'><i class='glyphicon glyphicon-picture'></i>&nbsp;Image Only</a></li>"
                    navcontents += """
                                </ul>
                                </li>
                                """
                navcontents += """
                                 <li class='dropdown'>
                                 <a class='dropdown-toggle' data-toggle='dropdown' href='#'>
                                 <i class='glyphicon glyphicon-user'></i>&nbsp;Account
                                 <b class='caret'></b>
                                 </a>
                                 <ul class='dropdown-menu'>
                                """
                navcontents += "<li><a href='#uploadModal' data-toggle='modal'><i class='glyphicon glyphicon-upload'></i>&nbsp;Upload New Story</a></li>"
                if 'admin' in user['roles'] :
                    navcontents += "<li><a href='#newAccountModal' data-toggle='modal'><i class='glyphicon glyphicon-plus-sign'></i>&nbsp;New Account</a></li>"
                navcontents += "<li><a href=\"BOOTDEST/account\"><i class='glyphicon glyphicon-user'></i>&nbsp;Preferences</a></li>\n"
                navcontents += "<li><a href=\"BOOTDEST/disconnect\"><i class='glyphicon glyphicon-off'></i>&nbsp;Disconnect</a></li>\n"
                navcontents += "<li><a href='#aboutModal' data-toggle='modal'><i class='glyphicon glyphicon-info-sign'></i>&nbsp;About</a></li>\n"
                navcontents += "<li><a href=\"BOOTDEST/help\"><i class='glyphicon glyphicon-question-sign'></i>&nbsp;Help</a></li>\n"
                navcontents += "</ul>"
                navcontents += "</li>"
            else :
                navcontents += """
                    <li><a id='connectpop'>Connect!</a></li>
                """
    
        if req.action == "index" :
            mpath = req.uri + relative_prefix_suffix
            bootstrappath = req.uri + relative_prefix_suffix + "/bootstrap"
        else :
            mpath = req.uri + "/.." + relative_prefix
            bootstrappath = req.uri + "/.." + relative_prefix + "/bootstrap"
    
        replacements = [    
                         navcontents, 
                         newaccountadmin,
                         "[MICA LEARNING]" if req.session.value['connected'] else "Disconnected",
                         cloudcontents,
                         availablecontents,
                         body,
                         popoveractivate if (not req.session.value["connected"] and not req.skip_show) else "",
                         spinner,
                         req.dest,
                         req.active if req.active else "",
                         req.active_obj[:-1] if req.active_obj else "",
                         bootstrappath,
                         mpath,
                         req.session.value['last_username'] if 'last_username' in req.session.value else '',
                         req.session.value['last_remember'] if 'last_remember' in req.session.value else '',
                      ]
    
        if not nodecode :
            for idx in range(0, len(self.replacement_keys)) :
                x = replacements[idx]
                y = self.replacement_keys[idx]
                contents = contents.replace(y, x)
    
        return contents

    
    def online_cross_reference(self, uuid, name, story, all_source, cjk) :
        mdebug("Going online...")
        ms = []
        eng = []
        trans = []
        source = []
        pinyin = []
        groups = []
        reversep = []

        msg = "source: \n"
        idx = 0
        for char in all_source :
           source.append(char)
           cr = cjk.getReadingForCharacter(char,'Pinyin')
           if not cr or not len(cr) :
               py = convertPinyin(get_pinyin(char))
           else :
               py = cr[0]
           pinyin.append(py)
           msg += " " + py + "(" + char + "," + str(idx) + ")"
           idx += 1

#        mdebug(msg.replace("\n",""))

#        minfo("translating chinese to english....")
        result = self.translate_and_check_array([all_source], u"en")
#        mdebug("english translation finished." + str(result))

        if not len(result) or "TranslatedText" not in result[0] :
            return []
        
        msenglish = result[0]["TranslatedText"]

#        mdebug("english is: " + str(msenglish))
        msenglish = msenglish.split(" ")

#        mdebug("Translating english pieces back to chinese")
        result = self.translate_and_check_array(msenglish, u"zh-CHS")
#        mdebug("Translation finished. Writing in json.")

        for idx in range(0, len(result)) :
            ms.append((msenglish[idx], result[idx]["TranslatedText"]))

        count = 0
        for idx in range(0, len(ms)) :
           pair = ms[idx]
           eng.append(pair[0])
           for char in pair[1] :
               trans.append(char)
               groups.append((idx,char))
               cr = cjk.getReadingForCharacter(char,'Pinyin')
               if not cr or not len(cr) :
                   py = convertPinyin(get_pinyin(char))
               else :
                   py = cr[0]
               reversep.append(py)
               count += 1

        matches = lcs(source,trans)

        current_source_idx = 0
        current_trans_idx = 0
        current_eng_idx = 0
        units = []

        tmatch = ""
        match_pinyin = ""
        for triple in matches :
          char, source_idx, trans_idx = triple
#          mdebug("orig idx " + str(source_idx) + " trans idx " + str(trans_idx) + " => " + char)
          pchar = convertPinyin(get_pinyin(char))
          tmatch += " " + pchar + "(s" + str(source_idx) + ",t" + str(trans_idx) + "," + char + ")"
          match_pinyin += pchar + " "

#        mdebug("matches: \n" + tmatch.replace("\n",""))
          
        for triple in matches :
          char, source_idx, trans_idx = triple
          pchar = convertPinyin(get_pinyin(char))
          
          if source_idx > current_source_idx :
              # only append if there's something in the source
              units.append(make_unit(source_idx, current_source_idx, trans_idx, current_trans_idx, groups, reversep, eng, source, pinyin, [])) 
          current_source_idx = source_idx
          current_trans_idx = trans_idx

          units.append(make_unit(source_idx + 1, current_source_idx, trans_idx + 1, current_trans_idx, groups, reversep, eng, source, pinyin, [match_pinyin]))

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
                    new_unit = copy.deepcopy(units[idx])
                    if new_unit["trans"] :
                        new_english = []
                        for word in new_unit["english"] :
                           word = strip_punct(word)
                           if not len(new_english) or strip_punct(new_english[-1]) != word :
                               new_english.append(word)
                        new_unit["english"] = new_english
    
                    all_punctuation = True
                    for char in new_unit["source"] :
                        if char not in punctuation :
                            all_punctuation = False
                            break
    
                    if all_punctuation :
                        new_unit["trans"] = False
                        new_unit["english"] = ""
                    else :
                        append_units = []
                        for fidx in range(idx + 1, min(idx + 2, len(units))) :
                            unit = units[fidx]
                            if not unit["trans"] :
                               continue
                            all_equal = True
                            for worda in new_unit["english"] :
                                for wordb in unit["english"] :
                                    if strip_punct(worda) != strip_punct(wordb) :
                                        all_equal = False
                                        break
    
                            if not all_equal :
                                if strip_punct(unit["english"][0]) == strip_punct(new_unit["english"][-1]) :
                                    all_equal = True
    
                            if all_equal :
                               idx += 1
                               append_units.append(unit)
    
                        if len(append_units) :
                            changes = True
    
                        for unit in append_units :
                            for char in unit["source"] :
                                new_unit["source"].append(char)
                            for pinyin in unit["spinyin"] :
                                new_unit["spinyin"].append(pinyin)
                            for pair in unit["trans"] :
                                if new_unit["trans"] :
                                    new_unit["trans"].append(pair)
                                else :
                                    new_unit["trans"] = [pair]
                            for pinyin in unit["tpinyin"] :
                                if "tpinyin" in new_unit :
                                    new_unit["tpinyin"].append(pinyin)
                                else :
                                    new_unit["tpinyin"] = [pinyin]
                            if unit["trans"] :
                                for word in unit["english"] :
                                    word = strip_punct(word)
                                    if not len(new_unit["english"]) or strip_punct(new_unit["english"][-1]) != word :
                                        new_unit["english"].append(word)
                    new_units.append(new_unit)
                    idx += 1
                units = new_units
                passes += 1
    
            msg = ""
            for unit in new_units :
                all_punctuation = True
                for char in unit["source"] :
                    if char not in punctuation :
                        all_punctuation = False
                        break
                #for char in unit["source"] :
                #    msg += " " + char
                for pinyin in unit["spinyin"] :
                    if all_punctuation :
                        msg += pinyin
                    else :
                        msg += " " + pinyin 
                if unit["trans"] :
                    msg += "("
                    #for pair in unit["trans"] :
                    #    msg += " " + pair[1]
                    #for pinyin in unit["tpinyin"] :
                    #    msg += " " + pinyin 
                    for word in unit["english"] :
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

    def add_unit(self, trans, uni_source, eng, online = False, punctuation = False) :
        unit = {}
        unit["spinyin"] = trans
        unit["source"] = []
        unit["multiple_spinyin"] = []
        unit["multiple_english"] = []
        unit["multiple_correct"] = -1
        for char in uni_source : 
            unit["source"].append(char)
        if trans == u'' :
            unit["trans"] = False
            unit["english"] = []
        else :
            unit["trans"] = True 
            unit["english"] = eng

        unit["online"] = online
        unit["punctuation"] = punctuation
        return unit

    def get_first_translation(self, d, char, pinyin, none_if_not_found = True, debug = False) :
        eng = []
        temp_r = d.getFor(char)
        if debug :
            mdebug("CJK result: " + str(temp_r))
        for tr in temp_r :
            if debug :
                mdebug("CJK iter result: " + str(tr))
            if not pinyin or tr[2].lower() == pinyin.lower() :
                eng.append("" + tr[3])
                if not pinyin :
                    break
            
        if len(eng) == 0 :
            if none_if_not_found :
                return ["No english translation found."]
            return False
        
        return eng
     
    def get_polyphome_hash(self, correct, source) :
        return hashlib.md5(str(correct).lower() + "".join(source).encode("utf-8").lower()).hexdigest()

    def rehash_correct_polyphome(self, unit):
        unit["hash"] = self.get_polyphome_hash(unit["multiple_correct"], unit["source"])

    def recursive_translate(self, req, uuid, name, story, cjk, cjkdb, d, uni, temp_units, page) :
        units = []
        
        mdebug("Requested: " + uni)
        if uni == "人家" :
            mdebug("Found our breakpoint")

        all_punct = True
        for char in uni :
            if len(uni) and char not in punctuation :
                all_punct = False
                break
            
        if all_punct :
            units.append(self.add_unit([uni], uni, [uni], punctuation = True))
        else :
            trans = []
            eng = []

            for e in d.getFor(uni) :
                trans.append(e[2])
                eng.append(e[3])

            if len(trans) == 1 :
                unit = self.add_unit(trans[0].split(" "), uni, [eng[0]])
                units.append(unit)
            elif len(trans) == 0 :
                if len(uni) > 1 :
                    for char in uni :
                        self.recursive_translate(req, uuid, name, story, cjk, cjkdb, d, char, temp_units, page)
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
                    online_units = self.online_cross_reference(uuid, name, story, uni, cjk) if len(uni) > 1 else False
                    if not online_units or not len(online_units) :
                        eng = self.get_first_translation(d, uni, readings[0])
                        unit = self.add_unit([readings[0]], uni, [eng[0]])
                        for x in readings :
                            eng = self.get_first_translation(d, uni, x, False)
                            if not eng :
                                continue
                            for e in eng :
                                unit["multiple_spinyin"].append([x])
                                unit["multiple_english"].append([e])
                        
                        if unit["multiple_correct"] == -1 :
                            source = "".join(unit["source"])
                            total_changes = 0.0
                            changes = False
                            highest = -1
                            highest_percentage = -1.0
                            selector = -1
                            
                            changes = self.db[self.tones(req, source)]
                            
                            if changes :
                                total_changes = float(changes["total"])

                                for idx in range(0, len(unit["multiple_spinyin"])) :
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
                                
                                for idx in range(0, len(unit["multiple_spinyin"])) :
                                    comb_eng = " ".join(unit["multiple_english"][idx])
                                    
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
                                unit["spinyin"] = unit["multiple_spinyin"][selector]
                                unit["english"] = unit["multiple_english"][selector]
                                unit["multiple_correct"] = selector 

                        units.append(unit)
                    else :
                        for unit in online_units :
                           if len(unit["match_pinyin"]) :
                               unit["spinyin"] = unit["match_pinyin"]
                           if len(unit["spinyin"]) == 1 and unit["spinyin"][0] == u'' :
                               continue
                           units.append(unit)
                else :
                    eng = self.get_first_translation(d, uni, readings[0])
                    units.append(self.add_unit(readings[0].split(" "), uni, [eng[0]]))
        
        for unit in units :
            if len(unit["spinyin"]) == 1 and unit["spinyin"][0] == u'' :
               continue

            self.rehash_correct_polyphome(unit)
            mdebug(("Translation: (" + "".join(unit["source"]) + ") " + " ".join(unit["spinyin"]) + ":" + " ".join(unit["english"])).replace("\n",""))
            
        if temp_units :
            story["temp_units"] = story["temp_units"] + units
        else :
            story["pages"][page]["units"] = story["pages"][page]["units"] + units

    def get_cjk_handle(self, location) :
        cjk = CharacterLookup('C')
        if location : 
            mdebug("Opening CEDICT from: " + location)
            cjkdb = getDBConnector({'sqlalchemy.url': 'sqlite:///' + location, 'attach': ['cjklib']})
        else :
            mdebug("Opening CEDICT from default location.")
            cjkdb = getDBConnector({'sqlalchemy.url': 'sqlite://', 'attach': ['cjklib']})
        d = CEDICT(dbConnectInst = cjkdb)
        return (cjk, cjkdb, d)

    def parse_page(self, req, uuid, name, story, groups, page, temp_units = False) :
        (cjk, cjkdb, d) = self.get_cjk_handle(self.cjklocation)

        if temp_units :
            story["temp_units"] = []
        else :
            if "pages" not in story :
                story['pages'] = {}
            story["pages"][page] = {}
            story["pages"][page]["units"] = []

        for idx in range(0, len(groups)) :
            group = groups[idx]
            try :
                uni = unicode(group.strip() if (group != "\n" and group != u'\n') else group, "utf-8")
            except UnicodeDecodeError, e :
                mwarn("Should we toss this group? " + str(group) + ": " + str(e))
                raise e
            self.recursive_translate(req, uuid, name, story, cjk, cjkdb, d, uni, temp_units, page)

            if idx % 10 == 0 :
                self.transmutex.acquire()
                try :
                    tmpstory = self.db[self.story(req, name)]
                    tmpstory["translating_current"] = idx 
                    tmpstory["translating_page"] = int(page)
                    tmpstory["translating_total"] = len(groups)
                    self.db[self.story(req, name)] = tmpstory
                except couch_adapter.ResourceConflict, e :
                    mdebug("Failure to sync translating_current. No big deal: " + str(e))
                finally :
                    self.transmutex.release()

    def parse(self, req, uuid, name, story, username, page = False) :
        mdebug("Ready to translate: " + name + ". Counting pages...")
    
        page_inputs = 0
        if "filetype" not in story or story["filetype"] == "txt" :
            page_inputs = 1
        else :
            for result in self.db.view('stories/original', startkey=[req.session.value['username'], name], endkey=[req.session.value['username'], name, {}]) :
                page_inputs = result['value']
       
        assert(page_inputs != 0) 
             
        if page :
            page_start = int(page)
            mdebug("Translating single page starting at " + str(page))
            page_inputs = page_start + 1 
        else :  
            page_start = 0
            nb_pages = self.nb_pages(req, name)
            if nb_pages :
                page_start += nb_pages
                
            if page_start != 0 :
                mdebug("Some pages already translated. Restarting @ offset page " + str(page_start))
        
        self.transmutex.acquire()
        try :
            tmpstory = self.db[self.story(req, name)]
            tmpstory["translating"] = True 
            if not page :
                tmpstory["translated"] = False
                tmpstory["translating_pages"] = page_inputs
            tmpstory["translating_current"] = 0
            tmpstory["translating_total"] = 100
            self.db[self.story(req, name)] = tmpstory
        except Exception, e :
            mdebug("Failure to sync: " + str(e))
        finally :
            self.transmutex.release()

        for iidx in range(page_start, page_inputs) :
            if "filetype" not in story or story["filetype"] == "txt" :
                page_input = self.db[self.story(req, name) + ":original"]["value"]
            else :
                page_input = eval(self.db.get_attachment(self.story(req, name) + ":original:" + str(iidx), "attach"))["contents"]
                
            mdebug("Parsing...")
            try :
                parsed = mica_ictclas.trans(page_input.encode("utf-8"))
            except mica_ictclas.error, e :
                raise e
            mdebug("Parsed result: " + parsed + " for page: " + str(iidx))
            lines = parsed.split("\n")
            groups = []
            for line in lines :
                temp_groups = []
                save_char_group = "" 
                for char_group in line.split(" ") :
                    if char_group not in punctuation_without_newlines :
                        if save_char_group != "" :
                            groups.append(save_char_group)
                            save_char_group = ""
                        groups.append(char_group)
                    else :
                        save_char_group += char_group
                        
                if save_char_group != "" :
                    groups.append(save_char_group)
                    
                groups.append("\n")
            

            self.transmutex.acquire()
            try :
                tmpstory = self.db[self.story(req, name)]
                tmpstory["translating_total"] = len(groups)
                tmpstory["translating_current"] = 1
                tmpstory["translating_page"] = iidx 
                self.db[self.story(req, name)] = tmpstory
            except Exception, e :
                mdebug("Failure to sync: " + str(e))
            finally :
                self.transmutex.release()

            try :
                self.parse_page(req, uuid, name, story, groups, str(iidx))
                online = 0
                offline = 0
                for unit in story["pages"][str(iidx)]["units"] :
                    if not unit["punctuation"] :
                        if unit["online"] :
                            online += 1
                        else :
                            offline += 1 
                mdebug("Translating page " + str(iidx) + " complete. Online: " + str(online) + ", Offline: " + str(offline))
                page_key = self.story(req, name) + ":pages:" + str(iidx)
                if self.db.doc_exist(page_key) :
                    mwarn("WARNING: page " + str(iidx) + " of story " + name + " already exists. Deleting.")
                    del self.db[page_key]
                self.db[page_key] = story["pages"][str(iidx)]
                del story["pages"][str(iidx)]
            except Exception, e :
                for line in traceback.format_exc().splitlines() :
                    merr(line)
                tmpstory = self.db[self.story(req, name)]
                tmpstory["translating"] = False 
                self.db[self.story(req, name)] = tmpstory
                self.db.compact("stories")
                raise e

        self.transmutex.acquire()
        try :
            tmpstory = self.db[self.story(req, name)]
            # What is this for?
            #storydb["stories"][name] = story
            tmpstory["translating"] = False 
            tmpstory["translated"] = True 
            self.db[self.story(req, name)] = tmpstory
        except Exception, e :
            mdebug("Failure to sync: " + str(e))
        finally :
            self.transmutex.release()

        self.transmutex.acquire()
        try :
            tmpstory = self.db[self.story(req, name)]
            if "translated" not in tmpstory or not tmpstory["translated"] :
                for result in self.db.view('stories/allpages', startkey=[req.session.value['username'], name], endkey=[req.session.value['username'], name, {}], stale='update_after') :
                    tmppage = result["key"][2]
                    del self.db[self.story(req, story['name']) + ":pages:" + str(tmppage)]
                    
        except Exception, e :
            mdebug("Failure to sync: " + str(e))
        finally :
            self.transmutex.release()

        self.db.compact("stories")
        minfo("Translation complete.")

    def get_parts(self, unit) :
        py = ""
        english = ""
        if unit["multiple_correct"] == -1 :
            for widx in range(0, len(unit["spinyin"])) :
                word = unit["spinyin"][widx]
                if word == u'\n' or word == '\n':
                    py += word
                elif py != "\n" and py not in punctuation_without_letters :
                    py += word + " "

            if py != u'\n' and py != "\n" :
                py = py.strip()

            if py == u'' :
#                mdebug("Not useful: " + py + " and " + english + " len: " + str(len(unit["spinyin"])))
                return False
            if unit["trans"] :
                english = " ".join(unit["english"])
        else :
            if unit["trans"] :
                py = " ".join(unit["multiple_spinyin"][unit["multiple_correct"]])
                english = " ".join(unit["multiple_english"][unit["multiple_correct"]])

        return py, english


    def get_polyphome_percentage(self, x, total_changes, changes, unit):
        percent = 0

        if total_changes :
            hcode = self.get_polyphome_hash(x, unit["source"])
            if hcode in changes["record"] :
                percent = int(float(changes["record"][hcode]["total_selected"]) / total_changes * 100.0)

        return percent

    def polyphomes(self, req, story, uuid, unit, nb_unit, trans_id, page) :
        out = ""
        out += "\nThis character (" + " ".join(unit["source"]) + ") is polyphonic: (has more than one pronunciation):<br>"
        out += "<table class='table table-hover table-striped' style='font-size: x-small'>"
        out += "<tr><td>Pinyin</td><td>Definition</td><td>Default?</td></tr>"
        source = "".join(unit["source"])

        total_changes = 0.0
        changes = self.db[self.tones(req, source)]
        
        if changes :
            total_changes = float(changes["total"])

        for x in range(0, len(unit["multiple_spinyin"])) :
             spy = " ".join(unit["multiple_spinyin"][x])
             percent = self.get_polyphome_percentage(x, total_changes, changes, unit) 

             out += "<tr><td>" + spy + " (" + str(percent) + " %) </td>"
             out += "<td>" + " ".join(unit["multiple_english"][x]).replace("\"", "\\\"").replace("\'", "\\\"").replace("/", " /<br/>") + "</td>"
             if unit["multiple_correct"] != -1 and x == unit["multiple_correct"] :
                 out += "<td>Default</td>"
             else :
                 out += "<td><a style='font-size: x-small' class='btn-default btn-xs' " + \
                        "onclick=\"multiselect('" + uuid + "', '" + str(x) + "', '" + \
                        str(nb_unit) + "','" + str(trans_id) + "', '" + spy + "', '" + page + "')\">Select</a></td>"

             out += "</tr>"

        out += "</table>"

        return out

    def view_keys(self, req, name, units) :
        source_queries = []
        for unit in units :
            if name == "memorized" :
                if "hash" in unit :
                    source_queries.append(unit["hash"])
            else :
                source_queries.append("".join(unit["source"]))
            
        keys = {}
        for result in self.db.view(name + "/all", keys = source_queries, username = req.session.value['username']) :
            keys[result['key'][1]] = result['value']
        
        return keys
        
    def history(self, req, story, uuid, page) :
        out = ""
        history = []
        found = {}
        tid = 0
        online = 0
        offline = 0
        page_dict = self.db[self.story(req, story['name']) + ":pages:" + str(page)]
        units = page_dict["units"]

        tone_keys = self.view_keys(req, "tonechanges", units) 
        
        for unit in units :
            char = "".join(unit["source"])
            if char not in found :
                if "punctuation" not in unit or not unit["punctuation"] :
                    if "online" in unit and unit["online"] :
                        online += 1
                    else :
                        offline += 1
                        
            changes = False if char not in tone_keys else tone_keys[char]
            
            if not changes :
                continue
            if unit["hash"] not in changes["record"] :
                continue
            record = changes["record"][unit["hash"]]
            if char not in found :
                found[char] = True
                history.append([char, str(changes["total"]), " ".join(record["spinyin"]), " ".join(record["english"]), tid])
                        
            tid += 1
        
        # Add sort options here
        def by_total( a ):
            return int(float(a[1]))

        history.sort( key=by_total, reverse = True )

        out += "Breakdown: Online: " + str(online) + ", Offline: " + str(offline) + "<p/>\n"
        out += "<div class='panel-group' id='panelHistory'>\n"
        
        for x in history :
            out += """
                <div class='panel panel-default'>
                  <div class="panel-heading">
                  """

            char, total, spy, eng, tid = x
            tid = str(tid)

            if len(eng) and eng[0] == '/' :
               eng = eng[1:-1]

            out += char + " (" + str(int(float(total))) + "): "

            out += "<a class='panel-toggle' style='display: inline' data-toggle='collapse' data-parent='#panelHistory'" + tid + " href='#collapse" + tid + "'>"

            out += "<i class='glyphicon glyphicon-arrow-down' style='size: 50%'></i>&nbsp;" + spy

            out += "</a>"
            out += "</div>"
            out += "<div id='collapse" + tid + "' class='panel-body collapse'>"
            out += "<div class='panel-inner'>" + eng.replace("\"", "\\\"").replace("\'", "\\\"").replace("/", " /<br/>") + "</div>"

            out += "</div>"
            out += "</div>"

        out += "</div>"

        return out

    def edits(self, req, story, uuid, page) :
        out = ""

        history = []
        found = {}
        tid = 0
        page_dict = self.db[self.story(req, story['name']) + ":pages:" + str(page)]
        units = page_dict["units"]

        merge_keys = self.view_keys(req, "mergegroups", units) 
        split_keys = self.view_keys(req, "splits", units) 
            
        for unit in units :
            char = "".join(unit["source"])
            if char in punctuation_without_letters or len(char.strip()) == 0:
                continue
            if char in found :
                continue

            changes = False if char not in split_keys else split_keys[char]
            
            if changes :
                if unit["hash"] not in changes["record"] :
                    continue
                record = changes["record"][unit["hash"]]
                history.append([char, str(record["total_splits"]), " ".join(record["spinyin"]), " ".join(record["english"]), tid, "<div style='color: blue; display: inline'>SPLIT&nbsp;&nbsp;&nbsp;</div>"])
            else: 
                changes = False if char not in merge_keys else merge_keys[char]
                
                if changes : 
                    if "hash" not in unit :
                        continue
                    if unit["hash"] not in changes["record"] :
                        continue
                    record = changes["record"][unit["hash"]]
                    memberlist = "<table class='table'>"
                    nb_singles = 0
                    for key, member in record["members"].iteritems() :
                        if len(key) == 1 :
                            nb_singles += 1
                            continue
                        memberlist += "<tr><td>" + member["pinyin"] + ":</td><td>" + key + "</td></tr>"
                    memberlist += "</table>\n"
                    if nb_singles == len(record["members"]) :
                        continue
                    history.append([char, str(changes["total"]), " ".join(record["spinyin"]), memberlist, tid, "<div style='color: red; display: inline'>MERGE</div>"])
                else :
                    continue

            if char not in found :
                found[char] = True
            tid += 1
        
        # Add sort options here
        def by_total( a ):
            return int(float(a[1]))

        history.sort( key=by_total, reverse = True )

        out += """
            <h5>Edit Legend:</h5>
            <p/>
            <table>
            <tr><td class='mergetop mergebottom mergeleft mergeright' style='vertical-align: top'>These characters were previously merged into a word</td></tr>
            <tr><td><p/></td></tr>
            <tr><td class='splittop splitbottom splitleft splitright' style='vertical-align: top'>This word was previously split into characters</td></tr>
            </table>
            <p/>
            """
        out += "<a href='#' class='btn btn-info' onclick=\"process_edits('" + uuid + "', 'all', true)\">Try Recommendations</a>\n<p/>\n"
        out += "<a href='BOOTDEST/" + req.action + "?retranslate=1&uuid=" + uuid + "&page=" + str(page) + "' class='btn btn-info'>Re-translate page</a>\n<p/>\n"
        if len(history) != 0 :
            out += """
                <div class='panel-group' id='panelEdit'>
                """
            
            for x in history :
                out += """
                    <div class='panel panel-default'>
                      <div class="panel-heading">
                      """

                char, total, spy, result, tid, op = x
                tid = str(tid)

                if len(result) and result[0] == '/' :
                   result = result[1:-1]

                out +=  op + " (" + str(total) + "): " + char + ": "

                out += "<a class='panel-toggle' style='display: inline' data-toggle='collapse' data-parent='#panelEdit' href='#collapse" + tid + "'>"

                out += "<i class='glyphicon glyphicon-arrow-down' style='size: 50%'></i>&nbsp;" + spy

                out += "</a>"
                out += "</div>"
                out += "<div id='collapse" + tid + "' class='panel-body collapse'>"
                out += "<div class='panel-inner'>" + result + "</div>"

                out += "</div>"
                out += "</div>"

            out += "</div>"
        else :
            out += "<h4>No edit history available.</h4>"

        return out

    def view(self, req, uuid, name, story, action, start_page, view_mode) :
        if not story["translated"] :
            return "Untranslated story! Ahhhh!"

        output = "<div class='row-fluid'>\n"
        output += "<div class='col-lg-12'>\n"
        output += """
                        <div class='row-fluid'>
                            <div class='col-lg-10'>
                                <div class='row-fluid'>
                                    <!-- this '12' is not intuitive, but it
                                    indicates the start of a new fluid
                                    nesting level that also is subdivided by
                                    units of 12 -->
                                    <div class='col-lg-12'>
                                        <div data-spy='affix' data-offset-top='55' data-offset-bottom='0' id='readingheader'>
                                        <div id='translationstatus'></div>
                                        <table><tr>
                                        <td><div style='display: inline' id='pagenav'></div></td>
                                        </tr></table>
                                        <script>installreading();</script>
                                        </div>
                                    </div><!-- col-lg-10 header section -->
                                </div><!-- row for header section -->
                                <div id='pagecontent' class='row-fluid'></div>
                            </div><!-- outer md-9 all section --> 

                """

        output += """
                            <div class='col-lg-2'>
                            <!--data-spy='affix'--><div  data-offset-top='55' data-offset-bottom='0' id='statsheader'>
                """
        output += "         <div id='instantspin' style='display: none'>Doing online translation..." + spinner + "</div>"
        output += "<h4><b>" + name + "</b></h4>"

        if action in ["read"] :
            output += "<div id='memolist'>" + spinner + "&nbsp;<h4>Loading statistics</h4></div>"
        elif action == "edit" :
            output += "<div id='editslist'>" + spinner + "&nbsp;<h4>Loading statistics</h4></div>"
        elif action == "home" :
            output += "<br/>Polyphome Legend:<br/>"
            output += self.template("legend")
            output += """
                <br/>
                Polyphome Change History:<br/>
            """
            output += "<div id='history'>" + spinner + "&nbsp;<h4>Loading statistics</h4></div>"

        output += "</div><!-- statsheader -->"
        output += "</div><!-- col-lg-2 stats section -->\n"
        output += "</div><!-- col-lg-12 for everything section -->\n"
        output += "</div><!-- row for everything -->\n"
        output += "<script>install_pages('" + action + "', " + str(self.nb_pages(req, name)) + ", '" + uuid + "', " + start_page + ", '" + view_mode + "');</script>"
        
        return output

    def nb_pages(self, req, name):
        nb_pages = 0
        for result in self.db.view('stories/pages', startkey=[req.session.value['username'], name], endkey=[req.session.value['username'], name, {}]) :
            nb_pages = result['value']
        return nb_pages

    def view_page(self, req, uuid, name, story, action, output, page, disk = False) :
        mdebug("View Page " + str(page) + " story " + name + " start...")
        page_dict = self.db[self.story(req, name) + ":pages:" + str(page)]
        mdebug("View Page " + str(page) + " story " + name + " fetched...")
        units = page_dict["units"]
        chars_per_line = 60
        words = len(units)
        lines = [] 
        line = [] 

        trans_id = 0
        chars = 0
        batch = -1

        mdebug("View Page " + str(page) + " story " + name + " building...")
        source_queries = []
        hash_queries = []
        un = req.session.value['username']
        for unit in units :
            source_queries.append([un, "".join(unit["source"])])
            if "hash" in unit :
                hash_queries.append([un, unit["hash"]])         
            
        mdebug("View Page " + str(page) + " story " + name + " querying...")
        
        sources = {}

        if action == "edit" :
            sources['mergegroups'] = self.view_keys(req, "mergegroups", units) 
            sources['splits'] = self.view_keys(req, "splits", units) 

        if action == "home" :
            sources['tonechanges'] = self.view_keys(req, "tonechanges", units) 
        if action == "read" :
            sources['memorized'] = self.view_keys(req, "memorized", units) 
        
        for x in range(0, len(units)) :
            unit = units[x]

            source = "".join(unit["source"])

            ret = self.get_parts(unit)

            if ret == False :
                continue

            py, english = ret

            if py not in punctuation_without_letters and chars >= chars_per_line :
               lines.append(line)
               line = []
               chars = 0

            if py in (punctuation_without_letters + ['\n', u'\n']) :
                if py != u'\n' and py != "\n":
                    line.append([py, False, trans_id, [], x, source])
                    chars += 1
                else :
                    lines.append(line)
                    line = []
                    chars = 0
            else :
                chars += len(py)
                p = [english, py, trans_id, unit, x, source]
                line.append(p)

            trans_id += 1

        if len(line) :
            lines.append(line)

        mdebug("View Page " + str(page) + " story " + name + " grouped...")
        
        # TODO: The rest of the code involed in viewing a page is just a bunch of
        # loops. We have already finished querying the database and are simply
        # splicing together content.
        # 
        # Nevertheless, putting together this content, even purely in memory
        # is by far the largest source of overhead that we have. I definitely
        # think the next optimization would be to cache this content and
        # build it offline during translation time and then refresh the rendered
        # page each time we perform edits.
        #
        # But even during the edit process, the time to perform individual
        # page renders here is incredibly slow if we have to render each page again.
        #
        # The final solution may be to abandon building the page altogether
        # and just send json to the client browser, but that's a problem to
        # be solved for another day.....
        # 
        # Anothers solution may be to incrementally update portions of
        # the page instead of the whole page.
        #
        # Another solution may be to attach HTML elements to the individual
        # units of the page without re-generating them from scratch as each
        # unit changes, but the problem there is that pages are not yet
        # grouped into lines (nor can they be statically if we're dealing
        # with free-flowing text.
        #
        # But at a minimum, we may at least be able to attach the unique
        # HTML for those modified units into the page dictionary and then
        # worry about line-groupings later....
        # 
        # Each unit would need to have a rendered HTML chunk for all three
        # modes for which the unit could be viewed.
        
        spacer = "<td style='margin-right: 20px'></td>"
        merge_spacer = "<td class='mergetop mergebottom' style='margin-right: 20px'></td>"
        merge_end_spacer = "<td class='mergeleft' style='margin-right: 20px'></td>"

        for line in lines :
            disk_out = ""
            line_out = ""

            if not disk :
                line_out += "\n<table>"
                line_out += "\n<tr>"

                prev_merge = False
                for word_idx in range(0, len(line)) :
                    word = line[word_idx]
                    english = word[0].replace("\"", "\\\"").replace("\'", "\\\"")
                    py = word[1]
                    trans_id = str(word[2])
                    unit = word[3]
                    tid = unit["hash"] if py else trans_id 
                    nb_unit = str(word[4])
                    source = word[5]
                    curr_merge = False
                    merge_end = False
                    use_batch = False
                    skip_prev_merge = False

                    line_out += "\n<td style='vertical-align: top; text-align: center; font-size: small' "

                    if py and action == "edit" :
                        sourcegroup = False if source not in sources['mergegroups'] else sources['mergegroups'][source]
                        
                        if sourcegroup and unit["hash"] in sourcegroup["record"] :
                            curr_merge = True

                            if word_idx < (len(line) - 1) :
                                endword = line[word_idx + 1]
                                if endword[1] :
                                    endunit = endword[3]
                                    endchars = "".join(endunit["source"])
                                    endgroup = self.db[self.merge(req, endchars)]
                                    if not endgroup or (endunit["hash"] not in endgroup["record"]) :
                                        merge_end = True
                                    else :
                                        end_members = endgroup["record"][endunit["hash"]]["members"]
                                        curr_members = sourcegroup["record"][unit["hash"]]["members"]
                                        source_found = False
                                        end_found = False
                                        for mchars, member in end_members.iteritems() :
                                            if source in mchars :
                                                source_found = True
                                        for mchars, member in curr_members.iteritems() :
                                            if endchars in mchars :
                                                end_found = True
                                                
                                        if not end_found or not source_found :
                                            #mdebug(source + " (" + str(py) + ") and " + endchars + " are not related to each other!")
                                            merge_end = True
                                            skip_prev_merge = True
                                            
                                else :
                                    merge_end = True


                    if py and action == "edit" :
                        if curr_merge :
                            if (word_idx == (len(line) - 1)) or (curr_merge and not prev_merge and merge_end ): 
                                merge_end = False
                                prev_merge = False
                                curr_merge = False

                        if curr_merge :
                            line_out += "class='mergetop mergebottom"
                            if not prev_merge : 
                                batch += 1
                                line_out += " mergeleft"
                            line_out += "'"
                            use_batch = "merge" 
                        else :
                            if not curr_merge :
                                sourcesplits = False if source not in sources['splits'] else sources['splits'][source]
                                if sourcesplits and unit["hash"] in sourcesplits["record"] :
                                    batch += 1
                                    use_batch = "split" 
                                    line_out += "class='splittop splitbottom splitleft splitright'"

                        prev_merge = curr_merge if not skip_prev_merge else False

                    line_out += ">"
                    line_out += "<span id='spanselect_" + trans_id + "' class='"
                    line_out += "batch" if use_batch else "none"
                    line_out += "'>"
                    line_out += "<a class='trans'"
                    line_out += " uniqueid='" + tid + "' "
                    line_out += " nbunit='" + nb_unit + "' "
                    line_out += " transid='" + trans_id + "' "
                    line_out += " batchid='" + (str(batch) if use_batch else "-1") + "' "
                    line_out += " operation='" + (str(use_batch) if use_batch else "none") + "' "
                    line_out += " page='" + page + "' "
                    line_out += " pinyin=\"" + (py if py else english) + "\" "
                    line_out += " index='" + (str(unit["multiple_correct"]) if py else '-1') + "' "
                    line_out += " style='color: black; font-weight: normal' "
                    line_out += " onclick=\"select_toggle('" + trans_id + "')\">"
                    line_out += source if py else english
                    line_out += "</a>"
                    line_out += "</span>"
                    line_out += "</td>"

                    if py :
                        if action == "edit" and merge_end :
                            # mergeright
                            line_out += merge_end_spacer 
                        elif action == "edit" and curr_merge :
                            line_out += merge_spacer 
                        else :
                            line_out += spacer 

                line_out += "</tr>\n<tr>"

            for word in line :
                english = word[0].replace("\"", "\\\"").replace("\'", "\\\"")
                py = word[1]
                unit = word[3]
                trans_id = str(word[2])
                tid = unit["hash"] if py else trans_id 
                nb_unit = str(word[4])
                source = word[5]
                line_out += "\n<td style='vertical-align: top; text-align: center; font-size: small'>"
                if py and (py not in punctuation) :
                    if not disk :
                        line_out += "<a class='trans' "

                        add_count = ""
                        if action == "home" :
                            color = ""
                            if py and len(unit["multiple_spinyin"]) :
                                color = "green"

                            changes = False if source not in sources['tonechanges'] else sources['tonechanges'][source]
                            
                            if changes :
                                if unit["hash"] in changes["record"] :
                                    color = "black"
                                    add_count = " (" + str(int(changes["total"])) + ")"

                            if color != "black" and py and len(unit["multiple_spinyin"]) :
                                fpy = " ".join(unit["multiple_spinyin"][0])
                                for ux in range(1, len(unit["multiple_spinyin"])) :
                                     upy = " ".join(unit["multiple_spinyin"][ux])
                                     if upy != fpy :
                                         color = "red"
                                         break

                            if color != "" :
                                line_out += " style='color: " + color + "' "
                        elif py :
                            line_out += " style='color: black' "

                        line_out += " id='ttip" + trans_id + "'"

                        if action in ["read","edit"] or not(len(unit["multiple_spinyin"])) :
                            line_out += " onclick=\"toggle('" + tid + "', "
                            line_out += ("0" if action == "read" else "1") + ")\""

                        line_out += ">"
                        line_out += ((py if py else english).lower()) + add_count 
                        line_out += "</a>"
                    else :
                        disk_out += (py if py else english).lower()
                else :
                    if disk :
                        disk_out += (py if py else english).lower()
                    else :
                        line_out += (py if py else english).lower()

                if not disk :
                    line_out += "<br/>"

                    if action == "home" and py and len(unit["multiple_spinyin"]) :
                        line_out += "<div style='display: none' id='pop" + str(trans_id) + "'>"
                        line_out += self.polyphomes(req, story, uuid, unit, nb_unit, trans_id, page)
                        line_out += "</div>"
                        line_out += "<script>"
                        line_out += "multipopinstall('" + str(trans_id) + "', 0);\n"
                        line_out += "</script>"

                    line_out += "</td>"

                    if py :
                        line_out += spacer
                else :
                    disk_out += " "

            if disk :
                disk_out += "\n"
            else :
                line_out += "</tr>"
                line_out += "<tr>"

            if not disk :
                for word in line :
                    english = word[0]
                    if len(english) and english[0] == '/' :
                        english = english[1:-1]
                    unit = word[3]
                    nb_unit = str(word[4])
                    py = word[1]
                    source = word[5]
                    memorized = False
                    
                    if py and action == 'read' :
                        if unit["hash"] in sources['memorized'] :
                            memorized = True
                            
                    tid = unit["hash"] if py else str(word[2])
                    line_out += "<td style='vertical-align: top; text-align: center'>"
                    line_out += "<table><tr>"
                    line_out += "<td><div style='display: none' class='memory" + tid + "'>" + spinner + "</div></td>"
                    line_out += "</tr><tr><td>"
                    '''
                    if action == "home" :
                        line_out += ("".join(unit["source"]) if py else "")
                    '''
                    line_out += "<div class='trans trans" + tid + "' style='display: "
                    line_out += "block" if (action == "read" and not memorized) else "none"
                    line_out += "' id='trans" + tid + "'>"
                    if py :
                        if action in ["read", "edit"] :
                            line_out += "<a class='trans' onclick=\"memorize('" + \
                                        tid + "', '" + uuid + "', '" + str(nb_unit) + "', '" + page + "')\">"

                        line_out += english.replace("/"," /<br/>")
                        if action in [ "read", "edit" ] :
                            line_out += "</a>"

                    line_out += "<br/>"
                    line_out += "</div>"
                    line_out += "<div style='display: "
                    line_out += "none" if (action in ["read", "edit"] and not memorized) else "block"
                    line_out += "' class='trans blank" + tid + "'>"
                    line_out += "&nbsp;</div>"
                    line_out += "</td>"
                    line_out += "</tr></table>"
                    line_out += "</td>"
                    if py :
                        line_out += "<td>&nbsp;</td>"
                line_out += "</tr>"
                line_out += "</table>"

            if not disk :
                output += line_out
            else :
                output += disk_out

        mdebug("View Page " + str(page) + " story " + name + " complete.")
        return output

    def translate_and_check_array(self, requests, lang) :
        again = True 

        self.mutex.acquire()

        try : 
            result = self.client.translate_array(requests, lang)
            if not len(result) or "TranslatedText" not in result[0] :
                mdebug("Probably key expired: " + str(result))
            else :
                again = False 
        except ArgumentOutOfRangeException, e :
            merr("Missing results. Probably we timed out. Trying again: " + str(e))
        except TranslateApiException, e :
            merr("First-try translation failed: " + str(e))
        except IOError, e :
            merr("Connection error. Will try one more time:" + str(e))

        finally :
            finished = not again
            error = ""
            if again :
                try : 
                    self.client.access_token = self.client.get_access_token()
                    result = self.client.translate_array(requests, lang)
                    if len(result) and "TranslatedText" in result[0] :
                        mdebug("Finished this translation on second try")
                        finished = True
                    else :
                        error = "Second try failed: " + str(result)
                        mdebug(error)
                        raise Exception(error)
                except Exception, e :
                    error = str(e)
                    mdebug("Second try still failed: " + error )
                    raise Exception(error)

            if not finished :
                result = []
                for x in range(0, len(requests)) :
                    result.append(str("Service is down: " + error))

        self.mutex.release()
        return result
    
    def makestorylist(self, req):
        untrans_count = 0
        reading = self.template("reading")
        noreview = self.template("noreview")
        untrans = self.template("untrans")
        
        items = []
        for result in self.db.view("stories/all", startkey=[req.session.value['username']], endkey=[req.session.value['username'], {}]) :
            tmp_story = result["value"]
            tmp_storyname = tmp_story["name"]
            items.append((tmp_storyname, tmp_story))

        items.sort(key = itemhelp, reverse = True)

        for name, story in items :
            reviewed = not ("reviewed" not in story or not story["reviewed"])
            if isinstance(story['uuid'], tuple) :
                uuid = story['uuid']
                mdebug("skipping UUID: " + uuid[0])
                continue

            if not story["translated"] : 
                untrans_count += 1
                untrans += self.sidestart(req, name, username, story, reviewed)
                untrans += "\n<td style='font-size: x-small' colspan='3'>"
                untrans += "<div id='transbutton" + story['uuid'] + "'>"
                untrans += "<a title='Delete' style='font-size: x-small' class='btn-default btn-xs' onclick=\"trashstory('" + story['uuid'] + "', '" + story["name"] + "')\"><i class='glyphicon glyphicon-trash'></i></a>&nbsp;"
                untrans += "<a style='font-size: x-small' class='btn-default btn-xs' onclick=\"trans('" + story['uuid'] + "')\">Translate</a></div>&nbsp;"
                untrans += "<div style='display: inline' id='translationstatus" + story['uuid'] + "'></div>"
                untrans += "</div>"
                if "translating" in story and story["translating"] :
                    untrans += "\n<script>translist.push('" + story["uuid"] + "');</script>"
                untrans += "</td>"
                untrans += "</tr>"
            else :
                notsure = self.sidestart(req, name, username, story, reviewed)
                notsure += "<td><a title='Forget' style='font-size: x-small' class='btn-default btn-xs' onclick=\"dropstory('" + story['uuid'] + "')\"><i class='glyphicon glyphicon-remove'></i></a></td>"
                notsure += "<td><a title='Review' style='font-size: x-small' class='btn-default btn-xs' href=\"BOOTDEST/home?view=1&uuid=" + story['uuid'] + "\"><i class='glyphicon glyphicon-search'></i></a></td>"
                notsure += "<td><a title='Edit' style='font-size: x-small' class='btn-default btn-xs' href=\"BOOTDEST/edit?view=1&uuid=" + story['uuid'] + "\"><i class='glyphicon glyphicon-pencil'></i></a></td>"
                notsure += "<td><a title='Read' style='font-size: x-small' class='btn-default btn-xs' href=\"BOOTDEST/read?view=1&uuid=" + story['uuid'] + "\"><i class='glyphicon glyphicon-book'></i></a></td>"

                if reviewed :
                   reading += notsure
                   reading += "<td><a title='Review not complete' style='font-size: x-small' class='btn-default btn-xs' onclick=\"reviewstory('" + story['uuid'] + "',0)\"><i class='glyphicon glyphicon-arrow-down'></i></a></td>"
                   reading += "</tr>"
                else :
                   noreview += notsure
                   noreview += "<td><a title='Review Complete' style='font-size: x-small' class='btn-default btn-xs' onclick=\"reviewstory('" + story['uuid'] + "', 1)\"><i class='glyphicon glyphicon-arrow-up'></i></a></td>"
                   noreview += "</tr>"
                   
        return [untrans_count, reading, noreview, untrans] 
    
    # IMPROVE ALL OF THE SUMMARY FUNCTIONS LIKE THESE WITH THE NEW VIEWS
    def memocount(self, req, story, page):
        added = {}
        unique = {}
        progress = []
        total_memorized = 0
        total_unique = 0
        trans_id = 0
        page_dict = self.db[self.story(req, story["name"]) + ":pages:" + str(page)]
        units = page_dict["units"]
        
        memorized = self.view_keys(req, "memorized", units) 

        for x in range(0, len(units)) :
            unit = units[x]
            if "hash" not in unit :
                trans_id += 1
                continue
            ret = self.get_parts(unit)
            if not ret :
                trans_id += 1
                continue
            py, english = ret
            if unit["hash"] in memorized :
                if unit["hash"] not in added :
                    added[unit["hash"]] = unit
                    progress.append([py, english, unit, x, trans_id, page])
                    total_memorized += 1

            if py and py not in punctuation :
                unique[unit["hash"]] = True

            trans_id += 1
        
        total_unique = len(unique)
        if "total_memorized" not in story or story["total_memorized"] != total_memorized :
            story["total_memorized"] = total_memorized
        if "total_unique" not in story or story["total_unique"] != total_unique :
            story["total_unique"] = total_unique 
        
        return [total_memorized, total_unique, unique, progress]

    def add_record(self, req, unit, mindex, which, key) :
        char = "".join(unit["source"])
        hcode = self.get_polyphome_hash(mindex, unit["source"])

        changes = self.db[which(req, char)]
        if not changes :
            changes = {} 
            changes["record"] = {}
        
        changes["source"] = unit["source"]

        if hcode not in changes["record"] :
            hcode_contents = {"total_" + key : 0}
        else :
            hcode_contents = changes["record"][hcode]

        hcode_contents["total_" + key] += 1
        hcode_contents["spinyin"] = unit["multiple_spinyin"][mindex] if mindex != -1 else unit["spinyin"]
        hcode_contents["english"] = unit["multiple_english"][mindex] if mindex != -1 else unit["english"]

        changes["record"][hcode] = hcode_contents

        if "total" not in changes :
            changes["total"] = 0

        changes["total"] += 1

        self.db[which(req, char)] = changes
                
    def operation(self, req, story, edit, offset):
        operation = edit["operation"]
        if operation == "split" :
            nb_unit = int(edit["nbunit"]) + offset
            mindex = int(edit["index"])
            mhash = edit["tid"]
            page = edit["pagenum"]
            page_dict = self.db[self.story(req, story['name']) + ":pages:" + str(page)]
            units = page_dict["units"]
            before = units[:nb_unit] if (nb_unit > 0) else []
            after = units[nb_unit + 1:] if (nb_unit != (len(units) - 1)) else []
            curr = units[nb_unit]
            groups = []

            for char in curr["source"] :
                groups.append(char.encode("utf-8"))

            self.parse_page(req, story['uuid'], story['name'], story, groups, page, temp_units = True)
            page_dict["units"] = before + story["temp_units"] + after
            self.db[self.story(req, story['name']) + ":pages:" + str(page)] = page_dict
            offset += (len(story["temp_units"]) - len(curr))
            del story["temp_units"]
            self.add_record(req, curr, mindex, self.splits, "splits")

        elif operation == "merge" :
            nb_units = int(edit["units"])
            nb_unit_start = int(edit["nbunit0"]) + offset
            mindex_start = int(edit["index0"])
            page = int(edit["page0"]) # all edits should be on the same page
            mhash_start = edit["tid0"]
            mindex_stop = int(edit["index" + str(nb_units - 1)])
            nb_unit_stop = int(edit["nbunit" + str(nb_units - 1)]) + offset
            mhash_stop = edit["tid" + str(nb_units - 1)]
            page_dict = self.db[self.story(req, story['name']) + ":pages:" + str(page)]
            units = page_dict["units"]
            before = units[:nb_unit_start] if (nb_unit_start > 0) else [] 
            after = units[nb_unit_stop + 1:] if (nb_unit_stop != (len(units) - 1)) else [] 
            curr = units[nb_unit_start:(nb_unit_stop + 1)]
            group = ""

            for chargroup in curr :
                for char in chargroup["source"] :
                    group += char.encode("utf-8")

            self.parse_page(req, story["uuid"], story["name"], story, [group], page, temp_units = True)

            if len(story["temp_units"]) == 1 :
                merged = story["temp_units"][0]
                merged_chars = "".join(merged["source"])
                page_dict["units"] = before + [merged] + after
                self.db[self.story(req, story['name']) + ":pages:" + str(page)] = page_dict

                for unit in curr :
                    char = "".join(unit["source"])
                    mindex = unit["multiple_correct"]
                    hcode = self.get_polyphome_hash(mindex, unit["source"])

                    changes = self.db[self.merge(req, char)]
                    if not changes :
                        changes = {} 
                        changes["record"] = {}
                        changes["source"] = unit["source"]

                    if hcode not in changes["record"] :
                        hcode_contents = {}
                        hcode_contents["spinyin"] = unit["multiple_spinyin"][mindex] if mindex != -1 else unit["spinyin"]
                        hcode_contents["english"] = unit["multiple_english"][mindex] if mindex != -1 else unit["english"]
                        hcode_contents["members"] = {}
                    else :
                        hcode_contents = changes["record"][hcode]
    
                    if merged_chars not in hcode_contents["members"] :
                        merged_pinyin = merged["multiple_spinyin"][merged["multiple_correct"]] if merged["multiple_correct"] != -1 else merged["spinyin"]
                        hcode_contents["members"][merged_chars] = { "total_merges" : 0, "pinyin" : " ".join(merged_pinyin)}

                    hcode_contents["members"][merged_chars]["total_merges"] += 1

                    changes["record"][hcode] = hcode_contents

                    if "total" not in changes :
                        changes["total"] = 0

                    changes["total"] += 1

                    self.db[self.merge(req, char)] = changes

                offset += (len(story["temp_units"]) - len(curr))
            if "temp_units" in story :
                del story["temp_units"]
            
        mdebug("Completed edit with offset: " + str(offset))
        return [True, offset]

    def add_story_from_source(self, req, filename, source, filetype) :
        if self.db.doc_exist(self.story(req, filename)) :
            return self.bootstrap(req, self.heromsg + "\nUpload Failed! Story already exists: " + filename + "</div>")
        
        mdebug("Received new story name: " + filename)
        
        if filetype == "txt" :
            mdebug("Source: " + source)

        new_uuid = str(uuid4.uuid4())

        story = {
            'uuid' : new_uuid,
            'translated' : False,
            'name' : filename,
            'filetype' : filetype,
        }
        
        if filetype == "pdf" :
            new_source = {}
            fp = StringIO(source)
            pagenos = set()

            pagecount = 0

            rsrcmgr = PDFResourceManager()
            device = PDFPageAggregator(rsrcmgr, laparams=LAParams())
            interpreter = PDFPageInterpreter(rsrcmgr, device)

            for page in PDFPage.get_pages(fp, pagenos, 0, password='', caching=True, check_extractable=True):
                interpreter.process_page(page)
                layout = device.get_result()

                data2 = []
                images = []
                for obj in layout :
                    sub_data, sub_images = parse_lt_objs(obj, pagecount)
                    data2 += sub_data
                    images += sub_images

                new_page = filter_lines(data2)

                data = "\n".join(new_page)
                mdebug("Page input:\n " + data + " \nfor page: " + str(pagecount))
                de_data = data.decode("utf-8") if isinstance(data, str) else data
                '''
                FIXME: We're not deleting the attachments here properly upon failure.
                '''
                
                self.db.put_attachment(self.story(req, filename) + ":original:" + str(pagecount),
                                        "attach",
                                        str({ "images" : images, "contents" : de_data }), 
                                       )

                pagecount += 1

            device.close()
            fp.close()
        elif filetype == "txt" :
            self.db[self.story(req, filename) + ":original"] = { "value" : source.decode("utf-8") }
        
        self.db[self.story(req, filename)] = story
        self.db[self.index(req, story["uuid"])] = { "value" : filename }

        if "current_story" in req.session.value :
            del req.session.value["current_story"]
            req.session.save()
        if "current_page" in req.session.value :
            del req.session.value["current_page"]
            req.session.save()

        uc = self.heromsg + "\nUpload Complete! Story ready for translation: " + filename + "</div><script>loadstories();</script>"
        self.db.compact("stories")
        return self.bootstrap(req, uc)
        
        
    def flush_pages(self, req, name):
        for result in self.db.view('stories/allpages', startkey=[req.session.value['username'], name], endkey=[req.session.value['username'], name, {}], stale='update_after') :
            tmppage = result["key"][2]
            mdebug("Deleting page " + str(tmppage) + " from story " + name)
            del self.db[self.story(req, name) + ":pages:" + str(tmppage)]
            
        if self.db.doc_exist(self.story(req, name) + ":final") :
            mdebug("Deleting final version from story " + name)
            del self.db[self.story(req, name) + ":final"]
        self.db.compact("stories")

    def common(self, req) :
        try :
            if req.http.params.get("connect") :

                username = req.http.params.get('username')
                password = req.http.params.get('password')

                user = self.db[self.acct(username)]
                auth = True if user else False

                if auth and user["password"] != hashlib.md5(password).hexdigest() :
                    auth = False

                if not auth :
                    return self.bootstrap(req, self.heromsg + "\n<h4>Invalid credentials. Please try again.</h4></div>")

                req.action = "home"
                req.session.value['connected'] = True 

                if req.http.params.get('remember') and req.http.params.get('remember') == 'on' :
                    req.session.value['last_username'] = username
                    req.session.value['last_remember'] = 'checked'
                elif 'last_username' in req.session.value :
                    del req.session.value['last_username']
                    req.session.value['last_remember'] = ''

                req.session.value["username"] = username

                if "current_story" in req.session.value :
                    del req.session.value["current_story"]
                if "current_page" in req.session.value :
                    del req.session.value["current_page"]

                req.session.value["last_refresh"] = str(timest())
                req.session.save()
                
            if 'connected' not in req.session.value or req.session.value['connected'] != True :
                msg = """
                        <h4>You need to connect, first.</h4>
                        <p/>
                        <br/>This is experimental language-learning software,
                        <br/>and thus accounts are granted on-demand.
                        <br/>Contact: <a href="http://michael.hinespot.com">http://michael.hinespot.com</a> for assistance.
                        </div>
                      """
                return self.bootstrap(req, self.heromsg + msg)
                
            username = req.session.value['username']

            if username not in self.first_request :
                self.first_request[username] = True 

                for result in self.db.view("stories/translating", startkey=[req.session.value['username']], endkey=[req.session.value['username'], {}], stale='update_after') :
                    tmp_storyname = result["key"][1]
                    tmp_story = self.db[self.story(req, tmp_storyname)]
                    mdebug("Killing stale translation session: " + tmp_storyname)
                    tmp_story["translating"] = False
                    try :
                        self.db[self.story(req, tmp_storyname)] = tmp_story
                    except couch_adapter.ResourceConflict, e :
                        mdebug("Conflict: No big deal. Another thread killed the session correctly.") 
                        
                    self.flush_pages(req, tmp_storyname)
                    
            if req.http.params.get("uploadfile") :
                fh = req.http.params.get("storyfile")
                filetype = req.http.params.get("filetype")
                source = fh.file.read()
                return self.add_story_from_source(req, fh.filename.lower().replace(" ","_"), source, filetype)

            if req.http.params.get("uploadtext") :
                source = req.http.params.get("storytext") + "\n"
                filename = req.http.params.get("storyname").lower().replace(" ","_")
                return self.add_story_from_source(req, filename, source, "txt")

            start_page = "0"
            view_mode = "text"
            uuid = False
            name = False
            story = False

            if req.http.params.get("uuid") :
                uuid = req.http.params.get("uuid") 

                name = self.db[self.index(req, uuid)]["value"]
                name_found = True if name else False
                    
                if not name :
                    if req.http.params.get("name") :
                        name = req.http.params.get("name")
                    
                if name and name_found :
                    story = self.db[self.story(req, name)]

            if req.http.params.get("delete") :
                story_found = False if not name else self.db.doc_exist(self.story(req, name))
                if name and not story_found :
                    mdebug(name + " does not exist. =(")
                else :
                    if name :
                        tmp_story = self.db[self.story(req, name)]
                        if "filetype" not in tmp_story or tmp_story["filetype"] == "txt" :
                            mdebug("Deleting txt original contents.")
                            del self.db[self.story(req, name) + ":original"]
                        else :
                            for result in self.db.view('stories/alloriginal', startkey=[req.session.value['username'], name], endkey=[req.session.value['username'], name, {}], stale='update_after') :
                                tmppage = result["key"][2]
                                mdebug("Deleting original " + str(tmppage) + " from story " + name)
                                del self.db[self.story(req, name) + ":original:" + str(tmppage)]
                        
                    if name and story_found :
                        del self.db[self.story(req, name)]
                    
                    if self.db.doc_exist(self.index(req, uuid)) :
                        del self.db[self.index(req, uuid)]
                
                        
                if "current_story" in req.session.value and req.session.value["current_story"] == uuid :
                    del req.session.value["current_story"]
                    if "current_page" in req.session.value :
                        del req.session.value["current_page"]
                    req.session.save()
                    uuid = False
                self.db.compact("stories")
                return self.bootstrap(req, self.heromsg + "\n<h4>Deleted.</h4></div>", now = True)

            if uuid :
                if not self.db.doc_exist(self.index(req, uuid)) :
                    if "current_story" in req.session.value :
                        del req.session.value["current_story"]
                        req.session.save()
                    if "current_page" in req.session.value :
                        del req.session.value["current_page"]
                        req.session.save()
                    return self.bootstrap(req, self.heromsg + "\n<h4>Invalid story uuid: " + uuid + "</h4></div>")

            if req.http.params.get("tstatus") :
                out = "<div id='tstatusresult'>"
                if not self.db.doc_exist(self.index(req, uuid)) :
                    out += "error 25 0 0"
                else :
                    if "translating" not in story or not story["translating"] :
                        out += "no 0 0 0"
                    else :
                        curr = float(int(story["translating_current"]))
                        total = float(int(story["translating_total"]))

                        out += "yes " + str(int(curr / total * 100))
                        out += (" " + str(story["translating_page"])) if "translating_page" in story else "0"
                        out += (" " + str(story["translating_pages"])) if "translating_pages" in story else "1"
                        
                out += "</div>"
                return self.bootstrap(req, self.heromsg + "\n" + out + "</div>", now = True)

            if req.http.params.get("reviewed") :
                reviewed = True if req.http.params.get("reviewed") == "1" else False
                tmp_story = self.db[self.story(req, name)]
                tmp_story["reviewed"] = reviewed
                if reviewed :
                    final = {}
                    minfo("Generating final pagesets...")
                    
                    for page in range(0, self.nb_pages(req, tmp_story["name"])) :
                        minfo("Page " + str(page) + "...")
                        final[str(page)] = self.view_page(req, uuid, name, story, req.action, "", str(page), disk = True)
                        
                    self.db[self.story(req, name) + ":final"] = final
                self.db[self.story(req, name)] = tmp_story 
                return self.bootstrap(req, self.heromsg + "\n<h4>Reviewed.</h4></div>", now = True)

            if req.http.params.get("forget") :
                tmp_story = self.db[self.story(req, name)]
                tmp_story["translated"] = False
                tmp_story["reviewed"] = False
                self.db[self.story(req, name)] = tmp_story 
                self.flush_pages(req, name)

                story = tmp_story
                
                if "current_story" in req.session.value and req.session.value["current_story"] == uuid :
                    del req.session.value["current_story"]
                    if "current_page" in req.session.value :
                        del req.session.value["current_page"]
                    req.session.save()
                    uuid = False
                self.db.compact("stories")
                return self.bootstrap(req, self.heromsg + "\n<h4>Forgotten.</h4></div>", now = True)

            if req.http.params.get("switchmode") :
                req.session.value["view_mode"] = req.http.params.get("switchmode")
                req.session.save()
                return self.bootstrap(req, self.heromsg + "\n<h4>View mode changed.</h4></div>", now = True)

            if req.http.params.get("instant") :
                source = req.http.params.get("instant")
                human = int(req.http.params.get("human")) if req.http.params.get("human") else 0
                out = ""
                out += "<div id='instantresult'>"
                final = { }
                requests = [source]
                breakout = source.decode("utf-8") if isinstance(source, str) else source
                if len(breakout) > 1 :
                    for x in range(0, len(breakout)) :
                        requests.append(breakout[x].encode("utf-8"))

                result = self.translate_and_check_array(requests, u"en")
                p = ""
                for x in range(0, len(requests)) : 
                    part = result[x]
                    if "TranslatedText" not in part :
                        mdebug("Why didn't we get anything: " + json.dumps(result))
                        english = "No english translation available."
                    else :
                        english = part["TranslatedText"].encode("utf-8")
                    
                    if x == 0 :
                        p += "Selected translation (" + source + "): " + english + "<br/>\n"
                        final["whole"] = (source, english)
                    else :
                        char = breakout[x-1].encode("utf-8")
                        if "parts" not in final :
                            p += "Piecemeal translation:<br/>\n"
                            final["parts"] = []
                        p += "(" + char + "): "
                        p += english
                        p += "<br/>\n"
                        final["parts"].append((char, english))
                       
                if human :
                    out += "<h4>Online translation:</h4>"
                    out += p 
                    out += "<h4>Offline translation:</h4>"

                    (cjk, cjkdb, d) = self.get_cjk_handle(self.cjklocation)
                    eng = self.get_first_translation(d, source.decode("utf-8"), False, debug = True)
                    if eng :
                        for english in eng :
                            out += english.encode("utf-8")
                    else :
                        out += "None found."
                else :
                    out += json.dumps(final)
                out += "</div>"
                return self.bootstrap(req, self.heromsg + "\n<h4>" + out + "</h4></div>", now = True)

            if req.http.params.get("translate") :
                output = "<div id='translationstatusresult'>" + self.heromsg
                if story["translated"] :
                    output += "Story already translated. To re-translate, please select 'Forget'."
                else :
                    try :
                        self.parse(req, uuid, name, story, username)
                        output += self.heromsg + "Translation complete!"
                    except Exception, e :
                        output += "Failed to translate story: " + str(e)
                output += "</div></div>"
                return self.bootstrap(req, output, now = True)

            # Functions only go here if they are actions against the currently reading story
            # Functions above here can happen on any story
            
            story_changed = False
            if "current_story" in req.session.value :
                if uuid :
                    if req.session.value["current_story"] != uuid :
                        story_changed = True
                    req.session.value["current_story"] = uuid
                    req.session.save()
                else :
                    uuid = req.session.value["current_story"]
            elif uuid :
                story_changed = True
                req.session.value["current_story"] = uuid
                req.session.save()
                
            if story_changed :
                if "current_page" in req.session.value:
                    del req.session.value["current_page"]
                    req.session.save()
            
            if "current_page" in req.session.value :
                start_page = req.session.value["current_page"]
            else :
                req.session.value["current_page"] = start_page 
                req.session.save()
                
            if "view_mode" in req.session.value :
                view_mode = req.session.value["view_mode"]
            else :
                req.session.value["view_mode"] = view_mode 
                req.session.save()

            if req.http.params.get("multiple_select") :
                nb_unit = int(req.http.params.get("nb_unit"))
                mindex = int(req.http.params.get("index"))
                trans_id = int(req.http.params.get("trans_id"))
                page = req.http.params.get("page")
                
                # This is also kind of silly: getting a whole page
                # of units just to update one of them.
                # Maybe it's not so high overhead. I dunno.
                page_dict = self.db[self.story(req, name) + ":pages:" + str(page)]
                unit = page_dict["units"][nb_unit]
                
                unit["multiple_correct"] = mindex
                
                self.rehash_correct_polyphome(unit) 
                
                page_dict["units"][nb_unit] = unit
                self.db[self.story(req, name) + ":pages:" + str(page)] = page_dict

                self.add_record(req, unit, mindex, self.tones, "selected") 

                return self.bootstrap(req, self.heromsg + "\n<div id='multiresult'>" + \
                                           self.polyphomes(req, story, uuid, unit, nb_unit, trans_id, page) + \
                                           "</div></div>", now = True)

            output = ""

            if req.http.params.get("phistory") :
                page = req.http.params.get("page")
                return self.bootstrap(req, self.heromsg + "\n<div id='historyresult'>" + \
                                           self.history(req, story, uuid, page) + \
                                           "</div></div>", now = True)

            if req.http.params.get("editslist") :
                page = req.http.params.get("page")
                return self.bootstrap(req, self.heromsg + "\n<div id='editsresult'>" + \
                                           self.edits(req, story, uuid, page) + \
                                           "</div></div>", now = True)

            if req.http.params.get("memorized") :
                memorized = int(req.http.params.get("memorized"))
                nb_unit = int(req.http.params.get("nb_unit"))
                page = req.http.params.get("page")
                
                # FIXME This is kind of stupid - looking up the whole page
                # just to get the hash of one unit.
                # But, we are storing the whole unit dict inside
                # the memorization link - maybe or maybe not we shouldn't
                # be doing that, or we could put the whole unit's json
                # into the original memorization request. I dunno.
                
                page_dict = self.db[self.story(req, name) + ":pages:" + str(page)]
                unit = page_dict["units"][nb_unit]
                
                if memorized :
                    self.db[self.memorized(req, unit["hash"])] = unit
                else :
                    del self.db[self.memorized(req, unit["hash"])]
                    
                return self.bootstrap(req, self.heromsg + "\n<div id='memoryresult'>Memorized! " + \
                                           unit["hash"] + "</div></div>", now = True)

            if req.http.params.get("oprequest") :
                oprequest = req.http.params.get("oprequest");
                edits = json.loads(oprequest) 
                offset = 0
                
                for edit in edits :
                    mdebug("Processing edit: " + str(edit))
                    if isinstance(edit, str) or str(edit).strip() == "" :
                        merr("Skipping Wierd edit request: " + str(edit))
                        continue
                    if edit["failed"] :
                        mdebug("This edit failed. Skipping.")
                        continue
                    result = repeat(self.operation, args = [req, story, edit, offset], kwargs = {})
                    
                    if not result[0] and len(result) > 1 :
                        return self.bootstrap(req, result[1])
                    
                    ret = result[1:]
                    success = ret[0]
                    offset = ret[1]
                    
                    if not success :
                        return self.bootstrap(req, self.heromsg + "\nInvalid Operation: " + str(edit) + "</div>")
                    
            if req.http.params.get("memolist") :
                page = req.http.params.get("page")
                output = ""
                        
                result = repeat(self.memocount, args = [req, story, page], kwargs = {})
                
                if not result[0] and len(result) > 1 :
                    return self.bootstrap(req, result[1])
                
                total_memorized, total_unique, unique, progress = result[1:]

                pr = str(int((float(total_memorized) / float(total_unique)) * 100)) if total_unique > 0 else 0
                for result in self.db.view('memorized/allcount', startkey=[req.session.value['username']], endkey=[req.session.value['username'], {}]) :
                    output += "Total words memorized from all stories: " + str(result['value']) + "<br/>"
                output += "Total unique memorized from this page: " + str(total_memorized) + "<br/>"
                output += "Total unique words from this page: " + str(len(unique)) + "<br/>"
                output += "<div class='progress progress-success progress-striped'><div class='progress-bar' style='width: "
                output += str(pr) + "%;'> (" + str(pr) + "%)</div></div>"

                if total_memorized :
                    output += "<div class='panel-group' id='panelMemorized'>\n"
                    for p in progress :
                        output += """
                                <div class='panel panel-default'>
                                  <div class="panel-heading">
                                  """
                        py, english, unit, nb_unit, trans_id, page_idx = p
                        if len(english) and english[0] == '/' :
                            english = english[1:-1]
                        tid = unit["hash"] if py else trans_id 

                        output += "<a class='trans btn-default btn-xs' onclick=\"forget('" + \
                                str(tid) + "', '" + uuid + "', '" + str(nb_unit) + "', '" + str(page_idx) + "')\">" + \
                                "<i class='glyphicon glyphicon-remove'></i></a>"

                        output += "&nbsp; " + "".join(unit["source"]) + ": "
                        output += "<a class='panel-toggle' style='display: inline' data-toggle='collapse' data-parent='#panelMemorized' href='#collapse" + tid + "'>"

                        output += "<i class='glyphicon glyphicon-arrow-down' style='size: 50%'></i>&nbsp;" + py
                        output += "</a>"
                        output += "</div>"
                        output += "<div id='collapse" + tid + "' class='panel-body collapse'>"
                        output += "<div class='panel-inner'>" + english.replace("/"," /") + "</div>"
                        output += "</div>"
                        output += "</div>"
                    output += "</div>"
                else :
                    output += "No words memorized. Get to work!"

                return self.bootstrap(req, self.heromsg + "\n<div id='memolistresult'>" + output + "</div></div>", now = True)
               
            if req.http.params.get("retranslate") :
                page = req.http.params.get("page")
                self.parse(req, uuid, name, story, username, page = page)
                
            if req.action in ["home", "read", "edit" ] :
                if uuid :
                    # Reload just in case the translation changed anything
                    name = self.db[self.index(req, uuid)]["value"]
                    story = self.db[self.story(req, name)]
                    if req.http.params.get("page") and not req.http.params.get("retranslate") :
                        page = req.http.params.get("page")
                        req.session.value["current_page"] = str(page)
                        req.session.save()
                        if req.http.params.get("image") :
                            nb_image = req.http.params.get("image")
                            output = "<div><div id='pageresult'>"
                            image_found = False
                            if "filetype" in story and story["filetype"] != "txt" :
                                attach_raw = self.db.get_attachment(self.story(req, name) + ":original:" + str(page), "attach")
                                mdebug("OK, received raw attachment, type: " + str(type(attach_raw)) + ", evalling...")
                                original = eval(attach_raw)
                                mdebug("OK, evaluated with keys: " + str(original.keys()))

                                if "images" in original and int(nb_image) < len(original["images"]) :
                                    # I think couch is already base-64 encoding this, so if we can find
                                    # away to get that out of couch raw, then we shouldn't have to re-encode this ourselves.
                                    output += "<img src='data:image/jpeg;base64," + base64.b64encode(original["images"][int(nb_image)]) + "' width='100%' height='100%'/>"
                                    image_found = True
                            if not image_found :
                               output += "Image #" + str(nb_image) + " not available on this page"
                            output += "</div></div>"
                            return self.bootstrap(req, output, now = True)
                        else :
                            output = self.view_page(req, uuid, name, story, req.action, output, page)
                                
                            return self.bootstrap(req, "<div><div id='pageresult'>" + output + "</div></div>", now = True)
                    output = self.view(req, uuid, name, story, req.action, start_page, view_mode)
                else :
                    output += self.heromsg + "<h4>No story loaded. Choose a story to read from the sidebar<br/>or create one by clicking on 'Account' at the top.</h4></div>"
                output += "<script>loadstories();</script>"
                return self.bootstrap(req, output)
            elif req.action == "stories" :
                if story["filetype"] != "txt" :
                    return self.bootstrap(req, self.heromsg + "\n<h4>Story is a " + story["filetype"] + " file with multiple pages. Not yet implemented.</h4></div>\n")
                
                if req.http.params.get("type") :
                    which = req.http.params.get("type")
                    
                    if which == "original" :
                        original = self.db[self.story(req, name) + ":original"]["value"]
                        return self.bootstrap(req, original.encode("utf-8").replace("\n","<br/>"))
                    elif which == "pinyin" :
                        final = self.db[self.story(req, name) + ":final"]["0"]
                        return self.bootstrap(req, final.encode("utf-8").replace("\n","<br/>"))
                    
            elif req.action == "storylist" :
                storylist = self.template("storylist")

                result = repeat(self.makestorylist, args = [req], kwargs = {})
                
                if not result[0] and len(result) > 1 :
                    return self.bootstrap(req, result[1])
                
                untrans_count, reading, noreview, untrans = result[1:]
                
                reading += "</table></div></div></div>\n"
                noreview += "</table></div></div></div>\n"
                untrans += "</table></div></div></div>\n"

                if untrans_count :
                    storylist += untrans + reading + noreview + "</div></td></tr></table>"
                    storylist += """
                            <script>$('#collapseUntranslated').collapse('show');</script>
                            """
                else :
                    storylist += reading + untrans + noreview + "</div></td></tr></table>"
                    storylist += """
                            <script>$('#collapseReading').collapse('show');</script>
                            """
                storylist += """
                            
                           <script>
                           for(var tidx = 0; tidx < translist.length; tidx++) {
                               trans_start(translist[tidx]);
                           }
                           </script>
                          """
                return self.bootstrap(req, "<div><div id='storylistresult'>" + storylist + "</div></div>", now = True)
            
            elif req.action == "account" :
                out = ""
                
                if req.http.params.get("pack") :
                    self.db.compact()
                    design_docs = self.db.all_docs(startkey="_design", endkey="_design/"+u"\u9999")
                    design_doc_names = [ d["id"][8:] for d in design_docs ]
                    for name in design_doc_names :
                        self.db.compact(name)
                    out += self.heromsg + "\n<h4>Database compaction complete for your account.</h4></div>\n"
                    
                user = self.db[self.acct(username)]

                if 'admin' in user['roles'] :
                    out += "<h5>Accounts:</h5>"
                    out += "<table>"
                    for result in self.db.view('accounts/all') :
                        tmp_user = result["value"]
                        tmp_username = result["key"]
                        out += "<tr><td>" + tmp_username + "</td><td>Roles: " + ",".join(tmp_user["roles"]) + "</td></tr>"
                    out += "</table>"
                out += """
                    <p/>
                    <form action='BOOTDEST/account' method='post' enctype='multipart/form-data'>
                    <table>
                    <tr><td><h5>&nbsp;Old Password: </td><td><input type="password" name="oldpassword"/></h5></td></tr>
                    <tr><td><h5>&nbsp;Password: </td><td><input type="password" name="password"/></h5></td></tr>
                    <tr><td><h5>&nbsp;Confirm:&nbsp; </td><td><input type="password" name="confirm"/></h5></td></tr>
                    <tr><td><button name='changepassword' type="submit" class="btn-primary" value='1'>Change Password</button></td></tr>
                    </table>
                    </form>                                   
                    <a class='btn btn-default btn-primary' href='BOOTDEST/account?pack=1'>Compact databases</a>
                    """

                
                if req.http.params.get("newaccount") :
                    newusername = req.http.params.get("username")
                    newpassword = req.http.params.get("password")
                    newpasswordconfirm = req.http.params.get("confirm")
                    admin = req.http.params.get("isadmin", 'off')

                    if newpassword != newpasswordconfirm :
                        return self.bootstrap(req, self.heromsg + "\n<h4>Passwords don't match! Try again.</h4></div>")

                    if self.db.doc_exist(self.acct(newusername)) :
                        return self.bootstrap(req, self.heromsg + "\n<h4>Account already exists! Try again.</h4></div>")
                    if 'admin' not in user["roles"] and admin == 'on' :
                        return self.bootstrap(req, self.heromsg + "\n<h4>Non-admin users can't create admin accounts. What are you doing?!</h4></div>")

                    roles = ['normal']
                    if admin == 'on' :
                        roles.append('admin')

                    self.db[self.acct(newusername)] = { 'password' : hashlib.md5(newpassword).hexdigest(), 'roles' : roles }

                    out += self.heromsg + "\n<h4>Success! New user " + newusername + " created.</h4></div>"
                    self.db.compact("accounts")

                elif req.http.params.get("changepassword") :
                    oldpassword = req.http.params.get("oldpassword")
                    newpassword = req.http.params.get("password")
                    newpasswordconfirm = req.http.params.get("confirm")
                    newhash = hashlib.md5(newpassword).hexdigest()
                    oldhash = hashlib.md5(oldpassword).hexdigest()

                    if newpassword != newpasswordconfirm :
                        return self.bootstrap(req, self.heromsg + "\n<h4>Passwords don't match! Try again.</h4></div>")
                    if oldhash != user['password'] :
                        return self.bootstrap(req, self.heromsg + "\n<h4>Old passwords don't match! Try again.</h4></div>")
                    user['password'] = newhash
                    self.db[self.acct(username)] = user
                    out += self.heromsg + "\n<h4>Success! User " + username + "'s password changed.</h4></div>"

                return self.bootstrap(req, out)
                    
            elif req.action == "disconnect" :
                req.session.value['connected'] = False
                del self.first_request[username]
                #del req.session.value['cloud_name'] # delete whatever shouldn't be in the session
                req.session.save()
                return self.bootstrap(req, self.heromsg + "\n<h4>Disconnected from MICA</h4></div>")
            elif req.action == "help" :
                output = ""
                helpfh = codecs.open(cwd + "serve/info_template.html", "r", "utf-8")
                output += helpfh.read().encode('utf-8').replace("\n", "<br/>")
                helpfh.close()
                return self.bootstrap(req, output)
            else :
                return self.bootstrap(req, "Nothing to do!")

        except exc.HTTPTemporaryRedirect, e :
            raise e
        except Exception, msg:
            mdebug("Exception: " + str(msg))
            out = "Exception:\n" 
            resp = "<h4>Exception:</h4>"
            for line in traceback.format_exc().splitlines() :
                resp += "<br>" + line
                out += line + "\n"
            mdebug(out )

            try :
                if isinstance(resp, str) :
                    resp = resp.decode("utf-8")
                return self.bootstrap(req, self.heromsg + "\n<h4 id='gerror'>Error: Something bad happened: " + str(msg) + "</h4>" \
                                            + resp + "</div>")
            except Exception, e :
                merr("OTHER MICA ********Exception:")
                for line in traceback.format_exc().splitlines() :
                    merr("OTHER MICA ********" + line)
            return out

'''
session_opts = {
    'session.data_dir' : '/tmp/mica_sessions_' + getpwuid(os.getuid())[0] + '_data',
    'session.lock_dir' : '/tmp/mica_sessions_' + getpwuid(os.getuid())[0] + '_lock',
    'session.type' : 'file',
    }
'''

class IDict(Interface):
    value = Attribute("Dictionary for holding session keys and values.")

class CDict(object):
    implements(IDict)
    def __init__(self, session):
        self.value = {}
    def save(self) :
        # Just here to emulate beaker. Doesn't really do anything.
        pass

class GUIDispatcher(Resource) :
    def __init__(self, mica) :

        Resource.__init__(self)
        self.serve = File(cwd + relative_prefix)
        # example of how to serve individual utf-8 encoded files:
        # self.stories = File(cwd + relative_prefix + "/../stories/")
        # self.stories.contentTypes['.txt'] = 'text/html; charset=utf-8'
        self.files = File(cwd)
        self.icon = File(cwd + relative_prefix + "/favicon.ico")
        self.git = File(cwd + "/.git")
        self.git.indexNames = ["test.rpy"]
        self.mica = mica
            
#        self.app = WSGIResource(reactor, reactor.threadpool, SessionMiddleware(self.mica, session_opts))
        self.app = WSGIResource(reactor, reactor.threadpool, self.mica)

    def getChild(self, name, request) :
        # Hack to make WebOb work with Twisted
        request.content.seek(0,0)
        request.setHeader('Access-Control-Allow-Origin', '*')
        request.setHeader('Access-Control-Allow-Origin', '*')
        request.setHeader('Access-Control-Allow-Methods', 'GET')
        request.setHeader('Access-Control-Allow-Headers', 'x-prototype-version,x-requested-with')
        request.setHeader('Access-Control-Max-Age', 2520)
        request.setHeader('Content-Type', 'text/html; charset=utf-8')

        request.session = IDict(request.getSession())
        
        if name.count(relative_prefix_suffix):
            return self.serve
        #if name.count("stories") :
        #    return self.stories
        if name.count("favicon.ico"):
            return self.icon
        elif name.count("git"):
            return self.git
        else :
            return self.app

class MicaSession(Session) :
    sessionTimeout = 604800 # one week 

class NONSSLRedirect(object) :
    def __init__(self):
        pass

    def __call__(self, environ, start_response):
        req = Params(environ, start_response.im_self.request.session)
        (req.dest, req.path) = prefix(req.unparsed_uri)
        tossl = "https://" + req.dest + ":" + str(params["sslport"]) + "/" + req.path 
        mdebug("Redirecting non-ssl request to: " + tossl)
        resp = exc.HTTPTemporaryRedirect(location = tossl)
        return resp(environ, start_response)
        
class NONSSLDispatcher(Resource) :
    def __init__(self) :

        Resource.__init__(self)
            
        self.nonssl = NONSSLRedirect()
#        self.app = WSGIResource(reactor, reactor.threadpool, SessionMiddleware(self.nonssl, session_opts))
        self.app = WSGIResource(reactor, reactor.threadpool, self.nonssl)

    def getChild(self, name, request) :
        request.session = IDict(request.getSession())
        return self.app

mdebug("Registering session adapter.")
registerAdapter(CDict, Session, IDict)

def get_options() :
    from optparse import OptionParser

    parser = OptionParser()

    parser.add_option("-p", "--port", dest = "port", default = "80", help ="port")
    parser.add_option("-s", "--sslport", dest = "sslport", default = "443", help ="sslport")
    parser.add_option("-H", "--host", dest = "host", default = "0.0.0.0", help ="hostname")
    parser.add_option("-k", "--keepsession", dest = "keepsession", action = "store_true", default = False, help ="do not destroy the previous HTTP session")
    parser.add_option("-d", "--debug_host", dest = "debug_host", default = None, help ="Hostname for remote debugging")
    parser.add_option("-l", "--log", dest = "log", default = cwd + "logs/mica.log", help ="MICA main log file.")
    parser.add_option("-t", "--tlog", dest = "tlog", default = cwd + "logs/twisted.log", help ="Twisted log file.")
    parser.add_option("-I", "--client-id", dest = "client_id", default = False, help = "Microsoft Translation Client App ID (why? Because it's free, and google is not)")
    parser.add_option("-S", "--client-secret", dest = "client_secret", default = False, help = "Microsoft Translation Client App Secret (why? Because it's free, and google is not)")
    parser.add_option("-C", "--cert", dest = "cert", default = False, help = "Path to certificate for Twisted to run OpenSSL")
    parser.add_option("-K", "--privkey", dest = "privkey", default = False, help = "Path to private key for Twisted to run OpenSSL")
    parser.add_option("-a", "--slaves", dest = "slaves", default = "127.0.0.1", help = "List of slave addresses")
    parser.add_option("-w", "--slave_port", dest = "slave_port", default = "5050", help = "Port on which the slaves are running")
    parser.add_option("-c", "--couch", dest = "couch", default = "https://admin:super_secret_pass@localhost:6984", help = "URL of remote apache couchdb database")
    parser.add_option("-n", "--dbname", dest = "dbname", default = "mica", help = "Name of the couchdb database to use for this server")
    parser.add_option("-e", "--cedict", dest = "cedict", default = False, help = "Location of cedict.db file used by cjklib library.")
    parser.add_option("-T", "--tonefile", dest = "tonefile", default = False, help = "Location of pinyin tone txt file.")

    parser.set_defaults()
    options, args = parser.parse_args()

    params = {
               "port" : options.port,
               "sslport" : options.sslport,
               "host" : options.host,
               "keepsession" : options.keepsession,
               "debug_host" : options.debug_host,
               "log" : options.log,
               "tlog" : options.tlog,
               "client_id" : options.client_id,
               "client_secret" : options.client_secret,
               "cert" : options.cert,
               "privkey" : options.privkey,
               "slaves" : options.slaves,
               "slave_port" : options.slave_port,
               "couch" : options.couch,
               "dbname" : options.dbname,
               "cedict" : options.cedict,
               "tonefile" : options.tonefile,
    }

    return params 


slaves = {}
params = None

def go(params) :
    mdebug("Verifying options.")
    if not params["cert"] or not params["privkey"] :
        merr("Need locations of SSL certificate and private key (options -C and -K). You can generate self-signed ones if you want, see the README.")
        exit(1)

    if not params["client_id"] or not params["client_secret"]:
        merr("Microsoft Client ID and Secret are for their translation service is required (options -I and -S). Why? Because it's free and google is not =)")
        exit(1)

    '''
    if not options.keepsession and 'session.data_dir' in session_opts and 'session.lock_dir' in session_opts :
        try :
            shutil.rmtree(session_opts['session.data_dir'])
            shutil.rmtree(session_opts['session.lock_dir'])
        except OSError :
            pass
    '''

    mdebug("Initializing logging.")
    mica_init_logging(params["log"])

    if "tonefile" not in params or not params["tonefile"] :
        params["tonefile"] = cwd + "/chinese.txt" # from https://github.com/lxyu/pinyin

    mdebug("Building tone file")
    dpfh = open(params["tonefile"])
    for line in dpfh.readlines() :
        k, v = line.split('\t')
        cd[k] = v

    dpfh.close()

    if params["tlog"] :
        if params["tlog"] != 1 :
            mdebug("Initializing twisted log.")
            log.startLogging(DailyLogFile.fromFullPath(params["tlog"]), setStdout=True)
    else :
        mdebug("Skipping twisted log")

    try :
        if params["slaves"] :
            slave_addresses = params["slaves"].split(",")

            for slave_address in slave_addresses :
                slave_uri = "http://" + slave_address + ":" + str(params["slave_port"])
                minfo("Registering slave @ " + slave_uri)
                slaves[slave_uri] = MICASlaveClient(slave_uri)
                #slaves[slave_uri].foo("bar")

            assert(len(slaves) >= 1)

        db_adapter = getattr(couch_adapter, params["couch_adapter_type"])

        mica = MICA(params["client_id"], params["client_secret"], params["couch"], params["dbname"], params["cedict"], db_adapter)

        mdebug("Testing cjk")
        mica.get_cjk_handle(params["cedict"])

        reactor._initThreadPool()
        site = Site(GUIDispatcher(mica))
        site.sessionFactory = MicaSession
        nonsslsite = Site(NONSSLDispatcher())
        nonsslsite.sessionFactory = MicaSession

        reactor.listenTCP(int(params["port"]), nonsslsite, interface = params["host"])
        reactor.listenSSL(int(params["sslport"]), site, ssl.DefaultOpenSSLContextFactory(params["privkey"], params["cert"]), interface = params["host"])
        minfo("Point your browser at port: " + str(params["sslport"]) + ". (Bound to interface: " + params["host"] + ")")

        if params["debug_host"] :
            try :
                import debug
                mdebug(str(sys.path))
                import pydevd
                pydevd.settrace(host=params["debug_host"])
            except ImportError, msg :
                mwarn("Failed to import debug file for remote debugging: " + str(msg), True)
                params["debug_host"] = None
                exit(1)

        reactor.run()
    except Exception, e :
        merr("Startup exception: " + str(e))
        for line in traceback.format_exc().splitlines() :
            merr(line)

if __name__ == "__main__":
    mdebug("Ready to go.")
    params = get_options()
    params["couch_adapter_type"] = "MicaServerCouchDB"
    go(params)
