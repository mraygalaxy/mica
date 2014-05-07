#!/usr/bin/env python
# coding: utf-8
from cmd import Cmd
from pwd import getpwuid
from sys import stdout, path
from subprocess import Popen, PIPE
from optparse import OptionParser
from re import sub, compile
from time import time as timest
from os import listdir
from os.path import isfile, join
from threading import Thread, Lock
from daemon import DaemonContext
from sys import _getframe
from simplejson import JSONDecodeError
from datetime import datetime
from pwd import getpwuid
from copy import deepcopy
from operator import itemgetter
from twisted.web.wsgi import WSGIResource
from twisted.internet import reactor, ssl
from twisted.web.static import File
from twisted.web.resource import Resource
from twisted.web.server import Site
from twisted.web import proxy, server
from twisted.python import log
from twisted.python.logfile import DailyLogFile
from twisted.python import log
from webob import Request, Response, exc
from beaker.middleware import SessionMiddleware
from cjklib.dictionary import CEDICT
from cjklib.characterlookup import CharacterLookup
from cjklib.dbconnector import getDBConnector
from common import *

import threading
import traceback
import os
import re
import shutil
import urllib
import urllib2
import copy
import warnings
import codecs
import shelve
import uuid as uuid4
import cjklib
import mica_ictclas
import hashlib
import errno
import simplejson as json
import __builtin__

bins = dir(__builtin__)

cwd = re.compile(".*\/").search(os.path.realpath(__file__)).group(0)
path.append(cwd)
data_path = cwd + "/chinese.txt" # from https://github.com/lxyu/pinyin

cd = {}
dpfh = open(data_path)
for line in dpfh.readlines() :
    k, v = line.split('\t')
    cd[k] = v

dpfh.close()

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
        response = json.loads(urllib.urlopen(
            'https://datamarket.accesscontrol.windows.net/v2/OAuth2-13', args
        ).read())

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
        rv =  json.loads(response.decode("UTF-8-sig"))

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
    def __init__(self, environ):
        self.pid = "none"
        self.http = Request(environ)  
        self.action = self.http.path[1:] if len(self.http.path) > 0 else None
        if self.action is None or self.action == "":
            self.action = "index"

        self.session = environ['beaker.session']
        if 'connected' not in self.session :
            self.session['connected'] = False
            if 'cloud_name' in self.session :
                del self.session['cloud_name']
                
        self.session.save()
        self.unparsed_uri = self.http.url
        self.uri = self.http.path
        self.active = None 
        self.active_obj = None 
        self.skip_show = False
        self.skip_sidebar = False
        
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

punctuation = [u'\n', u'-', u'_', u'—', u',', u'，',u'.',u'。', u'?', u'？', u':', u'：', u'、', u'“', u'”', u'~', u'`', u'"', u'\'', u'…', u'！', u'!', u'（', u'(', u'）', u')' ]
punctuation += ['\n', '-', '_', '—', ',', '，','.','。', '?', '？', ':', '：', '、', '“', '”', '~', '`', '"', '\'', '…', '！', '!', '（', '(', '）', ')' ]

for num in range(0, 9) :
    punctuation.append(unicode(str(num)))
    punctuation.append(str(num))

def strip_punct(word) :
    new_word = ""
    for char in word :
        if char not in punctuation :
            new_word += char
    return new_word

spinner = "<img src='MSTRAP/spinner.gif' width='15px'/>&nbsp;"

class MICA(object):
    def __init__(self, client_id, client_secret):
        self.mutex = Lock()
        self.transmutex = Lock()
        self.heromsg = "<div class='span1'></div><div class='span 1 hero-unit' style='padding: 5px'>"
        self.pid = "none"

        if not os.path.isdir(cwd + "databases/") :
           os.makedirs(cwd + "databases/")

        self.first_request = {}

        self.client = Translator(client_id, client_secret)

        self.menu = [ 
             ("home" , ("/home", "<i class='icon-home'></i>&nbsp;Review")), 
             ("edit" , ("/edit", "<i class='icon-pencil'></i>&nbsp;Edit")), 
             ("read" , ("/read", "<i class='icon-book'></i>&nbsp;Read")), 
        ]
        
        # Replacements must be in this order
        
        self.replacement_keys = [ 
                                    "BOOTNAV", 
                                    "BOOTNEWACCOUNTADMIN",
                                    "BOOTSIDEBAR", 
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

        self.dbs = {}
        self.acctdb = shelve.open(cwd + "accounts.db", writeback=True)
        if "accounts" not in self.acctdb :
            # default installations use 'admin' password of 'password'
            self.acctdb["accounts"] = { 
                                'admin' : 
                                    { 
                                      'password' : '5f4dcc3b5aa765d61d8327deb882cf99', 
                                      'roles' : ['admin','normal'] 
                                    } 
                             }
            self.acctdb.sync()

        
    def __call__(self, environ, start_response):
        # Hack to make WebOb work with Twisted
        setattr(environ['wsgi.input'], "readline", environ['wsgi.input']._wrapped.readline)

        req = Params(environ)
        req.dest = ""#prefix(req.unparsed_uri)
        
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
            print "RESPONSE MICA ********Exception:"
            for line in traceback.format_exc().splitlines() :
                print "RESPONSE MICA ********" + line

        return r

    def dbcheck(self, req) :
        username = req.session['username']
        if username not in self.dbs : 
            self.dbs[username] = shelve.open(cwd + "databases/" + username + ".db", writeback=True)
        return self.dbs[username], username

    def bootstrap(self, req, body, now = False, pretend_disconnected = False) :
        navcontents = ""
        newaccountadmin = ""
        cloudcontents = "None Available"
        availablecontents = "None Available"
        popoveractivate = "$('#connectpop').popover('show');"
        sidebar = ""
        if now :
            contents = body
        else :
            contents_fh = open(cwd + relative_prefix + "/head_template.html", "r")
            contents = contents_fh.read()
            contents_fh.close()
            
            navactive = req.action
            if navactive == 'home' or navactive == 'index' :
                navactive = 'home'
            for (key, value) in self.menu :
                if key in ["home", "read", "edit"] and not req.session['connected'] :
                    continue

                navcontents += "<li"
                if navactive == key :
                    navcontents += " class='active'"
                navcontents += "><a href=\"BOOTDEST" + value[0] + "\">" + value[1] + "</a></li>\n"
        
            if req.session['connected'] and not pretend_disconnected :
                db, username = self.dbcheck(req)

                if 'admin' in self.acctdb["accounts"][username]["roles"] :
                    newaccountadmin += """
                            <h5>&nbsp;<input type="checkbox" name="isadmin"/>&nbsp;Admin?</h5>
                    """
                sidebar += """
                           <script>var translist = [];</script>
                           <table><tr><td>&nbsp;&nbsp;</td><td>
                           <h4>Stories:</h4>
                            <div class='accordion' id='accordionStories'>
                           """

                reading = """
                                            <div class='accordion-group'>
                                              <div class="accordion-heading">
                                               <a class='accordion-toggle' style='display: inline' data-toggle='collapse' data-parent='#accordionStories' href='#collapseReading'>
                                               <i class='icon-arrow-down' style='size: 50%'></i>&nbsp;Reading:
                                                </a>
                                                </div>
                                                <div id='collapseReading' class='accordion-body'>
                                                <div class='accordion-inner'>
                          <table class='table table-hover table-striped'>
                          """
                noreview = """
                                            <div class='accordion-group'>
                                              <div class="accordion-heading">
                                               <a class='accordion-toggle' style='display: inline' data-toggle='collapse' data-parent='#accordionStories' href='#collapseReviewing'>
                                               <i class='icon-arrow-down' style='size: 50%'></i>&nbsp;Not Reviewed:
                                                </a>
                                                </div>
                                                <div id='collapseReviewing' class='accordion-body collapse'>
                                                <div class='accordion-inner'>
                          <table class='table table-hover table-striped'>
                          """
                untrans = """
                                            <div class='accordion-group'>
                                              <div class="accordion-heading">
                                               <a class='accordion-toggle' style='display: inline' data-toggle='collapse' data-parent='#accordionStories' href='#collapseUntranslated'>
                                               <i class='icon-arrow-down' style='size: 50%'></i>&nbsp;Untranslated:
                                                </a>
                                                </div>
                                                <div id='collapseUntranslated' class='accordion-body collapse'>
                                                <div class='accordion-inner'>
                          <table class='table table-hover table-striped'>
                          """

                def sidestart(name, username, story, reviewed) :
                    rname = name.replace(".txt","").replace("\n","").replace("_", " ")
                    sideout = ""
                    sideout += "\n<tr>"
                    sideout += "<td style='font-size: x-small; width: 100px'>" 
                    sideout += "<a title='Download Original' href=\"BOOTDEST/stories?type=original&uuid=" + story["uuid"] + "\">" + rname + "</a>"
                    if "units" in story and (reviewed or story["translated"]) :
                        pr = story["pr"]
                        sideout += "<br/><div class='progress progress-success progress-striped'><div class='bar' style='width: "
                        sideout += pr + "%;'> (" + pr + "%)</div>"
                    sideout += "</td>"
                    if "units" in story and reviewed :
                        sideout += "<td><a title='Download Pinyin' class='btn btn-mini' href=\"BOOTDEST/stories?type=pinyin&uuid=" + story["uuid"]+ "\">"
                        sideout += "<i class='icon-download-alt'></i></a></td>"

                    return sideout

                def itemhelp(pairs) :
                    story = pairs[1]
                    total_memorized = story["total_memorized"] if "total_memorized" in story else 0
                    total_unique = story["total_unique"] if "total_unique" in story else 0
                    pr = int((float(total_memorized) / float(total_unique)) * 100) if total_unique else 0
                    story["pr"] = str(pr)
                    reviewed = not ("reviewed" not in story or not story["reviewed"])
                    return pr

                items = []
                for name, story in db["stories"].iteritems() :
                    items.append((name, story))

                items.sort(key = itemhelp, reverse = True)

                for name, story in items :
                    reviewed = not ("reviewed" not in story or not story["reviewed"])

                    if not story["translated"] : 
                        untrans += sidestart(name, username, story, reviewed)
                        untrans += "\n<td style='font-size: x-small' colspan='3'>"
                        untrans += "<div id='transbutton" + story['uuid'] + "'>"
                        untrans += "<a title='Delete' style='font-size: x-small' class='btn btn-mini' href=\"BOOTDEST/home?delete=1&uuid=" + story['uuid'] + "\"><i class='icon-trash'></i></a>&nbsp;"
                        untrans += "<a style='font-size: x-small' class='btn btn-mini' onclick=\"trans('" + story['uuid'] + "')\">Translate</a></div>&nbsp;"
                        untrans += "<div style='display: inline' id='translationstatus" + story['uuid'] + "'></div>"
                        untrans += "</div>"
                        if "translating" in story and story["translating"] :
                            untrans += "\n<script>translist.push('" + story["uuid"] + "');</script>"
                        untrans += "</td>"
                        untrans += "</tr>"
                    else :
                        notsure = sidestart(name, username, story, reviewed)
                        notsure += "<td><a title='Forget' style='font-size: x-small' class='btn btn-mini' href=\"BOOTDEST/home?forget=1&uuid=" + story['uuid'] + "\"><i class='icon-remove'></i></a></td>"
                        notsure += "<td><a title='Review' style='font-size: x-small' class='btn btn-mini' href=\"BOOTDEST/home?view=1&uuid=" + story['uuid'] + "\"><i class='icon-search'></i></a></td>"
                        notsure += "<td><a title='Edit' style='font-size: x-small' class='btn btn-mini' href=\"BOOTDEST/edit?view=1&uuid=" + story['uuid'] + "\"><i class='icon-pencil'></i></a></td>"
                        notsure += "<td><a title='Read' style='font-size: x-small' class='btn btn-mini' href=\"BOOTDEST/read?view=1&uuid=" + story['uuid'] + "\"><i class='icon-book'></i></a></td>"

                        if reviewed :
                           reading += notsure
                           reading += "<td><a title='Review not complete' style='font-size: x-small' class='btn btn-mini' href=\"BOOTDEST/read?reviewed=0&uuid=" + story['uuid'] + "\"><i class='icon-arrow-down'></i></a></td>"
                           reading += "</tr>"
                        else :
                           noreview += notsure
                           noreview += "<td><a title='Review Complete' style='font-size: x-small' class='btn btn-mini' href=\"BOOTDEST/read?reviewed=1&uuid=" + story['uuid'] + "\"><i class='icon-arrow-up'></i></a></td>"
                           noreview += "</tr>"

                reading += "</table></div></div></div>\n"
                noreview += "</table></div></div></div>\n"
                untrans += "</table></div></div></div>\n"

                sidebar += reading + noreview + untrans + "</div></td></tr></table>"
                sidebar += """
                            
                           <script>
                           for(var tidx = 0; tidx < translist.length; tidx++) {
                               trans_start(translist[tidx]);
                           }
                           </script>
                          """
                if req.action == "edit" :
                    navcontents += """
                                 <li class='dropdown'>
                                 <a class='dropdown-toggle' data-toggle='dropdown' href='#'>
                                 <i class='icon-random'></i>&nbsp;Re-Group
                                 <b class='caret'></b>
                                 </a>
                                 <ul class='dropdown-menu'>
                                 """
                    uuid = 'bad_uuid';
                    navcontents += "<li><a onclick=\"process_edits('"
                    if "current_story" in req.session :
                        uuid = req.session["current_story"]
                    navcontents += uuid
                    navcontents += "', 'split')\"><i class='icon-resize-full'></i>&nbsp;Split Word Apart</a></li>"
                    navcontents += "<li><a onclick=\"process_edits('"
                    if "current_story" in req.session :
                        uuid = req.session["current_story"]
                    navcontents += uuid
                    navcontents += "','merge')\"><i class='icon-resize-small'></i>&nbsp;Merge Characters</a></li>"
                    navcontents += "</ul>"
                    navcontents += "</li>"
                if req.action != "help" :
                    navcontents += "<li><a onclick='process_instant()'><i class='icon-share'></i>&nbsp;Instant</a></li>"
                navcontents += """
                                 <li class='dropdown'>
                                 <a class='dropdown-toggle' data-toggle='dropdown' href='#'>
                                 <i class='icon-user'></i>&nbsp;Account
                                 <b class='caret'></b>
                                 </a>
                                 <ul class='dropdown-menu'>
                                """
                navcontents += "<li><a href='#uploadModal' data-toggle='modal'><i class='icon-upload'></i>&nbsp;Upload New Story</a></li>"
                if 'admin' in self.acctdb["accounts"][username]["roles"] :
                    navcontents += "<li><a href='#newAccountModal' data-toggle='modal'><i class='icon-plus-sign'></i>&nbsp;New Account</a></li>"
                navcontents += "<li><a href=\"BOOTDEST/account\"><i class='icon-user'></i>&nbsp;Preferences</a></li>\n"
                navcontents += "<li><a href=\"BOOTDEST/disconnect\"><i class='icon-off'></i>&nbsp;Disconnect</a></li>\n"
                navcontents += "<li><a href='#aboutModal' data-toggle='modal'><i class='icon-info-sign'></i>&nbsp;About</a></li>\n"
                navcontents += "<li><a href=\"BOOTDEST/help\"><i class='icon-question-sign'></i>&nbsp;Help</a></li>\n"
                navcontents += "</ul>"
                navcontents += "</li>"
            else :
                navcontents += """
                    <li><a id='connectpop'>Connect!</a></li>
                """
    
        if req.action == "index" :
            mpath = req.uri + relative_prefix_suffix
            bootstrappath = req.uri + relative_prefix_suffix + "/bootstrap/docs/assets"
        else :
            mpath = req.uri + "/.." + relative_prefix
            bootstrappath = req.uri + "/.." + relative_prefix + "/bootstrap/docs/assets"
    
        replacements = [    
                         navcontents, 
                         newaccountadmin,
                         sidebar,
                         "[MICA LEARNING]" if req.session['connected'] else "Disconnected",
                         cloudcontents,
                         availablecontents,
                         body,
                         popoveractivate if (not req.session["connected"] and not req.skip_show) else "",
                         spinner,
                         req.dest,
                         req.active if req.active else "",
                         req.active_obj[:-1] if req.active_obj else "",
                         bootstrappath,
                         mpath,
                         req.session['last_username'] if 'last_username' in req.session else '',
                         req.session['last_remember'] if 'last_remember' in req.session else '',
                      ]
    
        for idx in range(0, len(self.replacement_keys)) :
            x = replacements[idx]
            y = self.replacement_keys[idx]
            contents = contents.replace(y, x)
    
        return contents

    
    def online_cross_reference(self, uuid, name, story, all_source, cjk) :
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
                            new_unit["trans"].append(pair)
                        for pinyin in unit["tpinyin"] :
                            new_unit["tpinyin"].append(pinyin)
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
#        mdebug(msg)
        return units 

    def add_unit(self, trans, uni_source, eng) :
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

        return unit

    def get_first_translation(self, d, char, pinyin, none_if_not_found = True) :
        eng = []
        temp_r = d.getFor(char)
        for tr in temp_r :
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

    def recursive_translate(self, uuid, name, story, cjk, db, d, uni, storydb, temp_units) :
        units = []

        if uni in punctuation or not len(uni) :
            units.append(self.add_unit([uni], uni, [uni]))
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
                        self.recursive_translate(uuid, name, story, cjk, db, d, char, storydb, temp_units)
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
                            changes = None
                            highest = -1
                            highest_percentage = -1.0
                            selector = -1

                            if source in storydb["tonechanges"] :
                                changes = storydb["tonechanges"][source]
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
            story["units"] = story["units"] + units

    def get_cjk_handle(self) :
        cjk = CharacterLookup('C')
        db = getDBConnector({'sqlalchemy.url': 'sqlite://', 'attach': ['cjklib']})
        d = CEDICT(dbConnectInst = db)
        return (cjk, db, d)

    def parse_actual(self, uuid, name, story, storydb, groups, temp_units = False) :
        (cjk, db, d) = self.get_cjk_handle()

        if temp_units :
            story["temp_units"] = []
        else :
            story["units"] = []

        for idx in range(0, len(groups)) :
            group = groups[idx]
            uni = unicode(group.strip() if (group != "\n" and group != u'\n') else group, "UTF-8")
            self.recursive_translate(uuid, name, story, cjk, db, d, uni, storydb, temp_units)

            self.transmutex.acquire()
            try :
                storydb["stories"][name]["translating_current"] = idx 
                storydb.sync()
            except Exception, e :
                mdebug("Failure to sync: " + str(e))
            finally :
                self.transmutex.release()

    def parse(self, uuid, name, story, username, storydb) :
        mdebug("Ready to translate: " + name)
        parsed = mica_ictclas.trans(story["original"].encode("UTF-8"))
        mdebug("Parsed result: " + parsed)
        lines = parsed.split("\n")
        groups = []
        for line in lines :
            groups = groups + line.split(" ")
            groups.append("\n")

        self.transmutex.acquire()
        try :
            storydb["stories"][name]["translating_total"] = len(groups)
            storydb["stories"][name]["translating_current"] = 1
            storydb["stories"][name]["translating"] = True 
            storydb.sync()
        except Exception, e :
            mdebug("Failure to sync: " + str(e))
        finally :
            self.transmutex.release()

        try :
            self.parse_actual(uuid, name, story, storydb, groups)
        except Exception, e :
            storydb["stories"][name]["translating"] = False 
            storydb.sync()
            raise e
            

        self.transmutex.acquire()
        try :
            storydb["stories"][name] = story
            storydb["stories"][name]["translating"] = False 
            storydb["stories"][name]["translated"] = True 
            storydb.sync()
        except Exception, e :
            mdebug("Failure to sync: " + str(e))
        finally :
            self.transmutex.release()

        minfo("Translation complete.")

    def get_parts(self, unit) :
        py = ""
        english = ""
        if unit["multiple_correct"] == -1 :
            for widx in range(0, len(unit["spinyin"])) :
                word = unit["spinyin"][widx]
                if word == u'\n' or word == '\n':
                    py += word
                elif py != "\n" and py not in punctuation :
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

    def polyphomes(self, story, uuid, unit, nb_unit, trans_id, db) :
        out = ""
        out += "\nThis character (" + " ".join(unit["source"]) + ") is polyphonic: (has more than one pronunciation):<br>"
        out += "<table class='table table-hover table-striped' style='font-size: x-small'>"
        out += "<tr><td>Pinyin</td><td>Definition</td><td>Default?</td></tr>"
        source = "".join(unit["source"])

        total_changes = 0.0
        changes = None
        if source in db["tonechanges"] :
            changes = db["tonechanges"][source]
            total_changes = float(changes["total"])

        for x in range(0, len(unit["multiple_spinyin"])) :
             spy = " ".join(unit["multiple_spinyin"][x])
             percent = self.get_polyphome_percentage(x, total_changes, changes, unit) 

             out += "<tr><td>" + spy + " (" + str(percent) + " %) </td>"
             out += "<td>" + " ".join(unit["multiple_english"][x]).replace("\"", "\\\"").replace("\'", "\\\"").replace("/", " /<br/>") + "</td>"
             if unit["multiple_correct"] != -1 and x == unit["multiple_correct"] :
                 out += "<td>Default</td>"
             else :
                 out += "<td><a style='font-size: x-small' class='btn btn-mini' " + \
                        "onclick=\"multiselect('" + uuid + "', '" + str(x) + "', '" + \
                        str(nb_unit) + "','" + str(trans_id) + "', '" + spy + "')\">Select</a></td>"

             out += "</tr>"

        out += "</table>"

        return out

    def history(self, story, uuid, db) :
        out = ""

        out += "<div class='accordion' id='accordionHistory'>\n"
        
        history = []
        found = {}
        tid = 0
        for unit in story["units"] :
            char = "".join(unit["source"])
            if char not in db["tonechanges"] :
                continue
            changes = db["tonechanges"][char]
            if unit["hash"] not in changes["record"] :
                continue
            record = changes["record"][unit["hash"]]
            if char not in found :
                found[char] = True
                history.append([char, str(changes["total"]), " ".join(record["spinyin"]), " ".join(record["english"]), tid])
            tid += 1
        
        # Add sort options here
        def by_total( a ):
            return int(a[1])

        history.sort( key=by_total, reverse = True )

        for x in history :
            out += """
                <div class='accordion-group'>
                  <div class="accordion-heading">
                  """

            char, total, spy, eng, tid = x
            tid = str(tid)

            if len(eng) and eng[0] == '/' :
               eng = eng[1:-1]

            out += char + " (" + str(total) + "): "

            out += "<a class='accordion-toggle' style='display: inline' data-toggle='collapse' data-parent='#accordionHistory'" + tid + " href='#collapse" + tid + "'>"

            out += "<i class='icon-arrow-down' style='size: 50%'></i>&nbsp;" + spy

            out += "</a>"
            out += "</div>"
            out += "<div id='collapse" + tid + "' class='accordion-body collapse'>"
            out += "<div class='accordion-inner'>" + eng.replace("\"", "\\\"").replace("\'", "\\\"").replace("/", " /<br/>") + "</div>"

            out += "</div>"
            out += "</div>"

        out += "</div>"

        return out

    def edits(self, story, uuid, db) :
        out = ""

        history = []
        found = {}
        tid = 0
        for unit in story["units"] :
            char = "".join(unit["source"])
            if char in found :
                continue

            if char in db["splits"] :
                changes = db["splits"][char]
                if unit["hash"] not in changes["record"] :
                    continue
                record = changes["record"][unit["hash"]]
                history.append([char, str(record["total_splits"]), " ".join(record["spinyin"]), " ".join(record["english"]), tid, "<div style='color: blue; display: inline'>SPLIT&nbsp;&nbsp;&nbsp;</div>"])
            elif char in db["mergegroups"] :
                changes = db["mergegroups"][char]
                if unit["hash"] not in changes["record"] :
                    continue
                record = changes["record"][unit["hash"]]
                memberlist = "<table class='table'>"
                for key, member in record["members"].iteritems() :
                    memberlist += "<tr><td>" + member["pinyin"] + ":</td><td>" + key + "</td></tr>"
                memberlist += "</table>\n"
                history.append([char, str(changes["total"]), " ".join(record["spinyin"]), memberlist, tid, "<div style='color: red; display: inline'>MERGE</div>"])
            else :
                continue

            if char not in found :
                found[char] = True
            tid += 1
        
        # Add sort options here
        def by_total( a ):
            return int(a[1])

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
        if len(history) != 0 :
            out += """
                <div class='accordion' id='accordionEdit'>
                """
            
            for x in history :
                out += """
                    <div class='accordion-group'>
                      <div class="accordion-heading">
                      """

                char, total, spy, result, tid, op = x
                tid = str(tid)

                if len(result) and result[0] == '/' :
                   result = result[1:-1]

                out +=  op + " (" + str(total) + "): " + char + ": "

                out += "<a class='accordion-toggle' style='display: inline' data-toggle='collapse' data-parent='#accordionEdit' href='#collapse" + tid + "'>"

                out += "<i class='icon-arrow-down' style='size: 50%'></i>&nbsp;" + spy

                out += "</a>"
                out += "</div>"
                out += "<div id='collapse" + tid + "' class='accordion-body collapse'>"
                out += "<div class='accordion-inner'>" + result + "</div>"

                out += "</div>"
                out += "</div>"

            out += "</div>"
        else :
            out += "<h4>No edit history available.</h4>"

        return out

    def view(self, uuid, name, story, action, output, db, disk = False) :
        if not story["translated"] :
            return "Untranslated story! Ahhhh!"

        if not disk :
            output = "<div class='span8'>" + output
            output += """
                    <div id='translationstatus'></div>
                    <div id='pagecontent'></div>
                    <div id='pagenav'></div>
                    """

        output += """
                  <script>
                    $('#pagenav').bootpag({
                           total: 23,
                              page: 1,
                                 maxVisible: 10 
                    }).on('page', function(event, num){
                        $('#pagecontent').html('Page ' + num); 
                    });
                  </script>
                  """

        if not disk :
            output += """
                    </div> <!-- span8 reading section -->
                    <div class='span3'>
                    """
            output += "<div id='instantspin' style='display: none'>Doing online translation..." + spinner + "</div>"

            if action in ["read"] :
                output += "<div id='memolist'>" + spinner + "&nbsp;<h4>Loading statistics</h4></div><script>memolist('" + uuid + "');</script>"
            elif action == "edit" :
                output += "<div id='editslist'>" + spinner + "&nbsp;<h4>Loading statistics</h4></div><script>editslist('" + uuid + "');</script>"
            elif action == "home" :
                output += "<br/>Polyphome Legend:<br/>"
                pfh = open(cwd + "serve/legend_template.html", 'r')
                output += pfh.read()
                pfh.close()
                output += """
                    <br/>
                    Polyphome Change History:<br/>
                """
                output += "<div id='history'>" + spinner + "&nbsp;<h4>Loading statistics</h4></div><script>history('" + uuid + "');</script>"

            output += "</div>"

        return output

    def view_page(self, uuid, name, story, action, output, db, page, disk = False) :
        units = story["units"]
        chars_per_line = 60 
        words = len(units)
        pages = []
        lines = [] 
        line = [] 
        curr_page = 0

        trans_id = 0
        chars = 0

        for x in range(0, len(units)) :
            unit = units[x]

            if unit["page"] > curr_page :
                if len(line) :
                    lines.append(line)
                    line = []
                if len(lines) :
                    pages.append(lines)
                    lines = []
                chars = 0
                curr_page += 1

            source = "".join(unit["source"])

            ret = self.get_parts(unit)

            if ret == False :
                continue

            py, english = ret

            if py not in punctuation and chars >= chars_per_line :
               lines.append(line)
               line = []
               chars = 0

            if py in punctuation :
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
        if len(lines) :
            pages.append(lines)

        spacer = "<td style='margin-right: 20px'></td>"
        merge_spacer = "<td class='mergetop mergebottom' style='margin-right: 20px'></td>"
        merge_end_spacer = "<td class='mergeleft' style='margin-right: 20px'></td>"

        for pidx in range(0, len(pages)) :
            lines = pages[pidx]
            for line in lines :
                disk_out = ""
                line_out = ""

                if not disk :
                    line_out += "\n<table"
                    if pidx != 0 :
                        line_out += " style='display: none'" 
                    ">"
                    
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

                        line_out += "\n<td style='vertical-align: top; text-align: center; font-size: small' "

                        if py and action == "edit" :
                            if source in db["mergegroups"] and (unit["hash"] in db["mergegroups"][source]["record"]) :
                                curr_merge = True

                                if word_idx < (len(line) - 1) :
                                    endword = line[word_idx + 1]
                                    if endword[1] :
                                        endunit = endword[3]
                                        endchars = "".join(endunit["source"])
                                        if endchars not in db["mergegroups"] or (endunit["hash"] not in db["mergegroups"][endchars]["record"]) :
                                            merge_end = True
                                    else :
                                        merge_end = True


                        if py and action == "edit" :
                            if curr_merge :
                                if curr_merge and not prev_merge and merge_end : 
                                    merge_end = False
                                    prev_merge = False
                                    curr_merge = False

                            if curr_merge :
                                line_out += "class='mergetop mergebottom"
                                if not prev_merge : 
                                    line_out += " mergeleft"
                                line_out += "'"
                            else :
                                if not curr_merge and source in db["splits"] and unit["hash"] in db["splits"][source]["record"] :
                                    line_out += "class='splittop splitbottom splitleft splitright'"

                            prev_merge = curr_merge

                        line_out += ">"
                        line_out += "<span id='spanselect_" + trans_id + "' class='none'>"
                        line_out += "<a class='trans'"
                        line_out += " uniqueid='" + tid + "' "
                        line_out += " nbunit='" + nb_unit + "' "
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

                                if source in db["tonechanges"] :
                                    changes = db["tonechanges"][source]
                                    if unit["hash"] in changes["record"] :
                                        color = "black"
                                        add_count = " (" + str(changes["total"]) + ")"

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
                            line_out += self.polyphomes(story, uuid, unit, nb_unit, trans_id, db)
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
                        memorized = True if (py and unit["hash"] in db["memorized"]) else False
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
                                            tid + "', '" + uuid + "', '" + str(nb_unit) + "')\">"

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
            mdebug("Missing results. Probably we timed out. Trying again: " + str(e))
        except IOError, e :
            mdebug("Connection error. Will try one more time:" + str(e))

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

    def add_story(self, db, name, original = None) :
        uuid = str(uuid4.uuid4())

        story = { 
                  'uuid' : uuid,
                  'translated' : False,
                  'name' : name,
                  }

        if original is not None :
            story["original"] = original

        db["stories"][name] = story
        db["story_index"][uuid] = name
        db.sync()

    def common(self, req) :
        try :
            if req.http.params.get("connect") :

                username = req.http.params.get('username')
                password = req.http.params.get('password')

                mhash = hashlib.md5(password).hexdigest()

                if username not in self.acctdb["accounts"] or self.acctdb["accounts"][username]["password"] != mhash :
                    return self.bootstrap(req, self.heromsg + "\n<h4>Invalid credentials. Please try again.</h4></div>")

                req.action = "home"
                req.session['connected'] = True 

                if req.http.params.get('remember') and req.http.params.get('remember') == 'on' :
                    req.session['last_username'] = username
                    req.session['last_remember'] = 'checked'
                elif 'last_username' in req.session :
                    del req.session['last_username']
                    req.session['last_remember'] = ''

                req.session["username"] = username

                db, unused = self.dbcheck(req)

                if "stories" not in db :
                    db["stories"] = {}
                if "story_index" not in db :
                    db["story_index"] = {}
                if "memorized" not in db :
                    db["memorized"] = {}
                if "tonechanges" not in db :
                    db["tonechanges"] = {}
                if "splits" not in db :
                    db["splits"] = {}
                if "mergegroups" not in db :
                    db["mergegroups"] = {}
                if "tags" not in db :
                    db["tags"] = {}

                for name, story in db["stories"].iteritems() :
                    db["stories"][name]["pages"] = 1
                    if "units" in story :
                        for sidx in range(0, len(story["units"])) :
                            db["stories"][name]["units"][sidx]["page"] = 0

                    db["stories"][name]["tags"] = {}

                if "current_story" in req.session :
                    del req.session["current_story"]

                req.session["last_refresh"] = str(timest())
                req.session.save()

                db.sync()

            if 'connected' not in req.session or req.session['connected'] != True :
                msg = """
                        <h4>You need to connect, first.</h4>
                        <p/>
                        <br/>This is experimental language-learning software,
                        <br/>and thus accounts are granted on-demand.
                        <br/>Contact: <a href="http://michael.hinespot.com">http://michael.hinespot.com</a> for assistance.
                        </div>
                      """
                return self.bootstrap(req, self.heromsg + msg)
                
            db, username = self.dbcheck(req)
            req.db = db

            if username not in self.first_request :
               self.first_request[username] = True 

               for name, story in db["stories"].iteritems() :
                   if "translating" in story and story["translating"] :
                       mdebug("Killing stale translation session: " + name)
                       db["stories"][name]["translating"] = False
                       db.sync()

            def add_story_from_source(req, filename, source, db) :
                if filename in db["stories"] :
                    return self.bootstrap(req, self.heromsg + "\nUpload Failed! Story already exists: " + filename + "</div>")
                mdebug("Received new story contents: " + source + ", name: " + filename)

                self.add_story(db, filename, source.decode("utf-8"))

                if "current_story" in req.session :
                    del req.session["current_story"]
                    req.session.save()

                return self.bootstrap(req, self.heromsg + "\nUpload Complete! Story ready for translation: " + filename + "</div>")

            if req.http.params.get("uploadfile") :
                fh = req.http.params.get("storyfile")
                source = fh.file.read()
                return add_story_from_source(req, fh.filename.lower().replace(" ","_"), source, db)

            if req.http.params.get("uploadtext") :
                source = req.http.params.get("storytext") + "\n"
                filename = req.http.params.get("storyname").lower().replace(" ","_")
                return add_story_from_source(req, filename, source, db)

            if req.action != "home" :
                req.skip_sidebar = True
            else :
                if "current_story" in req.session :
                    req.skip_sidebar = True
                else :
                    for skippable_option in [ "view", "forget", "translate"  ] :
                       if req.http.params.get(skippable_option) :
                           req.skip_sidebar = True

                
            uuid = False
            name = False
            story = False

            if req.http.params.get("uuid") :
                uuid = req.http.params.get("uuid") 

                if req.http.params.get("tstatus") :
                    out = "<div id='tstatusresult'>"
                    if uuid not in db["story_index"] :
                        out += "error 25"
                    else :
                        name = db["story_index"][uuid]
                        story = db["stories"][name]
                        if "translating" not in story or not story["translating"] :
                            out += "no 0"
                        else :
                            curr = float(int(story["translating_current"]))
                            total = float(int(story["translating_total"]))

                            out += "yes " + str(int(curr / total * 100))
                    out += "</div>"
                    return self.bootstrap(req, self.heromsg + "\n" + out + "</div>")

            if "current_story" in req.session :
                if uuid :
                    req.session["current_story"] = uuid
                    req.session.save()
                else :
                    uuid = req.session["current_story"]
            elif uuid :
                req.session["current_story"] = uuid
                req.session.save()

            if uuid :
                if uuid not in db["story_index"] :
                    if "current_story" in req.session :
                        del req.session["current_story"]
                        req.session.save()
                    return self.bootstrap(req, self.heromsg + "\n<h4>Invalid story uuid: " + uuid + "</h4></div>")

                name = db["story_index"][uuid]
                story = db["stories"][name]

            if req.http.params.get("reviewed") :
                reviewed = True if req.http.params.get("reviewed") == "1" else False
                db["stories"][name]["reviewed"] = reviewed 
                if reviewed :
                    db["stories"][name]["final"] = self.view(uuid, name, story, req.action, "", db, disk = True)
                db.sync()

            if req.http.params.get("forget") :
                req.skip_sidebar = False
                if "units" not in db["stories"][name] :
                    return self.bootstrap(req, self.heromsg + "\n<h4>Invalid Forget request for story: " + name + ", uuid: " + uuid + "</h4></div>")
                db["stories"][name]["translated"] = False
                db.sync()

                story = db["stories"][name]

                if "current_story" in req.session and req.session["current_story"] == uuid :
                    del req.session["current_story"]
                    req.session.save()
                    uuid = False

            if req.http.params.get("delete") :
                if name not in db["stories"] :
                    mdebug(sf + " does not exist. =(")
                else :
                    del db["stories"][name]
                    del db["story_index"][uuid]
                    db.sync()
                uuid = False

            if req.http.params.get("instant") :
                source = req.http.params.get("instant")
                human = int(req.http.params.get("human")) if req.http.params.get("human") else 0
                out = ""
                out += "<div id='instantresult'>"
                final = { }
                requests = [source]
                breakout = source.decode("utf-8")
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
                        p += "(" + char + "): " + english + "<br/>\n"
                        final["parts"].append((char, english))
                       
                if human :
                    out += "<h4>Online translation:</h4>"
                    out += p 
                    out += "<h4>Offline translation:</h4>"

                    (cjk, db, d) = self.get_cjk_handle()
                    eng = self.get_first_translation(d, source.decode("utf-8"), False)
                    if eng :
                        for english in eng :
                            out += english.encode("utf-8")
                    else :
                        out += "None found."
                else :
                    out += json.dumps(final)
                out += "</div>"
                return self.bootstrap(req, self.heromsg + "\n<h4>" + out + "</h4></div>", now = True)

            def add_record(db, unit, mindex, which, key) :
                char = "".join(unit["source"])
                hcode = self.get_polyphome_hash(mindex, unit["source"])

                if char in db[which] :
                    changes = db[which][char]
                else :
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

                db[which][char] = changes

            if req.http.params.get("multiple_select") :
                nb_unit = int(req.http.params.get("nb_unit"))
                mindex = int(req.http.params.get("index"))
                trans_id = int(req.http.params.get("trans_id"))
                unit = db["stories"][name]["units"][nb_unit]
                unit["multiple_correct"] = mindex
                self.rehash_correct_polyphome(unit) 
                db["stories"][name]["units"][nb_unit] = unit

                add_record(db, unit, mindex, "tonechanges", "selected") 
                db.sync()

                return self.bootstrap(req, self.heromsg + "\n<div id='multiresult'>" + \
                                           self.polyphomes(story, uuid, unit, nb_unit, trans_id, db) + \
                                           "</div></div>", now = True)

            output = ""

            if req.http.params.get("phistory") :
                return self.bootstrap(req, self.heromsg + "\n<div id='historyresult'>" + \
                                           self.history(story, uuid, db) + \
                                           "</div></div>", now = True)

            if req.http.params.get("editslist") :
                return self.bootstrap(req, self.heromsg + "\n<div id='editsresult'>" + \
                                           self.edits(story, uuid, db) + \
                                           "</div></div>", now = True)

            if req.http.params.get("translate") :
                output += "<div id='translationstatusresult'>" + self.heromsg
                if story["translated"] :
                    output += "Story already translated. To re-translate, please select 'Forget'."
                else :
                    try :
                        self.parse(uuid, name, story, username, db)
                        output += self.heromsg + "Translation complete!"
                    except Exception, e :
                        output += "Failed to translate story: " + str(e)
                output += "</div></div>"
                return self.bootstrap(req, output, now = True)

            if req.http.params.get("memorized") :
                memorized = int(req.http.params.get("memorized"))
                nb_unit = int(req.http.params.get("nb_unit"))
                unit = db["stories"][name]["units"][nb_unit]
                if memorized :
                    db["memorized"][unit["hash"]] = unit
                else :
                    del db["memorized"][unit["hash"]];
                db.sync()
                return self.bootstrap(req, self.heromsg + "\n<div id='memoryresult'>Memorized! " + \
                                           unit["hash"] + "</div></div>", now = True)

            if req.http.params.get("operation") :
                operation = req.http.params.get("operation")
                if operation == "split" :
                    nb_unit = int(req.http.params.get("nbunit"))
                    mindex = int(req.http.params.get("index"))
                    mhash = req.http.params.get("tid")

                    units = db["stories"][name]["units"]
                    before = units[:nb_unit] if (nb_unit > 0) else []
                    after = units[nb_unit + 1:] if (nb_unit != (len(units) - 1)) else []
                    curr = units[nb_unit]
                    groups = []

                    for char in curr["source"] :
                        groups.append(char.encode("UTF-8"))

                    self.parse_actual(uuid, name, story, db, groups, temp_units = True)
                    db["stories"][name]["units"] = before + story["temp_units"] + after
                    del story["temp_units"]
                    add_record(db, curr, mindex, "splits", "splits")
                    db.sync()

                elif operation == "merge" :
                    nb_units = int(req.http.params.get("units"))
                    nb_unit_start = int(req.http.params.get("nbunit0"))
                    mindex_start = int(req.http.params.get("index0"))
                    mhash_start = req.http.params.get("tid0")
                    mindex_stop = int(req.http.params.get("index" + str(nb_units - 1)))
                    nb_unit_stop = int(req.http.params.get("nbunit" + str(nb_units - 1)))
                    mhash_stop = req.http.params.get("tid" + str(nb_units - 1))

                    units = db["stories"][name]["units"]
                    before = units[:nb_unit_start] if (nb_unit_start > 0) else []
                    after = units[nb_unit_stop + 1:] if (nb_unit_stop != (len(units) - 1)) else []
                    curr = units[nb_unit_start:(nb_unit_stop + 1)]
                    group = ""

                    for chargroup in curr :
                        for char in chargroup["source"] :
                            group += char.encode("UTF-8")

                    self.parse_actual(uuid, name, story, db, [group], temp_units = True)

                    if len(story["temp_units"]) == 1 :
                        merged = story["temp_units"][0]
                        merged_chars = "".join(merged["source"])
                        db["stories"][name]["units"] = before + [merged] + after

                        for unit in curr :
                            char = "".join(unit["source"])
                            mindex = unit["multiple_correct"]
                            hcode = self.get_polyphome_hash(mindex, unit["source"])

                            if char in db["mergegroups"] :
                                changes = db["mergegroups"][char]
                            else :
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
                                hcode_contents["members"][merged_chars] = { 
                                                                "total_merges" : 0,
                                                                "pinyin" : " ".join(merged_pinyin)}

                            hcode_contents["members"][merged_chars]["total_merges"] += 1

                            changes["record"][hcode] = hcode_contents

                            if "total" not in changes :
                                changes["total"] = 0

                            changes["total"] += 1

                            db["mergegroups"][char] = changes

                    del story["temp_units"]
                    db.sync()
                else :
                    return self.bootstrap(req, self.heromsg + "\nInvalid Operation!</div>")

            if req.http.params.get("memolist") :
                output = ""
                added = {}
                unique = {}
                progress = []
                total_memorized = 0
                total_unique = 0
                trans_id = 0
                story = db["stories"][name]
                units = story["units"]

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
                    if unit["hash"] in db["memorized"] :
                        if unit["hash"] not in added :
                            added[unit["hash"]] = unit
                            progress.append([py, english, unit, x, trans_id])
                            total_memorized += 1

                    if py and py not in punctuation :
                        unique[unit["hash"]] = True

                    trans_id += 1
                
                total_unique = len(unique)
                sync = False
                if "total_memorized" not in story or story["total_memorized"] != total_memorized :
                    db["stories"][name]["total_memorized"] = total_memorized
                    sync = True
                if "total_unique" not in story or story["total_unique"] != total_unique :
                    db["stories"][name]["total_unique"] = total_unique 
                    sync = True
                if sync :
                    db.sync()

                pr = str(int((float(total_memorized) / float(total_unique)) * 100))
                output += "Total words memorized from all stories: " + str(len(db["memorized"])) + "<br/>"
                output += "Total unique memorized from this story: " + str(total_memorized) + "<br/>"
                output += "Total unique words from this story: " + str(len(unique)) + "<br/>"
                output += "<div class='progress progress-success progress-striped'><div class='bar' style='width: "
                output += pr + "%;'> (" + pr + "%)</div></div>"

                if total_memorized :
                    output += "<div class='accordion' id='accordionMemorized'>\n"
                    for p in progress :
                        output += """
                                <div class='accordion-group'>
                                  <div class="accordion-heading">
                                  """
                        py, english, unit, nb_unit, trans_id = p
                        if len(english) and english[0] == '/' :
                            english = english[1:-1]
                        tid = unit["hash"] if py else trans_id 

                        output += "<a class='trans btn btn-mini' onclick=\"forget('" + \
                                str(tid) + "', '" + uuid + "', '" + str(nb_unit) + "')\">" + \
                                "<i class='icon-remove'></i></a>"

                        output += "&nbsp; " + "".join(unit["source"]) + ": "
                        output += "<a class='accordion-toggle' style='display: inline' data-toggle='collapse' data-parent='#accordionMemorized' href='#collapse" + tid + "'>"

                        output += "<i class='icon-arrow-down' style='size: 50%'></i>&nbsp;" + py
                        output += "</a>"
                        output += "</div>"
                        output += "<div id='collapse" + tid + "' class='accordion-body collapse'>"
                        output += "<div class='accordion-inner'>" + english.replace("/"," /") + "</div>"
                        output += "</div>"
                        output += "</div>"
                    output += "</div>"
                else :
                    output += "No words memorized. Get to work!"

                return self.bootstrap(req, self.heromsg + "\n<div id='memolistresult'>" + output + "</div></div>", now = True)
               
            if req.action in ["home", "read", "edit" ] :
                if uuid :
                    # Reload just in case the translation changed anything
                    name = db["story_index"][uuid]
                    story = db["stories"][name]
                    output = self.view(uuid, name, story, req.action, output, db)
                else :
                    output += self.heromsg + "<h4>No story loaded. Choose a story to read from the sidebar<br/>or create one by clicking on 'Account' at the top.</h4></div>"

                return self.bootstrap(req, output)
            elif req.action == "stories" :
                if req.http.params.get("type") :
                    which = req.http.params.get("type")
                    if which == "original" :
                        return self.bootstrap(req, story["original"].encode("UTF-8").replace("\n","<br/>"))
                    elif which == "pinyin" :
                        return self.bootstrap(req, story["final"].encode("UTF-8").replace("\n","<br/>"))
            elif req.action == "account" :
                db, username = self.dbcheck(req)
                req.db = db
                out = ""

                if 'admin' in self.acctdb["accounts"][username]["roles"] :
                    out += "<h5>Accounts:</h5>"
                    out += "<table>"
                    for u, acct in self.acctdb["accounts"].iteritems() :
                        out += "<tr><td>" + u + "</td><td>Roles: " + ",".join(acct["roles"]) + "</td></tr>"
                    out += "</table>"
                out += """
                    <p/>
                    <form action='BOOTDEST/account' method='post' enctype='multipart/form-data'>
                    <table>
                    <tr><td><h5>&nbsp;Old Password: </td><td><input type="password" name="oldpassword"/></h5></td></tr>
                    <tr><td><h5>&nbsp;Password: </td><td><input type="password" name="password"/></h5></td></tr>
                    <tr><td><h5>&nbsp;Confirm:&nbsp; </td><td><input type="password" name="confirm"/></h5></td></tr>
                    <tr><td><button name='changepassword' type="submit" class="btn btn-primary" value='1'>Change Password</button></td></tr>
                    </table>
                    </form>                                   
                    """

                if req.http.params.get("newaccount") :
                    newusername = req.http.params.get("username")
                    newpassword = req.http.params.get("password")
                    newpasswordconfirm = req.http.params.get("confirm")
                    admin = req.http.params.get("isadmin", 'off')

                    if newpassword != newpasswordconfirm :
                        return self.bootstrap(req, self.heromsg + "\n<h4>Passwords don't match! Try again.</h4></div>")

                    if newusername in self.acctdb["accounts"] :
                        return self.bootstrap(req, self.heromsg + "\n<h4>Account already exists! Try again.</h4></div>")

                    if 'admin' not in self.acctdb["accounts"][username]["roles"] and admin == 'on' :
                        return self.bootstrap(req, self.heromsg + "\n<h4>Non-admin users can't create admin accounts. What are you doing?!</h4></div>")

                    roles = ['normal']
                    if admin == 'on' :
                        roles.append('admin')

                    self.acctdb["accounts"][newusername] = { 'password' : hashlib.md5(newpassword).hexdigest(),
                                                    'roles' : roles,
                                                  }
                    self.acctdb.sync()

                    out += self.heromsg + "\n<h4>Success! New user " + newusername + " created.</h4></div>"

                elif req.http.params.get("changepassword") :
                    oldpassword = req.http.params.get("oldpassword")
                    newpassword = req.http.params.get("password")
                    newpasswordconfirm = req.http.params.get("confirm")
                    newhash = hashlib.md5(newpassword).hexdigest()
                    oldhash = hashlib.md5(oldpassword).hexdigest()

                    if newpassword != newpasswordconfirm :
                        return self.bootstrap(req, self.heromsg + "\n<h4>Passwords don't match! Try again.</h4></div>")
                    if oldhash != self.acctdb["accounts"][username]['password'] :
                        return self.bootstrap(req, self.heromsg + "\n<h4>Old passwords don't match! Try again.</h4></div>")
                    self.acctdb["accounts"][username]['password'] = newhash
                    self.acctdb.sync()
                    out += self.heromsg + "\n<h4>Success! User " + username + "'s password changed.</h4></div>"

                return self.bootstrap(req, out)
                    
            elif req.action == "disconnect" :
                req.session['connected'] = False
                #del req.session['cloud_name'] # delete whatever shouldn't be in the session
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
        except mica_ictclas.error, e :
            return self.bootstrap(req, self.heromsg + "\n<h4 id='gerror'>Error: mica C-extension failed: " + str(e) + "</h4>")
        except Exception, msg:
            mdebug("Exception: " + str(msg))
            out = "Exception:\n" 
            resp = "<h4>Exception:</h4>"
            for line in traceback.format_exc().splitlines() :
                resp += "<br>" + line
                out += line + "\n"
            mdebug(out )

            try :
                return self.bootstrap(req, self.heromsg + "\n<h4 id='gerror'>Error: Something bad happened: " + str(msg) + "</h4>" \
                                            + resp + "</div>")
            except Exception, e :
                print "OTHER MICA ********Exception:"
                for line in traceback.format_exc().splitlines() :
                    print "OTHER MICA ********" + line
            return out

session_opts = {
    'session.data_dir' : '/tmp/mica_sessions_' + getpwuid(os.getuid())[0] + '_data',
    'session.lock_dir' : '/tmp/mica_sessions_' + getpwuid(os.getuid())[0] + '_lock',
    'session.type' : 'file',
    }

class GUIDispatcher(Resource) :
    def __init__(self, port, host) :

        Resource.__init__(self)
        self.serve = File(cwd + relative_prefix)
        # example of how to serve individual UTF-8 encoded files:
        # self.stories = File(cwd + relative_prefix + "/../stories/")
        # self.stories.contentTypes['.txt'] = 'text/html; charset=utf-8'
        self.files = File(cwd)
        self.icon = File(cwd + relative_prefix + "/favicon.ico")
        self.git = File(cwd + "/.git")
        self.git.indexNames = ["test.rpy"]
        self.mica = MICA(options.client_id, options.client_secret)
            
        self.app = WSGIResource(reactor, reactor.threadpool, SessionMiddleware(self.mica, session_opts))

    def getChild(self, name, request) :
        # Hack to make WebOb work with Twisted
        request.content.seek(0,0)
        request.setHeader('Access-Control-Allow-Origin', '*')
        request.setHeader('Access-Control-Allow-Origin', '*')
        request.setHeader('Access-Control-Allow-Methods', 'GET')
        request.setHeader('Access-Control-Allow-Headers', 'x-prototype-version,x-requested-with')
        request.setHeader('Access-Control-Max-Age', 2520)
        request.setHeader('Content-Type', 'text/html; charset=utf-8')

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

class NONSSLRedirect(object) :
    def __init__(self):
        pass

    def __call__(self, environ, start_response):
        req = Params(environ)
        (req.dest, req.path) = prefix(req.unparsed_uri)
        tossl = "https://" + req.dest + ":" + str(options.sslport) + "/" + req.path 
        mdebug("Redirecting non-ssl request to: " + tossl)
        resp = exc.HTTPTemporaryRedirect(location = tossl)
        return resp(environ, start_response)
        
class NONSSLDispatcher(Resource) :
    def __init__(self, sslport, host) :

        Resource.__init__(self)
            
        self.nonssl = NONSSLRedirect()
        self.app = WSGIResource(reactor, reactor.threadpool, SessionMiddleware(self.nonssl, session_opts))

    def getChild(self, name, request) :
        return self.app

parser = OptionParser()
client_id = "micalearning"
client_secret = "fge8PkcT/cF30AcBKOMuU9eDysKN/a7fUqH6Tq3M0W8="

parser.add_option("-p", "--port", dest = "port", default = "80", help ="port")
parser.add_option("-s", "--sslport", dest = "sslport", default = "443", help ="sslport")
parser.add_option("-H", "--host", dest = "host", default = "0.0.0.0", help ="hostname")
parser.add_option("-k", "--keepsession", dest = "keepsession", action = "store_true", default = False, help ="do not destroy the previous HTTP session")
parser.add_option("-d", "--daemon", dest = "daemon", action = "store_true", \
                   default = False, help ="Daemonize the service.")
parser.add_option("-l", "--log", dest = "logfile", default = cwd + "logs/mica.log", help ="MICA main log file.")
parser.add_option("-t", "--tlog", dest = "tlogfile", default = cwd + "logs/twisted.log", help ="Twisted log file.")
parser.add_option("-I", "--client-id", dest = "client_id", default = False, help = "Microsoft Translation Client App ID (why? Because it's free, and google is not)")
parser.add_option("-S", "--client-secret", dest = "client_secret", default = False, help = "Microsoft Translation Client App Secret (why? Because it's free, and google is not)")
parser.add_option("-C", "--cert", dest = "cert", default = False, help = "Path to certificate for Twisted to run OpenSSL")
parser.add_option("-K", "--privkey", dest = "privkey", default = False, help = "Path to private key for Twisted to run OpenSSL")
parser.add_option("-a", "--slaves", dest = "slaves", default = "127.0.0.1", help = "List of slave addresses")
parser.add_option("-w", "--slave_port", dest = "slave_port", default = "5050",
help = "Port on which the slaves are running")

parser.set_defaults()
options, args = parser.parse_args()

if not options.cert or not options.privkey :
    print "Need locations of SSL certificate and private key (options -C and -K). You can generate self-signed ones if you want, see the README."
    exit(1)

if not options.client_id or not options.client_secret:
    print "Microsoft Client ID and Secret are for their translation service is required (options -I and -S). Why? Because it's free and google is not =)"
    exit(1)

if not options.keepsession and 'session.data_dir' in session_opts and 'session.lock_dir' in session_opts :
    try :
        shutil.rmtree(session_opts['session.data_dir'])
        shutil.rmtree(session_opts['session.lock_dir'])
    except OSError :
        pass

slaves = {}

def main() :
    mica_init_logging(options.logfile)

    log.startLogging(DailyLogFile.fromFullPath(options.tlogfile), setStdout=True)

    try :
        slave_addresses = options.slaves.split(",")

        for slave_address in slave_addresses :
            slave_uri = "http://" + slave_address + ":" + options.slave_port
            minfo("Registering slave @ " + slave_uri)
            slaves[slave_uri] = MICASlaveClient(slave_uri)
            #slaves[slave_uri].foo("bar")

        assert(len(slaves) >= 1)

        reactor._initThreadPool()
        site = Site(GUIDispatcher(options.port, options.host))
        nonsslsite = Site(NONSSLDispatcher(options.sslport, options.host))

        reactor.listenTCP(int(options.port), nonsslsite, interface = options.host)
        reactor.listenSSL(int(options.sslport), site, ssl.DefaultOpenSSLContextFactory(options.privkey, options.cert), interface = options.host)
        minfo("Point your browser at port: " + str(options.sslport) + ". (Bound to interface: " + options.host + ")")

        reactor.run()
    except Exception, e :
        minfo("What the hell is going on? " + str(e))

if options.daemon :
    with DaemonContext(
            working_directory=cwd,
            pidfile=None,
        ) :
        main()
else :
    main()
