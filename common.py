#!/usr/bin/env python
# coding: utf-8
from logging.handlers import RotatingFileHandler 
from logging import getLogger, StreamHandler, Formatter, Filter, DEBUG, ERROR, INFO, WARN, CRITICAL
from datetime import datetime as datetime_datetime
from time import time as timestlocal, strftime, strptime, localtime, timezone
from threading import Lock
from xmlrpclib import Server
from re import compile as re_compile
from os import path as os_path
from sys import getdefaultencoding
from locale import setlocale, LC_ALL, getlocale
from gettext import install as gettext_install, GNUTranslations, NullTranslations
from urllib2 import quote, unquote
from time import time as timest
from traceback import extract_stack
from sys import _getframe
from json import loads as json_loads, dumps as json_dumps

import __builtin__
import xmlrpclib
import sys
import threading

spinner = "jqmica/images/ajax-loader.gif"

def timest() :
    return timestlocal() - timezone

texts = {}

cwd = re_compile(".*\/").search(os_path.realpath(__file__)).group(0)
sys.path = [cwd] + sys.path

if getdefaultencoding() != "utf-8" :
    print "Correcting the default encoding back to UTF-8 from " + getdefaultencoding()
    reload(sys).setdefaultencoding("utf-8")

try :
    from jnius import autoclass
    String = autoclass('java.lang.String')
except ImportError, e :
    String = False
    print("pyjnius not available. Probably on a server.")

gnutextkwargs = {}
catalogs = threading.local()

if sys.version_info[0] < 3:
    # In Python 2, ensure that the _() that gets installed into built-ins
    # always returns unicodes.  This matches the default behavior under Python
    # 3, although that keyword argument is not present in the Python 3 API.
    gnutextkwargs['unicode'] = True

gettext_install("mica", **gnutextkwargs)

micalogger = False
txnlogger = False
duplicate_logger = False

def get_global_language() :
    global global_language
    return global_language

def dump_all_threads() :
    mdebug("\n*** STACKTRACE - START ***\n")

    for threadId, stack in sys._current_frames().items():
        mdebug("\n# ThreadID: " + str(threadId) + " " + str(stack))
        for filename, lineno, name, line in extract_stack(stack):
            mdebug("File: " + str(filename))
            mdebug("File: %s, line %d, in %s" % (filename, lineno, name))
            if line:
                mdebug("  %s" % (line.strip()))

    mdebug("\n*** STACKTRACE - END ***\n")


def gettext(message):
    global global_language
    try :
        result = texts[catalogs.language].ugettext(message)
        return result
    except AttributeError, e :
        return texts[global_language].ugettext(message)

def pre_init_localization(language, log = False) :
    global global_language 
    if String and log :
        log.debug(String("Beginning localization: " + language))

    for l in lang :
       locale = l.split("-")[0]
       try:
           texts[locale] = GNUTranslations(open(cwd + "res/messages_" + locale + ".mo", 'rb'))
       except IOError:
           if l == u"en" :
               texts[locale] = NullTranslations()
           else :
               print("Language translation " + l + " failed. Bailing...")
               exit(1)

    __builtin__.__dict__['_'] = gettext 

    if language.count("-") :
        language = language.split("-")[0]
    if language.count("_") :
        language = language.split("_")[0]

    if language in texts :
        global_language = language

    test = "Translation test: " + texts[global_language].ugettext("Please wait...")
    test2 = "Translation test 2: " + _("Please wait...")
    if String and log :
        log.debug(String("language set to: " + global_language))
        log.debug(String(test))
        log.debug(String(test2))
    else :
        print("Language set to: " + global_language)
        #print(test)
        #print(test2)

lang = {
         u"zh-CHS" : _(u"Chinese Simplified"),
         u"en" : _(u"English"),
         u"py" : _(u"Pinyin"),
         u"es" : _(u"Spanish"),
       }

supported = {
          u"en,zh-CHS" : _(u"English to Chinese"),
          u"zh-CHS,en" : _(u"Chinese to English"),
          u"es,en" : _(u"Spanish to English"),
          u"en,es" : _(u"English to Spanish"),
        }

supported_map = {
        u"zh-CHS" : u"zh-CHS",
        u"zh" : u"zh-CHS",
        u"en" : u"en",
        u"es" : u"es",
        u"py" : u"py",
}

processor_map = {
        u"zh-CHS,en" : u"ChineseSimplifiedToEnglish", 
        u"en,zh-CHS" : u"EnglishToChineseSimplified", 
        u"es,en" : u"SpanishToEnglish",
        u"en,es" : u"EnglishToSpanish",
        u"py": False,
}

tutorials = {
        u"zh" : "info_template.html", 
        u"en" : "info_template.html", 
        u"es" : "info_template.html", 
        u"py": "info_template.html",
}

verbose = False
#verbose = True

def prefix() :
   f = _getframe(2)
   log_prefix = f.f_code.co_filename.split('/')[-1] + '/'
   if 'self' in f.f_locals :
       log_prefix += f.f_locals['self'].__class__.__name__ + '.'
   log_prefix += f.f_code.co_name + ":" + str(f.f_lineno)
   log_prefix += " "
   return log_prefix

def minfo(msg) :
   if micalogger :
       micalogger.info(prefix() + msg)
   else :
       print prefix() + msg
   if duplicate_logger and String :
      duplicate_logger.info(String(prefix() + msg))

def mverbose(msg) :
    if verbose :
        mdebug(prefix() + msg)

def mdebug(msg) :
   if micalogger :
       micalogger.debug(prefix() + msg)
       #micalogger.debug(threading.current_thread().name + ": " + prefix() + msg)
   else :
       print prefix() + msg

   if duplicate_logger and String :
      duplicate_logger.debug(String(prefix() + msg))

def mwarn(msg) :
   if micalogger :
       micalogger.warn(prefix() + msg)
   else :
       print prefix() + msg
   if duplicate_logger and String :
      duplicate_logger.warn(String(prefix() + msg))

def merr(msg) :
   if micalogger :
       micalogger.error(prefix() + msg)
   else :
       print prefix() + msg
   if duplicate_logger and String :
      duplicate_logger.err(String(prefix() + msg))

mobile = True 

try :
    from jnius import autoclass
    String = autoclass('java.lang.String')
except ImportError, e :
    try :
        from pyobjus import autoclass, objc_f, objc_str as String, objc_l as Long, objc_i as Integer
    except ImportError, e :
        mdebug("pyjnius and pyobjus not available. Probably on a server.")
        mobile = False

if not mobile :
    from requests_oauthlib import OAuth2Session
    from requests_oauthlib.compliance_fixes import facebook_compliance_fix, weibo_compliance_fix

def mica_init_logging(logfile, duplicate = False) :
    global micalogger
    global duplicate_logger

    if duplicate :
        duplicate_logger = duplicate

    # Reset the logging handlers
    logger = getLogger()
    while len(logger.handlers) != 0 :
        logger.removeHandler(logger.handlers[0])

    restlogger = getLogger("restkit.client")
    restlogger.setLevel(level=INFO)
    txnlogger = getLogger("txn")
    txnlogger.setLevel(level=INFO)
    micalogger = getLogger("")
    micalogger.setLevel(DEBUG)

    formatter = Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    if logfile and logfile != 1 :
        handler = RotatingFileHandler(logfile, maxBytes=(1048576*5), backupCount=7)
        handler.setFormatter(formatter)

        micalogger.addHandler(handler)
        txnlogger.addHandler(handler)
        restlogger.addHandler(handler)

    streamhandler = StreamHandler()
    streamhandler.setFormatter(formatter)

    micalogger.addHandler(streamhandler)
    txnlogger.addHandler(streamhandler)
    restlogger.addHandler(streamhandler)

def wait_for_port_ready(hostname, port, try_once = False) :
    '''
    TBD
    '''
    while True :
        try:
            s = socket_socket()
            s.setsockopt(SOL_SOCKET, SO_REUSEADDR,1)
            s.bind((hostname, int(port)))
            s.close()
            break
        except socket_error, (value, message) :
            if value == 98 : 
                mwarn("Previous port " + str(port) + " taken! ...")
                if try_once :
                    return False
                sleep(30)
                continue
            else :
                merr("Could not test port " + str(port) + " liveness: " +  message)
                raise
    return True

class MICASlaveException(Exception) :
    def __init__(self, status, msg):
        Exception.__init__(self)
        self.msg = msg
        self.status = str(status)
    def __str__(self):
        return self.msg

def makeTimestampNoDate(supplied_epoch_time = False) :
    if not supplied_epoch_time :
        _now = datetime_datetime.now()
    else :
        _now = datetime_datetime.fromtimestamp(supplied_epoch_time)
        
    _date = _now.date()

    result = "" 
        
    result += strftime(" %I:%M:%S %p", 
                        strptime(str(_now.hour) + ":" + str(_now.minute) + ":" + \
                                 str(_now.second), "%H:%M:%S"))
    return result

def makeTimestamp(supplied_epoch_time = False) :
    if not supplied_epoch_time :
        _now = datetime_datetime.now()
    else :
        _now = datetime_datetime.fromtimestamp(supplied_epoch_time)
        
    _date = _now.date()

    result = ("%02d" % _date.month) + "/" + ("%02d" % _date.day) + "/" + ("%04d" % _date.year)
        
    result += strftime(" %I:%M:%S %p", 
                        strptime(str(_now.hour) + ":" + str(_now.minute) + ":" + \
                                 str(_now.second), "%H:%M:%S"))
        
    result += strftime(" %Z", localtime(time())) 
    return result

mutex = Lock()

class MICASlaveClient(Server):
    def slave_error_check(self, func):
        def wrapped(*args, **kwargs):
            try :
                mutex.acquire()
                resp = func(*args, **kwargs)
                mutex.release()
            except Exception, e :
                mutex.release()
                raise e
            if int(resp["status"]) :
                raise MICASlaveException(str(resp["status"]), resp["msg"])
            if self.print_message :
                print resp["msg"] 
            return resp["result"]
        return wrapped

    def __init__ (self, service_url, print_message = False):
        
        '''
         This rewrites the xmlrpc function bindings to use a
         decorator so that we can check the return status of the Slave
         functions before returning them back to the client
         It allows the client object to directly inherit all
         of the Slave calls exposed on the server side to the
         client side without writing ANOTHER lookup table.
        '''
        
        _orig_Method = xmlrpclib._Method
        
        '''
        XML-RPC doesn't support keyword arguments,
        so we have to do it ourselves...
        '''
        class KeywordArgMethod(_orig_Method):     
            def __call__(self, *args, **kwargs):
                args = list(args) 
                if kwargs:
                    args.append(("kwargs", kwargs))
                return _orig_Method.__call__(self, *args)
        
        xmlrpclib._Method = KeywordArgMethod
        
        Server.__init__(self, service_url)
        
        setattr(self, "_ServerProxy__request", self.slave_error_check(self._ServerProxy__request))
        self.vms = {}
        self.msattrs = None
        self.msci = None
        self.username = None
        self.print_message = print_message
        self.last_refresh = datetime_datetime.now()

def myquote(val):
    if isinstance(val, unicode) :
        val_unquoted = quote(val.encode("utf-8"))
    else :
        val_unquoted = quote(val)

    if isinstance(val_unquoted, str) :
        val_unquoted = val_unquoted.decode("utf-8")

    return val_unquoted

times = {}
tree = []

def tracefunc(frame, event, arg, indent=[0]):
    global times
    if event == "call":
        tree.append(frame.f_code.co_name)
        name = ".".join(tree)
        indent[0] += 1
        if name not in times :
            times[name] = {"level" : indent[0], "time" : 0, "calls" : 0}
        times[name]["start"] = timest()
        #mdebug("-" * indent[0] + "> call function: " + name)
    elif event == "return":
        name = ".".join(tree)
        if name in times :
            times[name]["time"] = times[name]["time"] + (timest() - times[name]["start"])
            times[name]["calls"] += 1

        indent[0] -= 1
        #mdebug("<" + "-" * indent[0] + " exit function: " + name)
        del tree[-1]

    return tracefunc

def call_report() :
    global times
    mdebug("Times length: " + str(len(times)))
    fulist = []
    for fname, fdata in times.iteritems() :
        fdata["fname"] = fname
        fulist.append(fdata)

    def by_time( a ):
        return a["time"]

    fulist.sort(key=by_time, reverse = True)

    for fidx in range(0, min(50, len(fulist))) :
        fdata = fulist[fidx]
        mdebug("Function: " + fdata["fname"] + " calls: " + str(fdata["calls"]) + " level: " + str(fdata["level"]) + " time: " + str(fdata["time"]))
    times = {}


def sdict(**kwargs) :
    return json_dumps(kwargs)

def test_log(test, **kwargs) :
    if test :
        logentry = sdict(**kwargs)
        mdebug("Logging: " + logentry)
        fh = open(test + "translator.log", 'a')
        fh.write(logentry + "\n")
        fh.close()
