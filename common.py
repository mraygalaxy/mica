# coding: utf-8
import logging
from logging.handlers import logging
from logging import getLogger, StreamHandler, Formatter, Filter, DEBUG, ERROR, INFO
import socket
import xmlrpclib
from xmlrpclib import Server
import sys
import copy
import socket
import inspect
import sys
import threading
import gettext
import locale
import os
import re
from datetime import datetime
from time import time, strftime, strptime, localtime
from threading import Lock

#memorytest = True 
memorytest = False

cwd = re.compile(".*\/").search(os.path.realpath(__file__)).group(0)

DEBUG = logging.DEBUG
INFO = logging.INFO
WARN = logging.WARN
ERROR = logging.ERROR
CRITICAL = logging.CRITICAL

if sys.getdefaultencoding() != "utf-8" :
    print sys.getdefaultencoding()
    print "FIXME! WE NEED THE CORRECT DEFAULT ENCODING! AHHHHHH!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    reload(sys).setdefaultencoding("utf-8")

gnutextkwargs = {}
gettext.install("mica", **gnutextkwargs)

if sys.version_info[0] < 3:
    # In Python 2, ensure that the _() that gets installed into built-ins
    # always returns unicodes.  This matches the default behavior under Python
    # 3, although that keyword argument is not present in the Python 3 API.
    gnutextkwargs['unicode'] = True
    
try :
    from jnius import autoclass
    String = autoclass('java.lang.String')
except ImportError, e :
    String = False
    print("pyjnius not available. Probably on a server.")


micalogger = False
txnlogger = False
duplicate_logger = False

lang = {
         u"zh-CHS" : _(u"Chinese Simplified"),
         u"en" : _(u"English"),
         u"py" : _(U"Pinyin"),
       }

samples = {
         u"zh-CHS" : [u"开源"],
         u"en" : ["test"],
         u"py" : _(U"pīnyīn"),
       }

romanization = {
        u"zh-CHS" : True,
        u"en" : False,
        u"py" : True,
        }

processor_map = {
        u"zh-CHS" : u"ChineseSimplified", 
        u"en" : u"English", 
        u"py": False,
}

def minfo(msg) :
   if micalogger :
       micalogger.info(msg)
   else :
       print msg
   if duplicate_logger and String :
      duplicate_logger.info(String(msg))

def mdebug(msg) :
   if micalogger :
       micalogger.debug(msg)
       #micalogger.debug(threading.current_thread().name + ": " + msg)
   else :
       print msg

   if duplicate_logger and String :
      duplicate_logger.debug(String(msg))

def mwarn(msg) :
   if micalogger :
       micalogger.warn(msg)
   else :
       print msg
   if duplicate_logger and String :
      duplicate_logger.warn(String(msg))

def merr(msg) :
   if micalogger :
       micalogger.error(msg)
   else :
       print msg
   if duplicate_logger and String :
      duplicate_logger.err(String(msg))

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

def mica_init_logging(logfile, duplicate = False) :
    global micalogger
    global duplicate_logger

    if duplicate :
        duplicate_logger = duplicate

    # Reset the logging handlers
    logger = getLogger()
    while len(logger.handlers) != 0 :
        logger.removeHandler(logger.handlers[0])

    restlogger = logging.getLogger("restkit.client")
    restlogger.setLevel(level=logging.INFO)
    txnlogger = logging.getLogger("txn")
    txnlogger.setLevel(level=logging.INFO)
    micalogger = logging.getLogger("")
    micalogger.setLevel(logging.DEBUG)

    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    if logfile and logfile != 1 :
        handler = logging.handlers.RotatingFileHandler(logfile, maxBytes=(1048576*5), backupCount=7)
        handler.setFormatter(formatter)

        micalogger.addHandler(handler)
        txnlogger.addHandler(handler)
        restlogger.addHandler(handler)

    streamhandler = logging.StreamHandler()
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
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
            s.bind((hostname, int(port)))
            s.close()
            break
        except socket.error, (value, message) :
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

def makeTimestamp(supplied_epoch_time = False) :
    '''
    TBD
    '''
    if not supplied_epoch_time :
        _now = datetime.now()
    else :
        _now = datetime.fromtimestamp(supplied_epoch_time)
        
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
        self.last_refresh = datetime.now()

def init_localization():
    try :
        locale.setlocale(locale.LC_ALL, '') # use user's preferred locale
        # take first two characters of country code
        return locale.getlocale()[0][0:2]
    except Exception, e :
        mdebug("Could not find locale. Defaulting to english.")
        return "en"
