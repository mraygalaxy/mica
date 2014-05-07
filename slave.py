#!/usr/bin/env python

import sys
import inspect
import threading
import SocketServer
import os
import re

from DocXMLRPCServer import DocXMLRPCServer
from optparse import OptionParser
from common import *
from time import sleep

cwd = re.compile(".*\/").search(os.path.realpath(__file__)).group(0)

def unwrap_kwargs(func, spec):
    def wrapper(*args, **kwargs):
        if args and isinstance(args[-1], list) and len(args[-1]) == 2 and "kwargs" == args[-1][0]:
            return func(*args[:-1], **args[-1][1])
        else:
            return func(*args, **kwargs)
        
    wrapper.__doc__ = str(spec)
    if func.__doc__ is not None :
        wrapper.__doc__ +=  "\n\n" + func.__doc__
    return wrapper

class MICASlave():
    def __init__(self, port, debug) :
        self.debug = debug
        self.port = port

    def register(self, address) :
       if address not in services :
           service = MICASlaveService(self.debug, \
                                   self.port, \
                                   address)
           append_service(address, service)
           msg = "Success, bound to hostname: " + address
           result = True
       else :
           msg = "Failed. already bound to hostname: " + address
           result = False 
       
       return {"status" : 0, "msg" : msg, "result" : result}
    
    def unregister(self, address) :
       service = remove_service(address)
       if service : 
           msg = "Success, unbound from hostname: " + address
           result = True
       else :
           msg = "Failed. was never bound to hostname: " + address
           result = False 
        
       return {"status" : 0, "msg" : msg, "result" : result}
    
    def success(self, result, msg = "") :
       mdebug(msg)
       return {"status" : 0, "msg" : msg, "result" : result }

    def error(self, status, msg, result) :
       cberr(msg)
       return {"status" : status, "msg" : msg, "result" : result }
    
    def get_functions(self):
       '''
       List the names of all the available MICA Slave functions
       '''
       return self.success(self.signatures, "success")
    
    def get_signature(self, name):
        '''
        Get the list of arguments of a specific MICA Slave function
        '''
        return self.success(self.signatures[name], "signature")

    def foo(self, bar) :
        return self.success(bar)
    
class AsyncDocXMLRPCServer(SocketServer.ThreadingMixIn,DocXMLRPCServer): pass

services = {}

def append_service(hostname, service) :
    if hostname not in services :
        services[hostname] = service
        service.abort = False
        service.start()
        return True
    return False

def remove_service(hostname):
    if hostname in services :
        service = services[hostname]
        del services[hostname]
        service.stop()
        service.join()
        return service
    return False

class MICASlaveService ( threading.Thread ):
    def __init__(self, debug, port, hostname) :
        super(MICASlaveService, self).__init__()
        
        self._stop = threading.Event()
        self.abort = False
        self.aborted = False
        self.port = port 
        self.hostname = hostname 
        self.slave = MICASlave(port, debug)
        mdebug("Initializing MICA Slave Service on " + hostname + ":" + str(port))
        if debug is None :
            self.server = AsyncDocXMLRPCServer((self.hostname, int(self.port)), allow_none = True)
        else :
            self.server = DocXMLRPCServer((self.hostname, int(self.port)), allow_none = True)
        self.server.abort = False
        self.server.aborted = False
        self.server.set_server_title("MICA Slave Service (xmlrpc)")
        self.server.set_server_name("MICA Slave Service (xmlrpc)")
        #self.server.register_introspection_functions()
        self.slave.signatures = {}
        for methodtuple in inspect.getmembers(self.slave, predicate=inspect.ismethod) :
            name = methodtuple[0]
            if name in ["__init__", "success", "error" ] :
                continue
            func = getattr(self.slave, name)
            argspec = inspect.getargspec(func) 
            spec = argspec[0]
            defaults = [] if argspec[3] is None else argspec[3]
            num_spec = len(spec)
            num_defaults = len(defaults)
            diff = num_spec - num_defaults
            named = diff - 1
            doc = "Usage: "
            for x in range(1, diff) :
                doc += spec[x] + ", "
            for x in range(diff, num_spec) :
                doc += spec[x] + " = " + str(defaults[x - diff]) + ", "
            doc = doc[:-2]
            self.slave.signatures[name] = {"args" : spec[1:], "named" : named }
            self.server.register_function(unwrap_kwargs(func, doc), name)
        mdebug("MICA Slave Service started")

    def run(self):
        mdebug("MICA Slave Service waiting for requests...")
        self.server.serve_forever()
        mdebug("MICA Slave Service shutting down...")
        
    def stop (self) :
        mdebug("Calling MICA Slave Service shutdown....")
        self._stop.set()
        self.server.shutdown()

parser = OptionParser()
parser.add_option("-p", "--port", dest = "port", default = "5050", help ="port")
parser.add_option("-H", "--host", dest = "host", default = "0.0.0.0", help
="Comma-separated list of hostnames to bind to")
parser.add_option("-D", "--daemon", dest = "daemon", action = "store_true", \
                   default = False, help ="Daemonize the service.")
parser.add_option("-d", "--debug_host", dest = "debug_host", \
                   default = False, help ="Hostname for remote debugging")
parser.add_option("-l", "--log", dest = "logfile", default = cwd +
"logs/slave.log", help ="MICA Slave Service log file.")

parser.set_defaults()
options, args = parser.parse_args()

def main() :
    mica_init_logging(options.logfile)
    apiservices = [] 
    debug = True if options.debug_host else False
    hostnames = options.host.split(",")
    abort = True 

    try :
        for hostname in hostnames :
            wait_for_port_ready(hostname, options.port)
            apiservice = MICASlaveService(debug, \
                                    options.port, \
                                    hostname)
            apiservices.append(apiservice)
            apiservice.daemon = True

        for apiservice in apiservices :
            if debug and not len(apiservices) > 1:
                apiservice.run()
                # only debug the first hostname
                break
            else :
                append_service(hostname, apiservice)

        abort = False

        # If this process is monitoring itself, then it could
        # call itself and loop here while it is alive.
        # So, we don't need this one: 
        #for apiservice in apiservices :
        #    remove_service(hostname)

        # Instead, just join to them all.

        while True :
            sleep(5)
            if abort :
                break

    except KeyboardInterrupt:
        merr("CTRL-C Exiting...")
    except Exception, e :
        merr("Failed to startup MICA Slave Service: " + str(e))
    finally :
        if not abort :
            minfo("Tearing down services...")
           
            for hostname in hostnames :
                remove_service(hostname)  

MainThread = threading.current_thread()
MainThread.abort = False

if options.daemon :
    with DaemonContext(
            working_directory=cwd,
            pidfile=None,
        ) :
        main()
else :
    main()
