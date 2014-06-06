# coding: utf-8
from common import *
import json

try :
    from couchdb import Server
except ImportError, e :
    mdebug("couchdb not available. Probably on mobile.") 

try :
    from jnius import autoclass
except ImportError, e :
    mdebug("pyjnius not available. We must be on a desktop.")

class ResourceNotFound(Exception) :
    def __init__(self, msg, e = False):
        Exception.__init__(self)
        self.msg = msg
        self.e = e

    def __str__(self) :
        return self.msg

class CommunicationError(Exception) :
    def __init__(self, msg, e = False):
        Exception.__init__(self)
        self.msg = msg
        self.e = e

    def __str__(self) :
        return self.msg

class ResourceConflict(Exception) :
    def __init__(self, msg, e = False):
        Exception.__init__(self)
        self.msg = msg
        self.e = e

    def __str__(self) :
        return self.msg

class MicaDatabaseCouchDB(object) :
    def __init__(self, db) :
        self.db = db

    def __setitem__(self, name, doc) :
        try :
            self.db[name] = doc
        except couchdb.http.ResourceNotFound, e :
            raise ResourceNotFound(str(e), e)

    def __getitem__(self, name) :
        try :
            return self.db[name]
        except couchdb.http.ResourceNotFound, e :
            raise ResourceNotFound(str(e), e)

    def __delitem__(self, name) :
        del self.db[name]

    def put_attachment(self, name, filename, contents, doc = False) :
        if not doc :
            doc = { "Nothing" : "yet" }

        if self.doc_exist(name) :
            del self.db[name]
        self.db[name] = doc

        return self.db.put_attachment(doc, contents, filename)

    def get_attachment(self, name, filename) :
        attachment = self.db.get_attachment(name, filename)

        return attachment.read()

    def doc_exist(self, name) :
        try :
            self.db[name]
        except couchdb.http.ResourceNotFound, e :
            return False
        return True

    def view(self, *args, **kwargs) :
        return self.db.view(*args, **kwargs)
       
class MicaServerCouchDB(object) :
    def __init__(self, url) :
        self.url = url
        self.server = Server(url)

    def __getitem__(self, dbname) :
        return MicaDatabaseCouchDB(self.server[dbname])

class MicaDatabaseCouchbaseMobile(object) :
    def __init__(self, db) :
        self.db = db
        self.dbname = 'mica'
        mdebug("CouchBase Mobile python adapter initialized")

    def __setitem__(self, name, doc) :
        try :
            err = self.db.put(self.dbname, name, json.dumps(doc))
            if err != "" :
                raise CommunicationError("Error occured putting document: " + name + " " + err)
        except Exception, e :
            raise CommunicationError("Error occured putting document: " + str(e), e)

    def __getitem__(self, name) :
        try :
            doc = self.db.get(self.dbname, name)
            if doc == "" :
                raise ResourceNotFound("Could not find document: " + name)
            return json.loads(doc)
        except Exception, e :
            raise CommunicationError("Error occured getting document: " + name + " " + str(e), e)

    def __delitem__(self, name) :
        try :
            err = self.db.delete(self.dbname, name)
            if err != "" :
                raise ResourceNotFound("Could not delete document: " + name + " " + err)
        except Exception, e :
            raise CommunicationError("Error occured deleting document: " + name + " " + str(e), e)

    def put_attachment(self, name, filename, contents, doc = False) :
        try :
            err = self.db.put_attachment(self.dbname, name, contents, filename, doc)
            if err != "" :
                raise CommunicationError("Error occured putting attachment for document: " + name + " " + err)
        except Exception, e :
            raise CommunicationError("Could not put attachment: " + name + " " + str(e), e)

    def get_attachment(self, name, filename) :
        try :
            attach = self.db.get_attachment(self.dbname, name, filename)
            if attach == "" :
                raise ResourceNotFound("Could not attachment for document: " + name)
        except Exception, e :
            raise CommunicationError("Could not put attachment: " + name + " " + str(e), e)

    def doc_exist(self, name) :
        try :
            result = self.db.doc_exist(self.dbname, name)
            if result == "error" :
                raise CommunicationError("Error occured checking document existence: " + name)
            return True if result == "true" else False
        except Exception, e :
            raise CommunicationError("Could test document existence: " + name + " " + str(e), e)

    def view(self, name, startkey = False, endkey = False, keys = False, stale = False) :
        try :
            params = {}
            if startkey :
                params["startkey"] = startkey
            if endkey :
                params["endkey"] = endkey
            if keys :
                params["keys"] = keys
            if stale :
                params["stale"] = stale

            out = self.db.view(self.dbname, name, json.dumps(params))
            if out == "" :
                raise CommunicationError("Error occured for view: " + name)
            return json.loads(out)
        except Exception, e :
            raise CommunicationError("Error getting view: " + name + " " + str(e), e)

class MicaServerCouchbaseMobile(object) :
    def __init__(self, db_already_local) :
        self.db = db_already_local

    def __getitem__(self, dbname) :
        self.dbname = dbname
        mdebug("Mobile Database " + dbname + " requested. Returning New Object")
        return MicaDatabaseCouchbaseMobile(self.db)
