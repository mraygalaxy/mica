# coding: utf-8
from common import *
import json
import uuid as uuid4

try :
    import couchdb
    from couchdb import Server
except ImportError, e :
    mdebug("couchdb not available. Probably on mobile.") 

try :
    from jnius import autoclass
    String = autoclass('java.lang.String')
except ImportError, e :
    mdebug("pyjnius not available. Probably on a server.")

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

class NotImplementedError(Exception) :
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
            return False

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
        attachment = self.db.get_attachment(name, filename).read()
        if isinstance(attachment, str) :
            return attachment.decode("utf-8")
        return attachment

    def doc_exist(self, name) :
        try :
            self.db[name]
        except couchdb.http.ResourceNotFound, e :
            return False
        return True

    def view(self, *args, **kwargs) :
        if "keys" in kwargs :
            keylist = []
            username = kwargs["username"]
            for key in kwargs["keys"] :
                keylist.append([username, key]) 
            kwargs["keys"] = keylist

        if "username" in kwargs :
            del kwargs["username"]
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
            err = self.db.put(self.dbname, name, String(json.dumps(doc)))
            if err != "" :
                raise CommunicationError("Error occured putting document: " + name + " " + err)
        except Exception, e :
            raise CommunicationError("Error occured putting document: " + str(e), e)

    def __getitem__(self, name) :
        try :
            doc = self.db.get(String(self.dbname), String(name))
            if doc == "" :
                return False
            if doc is not None :
                return json.loads(doc)
        except Exception, e :
            raise CommunicationError("Error occured getting document: " + name + " " + str(e), e)

        # return was None (null)
        raise CommunicationError("Bad exception occured getting document: " + name + " " + str(e))

    def __delitem__(self, name) :
        try :
            err = self.db.delete(String(self.dbname), String(name))
        except Exception, e :
            raise CommunicationError("Error occured deleting document: " + name + " " + str(e), e)
        if err != "" :
            raise ResourceNotFound("Could not delete document: " + name + " " + err)

    def put_attachment(self, name, filename, contents, doc = False) :
        raise NotImplementedError("Sorry, the mobile version does not allow importing new stories, so creating new attachments is not required today.")

    def get_attachment(self, name, filename) :
        try :
            attach = self.db.get_attachment(String(self.dbname), String(name), String(filename))
        except Exception, e :
            raise CommunicationError("Error getting attachment: " + name + " " + str(e), e)
        if attach is None :
            raise ResourceNotFound("Could not find attachment for document: " + name)
        # The ByteArray pyjnius is actually a 'memoryview' from java,
        # which you can google about
        joined = "".join(map(chr, attach))
        decoded = joined.decode("utf-8")
        return decoded

    def doc_exist(self, name) :
        try :
            result = self.db.doc_exist(String(self.dbname), String(name))
            if result == "error" :
                raise CommunicationError("Error occured checking document existence: " + name)
            return True if result == "true" else False
        except Exception, e :
            raise CommunicationError("Could test document existence: " + name + " " + str(e), e)

    def view(self, name, startkey = False, endkey = False, keys = False, stale = False, username = False) :
        seed = False
        uuid = False
        err_msg = False
        e = False

        try :
            parts = name.split("/")
            assert(len(parts) == 2)
            design = parts[0]
            vname = parts[1]
            params = {}
            if startkey :
                params["startkey"] = startkey
            if endkey :
                params["endkey"] = endkey
            if keys :
                uuid = str(uuid4.uuid4())
                for key in keys :
                    assert(isinstance(key, str) or isinstance(key, unicode))
                    self.db.view_seed(String(uuid), String(username), String(key))
                    seed = True

                params["keys"] = uuid 
            if stale :
                params["stale"] = stale

            if len(params) == 0 :
                params = ""
            else :
                params = json.dumps(params)

            it = self.db.view(String(self.dbname), String(design), String(vname), String(params), String(str(username)))
            if it is None :
                raise CommunicationError("Error occured for view: " + name)

            while True :
                has_next = self.db.view_has_next(it)

                if not has_next :
                   break

                result = self.db.view_next(it)
                if result is None :
                    raise CommunicationError("Iteration error occured for view: " + name)
                j = json.loads(result)
                yield j["result"]
        except Exception, err :
            err_msg = "Error getting view: " + name + " " + str(err)
        except CommunicationError, e :
            err_msg = str(err) 
        finally :
            if seed and uuid:
                self.db.view_seed_cleanup(String(uuid))
            if err_msg :
                raise CommunicationError(err_msg)
                

class MicaServerCouchbaseMobile(object) :
    def __init__(self, db_already_local) :
        self.db = db_already_local

    def __getitem__(self, dbname) :
        self.dbname = dbname
        return MicaDatabaseCouchbaseMobile(self.db)
