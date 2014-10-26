# coding: utf-8
from common import *
from json import loads, dumps
from uuid import uuid4
from urllib2 import quote
from locale import setlocale, LC_ALL, getlocale

try :
    from couchdb import Server
    from couchdb.http import Unauthorized, ResourceNotFound as couch_ResourceNotFound, ServerError
except ImportError, e :
    mdebug("couchdb not available. Probably on mobile.") 

try :
    from jnius import autoclass
    String = autoclass('java.lang.String')
except ImportError, e :
    try :
        from pyobjus import autoclass, objc_f, objc_str as String, objc_l as Long, objc_i as Integer
    except ImportError, e :
        mdebug("pyjnius and pyobjus not available. Probably on a server.")

def couchdb_pager(db, view_name='_all_docs',
                  startkey=None, startkey_docid=None,
                  endkey=None, endkey_docid=None, bulk=5000, stale = False):
    # Request one extra row to resume the listing there later.
    options = {'limit': bulk + 1}
    if stale :
        options["stale"] = stale
    if startkey:
        options['startkey'] = startkey
        if startkey_docid:
            options['startkey_docid'] = startkey_docid
    if endkey:
        options['endkey'] = endkey
        if endkey_docid:
            options['endkey_docid'] = endkey_docid
    done = False
    while not done:
        view = db.view(view_name, **options)
        rows = []
        # If we got a short result (< limit + 1), we know we are done.
        if len(view) <= bulk:
            done = True
            rows = view.rows
        else:
            # Otherwise, continue at the new start position.
            rows = view.rows[:-1]
            last = view.rows[-1]
            options['startkey'] = last.key
            options['startkey_docid'] = last.id

        for row in rows:
            yield row

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


    def get_security(self) :
        return self.db.security

    def set_security(self, doc) :
        self.db.security = doc

    def __setitem__(self, name, doc) :
        try :
            self.db[name] = doc
        except Unauthorized, e :
            raise CommunicationError("MICA Unauthorized: " + str(e))
        except couch_ResourceNotFound, e :
            raise ResourceNotFound(str(e), e)
        except ServerError, e :
            raise CommunicationError("MICA Unvalidated: " + str(e))

    def __getitem__(self, name, false_if_not_found = False) :
        try :
            return self.db[name]
        except Unauthorized, e :
            raise CommunicationError("MICA Unauthorized: " + str(e))
        except couch_ResourceNotFound, e :
            if false_if_not_found :
                return False
            else :
                mwarn(str(e))
                raise ResourceNotFound("Cannot lookup key: " + name, e)

    def __delitem__(self, name) :
        doc = self.db[name]
        del self.db[name]
        #self.db.purge([doc])

    def put_attachment(self, name, filename, contents, new_doc = False) :
        if not new_doc :
            trydelete = True
            if self.doc_exist(name, true_if_deleted = True) is True :
                mdebug("Deleting original @ " + name)
                doc = self.db[name]
                del self.db[name]
                self.db.purge([doc])
                trydelete = False 

            doc = { "foo" : "bar"}

            if trydelete :
                try :
                    doc["_rev"] = self.db[name]["_rev"]
                    mdebug("Old revision found.")
                except Unauthorized, e :
                    raise CommunicationError("MICA Unauthorized: " + str(e))
                except couch_ResourceNotFound, e :
                    mdebug("No old revision found.")
                    pass

            mdebug("Going to write: " + str(doc))
            self.db[name] = doc
            doc = self.db[name]
        else :
            doc = new_doc

        mdebug("Putting attachment..")

        return self.db.put_attachment(doc, contents, filename)

    def get_attachment(self, name, filename) :
        return self.db.get_attachment(name, filename).read()

    def doc_exist(self, name, true_if_deleted = False) :
        try :
            self.db[name]
        except Unauthorized, e :
            raise CommunicationError("MICA Unauthorized: " + str(e))
        except couch_ResourceNotFound, e :
            mdebug(str(e.args))
            ((error, reason),) = e.args
            mdebug("Doc exist returns not found: " + reason)
            if true_if_deleted and reason == "deleted" :
                try :
                    old = self.db.get(name, open_revs = "all")
                    for olddocp in old :
                        mdebug("Got old revision: " + str(olddocp))
                        olddoc = self.db.get(name, rev=olddocp["ok"]["_rev"])
                        mdebug("Got old doc too.")
                        mwarn("Purging old revision...")
                        self.db.purge([olddoc])
                        mwarn("Purged")
                    return False
                except couch_ResourceNotFound, e :
                    merr( "Failed to purge old revisions.")
                except Unauthorized, e :
                    raise CommunicationError("MICA Unauthorized: " + str(e))

                mdebug("Doc was deleted, returning true")
                return None 
            return False
        return True

    def view(self, *args, **kwargs) :
        view_name = args[0]
        if "keys" in kwargs :
            keylist = []
            username = kwargs["username"]
            for key in kwargs["keys"] :
                keylist.append([username, key]) 
            kwargs["keys"] = keylist

        if "username" in kwargs :
            del kwargs["username"]

        if "keys" in kwargs :
            for result in self.db.view(*args, **kwargs) :
                yield result
        else :
            args = [self.db]
            kwargs["view_name"] = view_name
            kwargs["bulk"] = 50

            for result in couchdb_pager(*args, **kwargs) :
                yield result

    def compact(self, *args, **kwargs) :
        self.db.compact(*args, **kwargs)

    def cleanup(self, *args, **kwargs) :
        self.db.cleanup(*args, **kwargs)

    def close(self) :
        pass

    def runloop(self) :
        mdebug("Server runloop - nothing to do.")

    def pull_percent(self) :
        return "100.0"

    def push_percent(self) :
        return "100.0"

       
# FIXME: need try's here so we return our "NotFound"
#        instead of our not found

class MicaServerCouchDB(object) :
    def __init__(self, url, username = False, password = False, cookie = False) :
        self.url = url
        self.cookie = cookie
        self.server = Server(url)

        if not self.cookie :
            mdebug("No cookie for user: " + username)
            username_unquoted = quote(username)
            password_unquoted = quote(password)

            full_url = url.replace("//", "//" + username_unquoted + ":" + password_unquoted + "@")

            tmp_server = Server(full_url)

            mdebug("Requesting cookie.")
            code, message, obj = tmp_server.resource.post('_session',headers={'Content-Type' : 'application/x-www-form-urlencoded'}, body="name=" + username_unquoted + "&password=" + password_unquoted)

            if (code != 200) :
                raise CommunicationError("MICA Unauthorized: " + username)

            self.cookie = message["Set-Cookie"].split(";", 1)[0].strip()
            mdebug("Received cookie: " + self.cookie)
        else :
            mdebug("Reusing cookie: " + self.cookie)

        self.server.resource.headers["Cookie"] = self.cookie

    def init_localization(self):
        try :
            mdebug("Locale is: " + setlocale(LC_ALL, '')) # use user's preferred locale
            # take first two characters of country code
            return getlocale()[0][0:2]
        except Exception, e :
            mdebug("Could not find locale. Defaulting to english.")
            return "en"

    def __getitem__(self, dbname) :
        try :
            if dbname in self.server :
                db = self.server[dbname]
            else :
                db = self.server.create(dbname)
            return MicaDatabaseCouchDB(db)
        except Unauthorized, e :
            raise CommunicationError("MICA Unauthorized: dbname: " + dbname + " " + str(e))

    def __delitem__(self, name) :
        del self.server[name]

    def __contains__(self, dbname) :
        return True if dbname in self.server else False

class AndroidMicaDatabaseCouchbaseMobile(object) :
    def __init__(self, db) :
        self.db = db
        self.dbname = 'mica'
        mdebug("Android CouchBase Mobile python adapter initialized")

    def __setitem__(self, name, doc) :
        try :
            err = self.db.put(self.dbname, name, String(dumps(doc)))
            if err != "" :
                raise CommunicationError("Error occured putting document: " + name + " " + err)
        except Exception, e :
            raise CommunicationError("Error occured putting document: " + str(e), e)

    def __getitem__(self, name, false_if_not_found = False) :
        try :
            doc = self.db.get(String(self.dbname), String(name))
        except Exception, e :
            raise CommunicationError("Error occured getting document: " + name + " " + str(e), e)

        if doc == "" :
            if false_if_not_found :
                return False
            else :
                mwarn("Cannot lookup key: " + name)
                raise ResourceNotFound("Cannot lookup key: " + name)

        if doc is not None :
            return loads(doc)

        # return was None (null)
        raise CommunicationError("Bad exception occured getting document: " + name)

    def __delitem__(self, name) :
        try :
            err = self.db.delete(String(self.dbname), String(name))
        except Exception, e :
            raise CommunicationError("Error occured deleting document: " + name + " " + str(e), e)
        if err != "" :
            raise ResourceNotFound("Could not delete document: " + name + " " + err)

    def put_attachment(self, name, filename, contents, doc = False) :
        raise NotImplementedError("Sorry, the mobile version does not allow importing new stories, so creating new attachments is not required today.")

    def get_attachment_to_path(self, name, filename, path) :
        try :
            attach = self.db.get_attachment_to_path(String(self.dbname), String(name), String(filename), String(path))
        except Exception, e :
            raise CommunicationError("Error getting attachment to path: " + name + " " + str(e), e)
        if attach is None :
            raise ResourceNotFound("Could not find attachment to path for document: " + name)

    def get_attachment(self, name, filename) :
        try :
            attach = self.db.get_attachment(String(self.dbname), String(name), String(filename))
        except Exception, e :
            raise CommunicationError("Error getting attachment: " + name + " " + str(e), e)
        if attach is None :
            raise ResourceNotFound("Could not find attachment for document: " + name)
        # The ByteArray pyjnius is actually a 'memoryview' from python that
        # represents the native java byte[] object that was returned,
        # which you can google about. MemoryViews are shared-memory versions
        # of native python bytearrays which can be maped into a string,
        # like this.
        return "".join(map(chr, attach))

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
                uuid = str(uuid4())
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
                params = dumps(params)

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
                j = loads(result)
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
                
    def compact(self, *args, **kwargs) :
        if len(args) > 0 :
            mwarn("Compacting a CBL view doesn't exist. Just pass.")
            return
        result = self.db.compact(self.dbname)
        if result != "" :
            raise CommunicationError("Compaction failed: " + result)

    def cleanup(self, *args, **kwargs) :
        # Does couchbase mobile have this?
        #self.db.cleanup(*args, **kwargs)
        pass

    def close(self) :
        try :
            self.db.close(self.dbname)
        except Exception, e :
            raise CommunicationError("Database close failed for: " + name)

    def runloop(self) :
        pass

    def pull_percent(self) :
        return self.db.get_pull_percent()

    def push_percent(self) :
        return self.db.get_push_percent()

    def replicate(self, url, user, pw, dbname, localdbname) :
        username_unquoted = quote(user)
        password_unquoted = quote(pw)
        full_url = url.replace("//", "//" + username_unquoted + ":" + password_unquoted + "@") + "/" + dbname

        if self.db.replicate(localdbname, String(full_url), False) == -1 :
            mdebug("Replication failed. Boo. =(")
            return False
        else :
            mdebug("Replication started. Yay.")
            return True

class AndroidMicaServerCouchbaseMobile(object) :
    def init_localization(self):
        return self.db.get_language()

    def __init__(self, db_already_local) :
        self.db = db_already_local

    def __getitem__(self, dbname) :
        self.dbname = dbname
        return AndroidMicaDatabaseCouchbaseMobile(self.db)

    def __delitem__(self, name) :
        try :
            self.db.drop(name)
        except Exception, e :
            raise CommunicationError("Database deletion failed for: " + name)

    def __contains__(self, dbname) :
        return True if self.db.exists(dbname) else False

class iosMicaDatabaseCouchbaseMobile(object) :
    def __init__(self, db) :
        self.db = db
        self.dbname = 'mica'
        mdebug("ios CouchBase Mobile python adapter initialized")

    def __setitem__(self, name, doc) :
        try :
            err = self.db.put___(self.dbname, name, String(dumps(doc))).UTF8String()
            if err != "" :
                raise CommunicationError("Error occured putting document: " + name + " " + err)
        except Exception, e :
            raise CommunicationError("Error occured putting document: " + str(e), e)

    def __getitem__(self, name, false_if_not_found = False) :
        try :
            doc = self.db.get__(String(self.dbname), String(name)).UTF8String()
        except Exception, e :
            raise CommunicationError("Error occured getting document: " + name + " " + str(e), e)

        #mdebug("Result of get is: " + str(doc) + " " + str(type(doc)))
        if doc == "" :
            if false_if_not_found :
                return False
            else :
                mwarn("Cannot lookup key: " + name)
                raise ResourceNotFound("Cannot lookup key: " + name)
        if doc is not None :
            return loads(doc)

        # return was None (null)
        raise CommunicationError("Bad exception occured getting document: " + name)

    def __delitem__(self, name) :
        try :
            err = self.db.delete__(String(self.dbname), String(name)).UTF8String()
        except Exception, e :
            raise CommunicationError("Error occured deleting document: " + name + " " + str(e), e)
        if err != "" :
            raise ResourceNotFound("Could not delete document: " + name + " " + err)

    def put_attachment(self, name, filename, contents, doc = False) :
        raise NotImplementedError("Sorry, the mobile version does not allow importing new stories, so creating new attachments is not required today.")

    def get_attachment(self, name, filename) :
        try :
            attach = self.db.get_attachment___(String(self.dbname), String(name), String(filename)).UTF8String()
        except Exception, e :
            raise CommunicationError("Error getting attachment: " + name + " " + str(e), e)
        if attach is None :
            raise ResourceNotFound("Could not find attachment for document: " + name)
        #print "Pyobjus returned attachment of type: " + str(type(attach))
        return attach 

    def doc_exist(self, name) :
        try :
            result = self.db.doc_exist__(String(self.dbname), String(name)).UTF8String()
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
                uuid = str(uuid4())
                for key in keys :
                    assert(isinstance(key, str) or isinstance(key, unicode))
                    try :
                        self.db.view_seed___(String(uuid), String(username), String(key))
                    except Exception, e :
                        raise CommunicationError("Failed to seed keys for view: " + str(e))

                    seed = True

                params["keys"] = uuid 
            if stale :
                params["stale"] = stale

            if len(params) == 0 :
                params = ""
            else :
                params = dumps(params)

            try :
                it = self.db.view____(String(self.dbname), String(design), String(vname), String(params), String(str(username)))
                total = it.count
            except Exception, e :
                raise CommunicationError("Could not get queryrow count: " + str(e))

            if total != 0 :
                mdebug("There are " + str(total) + " rows in the view results.")

                for vx in range(0, total) :
                    row = it.rowAtIndex_(Integer(vx).intValue())
                    result_obj = self.db.view_next_(row)

                    try :
                        result = result_obj.UTF8String() 
                    except Exception, e :
                        raise CommunicationError("Could string from result: " + str(e))

                    j = loads(result)
                    yield j["result"]
        except Exception, err :
            err_msg = "Error getting view: " + name + " " + str(err)
        except CommunicationError, e :
            err_msg = str(err) 
        finally :
            if seed and uuid:
                self.db.view_seed_cleanup_(String(uuid))
            if err_msg :
                raise CommunicationError(err_msg)
                
    def compact(self, *args, **kwargs) :
        if len(args) > 0 :
            mwarn("Compacting a CBL view doesn't exist. Just pass.")
            return
        result = self.db.compact_(self.dbname).UTF8String()
        if result != "" :
            raise CommunicationError("Compaction failed: " + result)

    def cleanup(self, *args, **kwargs) :
        # Does couchbase mobile have this?
        #self.db.cleanup(*args, **kwargs)
        pass

    def close(self) :
        try :
            self.db.close(self.dbname)
        except Exception, e :
            raise CommunicationError("Database close failed for: " + name)

    def runloop(self) :
        self.db.runloop()

    def pull_percent(self) :
        return self.db.get_pull_percent().UTF8String()

    def push_percent(self) :
        return self.db.get_push_percent().UTF8String()

    def get_attachment_to_path(self, name, filename, path) :
        try :
            attach = self.db.get_attachment_to_path____(self.dbname, name, filename, path).UTF8String()
        except Exception, e :
            raise CommunicationError("Error getting attachment to path: " + name + " " + str(e), e)
        if attach != "" :
            raise ResourceNotFound("Could write attachment to path for document: " + name + ": " + attach)

    def replicate(self, url, user, pw, dbname, localdbname) :
        username_unquoted = quote(user)
        password_unquoted = quote(pw)
        full_url = url.replace("//", "//" + username_unquoted + ":" + password_unquoted + "@") + "/" + dbname

        if self.db.replicate__(String(localdbname), String(full_url)) == -1 :
            mdebug("Replication failed. Boo. =(")
            return False
        else :
            mdebug("Replication started. Yay.")
            return True

class iosMicaServerCouchbaseMobile(object) :
    def __init__(self, db_already_local) :
        self.db = db_already_local

    def init_localization(self):
        return self.db.get_language().UTF8String()

    def __getitem__(self, dbname) :
        self.dbname = dbname
        return iosMicaDatabaseCouchbaseMobile(self.db)

    def __delitem__(self, name) :
        try :
            self.db.drop(name)
        except Exception, e :
            raise CommunicationError("Database deletion failed for: " + name)

    def __contains__(self, dbname) :
        return True if self.db.exists(dbname) else False

