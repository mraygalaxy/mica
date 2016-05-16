#!/usr/bin/env python
# coding: utf-8
from common import *
from json import loads, dumps
from uuid import uuid4
from time import sleep
from traceback import format_exc

try :
    from couchdb import Server
    from couchdb.http import Unauthorized, ResourceNotFound as couch_ResourceNotFound, ResourceConflict as couch_ResourceConflict, ServerError as couch_ServerError
except ImportError, e :
    mdebug("couchdb not available. Probably on mobile.") 

jnius_detachable = False
try :
    from jnius import autoclass
    String = autoclass('java.lang.String')
    from jnius import detach as jnius_detach
    jnius_detachable = True
except ImportError, e :
    try :
        from pyobjus import autoclass, objc_f, objc_str as String, objc_l as Long, objc_i as Integer
    except ImportError, e :
        mverbose("pyjnius and pyobjus not available. Probably on a server.")



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

class repeatable(object):
    def __init__(self, retries = 3):
        self.retries = retries 

    def __call__(self, f):
        def wrapped_f(*args):
            mverbose("Repeating function " + f.__name__ + " " + str(self.retries) + " times.")
            tries = self.retries
            while True :
                try :
                    return f(*args)
                except ResourceConflict, e : 
                    for line in format_exc().splitlines() :
                        mwarn(line)
                    tries = tries - 1
                    if tries == 0 :
                        merr("Ran out of tries =(")
                        raise e
                    mwarn("atomic Tries left: " + str(tries))
                
        return wrapped_f

def reauth(func):
    def wrapper(self, *args, **kwargs):
        try :
            result = func(self, *args, **kwargs)
        except Unauthorized, e :
            mwarn("Couch return unauthorized, likely due to a timeout: " + str(e))
            try :
                self.server.cookie = False
                self.server.auth()
                self.db.resource.headers["Cookie"] = self.server.cookie
                result = func(self, *args, **kwargs)
            except Exception, e :
                raise CommunicationError("Failed to re-authenticate: " + str(e))

        return result
    return wrapper

class MicaDatabase(object) :
    def try_get(self, name) :
        return self.__getitem__(name, false_if_not_found = True)

def check_for_unauthorized(e) :
    ((status, error),) = e.args
    mwarn("Server error: " + str(status) + " " + str(error))
    if int(status) == 413 :
        mdebug("Code 413 means nginx request entity too large or couch's attachment size is too small: " + name)
    if int(status) == 403 :
        raise Unauthorized
    raise CommunicationError("MICA Unvalidated: " + str(e))


class MicaDatabaseCouchDB(MicaDatabase) :
    def __init__(self, db, server) :
        self.db = db
        self.username = False
        self.password = False
        self.server = server

    @reauth
    def get_security(self) :
        return self.db.security

    @reauth
    def set_security(self, doc) :
        self.db.security = doc

    @reauth
    def __setitem__(self, name, doc) :
        try :
            self.db[name] = doc
        except couch_ResourceNotFound, e :
            if name.count("org.couchdb.user") :
                raise Unauthorized
            mdebug("Set key not found error: " + name)
            raise ResourceNotFound(str(e), e)
        except couch_ResourceConflict, e :
            mdebug("Set key conflict error: " + name)
            raise ResourceConflict(str(e), e)
        except couch_ServerError, e :
            check_for_unauthorized(e)

    @reauth
    def __getitem__(self, name, false_if_not_found = False) :
        try :
            return self.db[name]
        except couch_ServerError, e :
            check_for_unauthorized(e)
        except couch_ResourceNotFound, e :
            '''
            out = ""
            for line in format_exc().splitlines() :
                out += line + "\n"
            mwarn(out)
            mwarn(name + ":" + str(e))
            '''
            if false_if_not_found :
                return False
            else :
                raise ResourceNotFound("Cannot lookup key: " + name, e)

    @reauth
    def __delitem__(self, name) :
        try :
            doc = self.db[name]

            revs = []

            if "_conflicts" in doc :
                mdebug("Adding conflict revisions.")
                revs += doc["_conflicts"]
            if "_deleted_conflicts" in doc :
                mdebug("Adding deleted conflict revisions.")
                revs += doc["_deleted_conflicts"]

            for rev in revs :
                olddoc = self.db.get(name, rev=rev)
                self.db.delete(olddoc)

            del self.db[name]
        except couch_ServerError, e :
            check_for_unauthorized(e)

    @reauth
    def delete_attachment(self, doc, filename) :
        try :
            self.db.delete_attachment(doc, filename)
        except couch_ServerError, e :
            check_for_unauthorized(e)

    @reauth
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
                except couch_ServerError, e :
                    check_for_unauthorized(e)
                except couch_ResourceNotFound, e :
                    mdebug("No old revision found.")
                    pass

            mdebug("Going to write: " + str(doc))
            self.db[name] = doc
            doc = self.db[name]
        else :
            doc = new_doc

        if type(contents) != file :
            mdebug("Putting attachment of length: " + str(len(contents)))

        return self.db.put_attachment(doc, contents, filename)

    @reauth
    def get_attachment(self, name, filename) :
        obj = self.db.get_attachment(name, filename)
        if obj is not None :
            return obj.read()
        else :
            raise CommunicationError("No such attachment: " + name + " => " + filename)

    @reauth
    def get_attachment_to_path(self, name, filename, path) :
        sourcebytes = 0
        obj = self.db.get_attachment(name, filename)
        if obj is not None :
            fh = open(path, 'wb')
            while True :
                byte = obj.read(1)
                sourcebytes += 1
                if byte :
                    fh.write(byte)
                else :
                    break

            fh.close()
        else :
            raise CommunicationError("No such attachment: " + name + " => " + filename)
        return sourcebytes
            
    def listen(self, username, password, port) :
        return port 

    def get_attachment_meta(self, name, filename) :
        return self.__getitem__(name)["_attachments"][filename]

    @reauth
    def doc_exist(self, name, true_if_deleted = False) :
        try :
            self.db[name]
        except couch_ServerError, e :
            check_for_unauthorized(e)
        except couch_ResourceNotFound, e :
            #mdebug(str(e.args))
            ((error, reason),) = e.args
            mdebug("Doc exist returns not found: " + reason)
            if true_if_deleted and reason == "deleted" :
                try :
                    old = self.db.get(name, open_revs = "all")
                    for olddocp in old :
                        mdebug("Got old revision: " + str(olddocp))
                        revs = olddocp["ok"]["_rev"]
                        olddoc = self.db.get(name, rev=olddocp["ok"]["_rev"])
                        mdebug("Got old doc too.")
                        mwarn("Purging old revision...")
                        self.db.purge([olddoc])
                        mwarn("Purged")
                    return False
                except couch_ResourceNotFound, e :
                    merr( "Failed to purge old revisions.")
                except couch_ServerError, e :
                    check_for_unauthorized(e)

                mdebug("Doc was deleted, returning true")
                return None 
            return False
        return True

    def couchdb_pager(self, view_name='_all_docs',
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
        server_errors_left = 3
        while not done:
            try:
                view = self.db.view(view_name, **options)
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
            except couch_ServerError, e :
                # Occasionally after a previous document deletion, instead of pausing, couch doesn't finish the view mapreduce and returns a ServerError, code 500. So, let's try again one more time...
                ((status, error),) = e.args
                mwarn("Server error: " + str(status) + " " + str(error))
                if status == 403 :
                    mwarn("Re-authenticating.")
                    self.server.cookie = False
                    self.server.auth()
                    self.db.resource.headers["Cookie"] = self.server.cookie
                    continue
                elif status == 500 :
                    if server_errors_left > 0 :
                        mwarn("Server errors left: " + str(server_errors_left))
                        server_errors_left -= 1
                        continue
                    else :
                        merr("No server_errors_left remaining.")
                raise e 
    @reauth
    def view(self, *args, **kwargs) :
        view_name = args[0]
        mverbose("Query view: " + view_name)
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
            kwargs["view_name"] = view_name
            kwargs["bulk"] = 50

            for result in self.couchdb_pager(**kwargs) :
                yield result

    @reauth
    def compact(self, *args, **kwargs) :
        self.db.compact(*args, **kwargs)

    @reauth
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

    def detach_thread(self) :
        pass

# FIXME: need try's here so we return our "NotFound"
#        instead of our not found

class MicaServerCouchDB(object) :
    def get_cookie(self, url, username, password) :
        username_unquoted = myquote(username)
        password_unquoted = myquote(password)

        full_url = url.replace("//", "//" + username_unquoted + ":" + password_unquoted + "@")

        tmp_server = Server(full_url)

        mverbose("Requesting cookie.")
        try :
            code, message, obj = tmp_server.resource.post('_session',headers={'Content-Type' : 'application/x-www-form-urlencoded'}, body="name=" + username_unquoted + "&password=" + password_unquoted)
        except UnicodeDecodeError :
            # CouchDB folks messed up badly. This is ridiculous that I have
            # to do this
            username_unquoted = username_unquoted.encode("latin1").decode("latin1")
            password_unquoted = password_unquoted.encode("latin1").decode("latin1")
            code, message, obj = tmp_server.resource.post('_session',headers={'Content-Type' : 'application/x-www-form-urlencoded'}, body="name=" + username_unquoted + "&password=" + password_unquoted)

        if (code != 200) :
            raise CommunicationError("MICA Unauthorized: " + username)

        cookie = message["Set-Cookie"].split(";", 1)[0].strip()
        mverbose("Received cookie: " + cookie)

        return cookie

    def auth(self, username = False, password = False) :
        if not username or not password :
            assert(self.username)
            assert(self.password)
            assert(self.refresh)

            username = self.username
            password = self.password

        if not self.cookie :
            mverbose("No cookie for user: " + username)
            
            self.cookie = self.get_cookie(self.url, username, password)
        else :
            mverbose("Reusing cookie: " + self.cookie)

        assert(self.cookie)
        self.server.resource.headers["Cookie"] = self.cookie
        
    def __init__(self, url = False, username = False, password = False, cookie = False, refresh = False) :
        self.url = url
        self.cookie = cookie
        self.refresh = refresh
        if refresh :
            self.username = username
            self.password = password

        self.server = Server(url)

        if refresh :
            assert(self.url)
            assert(self.username)
            assert(self.password)

        self.auth(username, password)

    def __getitem__(self, dbname) :
        try :
            if dbname in self.server :
                db = self.server[dbname]
            else :
                db = self.server.create(dbname)
            return MicaDatabaseCouchDB(db, self)
        except Unauthorized, e :
            raise CommunicationError("MICA Unauthorized: dbname: " + dbname + " " + str(e))

    def __delitem__(self, name) :
        del self.server[name]

    def __contains__(self, dbname) :
        return True if dbname in self.server else False

class AndroidMicaDatabaseCouchbaseMobile(MicaDatabase) :
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

    def get_attachment_meta(self, name, filename) :
        try :
            meta = self.db.get_attachment_meta(String(self.dbname), String(name), String(filename))
        except Exception, e :
            raise CommunicationError("Error getting attachment metadata: " + name + " " + str(e), e)
        if meta is None :
            raise ResourceNotFound("Could not find attachment meta for document: " + name)

        return loads(meta)

    def doc_exist(self, name, true_if_deleted = False) :
        if true_if_deleted :
            mverbose("Mobile has no deleted-document detection.")

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

        self.updateView("$('#viewstat').addClass('alert-danger');")
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
            self.updateView("$('#viewstat').removeClass('alert-danger');")
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

    def stop_replication(self) :
        self.db.stop_replication(self.dbname)

    def replicate(self, url, user, pw, dbname, localdbname, filterparams) :
        username_unquoted = myquote(user)
        password_unquoted = myquote(pw)

        full_url = url.replace("//", "//" + username_unquoted + ":" + password_unquoted + "@") + "/" + dbname

        if self.db.replicate(localdbname, String(full_url), False, String(filterparams)) == -1 :
            mdebug("Replication failed. Boo. =(")
            return False
        else :
            mdebug("Replication started. Yay.")
            return True

    def updateView(self, js) :
        self.db.updateView(String(js))

    def detach_thread(self) :
        if jnius_detachable :
            mdebug("Trying to detach...")
            # https://github.com/kivy/pyjnius/commit/9e60152dc5172cfa0c2c90dbcc9e25d5c4cb2493
            jnius_detach()
            mdebug("Detached.")
        else :
            mdebug("No detach available. Need to upgrade. Will spin instead.")
            while True :
                sleep(3600)

    def listen(self, username, password, port) :
        # Since the user/pass will be fed locally through memory,
        # and then accessed through javascript, I haven't found
        # a need to escape them yet
        #username_unquoted = myquote(username)
        #password_unquoted = myquote(password)

        port = self.db.listen(String(username), String(password), port)
        if port == -1 :
            raise CommunicationError("We failed to start the listener service for Couch. Check log for errors.")

        return port 

class AndroidMicaServerCouchbaseMobile(object) :
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

class iosMicaDatabaseCouchbaseMobile(MicaDatabase) :
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

    def get_attachment_meta(self, name, filename) :
        try :
            meta = self.db.get_attachment_meta___(String(self.dbname), String(name), String(filename)).UTF8String()
        except Exception, e :
            raise CommunicationError("Error getting attachment meta: " + name + " " + str(e), e)

        if meta is None :
            raise ResourceNotFound("Could not find attachment meta for document: " + name)

        return loads(meta)

    def doc_exist(self, name, true_if_deleted = False) :
        if true_if_deleted :
            mverbose("Mobile has no deleted-document detection.")
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

        self.updateView("$('#viewstat').addClass('alert-danger');")
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
            self.updateView("$('#viewstat').removeClass('alert-danger');")
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

    def updateView(self, js) :
        self.db.updateView_(String(js))

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

    def stop_replication(self) :
        self.db.stop_replication_(self.dbname)

    def replicate(self, url, user, pw, dbname, localdbname, filterparams) :
        username_unquoted = myquote(user)
        password_unquoted = myquote(pw)

        full_url = url.replace("//", "//" + username_unquoted + ":" + password_unquoted + "@") + "/" + dbname

        if self.db.replicate___(String(localdbname), String(full_url), String(filterparams)) == -1 :
            mdebug("Replication failed. Boo. =(")
            return False
        else :
            mdebug("Replication started. Yay.")
            return True

    def listen(self, username, password, port) :
        # Since the user/pass will be fed locally through memory,
        # and then accessed through javascript, I haven't found
        # a need to escape them yet
        #username_unquoted = myquote(username)
        #password_unquoted = myquote(password)

        port = self.db.listen___(String(username), String(password), String(str(port)))
        if port == -1 :
            raise CommunicationError("We failed to start the listener service for Couch. Check log for errors.")

        return port 

    def detach_thread(self) :
        pass

class iosMicaServerCouchbaseMobile(object) :
    def __init__(self, db_already_local) :
        self.db = db_already_local

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

