#!/usr/bin/env python
# coding: utf-8

from common import *
from json import loads, dumps
from uuid import uuid4
from time import sleep
from traceback import format_exc
from httplib import IncompleteRead, CannotSendRequest
import errno
from time import time
from copy import deepcopy

try :
    from couchdb.http import Unauthorized, ResourceNotFound as couch_ResourceNotFound, ResourceConflict as couch_ResourceConflict, ServerError as couch_ServerError
    #from cookieclient import CookieServer as Server
    from couchdb import Server
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

def credentials(params) :
    return params["couch_proto"] + "://" + params["couch_server"] + ":" + str(params["couch_port"] + (params["couch_path"] if ("couch_path" in params and params["couch_path"] != "") else ""))

class ResourceNotFound(Exception) :
    def __init__(self, msg, e = False):
        Exception.__init__(self)
        self.msg = msg
        self.e = e

    def __str__(self) :
        return self.msg

# Couchdb bug returning NotFound instead of Unathorized during a timeout
class PossibleResourceNotFound(Exception) :
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
                        raise CommunicationError("Unauthorized: " + str(e))
                    mwarn("atomic Tries left: " + str(tries))

        return wrapped_f

limit = 20
retriable_errors = (Unauthorized, IncompleteRead, CannotSendRequest)
bad_errnos = [errno.EPIPE, errno.ECONNRESET, None]
server_errors = [403, 500, 502]

# Should we make this repeat more than once? kind of like serialized() with a parameter?
def reauth(func):
    def wrapper(self, *args, **kwargs):
        giveup_error = False

        for attempt in range(0, limit) :
            retry_auth = False
            permanent_error = False
            regular_error = False
            giveup_error = False

            try :
                result = func(self, *args, **kwargs)
            except PossibleResourceNotFound, e :
                mdebug("First time with possible resource not found (attempt " + str(attempt) + ". Will re-auth and try one more time: " + str(e))
                retry_auth = True
                # This parameter should never get removed from the kwargs
                # We do see cases where this exception gets thrown twice
                # if the argument is removed under simultaneous I/O failures, 
                # in which case we're just playing cat and mouse, and we really 
                # just need to fail to the user.
                kwargs["second_time"] = True
            except retriable_errors, e :
                retry_auth = True
                giveup_error = e
            except IOError, e:
                if e.errno in bad_errnos:
                    mverbose("IOError: " + str(e) + ". Probably due to a timeout: " + str(e))
                    retry_auth = True
                    giveup_error = e
                else :
                    mwarn("Actual error number: " + str(e.errno))
                    for line in format_exc().splitlines() :
                        mwarn(line)
                    permanent_error = e
            except (CommunicationError, ResourceNotFound, ResourceConflict), e :
                regular_error = e
            except couch_ServerError, e :
                ((status, error),) = e.args
                permanent_error = e
                if int(status) == 413 :
                    mdebug("Code 413 means nginx request entity too large or couch's attachment size is too small: " + name)
                elif int(status) in server_errors :
                    # Database failure. Retry again too.
                    retry_auth = True
                else :
                    mwarn("Server error: " + str(status) + " " + str(error))
            except Exception, e :
                for line in format_exc().splitlines() :
                    mwarn(line)
                permanent_error = e
            finally :
                if retry_auth :
                    if attempt == (limit - 1) :
                        break
                    if attempt >= 2 :
                        mdebug("Starting to get worried after " + str(attempt) + " attempts about: " + str(giveup_error))
                    try :
                        self.reauthorize(e = e)
                    except CommunicationError, e :
                        mdebug("Re-authorization failed at attempt " + str(attempt) + ", but we'll keep trying.")

                    if attempt > 0 :
                        sleep(1)
                elif regular_error :
                    raise regular_error
                elif permanent_error :
                    raise CommunicationError("Unauthorized: " + str(permanent_error))
                else :
                    return result

        raise CommunicationError("Ran out of couch retries on attempt: " + str(attempt) + ": " + str(giveup_error))

    return wrapper

class AuthBase(object) :
    def reauthorize(self, e = False) :
        if e :
            mwarn("Error Likely due to a timeout: " + str(e))
        mverbose("Re-authenticating database.")

        try :
            try :
                getattr(self, "server")
                self.server.cookie = False
                self.server.auth()
                self.db.resource.headers["Cookie"] = self.server.cookie
            except AttributeError, e :
                merr("Re-authenticating server.")
                self.cookie = False
                self.auth()
        except Exception, e :
            raise CommunicationError("Failed to re-authenticate: " + str(e))

        mverbose("Authenticated.")

class MicaDatabase(AuthBase) :
    def try_get(self, name) :
        return self.__getitem__(name, false_if_not_found = True)

def check_for_unauthorized(e) :
    ((status, error),) = e.args
    mwarn("Server error: " + str(status) + " " + str(error))
    if int(status) == 413 :
        mdebug("Code 413 means nginx request entity too large or couch's attachment size is too small: " + name)
    # Database failure. Retry again too.
    if int(status) in server_errors :
        raise Unauthorized
    raise CommunicationError("MICA Unvalidated: " + str(e))

class MicaDatabaseCouchDB(MicaDatabase) :
    def __init__(self, db, server, dbname) :
        self.db = db
        self.username = False
        self.password = False
        self.server = server
        self.dbname = dbname

    # example:
    #server will have: {u'update_seq': 7967, u'disk_size': 689025146, u'purge_seq': 0, u'doc_count': 6653, u'compact_running': False, u'db_name': u'mica', u'doc_del_count': 1048, u'instance_start_time': u'1472644998115128', u'committed_update_seq': 7967, u'data_size': 481650247, u'disk_format_version': 6}
    #mobile will have: db_name, db_uuid, doc_count, update_seq, disk_size, instance_start_time
    @reauth
    def info(self, second_time = False) :
        try :
            return self.db.info()
        except couch_ResourceNotFound, e :
            # This happens during DB timeouts only for the _users database
            if self.dbname.count("_users") and not second_time:
                raise PossibleResourceNotFound(self.dbname)
            mdebug("Get info not found error: " + self.dbname)
            raise ResourceNotFound(str(e))

    @reauth
    def get_security(self) :
        return self.db.security

    @reauth
    def set_security(self, doc) :
        self.db.security = doc

    @reauth
    def __setitem__(self, name, doc, second_time = False) :
        try :
            self.db[name] = doc
        except couch_ResourceNotFound, e :
            # This happens during DB timeouts only for the _users database
            if name.count("org.couchdb.user") and not second_time:
                raise PossibleResourceNotFound(name)
            mdebug("Set key not found error: " + name)
            raise ResourceNotFound(str(e))
        except couch_ResourceConflict, e :
            mdebug("Set key conflict error: " + name)
            setfail = True

            # This sometimes happens in the middle of a database failure
            # before the DB failed, then it will appear to be a conflict. Let's try to first
            # verify if that was the case no not fail the application.
            if self.doc_exist(name) :
                testdoc = doc.copy()
                olddoc = self.__getitem__(name).copy()
                if "_rev" in doc :
                    del testdoc["_rev"]
                if "_rev" in olddoc :
                    del olddoc["_rev"]
                if "_id" not in testdoc :
                    testdoc["_id"] = name
                    
                if name.count("org.couchdb.user") :
                    for subkey in ["iterations", "password_scheme", "salt", "derived_key"] :
                        if subkey in olddoc :
                            del olddoc[subkey]
                        if subkey in testdoc :
                            del testdoc[subkey]
                    if "password" in testdoc :
                        del testdoc["password"]
                            
                if olddoc == testdoc :
                    setfail = False
                    mwarn("Recovery complete. Yay.")
                else :
                    merr("It's not equal. That sucks: " + str(olddoc) + " != " + str(testdoc))


            if setfail :
                raise ResourceConflict(str(e), e)

    @reauth
    def __getitem__(self, name, false_if_not_found = False, second_time = False, rev = False, open_revs = False) :
        try :
            if rev :
                return self.db.get(name, rev = rev)
            elif open_revs :
                return self.db.get(name, open_revs = open_revs)
            else :
                return self.db[name]
        except couch_ResourceNotFound, e :
            # This happens during DB timeouts only for the _users database
            if name.count("org.couchdb.user") and not second_time :
                raise PossibleResourceNotFound(name)
            if false_if_not_found :
                return False
            else :
                raise ResourceNotFound("Cannot lookup key: " + name, e)

    @reauth
    def delete_doc(self, doc) :
        self.db.delete(doc)

    @reauth
    def __delitem__(self, name, second_time = False) :
        revs = []

        try :
            all_deleted = False
            count = -1
            while not all_deleted :
                count += 1
                all_deleted = True
                docs = self.__getitem__(name, open_revs = "all")
                for doc in docs :
                    if "_deleted" in doc["ok"] :
                        continue
                    all_deleted = False
                    mdebug(str(count) + ") DELETE Found undeleted revision: " + name + ": " + doc["ok"]["_rev"])
                    olddoc = self.__getitem__(name, rev = doc["ok"]["_rev"])
                    if olddoc is not None :
                        mdebug(str(count) + ") DELETE Deleting...")
                        try :
                            self.delete_doc(olddoc)
                        except (CommunicationError, couch_ResourceNotFound), e :
                            mwarn("OK if not found. Will try again: " + str(e))

            '''
            doc = self.db[name]
            if "_conflicts" in doc :
                mdebug("FOUND conflict revisions.")
                revs += doc["_conflicts"]
            if "_deleted_conflicts" in doc :
                mdebug("FOUND deleted conflict revisions.")
                revs += doc["_deleted_conflicts"]

            for rev in revs :
                olddoc = self.db.get(name, rev=rev)
                self.db.delete(olddoc)
            #del self.db[name]
            '''
        except couch_ResourceNotFound, e :
            # This happens during DB timeouts only for the _users database
            if name.count("org.couchdb.user") and not second_time  :
                raise PossibleResourceNotFound(name)
            raise ResourceNotFound(str(e))

    @reauth
    def delete_attachment(self, doc, filename) :
        self.db.delete_attachment(doc, filename)

    @reauth
    def purge(self, doc_list) :
        self.db.purge(doc_list)

    @reauth
    def put_attachment(self, name, filename, contents, new_doc = False) :
        if not new_doc :
            trydelete = True
            if self.doc_exist(name) is True :
                mdebug("Deleting original @ " + name)
                doc = self.__getitem__(name)
                self.__delitem__(name)
                self.purge([doc])
                trydelete = False

            doc = { "foo" : "bar"}
            # This 'translated_at' is because of bug: https://issues.apache.org/jira/browse/COUCHDB-1415
            # Supposedly fixed in CouchDB 2.0
            doc["translated_at"] = time()

            if trydelete :
                try :
                    doc["_rev"] = self.__getitem__(name)["_rev"]
                    mdebug("Old revision found.")
                except couch_ResourceNotFound, e :
                    mdebug("No old revision found.")
                    pass

            mdebug("Going to write: " + str(doc) + " to doc id " + name + " under filename " + filename)
            self.__setitem__(name, doc)
            doc = self.__getitem__(name)
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
                byte = obj.read(4096)
                if byte :
                    sourcebytes += len(byte)
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
    def doc_exist(self, name, second_time = False) :
        try :
            self.db[name]
        except couch_ResourceNotFound, e :
            # This happens during DB timeouts only for the _users database
            if name.count("org.couchdb.user") and not second_time :
                raise PossibleResourceNotFound(name)
            ((error, reason),) = e.args
            mverbose("Doc exist returns not found: " + reason)
            return False

        return True

    def iocheck(self, e) :
        if e.errno in bad_errnos :
            try :
                self.reauthorize(e = e)
            except CommunicationError, e :
                mdebug("iocheck Re-authorization failed, but we'll keep trying.")
        else :
            mwarn("Actual error number: " + str(e.errno))
            raise e

    def do_check_for_unauthorized(self, e) :
        try :
           check_for_unauthorized(e)
           raise CommunicationError("Failed to perform view: " + str(e))
        except Unauthorized, e :
            try :
                self.reauthorize(e = e)
            except CommunicationError, e :
                mdebug("error check Re-authorization failed, but we'll keep trying.")

    def error_check(self, errors) :
        if errors["errors_left"] > 0 :
            mwarn("Server errors left: " + str(errors["errors_left"]))
            errors["errors_left"] -= 1
            sleep(1)
        else :
            merr("No errors_left remaining.")
            raise CommunicationError("Failed to perform view. Ran out of tries.")

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

        yielded_rows = {}
        errors = {"errors_left" : limit}

        while errors["errors_left"]> 0 :
            try:
                view = self.db.view(view_name, **options)
                rows = []
                # If we got a short result (< limit + 1), we know we are done.
                if len(view) <= bulk:
                    rows = view.rows
                else:
                    # Otherwise, continue at the new start position.
                    rows = view.rows[:-1]
                    last = view.rows[-1]
                    options['startkey'] = last.key
                    options['startkey_docid'] = last.id

                for row in  self.do_rows(rows, yielded_rows) :
                    yield row
                break
            except retriable_errors, e :
                try :
                    self.reauthorize(e = e)
                except CommunicationError, e :
                    mdebug("view 1) check Re-authorization failed, but we'll keep trying.")
            except IOError, e:
                self.iocheck(e)
            except couch_ServerError, e :
                self.do_check_for_unauthorized(e)

            self.error_check(errors)

    def do_rows(self, rows, yielded_rows) :
        for row in rows :
            if row["key"] is None or (("id" in row and row["id"] not in yielded_rows) or row["value"]["_id"] not in yielded_rows) :
                if row["key"] is not None :
                    _id = row["id"] if "id" in row else row["value"]["_id"]
                    yielded_rows[_id] = True
                yield row
        

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
            yielded_rows = {}
            errors = {"errors_left" : limit}
            while errors["errors_left"] > 0 :
                try :
                    for row in self.do_rows(self.db.view(*args, **kwargs), yielded_rows) :
                        yield row
                    break
                    
                except retriable_errors, e :
                    try :
                        self.reauthorize(e = e)
                    except CommunicationError, e :
                        mdebug("view 2) check Re-authorization failed, but we'll keep trying.")
                except IOError, e:
                    self.iocheck(e)
                except couch_ServerError, e :
                    self.do_check_for_unauthorized(e)

                self.error_check(errors)
        else :
            kwargs["view_name"] = view_name
            kwargs["bulk"] = 50
            for row in self.couchdb_pager(**kwargs) :
                yield row

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

class MicaServerCouchDB(AuthBase) :
    def __init__(self, url = False, username = False, password = False, cookie = False, refresh = False) :
        self.url = url
        self.cookie = cookie
        self.refresh = refresh
        if refresh :
            self.username = username
            self.password = password

        self.couch_server = Server(url)

        if refresh :
            assert(self.url)
            assert(self.username)
            assert(self.password)

        self.first_auth(username, password)

    @reauth
    def first_auth(self, username, password) :
        self.auth(username, password)

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
        mverbose("Reauth start")
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
            mdebug("Reusing cookie: " + self.cookie)

        assert(self.cookie)
        self.couch_server.resource.headers["Cookie"] = self.cookie
        mverbose("Reauth done")

    @reauth
    def __getitem__(self, dbname) :
        if dbname in self.couch_server :
            db = self.couch_server[dbname]
        else :
            db = self.couch_server.create(dbname)
        return MicaDatabaseCouchDB(db, self, dbname)

    @reauth
    def __delitem__(self, name) :
        del self.couch_server[name]

    @reauth
    def __contains__(self, dbname) :
        return True if dbname in self.couch_server else False

class AndroidMicaDatabaseCouchbaseMobile(MicaDatabase) :
    def __init__(self, db, name) :
        self.db = db
        self.dbname = name
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

    def info(self) :
        try :
            return loads(self.db.info(String(self.dbname)))
        except Exception, e :
            raise CommunicationError("Error occured getting database info: " + self.dbname + " " + str(e), e)
        if info is None :
            raise ResourceNotFound("Could not get database info: " + self.dbname)

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
        return AndroidMicaDatabaseCouchbaseMobile(self.db, dbname)

    def __delitem__(self, name) :
        try :
            self.db.drop(name)
        except Exception, e :
            raise CommunicationError("Database deletion failed for: " + name)

    def __contains__(self, dbname) :
        return True if self.db.exists(dbname) else False

class iosMicaDatabaseCouchbaseMobile(MicaDatabase) :
    def __init__(self, db, name) :
        self.db = db
        self.dbname = name
        mdebug("ios CouchBase Mobile python adapter initialized")

    def info(self) :
        try :
            return loads(self.db.info_(String(self.dbname)).UTF8String())
        except Exception, e :
            raise CommunicationError("Error occured getting database info: " + self.dbname + " " + str(e), e)
        if info is None :
            raise ResourceNotFound("Could not get database info: " + self.dbname)

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
        return iosMicaDatabaseCouchbaseMobile(self.db, dbname)

    def __delitem__(self, name) :
        try :
            self.db.drop(name)
        except Exception, e :
            raise CommunicationError("Database deletion failed for: " + name)

    def __contains__(self, dbname) :
        return True if self.db.exists(dbname) else False
