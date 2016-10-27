# -*- coding: utf-8 -*-

# First steps towards actually refreshing the cookie
# Doesn't seem to work, despite the cookie getting refreshed.
# With persistent cookies or something related to 10% of the cookie's lifetime,
# it MIGHT work. Maybe 5 seconds is just to short to verify what's going on:
# https://github.com/apache/couchdb-couch/blob/master/src/couch_httpd_auth.erl#L244

from common import *
import itertools
import mimetypes
import os
from types import FunctionType
from inspect import getsource
from textwrap import dedent
import warnings
import sys

try :
    from couchdb.client import Server, Database, PermanentView, _doc_resource, _path_from_name, Document, View, _call_viewlike
    from couchdb import http, json, util
except ImportError, e :
    mdebug("couchdb not available. Probably on mobile.")

jnius_detachable = False
try :
    from jnius import autoclass
    String = autoclass('java.lang.String')
    #from jnius import detach as jnius_detach
    #jnius_detachable = True
except ImportError, e :
    try :
        from pyobjus import autoclass, objc_f, objc_str as String, objc_l as Long, objc_i as Integer
    except ImportError, e :
        mverbose("pyjnius and pyobjus not available. Probably on a server.")

__all__ = ['CookieServer', 'CookieDatabase']


DEFAULT_BASE_URL = os.environ.get('COUCHDB_URL', 'http://localhost:5984/')
class CookiePermanentView(PermanentView):
    """Representation of a permanent view on the server."""
    def cc(self, headers) :
        if "set-cookie" in headers :
            cookie = headers["set-cookie"].split(';', 1)[0]
            if cookie != self.resource.headers["Cookie"] :
                mdebug("New cookie: " + cookie + " != " + self.resource.headers["Cookie"])
                self.resource.headers["Cookie"] = cookie 

    def __init__(self, uri, name, wrapper=None, session=None):
        View.__init__(self, uri, wrapper=wrapper, session=session)
        self.name = name

    def __repr__(self):
        return '<%s %r>' % (type(self).__name__, self.name)

    def _exec(self, options):
        _, headers, data = _call_viewlike(self.resource, options)
        self.cc(headers)
        return data

class CookieServer(Server):
    def cc(self, headers) :
        if "set-cookie" in headers :
            cookie = headers["set-cookie"].split(';', 1)[0]
            if cookie != self.resource.headers["Cookie"] :
                mdebug("New cookie: " + cookie + " != " + self.resource.headers["Cookie"])
                self.resource.headers["Cookie"] = cookie 

    def __init__(self, url=DEFAULT_BASE_URL, full_commit=True, session=None):
        """Initialize the server object.

        :param url: the URI of the server (for example
                    ``http://localhost:5984/``)
        :param full_commit: turn on the X-Couch-Full-Commit header
        :param session: an http.Session instance or None for a default session
        """
        if isinstance(url, util.strbase):
            self.resource = http.Resource(url, session or http.Session())
        else:
            self.resource = url # treat as a Resource object
        if not full_commit:
            self.resource.headers['X-Couch-Full-Commit'] = 'false'

    def __contains__(self, name):
        try:
            _, headers, _ = self.resource.head(name)
            self.cc(headers)
            return True
        except http.ResourceNotFound:
            return False
    def __delitem__(self, name):
        _, headers, _ = self.resource.delete_json(name)
        self.cc(headers)

    def create(self, name):
        _, headers, _ = self.resource.put_json(name)
        self.cc(headers)
        return self[name]

    def delete(self, name):
        del self[name]

    def __getitem__(self, name):
        db = CookieDatabase(self.resource(name), name)
        _, headers, _ = db.resource.head() # actually make a request to the database
        self.cc(headers)
        return db

class CookieDatabase(Database):
    def cc(self, headers) :
        if "set-cookie" in headers :
            cookie = headers["set-cookie"].split(';', 1)[0]
            if cookie != self.resource.headers["Cookie"] :
                mdebug("New cookie: " + cookie + " != " + self.resource.headers["Cookie"])
                self.resource.headers["Cookie"] = cookie 
    def __init__(self, url, name=None, session=None):
        if isinstance(url, util.strbase):
            if not url.startswith('http'):
                url = DEFAULT_BASE_URL + url
            self.resource = http.Resource(url, session)
        else:
            self.resource = url
        self._name = name
    def __getitem__(self, name):
        db = CookieDatabase(self.resource(name), name)
        _, headers, _ = db.resource.head() # actually make a request to the database
        self.cc(headers)
        return db
    def __contains__(self, id):
        try:
            _, headers, _ = _doc_resource(self.resource, id).head()
            self.cc(headers)
            return True
        except http.ResourceNotFound:
            return False
    def __delitem__(self, id):
        resource = _doc_resource(self.resource, id)
        status, headers, data = resource.head()
        self.cc(headers)
        resource.delete_json(rev=headers['etag'].strip('"'))
    def __getitem__(self, id):
        _, headers, data = _doc_resource(self.resource, id).get_json()
        self.cc(headers)
        return Document(data)
    def __setitem__(self, id, content):
        resource = _doc_resource(self.resource, id)
        status, headers, data = resource.put_json(body=content)
        self.cc(headers)
        content.update({'_id': data['id'], '_rev': data['rev']})
    @property
    def security(self):
        _, headers, data = self.resource.get_json('_security')
        self.cc(headers)
        return data 

    @security.setter
    def security(self, doc):
        _, headers, _ = self.resource.put_json('_security', body=doc)
        self.cc(headers)
    def cleanup(self):
        tmp_headers = {'Content-Type': 'application/json'}
        _, headers, data = self.resource('_view_cleanup').post_json(headers=tmp_headers)
        self.cc(headers)
        return data['ok']
    def compact(self, ddoc=None):
        if ddoc:
            resource = self.resource('_compact', ddoc)
        else:
            resource = self.resource('_compact')
        _, headers, data = resource.post_json(
            headers={'Content-Type': 'application/json'})
        self.cc(headers)
        return data['ok']
    def delete(self, doc):
        if doc['_id'] is None:
            raise ValueError('document ID cannot be None')
        _, headers, _ = _doc_resource(self.resource, doc['_id']).delete_json(rev=doc['_rev'])
        self.cc(headers)
    def get(self, id, default=None, **options):
        try:
            _, headers, data = _doc_resource(self.resource, id).get_json(**options)
            self.cc(headers)
        except http.ResourceNotFound:
            return default
        if hasattr(data, 'items'):
            return Document(data)
        else:
            return data
    def info(self, ddoc=None):
        if ddoc is not None:
            _, headers, data = self.resource('_design', ddoc, '_info').get_json()
        else:
            _, headers, data = self.resource.get_json()
            self._name = data['db_name']
        self.cc(headers)
        return data
    def delete_attachment(self, doc, filename):
        resource = _doc_resource(self.resource, doc['_id'])
        _, headers, data = resource.delete_json(filename, rev=doc['_rev'])
        self.cc(headers)
        doc['_rev'] = data['rev']
    def get_attachment(self, id_or_doc, filename, default=None):
        if isinstance(id_or_doc, util.strbase):
            id = id_or_doc
        else:
            id = id_or_doc['_id']
        try:
            _, headers, data = _doc_resource(self.resource, id).get(filename)
            self.cc(headers)
            return data
        except http.ResourceNotFound:
            return default
    def put_attachment(self, doc, content, filename=None, content_type=None):
        if filename is None:
            if hasattr(content, 'name'):
                filename = os.path.basename(content.name)
            else:
                raise ValueError('no filename specified for attachment')
        if content_type is None:
            content_type = ';'.join(
                filter(None, mimetypes.guess_type(filename))
            )

        resource = _doc_resource(self.resource, doc['_id'])
        status, headers, data = resource.put_json(filename, body=content, headers={
            'Content-Type': content_type
        }, rev=doc['_rev'])
        self.cc(headers)
        doc['_rev'] = data['rev']
    def purge(self, docs):
        content = {}
        for doc in docs:
            if isinstance(doc, dict):
                content[doc['_id']] = [doc['_rev']]
            elif hasattr(doc, 'items'):
                doc = dict(doc.items())
                content[doc['_id']] = [doc['_rev']]
            else:
                raise TypeError('expected dict, got %s' % type(doc))
        _, headers, data = self.resource.post_json('_purge', body=content)
        self.cc(headers)
        return data
    def view(self, name, wrapper=None, **options):
        path = _path_from_name(name, '_view')
        return CookiePermanentView(self.resource(*path), '/'.join(path),
                             wrapper=wrapper)(**options)
