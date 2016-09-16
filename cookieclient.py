# -*- coding: utf-8 -*-

# First steps towards actually refreshing the cookie

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
    from jnius import detach as jnius_detach
    jnius_detachable = True
except ImportError, e :
    try :
        from pyobjus import autoclass, objc_f, objc_str as String, objc_l as Long, objc_i as Integer
    except ImportError, e :
        mverbose("pyjnius and pyobjus not available. Probably on a server.")

__all__ = ['CookieServer', 'CookieDatabase']


DEFAULT_BASE_URL = os.environ.get('COUCHDB_URL', 'http://localhost:5984/')
class CookiePermanentView(PermanentView):
    """Representation of a permanent view on the server."""

    def __init__(self, uri, name, wrapper=None, session=None):
        View.__init__(self, uri, wrapper=wrapper, session=session)
        self.name = name

    def __repr__(self):
        return '<%s %r>' % (type(self).__name__, self.name)

    def _exec(self, options):
        _, _, data = _call_viewlike(self.resource, options)
        return data

class CookieServer(Server):
    def __contains__(self, name):
        try:
            self.resource.head(name)
            return True
        except http.ResourceNotFound:
            return False
    def __delitem__(self, name):
        self.resource.delete_json(name)

    def create(self, name):
        self.resource.put_json(name)
        return self[name]

    def delete(self, name):
        del self[name]

    def __getitem__(self, name):
        db = CookieDatabase(self.resource(name), name)
        db.resource.head() # actually make a request to the database
        return db

class CookieDatabase(Database):
    def __getitem__(self, name):
        db = CookieDatabase(self.resource(name), name)
        db.resource.head() # actually make a request to the database
        return db
    def __contains__(self, id):
        try:
            _doc_resource(self.resource, id).head()
            return True
        except http.ResourceNotFound:
            return False
    def __delitem__(self, id):
        resource = _doc_resource(self.resource, id)
        status, headers, data = resource.head()
        resource.delete_json(rev=headers['etag'].strip('"'))
    def __getitem__(self, id):
        _, headers, data = _doc_resource(self.resource, id).get_json()
        #if "set-cookie" in headers :
        #    mdebug("New cookie: " + headers["set-cookie"])
        return Document(data)
    def __setitem__(self, id, content):
        resource = _doc_resource(self.resource, id)
        status, headers, data = resource.put_json(body=content)
        content.update({'_id': data['id'], '_rev': data['rev']})
    @property
    def security(self):
        return self.resource.get_json('_security')[2]
    @security.setter
    def security(self, doc):
        self.resource.put_json('_security', body=doc)
    def cleanup(self):
        headers = {'Content-Type': 'application/json'}
        _, _, data = self.resource('_view_cleanup').post_json(headers=headers)
        return data['ok']
    def compact(self, ddoc=None):
        if ddoc:
            resource = self.resource('_compact', ddoc)
        else:
            resource = self.resource('_compact')
        _, _, data = resource.post_json(
            headers={'Content-Type': 'application/json'})
        return data['ok']
    def delete(self, doc):
        if doc['_id'] is None:
            raise ValueError('document ID cannot be None')
        _doc_resource(self.resource, doc['_id']).delete_json(rev=doc['_rev'])
    def get(self, id, default=None, **options):
        try:
            _, _, data = _doc_resource(self.resource, id).get_json(**options)
        except http.ResourceNotFound:
            return default
        if hasattr(data, 'items'):
            return Document(data)
        else:
            return data
    def info(self, ddoc=None):
        if ddoc is not None:
            _, _, data = self.resource('_design', ddoc, '_info').get_json()
        else:
            _, _, data = self.resource.get_json()
            self._name = data['db_name']
        return data
    def delete_attachment(self, doc, filename):
        resource = _doc_resource(self.resource, doc['_id'])
        _, _, data = resource.delete_json(filename, rev=doc['_rev'])
        doc['_rev'] = data['rev']
    def get_attachment(self, id_or_doc, filename, default=None):
        if isinstance(id_or_doc, util.strbase):
            id = id_or_doc
        else:
            id = id_or_doc['_id']
        try:
            _, _, data = _doc_resource(self.resource, id).get(filename)
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
        _, _, data = self.resource.post_json('_purge', body=content)
        return data
    def view(self, name, wrapper=None, **options):
        path = _path_from_name(name, '_view')
        return CookiePermanentView(self.resource(*path), '/'.join(path),
                             wrapper=wrapper)(**options)
