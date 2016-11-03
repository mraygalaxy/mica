#!/usr/bin/env python 
# coding: utf-8

try:
    import http.client as http_client
except ImportError:
    # Python 2
    import httplib as http_client

#http_client.HTTPConnection.debuglevel = 1
#http_client.HTTPSConnection.debuglevel = 1

import sys, os
import urllib
import random, binascii
from urlparse import urlparse
import logging

from punjab.httpb import HttpbParse

from twisted.words.xish import domish
from twisted.words.protocols.jabber import jid

TLS_XMLNS = 'urn:ietf:params:xml:ns:xmpp-tls'
SASL_XMLNS = 'urn:ietf:params:xml:ns:xmpp-sasl'
BIND_XMLNS = 'urn:ietf:params:xml:ns:xmpp-bind'
SESSION_XMLNS = 'urn:ietf:params:xml:ns:xmpp-session'

from common import *

class BOSHClient:
    def __init__(self, jabberid, password, bosh_service, rid = False):
        if not rid :
            self.rid = random.randint(0, 10000000)
        else :
            self.rid = rid
        self.jabberid = jid.internJID(jabberid)
        self.password = password

        self.authid = None
        self.sid = None
        self.logged_in = False
        self.headers = {"Content-type": "text/xml",
                        "Accept": "text/xml"}

        self.bosh_service = urlparse(bosh_service)
        
    def buildBody(self, child=None, to = False):
        body = domish.Element(("http://jabber.org/protocol/httpbind", "body"))
        body['content'] = 'text/xml; charset=utf-8'
        self.rid = self.rid + 1
        body['rid'] = str(self.rid)
        body['sid'] = str(self.sid)
        body['xml:lang'] = 'en'
        if to :
            body['to'] = to
            body['xmpp:restart'] = "true"
            body['xmlns:xmpp'] = 'urn:xmpp:xbosh'
     
        if child is not None:
            body.addChild(child)

        return body
        
    def sendBody(self, body):
        parser = HttpbParse(True)

        mdebug("Body: " + str(body.toXml() + " to " + self.bosh_service.netloc + " " + self.bosh_service.path + " " + str(self.bosh_service.scheme)))
        if self.bosh_service.scheme == "https" : 
            conn = http_client.HTTPSConnection(self.bosh_service.netloc, timeout = 10)
        else :
            conn = http_client.HTTPConnection(self.bosh_service.netloc, timeout = 10)
        conn.request("POST", self.bosh_service.path, body.toXml(), self.headers)
        response = conn.getresponse()
        data = ''
        if response.status == 200:
            data = response.read()
            mdebug("Response: " + str(data))
        else :
            mdebug("Error: " + str(response.status))
        conn.close()

        return parser.parse(data)

    def startSessionAndAuth(self, hold='1', wait='70'):
        body = domish.Element(("http://jabber.org/protocol/httpbind", "body"))

        body['content'] = 'text/xml; charset=utf-8'
        body['hold'] = hold
        body['rid'] = str(self.rid)
        body['to'] = self.jabberid.host
        body['wait'] = wait
#        body['window'] = '5'
        body['xml:lang'] = 'en'
        body['ver'] = '1.6'
        body['xmpp:version'] = '1.0'
        body['xmlns:xmpp'] = 'urn:xmpp:xbosh'

        retb, elems = self.sendBody(body)
        if type(retb) != str and retb.hasAttribute('authid') and retb.hasAttribute('sid'):
            self.authid = retb['authid']
            self.sid = retb['sid']

            # go ahead and auth
            auth = domish.Element((SASL_XMLNS, 'auth'))
            auth['mechanism'] = 'PLAIN'
            
            # TODO: add authzid
            if auth['mechanism'] == 'PLAIN':
                auth_str = ""
                auth_str += "\000"
                auth_str += self.jabberid.user.encode('utf-8')
                auth_str += "\000"
                try:
                    auth_str += self.password.encode('utf-8').strip()
                except UnicodeDecodeError:
                    auth_str += self.password.decode('latin1').encode('utf-8').strip()
                        
                auth.addContent(binascii.b2a_base64(auth_str))
                
                retb, elems = self.sendBody(self.buildBody(auth))
                if len(elems) == 0:
                    # poll for data
                    retb, elems = self.sendBody(self.buildBody())

                if len(elems) > 0:
                    if elems[0].name == 'success':
                        retb, elems = self.sendBody(self.buildBody(to = 'readalien.com'))
                        
                        bind_found = False
                        for elem in elems[0].children :
                            if elem.name == 'bind':
                                bind_found = True
                                break

                        if bind_found :
                            iq = domish.Element(('jabber:client', 'iq'))
                            iq['type'] = 'set'
                            iq.addUniqueId()
                            iq.addElement('bind')
                            iq.bind['xmlns'] = BIND_XMLNS
                            if self.jabberid.resource:
                                iq.bind.addElement('resource')
                                iq.bind.resource.addContent(self.jabberid.resource)

                            retb, elems = self.sendBody(self.buildBody(iq))
                            if type(retb) != str and retb.name == 'body':
                                # send session
                                iq = domish.Element(('jabber:client', 'iq'))
                                iq['type'] = 'set'
                                iq.addUniqueId()
                                iq.addElement('session')
                                iq.session['xmlns'] = SESSION_XMLNS

                                retb, elems = self.sendBody(self.buildBody(iq))

                                # did not bind, TODO - add a retry?
                                if type(retb) != str and retb.name == 'body':
                                    self.logged_in = True
                                    # bump up the rid, punjab already received self.rid
                                    self.rid += 1

if __name__ == '__main__':
    USERNAME = sys.argv[1]
    PASSWORD = sys.argv[2]
    SERVICE = sys.argv[3]

    c = BOSHClient(USERNAME, PASSWORD, SERVICE)
    c.startSessionAndAuth()

    if c.logged_in :
        print "SID: " + c.sid
        print "JID: " + USERNAME
        print "RID: " + str(c.rid)
        exit(0)
    else :
        print "Failed"
        exit(1)
