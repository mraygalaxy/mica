#!/usr/bin/env python
# coding: utf-8

from urllib import urlencode as urllib_urlencode
from urllib2 import urlopen as urllib2_urlopen, Request as urllib2_Request
from json import loads, dumps
from copy import deepcopy
from xml import etree

from common import *

import requests
import re

class ArgumentOutOfRangeException(Exception):
    def __init__(self, message):
        self.message = message.replace('ArgumentOutOfRangeException: ', '')
        super(ArgumentOutOfRangeException, self).__init__(self.message)

class ArgumentException(Exception):
    def __init__(self, message):
        self.message = message.replace('ArgumentException: ', '')
        super(ArgumentException, self).__init__(self.message)

class OnlineTranslateException(Exception):
    def __init__(self, message, *args):
        self.message = message.replace('OnlineTranslateException: ', '')
        super(OnlineTranslateException, self).__init__(self.message, *args)

class TranslateApiException(Exception):
    def __init__(self, message, *args):
        self.message = message.replace('TranslateApiException: ', '')
        super(TranslateApiException, self).__init__(self.message, *args)

class Translator(object):
    def __init__(self, client_id, client_secret, scope, access_token_url,
               grant_type = "client_credentials", app_id = None, test = False):
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.grant_type = grant_type
        self.access_token = None
        self.test = test
        self.access_token_url = access_token_url + "/issueToken?Subscription-Key=" + client_secret

    def get_access_token(self):
        response = False
        try :
            mverbose("Sending to: " + self.access_token_url)
            data = urllib2_urlopen(self.access_token_url, "", timeout=30).read()
            mverbose("Response: " + str(data))
            response = data
            test_log(self.test, loc = self.access_token_url, response = data, method = "post")
        except IOError, e :
            if response :
                raise TranslateApiException(
                    response.get('error_description', 'Failed to authenticate with translation service'),
                    response.get('error', str(e))
                    )
            else :
                raise TranslateApiException("Translation Service Authentication failed", str(e))
        

        if response and "error" in response:
            merr("Error in authentication response.")
            raise TranslateApiException(
                response.get('error_description', 'No Error Description'),
                response.get('error', 'Unknown Error')
            )
        return response

    def call(self, url, p, data = False):
        """Calls the given url with the params urlencoded
        """
        if not self.access_token:
            self.access_token = self.get_access_token()
        final_url = "%s?%s" % (url, urllib_urlencode(p))
        headers={'Content-Type' : 'text/xml', 'Authorization': 'Bearer %s' % self.access_token}

        if data :
            r = requests.post(url, headers = headers, data = data, timeout=30)
        else :
            r = requests.get(final_url, headers = headers, timeout=30)

        response = r.text

        if response.count("ArgumentOutOfRangeException"):
            raise ArgumentOutOfRangeException(response)

        if response.count("ArgumentException"):
            raise ArgumentException(response)

        if response.count("TranslateApiException"):
            raise TranslateApiException(response)

        response = xmlstring = re.sub(' xmlns="[^"]+"', '', response, count=1)
        root = etree.ElementTree.fromstring(response.decode("utf-8-sig"))
        rv = []
        for child in root :
            result = {}
            for part in child :
                name = part.tag
                if name in ["TranslatedText", "From"] :
                    mverbose("Setting: " + name + " = " + str(part.text))
                    result[name] = part.text
                else :
                    for number in part :
                        mverbose("Setting: " + name + " = " + str(number.text))
                        result[name] = number.text
            rv.append(result)

        if len(rv) > 0 and self.test :
            rvc = deepcopy(rv)
            for idx in range(0, len(rvc)) : 
                mwarn("RVC idx: " + str(idx) + " is " + str(type(rvc[idx])) + ", " + str(rvc))
                rvc[idx]["TranslatedText"] = rvc[idx]["TranslatedText"].encode("utf-8")

            # Log the results of microsoft for unit testing.
            test_log(self.test, exchange = dict(inp = {'texts' : str(p["texts"]), 'from' : p['from'], 'options' : p['options'], 'to' : p['to']}, outp = rvc))
        return rv


    def translate(self, text, to_lang, from_lang=None,
            content_type='text/plain', category='general'):
        p = {
            'text': text.encode('utf8'),
            'to': to_lang,
            'contentType': content_type,
            'category': category,
            }
        if from_lang is not None:
            p['from'] = from_lang
        return self.call(self.scope + "/v2/http.svc/Translate", p)

    def translate_array(self, texts, to_lang, from_lang=None, **options):
        options = {
            'Category': u"general",
            'Contenttype': u"text/xml",
            'Uri': u'',
            'User': u'default',
            'State': u''
            }.update(options)
        p = {
            'to': to_lang,
            'options': dumps(options),
            }

        if from_lang is not None:
            p['from'] = from_lang

        xml = """
        <TranslateArrayRequest>
          <AppId />"""

        if from_lang is not None :
            if isinstance(from_lang, unicode) :
                from_lang = from_lang.encode("utf-8")
            xml += """
              <From>""" + from_lang + """</From>"""

        xml += """
          <Texts>
        """

        for text in texts :
            if isinstance(text, unicode) :
                text = text.encode("utf-8")
            xml += "<string xmlns=\"http://schemas.microsoft.com/2003/10/Serialization/Arrays\">" + text + "</string>"

        if isinstance(to_lang, unicode) :
            to_lang = to_lang.encode("utf-8")

        xml += """
            </Texts>
          <To>""" + to_lang + """</To>
        </TranslateArrayRequest>
        """

        return self.call(self.scope + "/v2/http.svc/TranslateArray", p, data = xml)
