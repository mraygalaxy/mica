#!/usr/bin/env python
# coding: utf-8

from urllib import urlencode as urllib_urlencode
from urllib2 import urlopen as urllib2_urlopen, Request as urllib2_Request
from json import loads, dumps

from common import *

class ArgumentOutOfRangeException(Exception):
    def __init__(self, message):
        self.message = message.replace('ArgumentOutOfRangeException: ', '')
        super(ArgumentOutOfRangeException, self).__init__(self.message)

class OnlineTranslateException(Exception):
    def __init__(self, message, *args):
        self.message = message.replace('OnlineTranslateException: ', '')
        super(OnlineTranslateException, self).__init__(self.message, *args)

class TranslateApiException(Exception):
    def __init__(self, message, *args):
        self.message = message.replace('TranslateApiException: ', '')
        super(TranslateApiException, self).__init__(self.message, *args)

class Translator(object):
    def __init__(self, client_id, client_secret,
            scope="http://api.microsofttranslator.com",
            grant_type="client_credentials", app_id=None, debug=False):
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.grant_type = grant_type
        self.access_token = None

    def get_access_token(self):
        args = urllib_urlencode({
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': self.scope,
            'grant_type': self.grant_type
        })
        
        mdebug("Authenticating...")
        response = False
        try :
            response = loads(urllib2_urlopen(
                'https://datamarket.accesscontrol.windows.net/v2/OAuth2-13', args, timeout=30
            ).read())
        except IOError, e :
            if response :
                raise TranslateApiException(
                    response.get('error_description', 'Failed to authenticate with translation service'),
                    response.get('error', str(e))
                    )
            else :
                raise TranslateApiException("Translation Service Authentication failed", str(e))
        

        mdebug("Authenticated")
        mdebug(str(response))

        if response and "error" in response:
            mdebug("Error in authentication response.")
            raise TranslateApiException(
                response.get('error_description', 'No Error Description'),
                response.get('error', 'Unknown Error')
            )
        mdebug("Authentication returning")
        return response['access_token']

    def call(self, url, p):
        """Calls the given url with the params urlencoded
        """
        mdebug("Translator ready for call.")
        if not self.access_token:
            self.access_token = self.get_access_token()

        mdebug("urllib request start.")

        request = urllib2_Request(
            "%s?%s" % (url, urllib_urlencode(p)),
            headers={'Authorization': 'Bearer %s' % self.access_token}
        )

        mdebug("urllib get response")
        response = urllib2_urlopen(request, timeout=30).read()

        mdebug("json load")
        rv =  loads(response.decode("utf-8-sig"))

        if isinstance(rv, basestring) and \
                rv.startswith("ArgumentOutOfRangeException"):
            raise ArgumentOutOfRangeException(rv)

        if isinstance(rv, basestring) and \
                rv.startswith("TranslateApiException"):
            raise TranslateApiException(rv)

        return rv

    def translate(self, text, to_lang, from_lang=None,
            content_type='text/plain', category='general'):
        """Translates a text string from one language to another.

        :param text: A string representing the text to translate.
        :param to_lang: A string representing the language code to
            translate the text into.
        :param from_lang: A string representing the language code of the
            translation text. If left None the response will include the
            result of language auto-detection. (Default: None)
        :param content_type: The format of the text being translated.
            The supported formats are "text/plain" and "text/html". Any HTML
            needs to be well-formed.
        :param category: The category of the text to translate. The only
            supported category is "general".
        """
        p = {
            'text': text.encode('utf8'),
            'to': to_lang,
            'contentType': content_type,
            'category': category,
            }
        if from_lang is not None:
            p['from'] = from_lang
        return self.call(
            "http://api.microsofttranslator.com/V2/Ajax.svc/Translate",
            p)

    def translate_array(self, texts, to_lang, from_lang=None, **options):
        """Translates an array of text strings from one language to another.

        :param texts: A list containing texts for translation.
        :param to_lang: A string representing the language code to 
            translate the text into.
        :param from_lang: A string representing the language code of the 
            translation text. If left None the response will include the 
            result of language auto-detection. (Default: None)
        :param options: A TranslateOptions element containing the values below. 
            They are all optional and default to the most common settings.

                Category: A string containing the category (domain) of the 
                    translation. Defaults to "general".
                ContentType: The format of the text being translated. The 
                    supported formats are "text/plain" and "text/html". Any 
                    HTML needs to be well-formed.
                Uri: A string containing the content location of this 
                    translation.
                User: A string used to track the originator of the submission.
                State: User state to help correlate request and response. The 
                    same contents will be returned in the response.
        """
        mdebug("Translator preparing options.")
        options = {
            'Category': u"general",
            'Contenttype': u"text/plain",
            'Uri': u'',
            'User': u'default',
            'State': u''
            }.update(options)
        p = {
            'texts': dumps(texts),
            'to': to_lang,
            'options': dumps(options),
            }
        mdebug("Translator options set.")
        if from_lang is not None:
            p['from'] = from_lang

        return self.call(
                "http://api.microsofttranslator.com/V2/Ajax.svc/TranslateArray",
                p)
