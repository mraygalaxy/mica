#!/usr/bin/env python
# coding: utf-8

from json import loads, dumps
from common import *

import requests

# ---------------------------------------------------------------------------
# Exception classes (kept for compatibility — caught in mica.py error handling)
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Language code → human-readable name for LLM prompts
# ---------------------------------------------------------------------------

_LANG_NAMES = {
    'zh-CHS': 'Chinese (Simplified)',
    'zh-CHT': 'Chinese (Traditional)',
    'zh':     'Chinese (Simplified)',
    'en':     'English',
    'es':     'Spanish',
    'fr':     'French',
    'de':     'German',
    'ja':     'Japanese',
    'ko':     'Korean',
    'pt':     'Portuguese',
    'ru':     'Russian',
    'ar':     'Arabic',
}

def _lang_name(code):
    return _LANG_NAMES.get(code, code)

# ---------------------------------------------------------------------------
# Ollama-backed translator — drop-in replacement for the old Translator class.
# translate_array() returns the same [{"TranslatedText": ..., "From": ...}]
# format that the rest of the codebase expects.
# ---------------------------------------------------------------------------

class OllamaTranslator(object):
    def __init__(self, ollama_url, model):
        self.ollama_url = ollama_url.rstrip('/')
        self.model = model
        self.access_token = None  # no-op: keeps retry loop in translate_and_check_array happy

    def get_access_token(self):
        return None  # no-op: Ollama needs no authentication token

    def translate_array(self, texts, to_lang, from_lang=None):
        to_name   = _lang_name(to_lang)
        from_name = _lang_name(from_lang) if from_lang else None

        results = []
        for text in texts:
            if isinstance(text, str):
                text = text.decode('utf-8')

            if from_name:
                user_msg = u"Translate from {} to {}: {}".format(from_name, to_name, text)
            else:
                user_msg = u"Translate to {}: {}".format(to_name, text)

            payload = {
                "model":  self.model,
                "think":  False,
                "stream": False,
                "messages": [
                    {
                        "role":    "system",
                        "content": (
                            "You are a professional translator. "
                            "Translate the given text accurately and concisely. "
                            "Respond with only the translation, nothing else — "
                            "no explanations, no punctuation added, no quotation marks."
                        )
                    },
                    {
                        "role":    "user",
                        "content": user_msg
                    }
                ]
            }

            r = requests.post(
                self.ollama_url + "/api/chat",
                headers={"Content-Type": "application/json"},
                data=dumps(payload),
                timeout=120
            )

            if r.status_code != 200:
                raise TranslateApiException(
                    "Ollama returned HTTP " + str(r.status_code) + ": " + r.text[:200]
                )

            translated = r.json()["message"]["content"].strip()
            results.append({"TranslatedText": translated, "From": from_lang or u""})

        return results


# ---------------------------------------------------------------------------
# Stub kept so that test.py mock infrastructure (TranslatorAccess /
# TranslatorRequest routes) can still be imported without errors.
# Not used at runtime on the server.
# ---------------------------------------------------------------------------

class Translator(object):
    def __init__(self, client_id, client_secret, scope, access_token_url,
                 grant_type="client_credentials", app_id=None, test=False):
        pass

    def get_access_token(self):
        raise TranslateApiException("Microsoft Translator is no longer used")

    def translate_array(self, texts, to_lang, from_lang=None, **options):
        raise TranslateApiException("Microsoft Translator is no longer used")
