#-*- coding=UTF-8 -*-
'''
Provide some patches to ignore checks may fail some
Chinese OAuth 2.0 Provider.
'''
import cgi
try:
    import json
except ImportError, e :
    import simplejson as json


def parse_authorization_code_response(uri, state=None):
    '''
    Ignore non https callback uri.
    '''
    if not is_secure_transport(uri):
        print("Insecure transport for %s" % uri)
        # raise InsecureTransportError()

    query = urlparse.urlparse(uri).query
    params = dict(urlparse.parse_qsl(query))

    if not 'code' in params:
        raise MissingCodeError("Missing code parameter in response.")

    if state and params.get('state', None) != state:
        raise MismatchingStateError()

    return params


def validate_token_parameters(params, scope=None):
    '''
    Ignore errors where no 'token_url' in token parameters.
    '''
    if 'error' in params:
        raise_from_error(params.get('error'), params)

    if not 'access_token' in params:
        print ("Params: " + str(params))
        raise MissingTokenError(description="Missing access token parameter.")

    if not 'token_type' in params:
        print("Missing token_type in parameters.")
        # raise MissingTokenTypeError()

    new_scope = params.get('scope', None)
    scope = scope_to_list(scope)
    if scope and new_scope and set(scope) != set(new_scope):
        raise Warning("Scope has changed to %s." % new_scope)


def qs_to_json(qs):
    data = dict(cgi.parse_qsl(qs))
    return json.dumps(data)


def fetch_token(self, token_url, code=None, authorization_response=None,
        body='', username=None, password=None, **kwargs):
    if not token_url.startswith('https://'):
        raise InsecureTransportError()

    if not code and authorization_response:
        self._client.parse_request_uri_response(authorization_response,
            state=self.state)
    #code = self._client.code
    print ("Not going to add: " + str(self._client.code))
    body = self._client.prepare_request_body(code=code,
            redirect_uri=self.redirect_uri, **kwargs)

    r = self.post(token_url, data=dict(urldecode(body)))
    content = r.content
    print ("Content is: " + str(content))
    if 'application/json' not in r.headers.get('content_type', ''):
        try:
            json.loads(content)
        except Exception, e:
            content = qs_to_json(content)
            print("Change the content returned to json")

    self._client.parse_request_body_response(content, scope=self.scope)
    self.token = self._client.token
    return self.token


def patch():
    import oauthlib.oauth2.rfc6749.parameters as parameters

    functions = ['parse_authorization_code_response',
                 'validate_token_parameters']

    for function in functions:
        print("Patching %s" % function)
        getattr(parameters, function).func_code\
            = globals()[function].func_code

    import requests_oauthlib.oauth2_session as oauth2_session
    oauth2_session.qs_to_json = qs_to_json
    oauth2_session.json = json

    print("Patching fetch_token")

    oauth2_session.OAuth2Session.fetch_token.__func__.func_code\
        = fetch_token.func_code
