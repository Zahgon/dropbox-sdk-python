import hashlib

__all__ = [
    'BadRequestException',
    'BadStateException',
    'CsrfException',
    'DropboxOAuth2Flow',
    'DropboxOAuth2FlowNoRedirect',
    'NotApprovedException',
    'OAuth2FlowNoRedirectResult',
    'OAuth2FlowResult',
    'ProviderException',
]

import base64
import os
import six
import urllib
import re
from datetime import datetime, timedelta

from .session import (
    API_HOST,
    WEB_HOST,
    pinned_session,
    DEFAULT_TIMEOUT,
)

if six.PY3:
    url_path_quote = urllib.parse.quote  # pylint: disable=no-member,useless-suppression
    url_encode = urllib.parse.urlencode  # pylint: disable=no-member,useless-suppression
else:
    url_path_quote = urllib.quote  # pylint: disable=no-member,useless-suppression
    url_encode = urllib.urlencode  # pylint: disable=no-member,useless-suppression

TOKEN_ACCESS_TYPES = ['offline', 'online', 'legacy']
INCLUDE_GRANTED_SCOPES_TYPES = ['user', 'team']
PKCE_VERIFIER_LENGTH = 128

class OAuth2FlowNoRedirectResult(object):
    """
    Authorization information for an OAuth2Flow performed with no redirect.
    """

    def __init__(self, access_token, account_id, user_id, refresh_token, expiration, scope):
        """
        :param str access_token: Token to be used to authenticate later requests.
        :param str account_id: The Dropbox user's account ID.
        :param str user_id: Deprecated (use :attr:`account_id` instead).
        :param str refresh_token: Token to be used to acquire new access token when existing one
            expires.
        :param expiration: Either the number of seconds from now that the token expires in or the
            datetime at which the token expires.
        :type expiration: int or datetime
        :param list scope: List of scopes to request in base oauth flow.
        """
        self.access_token = access_token
        if not expiration:
            self.expires_at = None
        elif isinstance(expiration, datetime):
            self.expires_at = expiration
        else:
            self.expires_at = datetime.utcnow() + timedelta(seconds=int(expiration))
        self.refresh_token = refresh_token
        self.account_id = account_id
        self.user_id = user_id
        self.scope = scope

    def __repr__(self):
        return 'OAuth2FlowNoRedirectResult(%s, %s, %s, %s, %s, %s)' % (
            self.access_token,
            self.account_id,
            self.user_id,
            self.refresh_token,
            self.expires_at,
            self.scope,
        )


class OAuth2FlowResult(OAuth2FlowNoRedirectResult):
    """
    Authorization information for an :class:`OAuth2Flow` with redirect.
    """

    def __init__(self, access_token, account_id, user_id, url_state, refresh_token,
                 expires_in, scope):
        """
        Same as :class:`OAuth2FlowNoRedirectResult` but with url_state.

        :param str url_state: The url state that was set by :meth:`DropboxOAuth2Flow.start`.
        """
        super(OAuth2FlowResult, self).__init__(
            access_token=access_token,
            account_id=account_id,
            user_id=user_id,
            refresh_token=refresh_token,
            expiration=expires_in,
            scope=scope)
        self.url_state = url_state

    @classmethod
    def from_no_redirect_result(cls, result, url_state):
        pass

    def __repr__(self):
        return 'OAuth2FlowResult(%s, %s, %s, %s, %s, %s, %s)' % (
            self.access_token,
            self.account_id,
            self.user_id,
            self.url_state,
            self.refresh_token,
            self.expires_at,
            self.scope,
        )


class DropboxOAuth2FlowBase(object):

    def __init__(self, consumer_key, consumer_secret=None, locale=None, token_access_type=None,
                 scope=None, include_granted_scopes=None, use_pkce=False, timeout=DEFAULT_TIMEOUT,
                 ca_certs=None):
        if scope is not None and (len(scope) == 0 or not isinstance(scope, list)):
            raise BadInputException("Scope list must be of type list")
        if token_access_type is not None and token_access_type not in TOKEN_ACCESS_TYPES:
            raise BadInputException("Token access type must be from the following enum: {}".format(
                TOKEN_ACCESS_TYPES))
        if not (use_pkce or consumer_secret):
            raise BadInputException("Must pass in either consumer secret or use PKCE")
        if include_granted_scopes and not scope:
            raise BadInputException("Must pass in scope to pass include_granted_scopes")

        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.locale = locale
        self.token_access_type = token_access_type
        self.requests_session = pinned_session(ca_certs=ca_certs)
        self.scope = scope
        self.include_granted_scopes = include_granted_scopes
        self._timeout = timeout

        if use_pkce:
            self.code_verifier = _generate_pkce_code_verifier()
            self.code_challenge = _generate_pkce_code_challenge(self.code_verifier)
        else:
            self.code_verifier = None
            self.code_challenge = None

    def _get_authorize_url(self, redirect_uri, state, token_access_type=None, scope=None,
                           include_granted_scopes=None, code_challenge=None):
        pass

    def _finish(self, code, redirect_uri, code_verifier):
        pass

    def build_path(self, target, params=None):
        """Build the path component for an API URL.

        This method urlencodes the parameters, adds them to the end of the target url, and puts a
        marker for the API version in front.

        :param str target: A target url (e.g. '/files') to build upon.
        :param dict params: Optional dictionary of parameters (name to value).
        :return: The path and parameters components of an API URL.
        :rtype: str
        """
        pass

    def build_url(self, target, params=None, host=API_HOST):
        """Build an API URL.

        This method adds scheme and hostname to the path returned from build_path.

        :param str target: A target url (e.g. '/files') to build upon.
        :param dict params: Optional dictionary of parameters (name to value).
        :return: The full API URL.
        :rtype: str
        """
        pass


class DropboxOAuth2FlowNoRedirect(DropboxOAuth2FlowBase):
    """
    OAuth 2 authorization helper for apps that can't provide a redirect URI
    (such as the command-line example apps).

    See examples under `example/oauth <https://github.com/dropbox/dropbox-sdk-python/tree/main/
    example/oauth>`_

    """

    def __init__(self, consumer_key, consumer_secret=None, locale=None, token_access_type=None,
                 scope=None, include_granted_scopes=None, use_pkce=False, timeout=DEFAULT_TIMEOUT,
                 ca_certs=None):  # noqa: E501;
        """
        Construct an instance.

        :param str consumer_key: Your API app's "app key".
        :param str consumer_secret: Your API app's "app secret".
        :param str locale: The locale of the user of your application.  For example "en" or "en_US".
            Some API calls return localized data and error messages; this setting tells the server
            which locale to use. By default, the server uses "en_US".
        :param str token_access_type: the type of token to be requested.
            From the following enum:

            * None - creates a token with the app default (either legacy or online)
            * legacy - creates one long-lived token with no expiration
            * online - create one short-lived token with an expiration
            * offline - create one short-lived token with an expiration with a refresh token

        :param list scope: list of scopes to request in base oauth flow.
            If left blank, will default to all scopes for app.
        :param str include_granted_scopes: which scopes to include from previous grants.
            From the following enum:

            * user - include user scopes in the grant
            * team - include team scopes in the grant
            * *Note*: if this user has never linked the app, include_granted_scopes must be None

        :param bool use_pkce: Whether or not to use Sha256 based PKCE. PKCE should be only use on
            client apps which doesn't call your server. It is less secure than non-PKCE flow but
            can be used if you are unable to safely retrieve your app secret.
        :param Optional[float] timeout: Maximum duration in seconds that
            client will wait for any single packet from the server. After the timeout the client
            will give up on connection. If `None`, client will wait forever. Defaults
            to 100 seconds.
        :param str ca_cert: path to CA certificate. If left blank, default certificate location \
            will be used
        """
        super(DropboxOAuth2FlowNoRedirect, self).__init__(
            consumer_key=consumer_key,
            consumer_secret=consumer_secret,
            locale=locale,
            token_access_type=token_access_type,
            scope=scope,
            include_granted_scopes=include_granted_scopes,
            use_pkce=use_pkce,
            timeout=timeout,
            ca_certs=ca_certs
        )

    def start(self):
        """
        Starts the OAuth 2 authorization process.

        :return: The URL for a page on Dropbox's website.  This page will let the user "approve"
            your app, which gives your app permission to access the user's Dropbox account.
            Tell the user to visit this URL and approve your app.
        """
        pass

    def finish(self, code):
        """
        If the user approves your app, they will be presented with an "authorization code".
        Have the user copy/paste that authorization code into your app and then call this method to
        get an access token.

        :param str code: The authorization code shown to the user when they
            approved your app.
        :rtype: :class:`OAuth2FlowNoRedirectResult`
        :raises: The same exceptions as :meth:`DropboxOAuth2Flow.finish()`.
        """
        pass


class DropboxOAuth2Flow(DropboxOAuth2FlowBase):
    """
    OAuth 2 authorization helper. Use this for web apps.

    OAuth 2 has a two-step authorization process. The first step is having the user authorize your
    app. The second involves getting an OAuth 2 access token from Dropbox.

    See examples under `example/oauth <https://github.com/dropbox/dropbox-sdk-python/tree/main/
    example/oauth>`_

    """

    def __init__(self, consumer_key, redirect_uri, session,
                 csrf_token_session_key, consumer_secret=None, locale=None,
                 token_access_type=None, scope=None,
                 include_granted_scopes=None, use_pkce=False, timeout=DEFAULT_TIMEOUT,
                 ca_certs=None):
        """
        Construct an instance.

        :param str consumer_key: Your API app's "app key".
        :param str redirect_uri: The URI that the Dropbox server will redirect the user to after the
            user finishes authorizing your app.  This URI must be HTTPS-based and pre-registered
            with the Dropbox servers, though localhost URIs are allowed without pre-registration and
            can be either HTTP or HTTPS.
        :param dict session: A dict-like object that represents the current user's web session
            (Will be used to save the CSRF token).
        :param str csrf_token_session_key: The key to use when storing the CSRF token in the session
            (For example: "dropbox-auth-csrf-token").
        :param str consumer_secret: Your API app's "app secret".
        :param str locale: The locale of the user of your application. For example "en" or "en_US".
            Some API calls return localized data and error messages; this setting tells the server
            which locale to use. By default, the server uses "en_US".
        :param str token_access_type: The type of token to be requested.
            From the following enum:

            * None - creates a token with the app default (either legacy or online)
            * legacy - creates one long-lived token with no expiration
            * online - create one short-lived token with an expiration
            * offline - create one short-lived token with an expiration with a refresh token

        :param list scope: List of scopes to request in base oauth flow.  If left blank,
            will default to all scopes for app.
        :param str include_granted_scopes: Which scopes to include from previous grants.
            From the following enum:

            * user - include user scopes in the grant
            * team - include team scopes in the grant
            * *Note*: If this user has never linked the app, :attr:`include_granted_scopes` must \
            be `None`

        :param bool use_pkce: Whether or not to use Sha256 based PKCE
        :param Optional[float] timeout: Maximum duration in seconds that client will wait for any
            single packet from the server. After the timeout the client will give up on connection.
            If `None`, client will wait forever. Defaults to 100 seconds.
        :param str ca_cert: path to CA certificate. If left blank, default certificate location \
            will be used
        """

        super(DropboxOAuth2Flow, self).__init__(
            consumer_key=consumer_key,
            consumer_secret=consumer_secret,
            locale=locale,
            token_access_type=token_access_type,
            scope=scope,
            include_granted_scopes=include_granted_scopes,
            use_pkce=use_pkce,
            timeout=timeout,
            ca_certs=ca_certs
        )
        self.redirect_uri = redirect_uri
        self.session = session
        self.csrf_token_session_key = csrf_token_session_key

    def start(self, url_state=None):
        """
        Starts the OAuth 2 authorization process.

        This function builds an "authorization URL". You should redirect your user's browser to this
            URL, which will give them an opportunity to grant your app access to their Dropbox
            account. When the user completes this process, they will be automatically redirected to
            the :attr:`redirect_uri` you passed in to the constructor. This function will also save
            a CSRF token to :attr:`session[csrf_token_session_key]`
            (as provided to the constructor). This CSRF token will be checked on :meth:`finish()`
            to prevent request forgery.

        :param str url_state: Any data that you would like to keep in the URL through the
            authorization process. This exact value will be returned to you by :meth:`finish()`.
        :return: The URL for a page on Dropbox's website. This page will let the user "approve" your
            app, which gives your app permission to access the user's Dropbox account. Tell the user
            to visit this URL and approve your app.
        """
        pass

    def finish(self, query_params):
        """
        Call this after the user has visited the authorize URL (see :meth:`start()`), approved your
        app and was redirected to your redirect URI.

        :param dict query_params: The query parameters on the GET request to your redirect URI.
        :rtype: class:`OAuth2FlowResult`
        :raises: :class:`BadRequestException` If the redirect URL was missing parameters or if the
            given parameters were not valid.
        :raises: :class:`BadStateException` If there's no CSRF token in the session.
        :raises: :class:`CsrfException` If the :attr:`state` query parameter doesn't contain the
            CSRF token from the user's session.
        :raises: :class:`NotApprovedException` If the user chose not to approve your app.
        :raises: :class:`ProviderException` If Dropbox redirected to your redirect URI with some
            unexpected error identifier and error message.
        """
        pass


class BadRequestException(Exception):
    """
    Thrown if the redirect URL was missing parameters or if the given parameters were not valid.

    The recommended action is to show an HTTP 400 error page.
    """
    pass


class BadStateException(Exception):
    """
    Thrown if all the parameters are correct, but there's no CSRF token in the session. This
    probably means that the session expired.

    The recommended action is to redirect the user's browser to try the approval process again.
    """
    pass


class CsrfException(Exception):
    """
    Thrown if the given 'state' parameter doesn't contain the CSRF token from the user's session.
    This is blocked to prevent CSRF attacks.

    The recommended action is to respond with an HTTP 403 error page.
    """
    pass


class NotApprovedException(Exception):
    """
    The user chose not to approve your app.
    """
    pass


class ProviderException(Exception):
    """
    Dropbox redirected to your redirect URI with some unexpected error identifier and error message.

    The recommended action is to log the error, tell the user something went wrong, and let them try
    again.
    """
    pass


class BadInputException(Exception):
    """
    Thrown if incorrect types/values are used

    This should only ever be thrown during testing, app should have validation of input prior to
    reaching this point
    """
    pass


def _safe_equals(a, b):
    pass


def _params_to_urlencoded(params):
    """
    Returns a application/x-www-form-urlencoded :class:`str` representing the key/value pairs in
    :attr:`params`.

    Keys are values are ``str()``'d before calling :meth:`urllib.urlencode`, with the exception of
    unicode objects which are utf8-encoded.
    """
    def encode(o):
        pass

    pass

def _generate_pkce_code_verifier():
    pass

def _generate_pkce_code_challenge(code_verifier):
    pass
