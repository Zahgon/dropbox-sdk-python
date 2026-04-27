__all__ = [
    'Dropbox',
    'DropboxTeam',
    'create_session',
]

# This should always be 0.0.0 in main. Only update this after tagging
# before release.
__version__ = '0.0.0'

import base64
import contextlib
import json
import logging
import random
import time

import requests
import six

from datetime import datetime, timedelta
from dropbox.auth import (
    AuthError_validator,
    RateLimitError_validator,
)
from dropbox import files
from dropbox.common import (
    PathRoot,
    PathRoot_validator,
    PathRootError_validator
)
from dropbox.base import DropboxBase
from dropbox.base_team import DropboxTeamBase
from dropbox.exceptions import (
    ApiError,
    AuthError,
    BadInputError,
    HttpError,
    PathRootError,
    InternalServerError,
    RateLimitError,
)
from dropbox.session import (
    API_HOST,
    API_CONTENT_HOST,
    API_NOTIFICATION_HOST,
    HOST_API,
    HOST_CONTENT,
    HOST_NOTIFY,
    pinned_session,
    DEFAULT_TIMEOUT
)
from stone.backends.python_rsrc import stone_serializers

PATH_ROOT_HEADER = 'Dropbox-API-Path-Root'
HTTP_STATUS_INVALID_PATH_ROOT = 422
TOKEN_EXPIRATION_BUFFER = 300

SELECT_ADMIN_HEADER = 'Dropbox-API-Select-Admin'

SELECT_USER_HEADER = 'Dropbox-API-Select-User'

USER_AUTH = 'user'
TEAM_AUTH = 'team'
APP_AUTH = 'app'
NO_AUTH = 'noauth'

class RouteResult(object):
    """The successful result of a call to a route."""

    def __init__(self, obj_result, http_resp=None):
        """
        :param str obj_result: The result of a route not including the binary
            payload portion, if one exists. Must be serialized JSON.
        :param requests.models.Response http_resp: A raw HTTP response. It will
            be used to stream the binary-body payload of the response.
        """
        assert isinstance(obj_result, six.string_types), \
            'obj_result: expected string, got %r' % type(obj_result)
        if http_resp is not None:
            assert isinstance(http_resp, requests.models.Response), \
                'http_resp: expected requests.models.Response, got %r' % \
                type(http_resp)
        self.obj_result = obj_result
        self.http_resp = http_resp

class RouteErrorResult(object):
    """The error result of a call to a route."""

    def __init__(self, request_id, obj_result):
        """
        :param str request_id: A request_id can be shared with Dropbox Support
            to pinpoint the exact request that returns an error.
        :param str obj_result: The result of a route not including the binary
            payload portion, if one exists.
        """
        self.request_id = request_id
        self.obj_result = obj_result

def create_session(max_connections=8, proxies=None, ca_certs=None):
    """
    Creates a session object that can be used by multiple :class:`Dropbox` and
    :class:`DropboxTeam` instances. This lets you share a connection pool
    amongst them, as well as proxy parameters.

    :param int max_connections: Maximum connection pool size.
    :param dict proxies: See the `requests module
            <http://docs.python-requests.org/en/latest/user/advanced/#proxies>`_
            for more details.
    :rtype: :class:`requests.sessions.Session`. `See the requests module
        <http://docs.python-requests.org/en/latest/user/advanced/#session-objects>`_
        for more details.
    """
    pass

class _DropboxTransport(object):
    """
    Responsible for implementing the wire protocol for making requests to the
    Dropbox API.
    """

    _API_VERSION = '2'

    # Download style means that the route argument goes in a Dropbox-API-Arg
    # header, and the result comes back in a Dropbox-API-Result header. The
    # HTTP response body contains a binary payload.
    _ROUTE_STYLE_DOWNLOAD = 'download'

    # Upload style means that the route argument goes in a Dropbox-API-Arg
    # header. The HTTP request body contains a binary payload. The result
    # comes back in a Dropbox-API-Result header.
    _ROUTE_STYLE_UPLOAD = 'upload'

    # RPC style means that the argument and result of a route are contained in
    # the HTTP body.
    _ROUTE_STYLE_RPC = 'rpc'

    def __init__(self,
                 oauth2_access_token=None,
                 max_retries_on_error=4,
                 max_retries_on_rate_limit=None,
                 user_agent=None,
                 session=None,
                 headers=None,
                 timeout=DEFAULT_TIMEOUT,
                 oauth2_refresh_token=None,
                 oauth2_access_token_expiration=None,
                 app_key=None,
                 app_secret=None,
                 scope=None,
                 ca_certs=None):
        """
        :param str oauth2_access_token: OAuth2 access token for making client
            requests.
        :param int max_retries_on_error: On 5xx errors, the number of times to
            retry.
        :param Optional[int] max_retries_on_rate_limit: On 429 errors, the
            number of times to retry. If `None`, always retries.
        :param str user_agent: The user agent to use when making requests. This
            helps us identify requests coming from your application. We
            recommend you use the format "AppName/Version". If set, we append
            "/OfficialDropboxPythonSDKv2/__version__" to the user_agent,
        :param session: If not provided, a new session (connection pool) is
            created. To share a session across multiple clients, use
            :func:`create_session`.
        :type session: :class:`requests.sessions.Session`
        :param dict headers: Additional headers to add to requests.
        :param Optional[float] timeout: Maximum duration in seconds that
            client will wait for any single packet from the
            server. After the timeout the client will give up on
            connection. If `None`, client will wait forever. Defaults
            to 100 seconds.
        :param str oauth2_refresh_token: OAuth2 refresh token for refreshing access token
        :param datetime oauth2_access_token_expiration: Expiration for oauth2_access_token
        :param str app_key: application key of requesting application; used for token refresh
        :param str app_secret: application secret of requesting application; used for token refresh
            Not required if PKCE was used to authorize the token
        :param list scope: list of scopes to request on refresh.  If left blank,
            refresh will request all available scopes for application
        :param str ca_certs: a path to a file of concatenated CA certificates in PEM format.
            Has the same meaning as when using :func:`ssl.wrap_socket`.
        """

        if not (oauth2_access_token or oauth2_refresh_token or (app_key and app_secret)):
            raise BadInputException(
                'OAuth2 access token or refresh token or app key/secret must be set'
            )

        if headers is not None and not isinstance(headers, dict):
            raise BadInputException('Expected dict, got {}'.format(headers))

        if oauth2_refresh_token and not app_key:
            raise BadInputException("app_key is required to refresh tokens")

        if scope is not None and (len(scope) == 0 or not isinstance(scope, list)):
            raise BadInputException("Scope list must be of type list")

        self._oauth2_access_token = oauth2_access_token
        self._oauth2_refresh_token = oauth2_refresh_token
        self._oauth2_access_token_expiration = oauth2_access_token_expiration

        self._app_key = app_key
        self._app_secret = app_secret
        self._scope = scope

        self._max_retries_on_error = max_retries_on_error
        self._max_retries_on_rate_limit = max_retries_on_rate_limit
        if session:
            if not isinstance(session, requests.sessions.Session):
                raise BadInputException('Expected requests.sessions.Session, got {}'
                                        .format(session))
            self._session = session
        else:
            self._session = create_session(ca_certs=ca_certs)
        self._headers = headers

        base_user_agent = 'OfficialDropboxPythonSDKv2/' + __version__
        if user_agent:
            self._raw_user_agent = user_agent
            self._user_agent = '{}/{}'.format(user_agent, base_user_agent)
        else:
            self._raw_user_agent = None
            self._user_agent = base_user_agent

        self._logger = logging.getLogger('dropbox')

        self._host_map = {HOST_API: API_HOST,
                          HOST_CONTENT: API_CONTENT_HOST,
                          HOST_NOTIFY: API_NOTIFICATION_HOST}

        self._timeout = timeout

    def clone(
            self,
            oauth2_access_token=None,
            max_retries_on_error=None,
            max_retries_on_rate_limit=None,
            user_agent=None,
            session=None,
            headers=None,
            timeout=None,
            oauth2_refresh_token=None,
            oauth2_access_token_expiration=None,
            app_key=None,
            app_secret=None,
            scope=None):
        """
        Creates a new copy of the Dropbox client with the same defaults unless modified by
        arguments to clone()

        See constructor for original parameter descriptions.

        :return: New instance of Dropbox client
        :rtype: Dropbox
        """
        pass

    def request(self,
                route,
                namespace,
                request_arg,
                request_binary,
                timeout=None):
        """
        Makes a request to the Dropbox API and in the process validates that
        the route argument and result are the expected data types. The
        request_arg is converted to JSON based on the arg_data_type. Likewise,
        the response is deserialized from JSON and converted to an object based
        on the {result,error}_data_type.

        :param host: The Dropbox API host to connect to.
        :param route: The route to make the request to.
        :type route: :class:`stone.backends.python_rsrc.stone_base.Route`
        :param request_arg: Argument for the route that conforms to the
            validator specified by route.arg_type.
        :param request_binary: String or file pointer representing the binary
            payload. Use None if there is no binary payload.
        :param Optional[float] timeout: Maximum duration in seconds
            that client will wait for any single packet from the
            server. After the timeout the client will give up on
            connection. If `None`, will use default timeout set on
            Dropbox object.  Defaults to `None`.
        :return: The route's result.
        """
        pass

    def check_and_refresh_access_token(self):
        """
        Checks if access token needs to be refreshed and refreshes if possible
        :return:
        """
        pass

    def refresh_access_token(self, host=API_HOST, scope=None):
        """
        Refreshes an access token via refresh token if available

        :param host: host to hit token endpoint with
        :param scope: list of permission scopes for access token
        :return:
        """
        pass

    def request_json_object(self,
                            host,
                            route_name,
                            route_style,
                            request_arg,
                            auth_type,
                            request_binary,
                            timeout=None):
        """
        Makes a request to the Dropbox API, taking a JSON-serializable Python
        object as an argument, and returning one as a response.

        :param host: The Dropbox API host to connect to.
        :param route_name: The name of the route to invoke.
        :param route_style: The style of the route.
        :param str request_arg: A JSON-serializable Python object representing
            the argument for the route.
        :param auth_type str
        :param Optional[bytes] request_binary: Bytes representing the binary
            payload. Use None if there is no binary payload.
        :param Optional[float] timeout: Maximum duration in seconds
            that client will wait for any single packet from the
            server. After the timeout the client will give up on
            connection. If `None`, will use default timeout set on
            Dropbox object.  Defaults to `None`.
        :return: The route's result as a JSON-serializable Python object.
        """
        pass

    def request_json_string_with_retry(self,
                                       host,
                                       route_name,
                                       route_style,
                                       request_json_arg,
                                       auth_type,
                                       request_binary,
                                       timeout=None):
        """
        See :meth:`request_json_object` for description of parameters.

        :param request_json_arg: A string representing the serialized JSON
            argument to the route.
        """
        pass

    def request_json_string(self,
                            host,
                            func_name,
                            route_style,
                            request_json_arg,
                            auth_type,
                            request_binary,
                            timeout=None):
        """
        See :meth:`request_json_string_with_retry` for description of
        parameters.
        """
        pass

    def raise_dropbox_error_for_resp(self, res):
        """Checks for errors from a res and handles appropiately.

        :param res: Response of an api request.
        """
        pass

    def _get_route_url(self, hostname, route_name):
        """Returns the URL of the route.

        :param str hostname: Hostname to make the request to.
        :param str route_name: Name of the route.
        :rtype: str
        """
        pass

    def _save_body_to_file(self, download_path, http_resp, chunksize=2**16):
        """
        Saves the body of an HTTP response to a file.

        :param str download_path: Local path to save data to.
        :param http_resp: The HTTP response whose body will be saved.
        :type http_resp: :class:`requests.models.Response`
        :rtype: None
        """
        pass

    def with_path_root(self, path_root):
        """
        Creates a clone of the Dropbox instance with the Dropbox-API-Path-Root header
        as the appropriate serialized instance of PathRoot.

        For more information, see
        https://www.dropbox.com/developers/reference/namespace-guide#pathrootmodes

        :param PathRoot path_root: instance of PathRoot to serialize into the headers field
        :return: A :class: `Dropbox`
        :rtype: Dropbox
        """
        pass

    def close(self):
        """
        Cleans up all resources like the request session/network connection.
        """
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class Dropbox(_DropboxTransport, DropboxBase):
    """
    Use this class to make requests to the Dropbox API using a user's access
    token. Methods of this class are meant to act on the corresponding user's
    Dropbox.
    """
    pass

class DropboxTeam(_DropboxTransport, DropboxTeamBase):
    """
    Use this class to make requests to the Dropbox API using a team's access
    token. Methods of this class are meant to act on the team, but there is
    also an :meth:`as_user` method for assuming a team member's identity.
    """
    def as_admin(self, team_member_id):
        """
        Allows a team credential to assume the identity of an administrator on the team
        and perform operations on any team-owned content.

        :param str team_member_id: team member id of administrator to perform actions with
        :return: A :class:`Dropbox` object that can be used to query on behalf
            of this admin of the team.
        :rtype: Dropbox
        """
        pass

    def as_user(self, team_member_id):
        """
        Allows a team credential to assume the identity of a member of the
        team.

        :param str team_member_id: team member id of team member to perform actions with
        :return: A :class:`Dropbox` object that can be used to query on behalf
            of this member of the team.
        :rtype: Dropbox
        """
        pass

    def _get_dropbox_client_with_select_header(self, select_header_name, team_member_id):
        """
        Get Dropbox client with modified headers

        :param str select_header_name: Header name used to select users
        :param str team_member_id: team member id of team member to perform actions with
        :return: A :class:`Dropbox` object that can be used to query on behalf
            of a member or admin of the team
        :rtype: Dropbox
        """
        pass

class BadInputException(Exception):
    """
    Thrown if incorrect types/values are used

    This should only ever be thrown during testing, app should have validation of input prior to
    reaching this point
    """
    pass
