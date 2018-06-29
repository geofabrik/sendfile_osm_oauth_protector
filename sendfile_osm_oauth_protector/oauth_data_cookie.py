import datetime
import base64
import urllib.parse
from http.cookies import SimpleCookie
import requests
from requests_oauthlib import OAuth1
import nacl.exceptions

from sendfile_osm_oauth_protector.data_cookie import DataCookie
from sendfile_osm_oauth_protector.authentication_state import AuthenticationState
from sendfile_osm_oauth_protector.key_manager import KeyManager
from sendfile_osm_oauth_protector.oauth_error import OAuthError
from sendfile_osm_oauth_protector.internal_error import InternalError


class OAuthDataCookie(DataCookie):
    def __init__(self, config, environ, key_manager=None):
        """
        Args:
            config (Config): configuration
            environ (Dictionary): contains CGI environment variables (see PEP 0333)
            key_manager (KeyManager): key store holding keys for encryption and signatures
        """
        super(OAuthDataCookie, self).__init__(config)
        self.read_cookie(environ)
        self.query_params = urllib.parse.parse_qs(environ["QUERY_STRING"])
        self.key_manager = key_manager
        if self.key_manager is not None:
            try:
                self.read_crypto_box = None
                self.write_crypto_box = self.key_manager.boxes[config.KEY_NAME]
                self.verify_key = None
                self.sign_key = self.key_manager.signing_keys[config.KEY_NAME]
            except KeyError as err:
                raise InternalError("key not found") from err
        self.access_token = ""
        self.access_token_secret = ""
        self.valid_until = datetime.datetime.utcnow() - datetime.timedelta(hours=config.AUTH_TIMEOUT)

    def _load_read_keys(self, key_name):
        """
        Fetch the keys for decrypting and verification of the cookie provided by the client.

        Args:
            key_name (str): name of the key to look up in the key manager
        """
        self.read_crypto_box = self.key_manager.boxes[key_name]
        self.verify_key = self.key_manager.verify_keys[key_name]

    def get_access_token_from_api(self):
        """
        Retriev an access_token and an access_token_secret from the OSM API
        using a temporary oauth_token and oauth_token_secret.

        The resulting tokens will be saved as properties of this class.

        Raises:
            OAuthError: if any OAuth related exception occured
        """
        try:
            oauth_token = self.query_params["oauth_token"][0]
            oauth_token_secret_encr = self.query_params["oauth_token_secret_encr"][0]
        except KeyError as err:
            raise OAuthError("oauth_token or oauth_token_secret_encr is missing.", "400 Bad Request") from err
        try:
            oauth_token_secret = self.write_crypto_box.decrypt(base64.urlsafe_b64decode(oauth_token_secret_encr))
        except Exception as err:
            raise OAuthError("decryption of tokens failed", "400 Bad Request") from err
        oauth = OAuth1(self.config.CLIENT_KEY, client_secret=self.config.CLIENT_SECRET, resource_owner_key=oauth_token,
                       resource_owner_secret=oauth_token_secret)
        r = requests.post(url=self.config.ACCESS_TOKEN_URL, auth=oauth)
        if r.status_code == 401:
            message = "The OSM API returned status \"401 Unauthorized\" when fetching an access token from the OSM API. You most probably declined any requested permissions for this application."
            if len(r.content) > 0:
                message += "\n------\n{}".format(r.content)
            raise OAuthError(message, "401 Unauthorized")
        if r.status_code != 200 or r.headers.get("Content-Type", "").split(";")[0].strip() != "text/plain":
            raise OAuthError("Error: Failed to retrieve access token\nstatus code: {}\ncontent-type: {}\nrepsonse: {}".format(r.status_code, r.headers.get("Content-Type", ""), r.text), "502 Bad Gateway")
        oauth_tokens = urllib.parse.parse_qs(r.text)
        try:
            self.access_token = oauth_tokens["oauth_token"][0]
            self.access_token_secret = oauth_tokens["oauth_token_secret"][0]
        except KeyError as err:
            raise OAuthError("Incomplete response of OSM API, oauth_token or oauth_token_secret is missing.", "502 Bad Gateway") from err

    def get_state(self):
        """
        Check if the signature of the cookie is valid, decrypt the cookie.

        Returns:
            AuthenticationState
        """
        ITERATION2_KEYS = {"oauth_token", "oauth_token_secret_encr"}
        is_redirected_from_osm = False
        if (ITERATION2_KEYS & set(iter(self.query_params))) == set(ITERATION2_KEYS):
            #return AuthenticationState.LOGGED_IN
            is_redirected_from_osm = True
        landing_page = self.query_params.get(self.config.LANDING_PAGE_URL_PARAM, ["false"])
        if self.cookie is None and landing_page[0] == "true":
            return AuthenticationState.NONE
        elif self.cookie is None and is_redirected_from_osm:
            return AuthenticationState.LOGGED_IN
        elif self.cookie is None:
            return AuthenticationState.SHOW_LANDING_PAGE
        try:
            contents = self.cookie[self.config.COOKIE_NAME].value.split("|")
            if len(contents) < 3 or contents[0] != "login":
                if is_redirected_from_osm:
                    return AuthenticationState.LOGGED_IN
                if landing_page[0] != "true":
                    return AuthenticationState.SHOW_LANDING_PAGE
                # landing page has been seen already
                return AuthenticationState.NONE
            key_name = contents[1]
            self._load_read_keys(key_name)
            signed = contents[2].encode("ascii")
            access_tokens_encr = self.verify_key.verify(base64.urlsafe_b64decode(signed))
        except nacl.exceptions.BadSignatureError:
            return AuthenticationState.SIGNATURE_VERIFICATION_FAILED
        except KeyError:
            # if something fails here, they normal authentication-authorization loop should start and
            # users not treated like not having seen the landing page
            return AuthenticationState.NONE
        try:
            parts = self.read_crypto_box.decrypt(access_tokens_encr).decode("ascii").split("|")
            self.access_token = parts[0]
            self.access_token_secret = parts[1]
            self.valid_until = datetime.datetime.strptime(parts[2], "%Y-%m-%dT%H:%M:%S")
        except Exception as err:
            raise OAuthError("decryption of tokens failed", "400 Bad Request") from err
        # If users sends us an old cookie but it is too old and has parameters like being redirected back to our site,
        # treat him like being redirected from OSM back to our site.
        if is_redirected_from_osm and datetime.datetime.utcnow() > self.valid_until:
            return AuthenticationState.LOGGED_IN
        if datetime.datetime.utcnow() > self.valid_until:
            return AuthenticationState.OAUTH_ACCESS_TOKEN_RECHECK
        return AuthenticationState.OAUTH_ACCESS_TOKEN_VALID

    def check_with_osm_api(self):
        """
        Initiate checking of the authorization and reset the validity of the
        cookie if the check passed.

        Returns:
            boolean: result of _check_with_osm_api()

        Raises:
            OAuthError: as raised by _check_with_osm_api()
        """
        if not self._check_with_osm_api():
            return False
        self.valid_until = datetime.datetime.utcnow() + datetime.timedelta(hours=self.config.AUTH_TIMEOUT)
        return True

    def _check_with_osm_api(self):
        """
        Recheck the authorization by requesting a protected resource from the OSM API.

        Returns:
            boolean: True if the source could be request, False if the request
                     failed (repsonse code other than 200)

        Raises:
            OAuthError: failed to get a connection to the OSM API or the API responded with code 500
        """
        oauth = OAuth1(self.config.CLIENT_KEY, client_secret=self.config.CLIENT_SECRET, resource_owner_key=self.access_token,
                       resource_owner_secret=self.access_token_secret)
        try:
            url = "{}user/details".format(self.config.API_URL_BASE)
            r = requests.get(url=url, auth=oauth)
        except ConnectionError as err:
            raise OAuthError("failed to (re)check the authorization", "502 Bad Gateway") from err
        if r.status_code == 200:
            return True
        if r.status_code == 500:
            raise OAuthError("received error 500 when (re)checking the authorization", "502 Bad Gateway")
        return False

    def output(self, output_format="http"):
        """
        Return an instance of http.cookies.SimpleCookie.

        See doc/cookie.md for a description of the contents of the cookie.

        This method concatenates the access token, access token secret and date
        when the next full check has to be done. This concatenated string is
        encrypted, signed and handed over to _output_cookie() whose result will
        be returned.
        """
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        valid_until = self.valid_until.strftime("%Y-%m-%dT%H:%M:%S")
        tokens = "{}|{}|{}".format(self.access_token, self.access_token_secret, valid_until)
        access_tokens_encr = self.write_crypto_box.encrypt(tokens.encode("ascii"), nonce)
        access_tokens_encr_signed = base64.urlsafe_b64encode(self.sign_key.sign(access_tokens_encr)).decode("ascii")
        if output_format == "http":
            return self._output_cookie_http(True, access_tokens_encr_signed)
        return self._output_cookie_netscape(True, access_tokens_encr_signed)
