import datetime
from http.cookies import SimpleCookie


class DataCookie:
    def __init__(self, config):
        """
        Args:
            config (Config): configuration
        """
        self.config = config

    def _output_cookie(self, logged_in, encrypted_signed_tokens=None):
        """
        Return an instance of http.cookies.SimpleCookie.

        See doc/cookie.md for a description of the contents of the cookie.

        Args:
            logged_in (boolean): if the user is logged in (successfully
                                 authenticated)
            encrypted_signed_tokens (str): encrypted and signed concatenation
                                           of the access token, access token
                                           secret and date of the next full
                                           verification

        Returns:
            http.cookies.SimpleCookie: the cookie
        """
        cookie = SimpleCookie()
        if logged_in:
            cookie[self.config.COOKIE_NAME] = "login|{}|{}".format(self.config.KEY_NAME, encrypted_signed_tokens)
            cookie[self.config.COOKIE_NAME]["Expires"] = (datetime.datetime.utcnow() + datetime.timedelta(hours=self.config.AUTH_TIMEOUT)).strftime("%a, %d %b %Y %H:%M:%S GMT")
        else:
            cookie[self.config.COOKIE_NAME] = "logout||"
            # set expiry in the past to get this cookie delete immediately
            cookie[self.config.COOKIE_NAME]["Expires"] = (datetime.datetime.utcnow() - datetime.timedelta(hours=2)).strftime("%a, %d %b %Y %H:%M:%S GMT")
        cookie[self.config.COOKIE_NAME]["httponly"] = True
        if self.config.COOKIE_SECURE:
            cookie[self.config.COOKIE_NAME]["secure"] = True
        return cookie[self.config.COOKIE_NAME].OutputString()

    def logout_cookie(self):
        """
        Return a cookie for a logged out user.

        Returns:
            http.cookies.SimpleCookie: the cookie
        """
        return self._output_cookie(False)

    def read_cookie(self, environ):
        """
        Read cookies from the enviroment variables.

        Args:
            environ (Dictionary): contains CGI environment variables (see PEP 0333)

        Returns:
            http.cookies.SimpleCookie: successfully read cookie, None otherwise
        """
        self.cookie = None
        if "HTTP_COOKIE" in environ:
            cookie = SimpleCookie(environ["HTTP_COOKIE"])
            if self.config.COOKIE_NAME in cookie:
                self.cookie = cookie
