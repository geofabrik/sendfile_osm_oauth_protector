import datetime
from http.cookies import SimpleCookie

COOKIE_DATE_FORMAT = "%a, %d %b %Y %H:%M:%S GMT"


class DataCookie:
    def __init__(self, config):
        """
        Args:
            config (Config): configuration
        """
        self.config = config

    def _get_expiry_date(self, delta):
        """
        Return the expiry date based on current time.

        Args:
            delta (int): delta in hours

        Returns:
            datetime.datetime
        """
        return datetime.datetime.utcnow() + datetime.timedelta(hours=delta)

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
            cookie[self.config.COOKIE_NAME]["expires"] = (self._get_expiry_date(self.config.AUTH_TIMEOUT)).strftime(COOKIE_DATE_FORMAT)
        else:
            cookie[self.config.COOKIE_NAME] = "logout||"
            # set expiry in the past to get this cookie delete immediately
            cookie[self.config.COOKIE_NAME]["expires"] = (self._get_expiry_date(-2)).strftime(COOKIE_DATE_FORMAT)
        cookie[self.config.COOKIE_NAME]["httponly"] = True
        if self.config.COOKIE_SECURE:
            cookie[self.config.COOKIE_NAME]["secure"] = True
        return cookie

    def _output_cookie_http(self, logged_in, encrypted_signed_tokens=None):
        return self._output_cookie(logged_in, encrypted_signed_tokens)[self.config.COOKIE_NAME].OutputString()

    def _output_cookie_netscape(self, logged_in, encrypted_signed_tokens=None):
        c = self._output_cookie(logged_in, encrypted_signed_tokens)
        values = [self.config.HOSTNAME, "TRUE", c[self.config.COOKIE_NAME]["path"], str(c[self.config.COOKIE_NAME]["secure"]).upper()]
        exp = str(int(datetime.datetime.strptime(c[self.config.COOKIE_NAME]["expires"], COOKIE_DATE_FORMAT).timestamp()))
        val = c[self.config.COOKIE_NAME].value
        values.extend([exp, self.config.COOKIE_NAME, val])
        net_str = "." + "\t".join(values)
        return net_str

    def logout_cookie(self):
        """
        Return a cookie for a logged out user.

        Returns:
            http.cookies.SimpleCookie: the cookie
        """
        return self._output_cookie_http(False)

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
