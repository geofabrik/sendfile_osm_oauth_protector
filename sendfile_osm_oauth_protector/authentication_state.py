import enum


class AuthenticationState(enum.Enum):
    SHOW_LANDING_PAGE = 0
    NONE = 1
    """Second visit by a client after they have granted the permission.
    """
    LOGGED_IN = 2
    """The access token is valid and access to the protected resource can be granted.
    """
    OAUTH_ACCESS_TOKEN_VALID = 4
    """The access token needs to be rechecked before access to the protected resource can be granted.
    """
    OAUTH_ACCESS_TOKEN_RECHECK = 8
    """The signature in the cookie could not be verified.
    """
    SIGNATURE_VERIFICATION_FAILED = 16
    OTHER_FAILURE = 32
