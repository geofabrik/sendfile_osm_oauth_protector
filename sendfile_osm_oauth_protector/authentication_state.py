import enum


class AuthenticationState(enum.Enum):
    SHOW_LANDING_PAGE = 0
    NONE = 1
    LOGGED_IN = 2
    OAUTH_ACCESS_TOKEN_VALID = 4
    OAUTH_ACCESS_TOKEN_RECHECK = 8
    SIGNATURE_VERIFICATION_FAILED = 16
