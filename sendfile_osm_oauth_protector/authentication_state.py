import enum


class AuthenticationState(enum.Enum):
    NONE = 0
    LOGGED_IN = 1
    OAUTH_ACCESS_TOKEN_VALID = 2
    OAUTH_ACCESS_TOKEN_RECHECK = 4
    SIGNATURE_VERIFICATION_FAILED = 8
