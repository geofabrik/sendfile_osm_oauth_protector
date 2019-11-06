#! /usr/bin/env python3

import argparse
import sys
import nacl.exceptions
from sendfile_osm_oauth_protector.config import Config
from sendfile_osm_oauth_protector.key_manager import KeyManager
from sendfile_osm_oauth_protector.oauth_data_cookie import OAuthDataCookie
from sendfile_osm_oauth_protector.oauth_error import OAuthError


def print_cookie_content(content):
    sys.stdout.write("Cookie content:\n")
    for i in range(0, len(contents)):
        field = ""
        if i == 0:
            field = "state"
        elif i == 1:
            field = "key_name"
        elif i == 2:
            field = "signed_content"
        sys.stdout.write("  {}: {}\n".format(field, contents[i]))


def print_tokens(cookie):
    sys.stdout.write("Decrypted cookie content:\n")
    sys.stdout.write("  access_token: {}\n".format(cookie.access_token))
    sys.stdout.write("  access_token_secret: {}\n".format(cookie.access_token_secret))
    sys.stdout.write("  valid_until: {}\n".format(cookie.valid_until))


parser = argparse.ArgumentParser(description="Read a cookie from standard input, decrypt its content and write to standard output. This program is intended to run on the server by an administrator for debugging purposes.")
args = parser.parse_args()

config = Config()
key_manager = KeyManager(config.KEY_DIR)

cookie_raw = sys.stdin.readline()

environ = {"HTTP_COOKIE": cookie_raw, "QUERY_STRING": ""}
data_cookie = OAuthDataCookie(config, environ, key_manager)

contents = data_cookie.parse_cookie_step1()

print_cookie_content(contents)
if len(contents) == 1:
    sys.stdout.write("WARNING: The cookie could not be verified because it is invalid or set to 'logout'.\n")
    exit(0)
if len(contents) != 3:
    sys.stdout.write("ERROR: The cookie has an unusual length.\n")
    exit(1)

try:
    access_tokens_encr = data_cookie.parse_cookie_step2(contents)
except nacl.exceptions.BadSignatureError:
    sys.stdout.write("RESULT: Verification of signature failed.\n")
    exit(0)
except KeyError:
    sys.stdout.write("ERROR: Key error during verification of signature. Maybe loading the key failed.\n")
    exit(1)
except Exception:
    sys.stdout.write("ERROR: Other error during verification of signature.\n")
    exit(1)

sys.stdout.write("INFO: Signed content has a valid signature.\n")

try:
    data_cookie.parse_cookie_step3(access_tokens_encr)
except OAuthError as err:
    sys.stdout.write("ERROR: {}\n".format(err))
print_tokens(data_cookie)
