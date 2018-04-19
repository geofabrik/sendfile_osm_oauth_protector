#! /usr/bin/env python3

import http.cookies

from sendfile_osm_oauth_protector.config import Config
from sendfile_osm_oauth_protector.data_cookie import DataCookie


config = Config()


def application(environ, start_response):
    oauth_cookie = DataCookie(config)
    oauth_cookie.read_cookie(environ)
    status = "200 OK"
    response_headers = [("Set-Cookie", oauth_cookie.cookie[config.COOKIE_NAME].OutputString()),
                        ("content-type", "text/plain")]
    start_response(status, response_headers)
    return [environ["HTTP_COOKIE"].encode("ascii")]
