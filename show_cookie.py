#! /usr/bin/env python3

import http.cookies

from sendfile_osm_oauth_protector.config import Config
from sendfile_osm_oauth_protector.data_cookie import DataCookie

import sys

config = Config()


def application(environ, start_response):
    oauth_cookie = DataCookie(config)
    oauth_cookie.read_cookie(environ)
    status = "200 OK"
    allowed_origin = "{}://{}".format(environ["wsgi.url_scheme"], config.HOSTNAME)
    response_headers = [("content-type", "text/plain"),
                        ("Access-Control-Allow-Origin", allowed_origin),
                        ("Access-Control-Allow-Credentials", "true")]
    if oauth_cookie.cookie is not None and config.COOKIE_NAME in oauth_cookie.cookie:
        response_headers.append(("Set-Cookie", oauth_cookie.cookie[config.COOKIE_NAME].OutputString()))
    data = b""
    if "HTTP_COOKIE" in environ:
        data = environ["HTTP_COOKIE"].encode("ascii")
    response_headers.append(("Content-Length", str(len(data))))
    start_response(status, response_headers)
    return [data]
