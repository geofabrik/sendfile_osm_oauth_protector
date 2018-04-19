#! /usr/bin/env python3

import urllib.parse
import http.cookies

from sendfile_osm_oauth_protector.config import Config
from sendfile_osm_oauth_protector.data_cookie import DataCookie


config = Config()

def application(environ, start_response):
    query_params = urllib.parse.parse_qs(environ["QUERY_STRING"])
    path_info = environ["PATH_INFO"]
    oauth_cookie = DataCookie(config)
    status = "200 OK"
    response_headers = [("Set-Cookie", oauth_cookie.logout_cookie()),
                        ("content-type", "text/plain")]
    start_response(status, response_headers)
    return [b"goodbye"]
