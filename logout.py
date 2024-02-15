#! /usr/bin/env python3

from sendfile_osm_oauth_protector.config import Config
from sendfile_osm_oauth_protector.data_cookie import DataCookie


config = Config()


def application(environ, start_response):
    oauth_cookie = DataCookie(config)
    status = "200 OK"
    response_headers = [("Set-Cookie", oauth_cookie.logout_cookie()),
                        ("content-type", "text/plain")]
    start_response(status, response_headers)
    return [b"goodbye"]
