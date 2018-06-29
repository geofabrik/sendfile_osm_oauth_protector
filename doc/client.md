# OSM OAuth Protector Cookie Client

This Python tool makes automated downloading of files from a website which
protected by *sendfile_osm_oauth_protector* easier. It only works if the
admistrator of the server permits automated access by providing an API for
automated OAuth authentication and authorization. This API is implemented in
[get_cookie.py](../get_cookie.py) in this repository.


## What does this tool?

This tool requests an temporary OAuth request token by sending a POST request
to `https://PROTECTED_WEBSITE/get_cookie?action=request_token` (The API itself
retrieves that token from OSM).  Using that token, the program scrapes the
login and OAuth authorization forms of openstreetmap.org. It is a
reimplementation of the [automatic OAuth authorization procedure of
JOSM](https://josm.openstreetmap.de/browser/josm/trunk/src/org/openstreetmap/josm/gui/oauth/OsmOAuthAuthorizationClient.java).
After filling out the login and authorization forms, the program sends a second
POST request to
`https://PROTECTED_WEBSITE/get_cookie?action=get_access_token_cookie&format=http` to
retrieve the cookie to be used. The parameter `format` determines the output
format. Possible values are `http` for the value of the HTTP `Set-Cookie`
header or `netscape` for the content of a Netscape cookie jar file.

Your OpenStreetMap username and password has to be saved in plain text on the
machine which runs this program!


## Usage

You can retrieve a cookie using this tool with following command. The cookie
will be written to `cookie_output_file.txt`.

```sh
python3 oauth_cookie_client.py -o cookie_output_file.txt -s settings.json
```

`settings.json` is a JSON file to store the settings if you don't want them
include in your command line invokation:

```json
{
  "user": "my_osm_username",
  "password": "very_secret_and_difficult",
  "osm_host": "https://www.openstreetmap.org",
  "consumer_url": "https://osm-internal.download.geofabrik.de/get_cookie"
}
```


## Which changes are necessary to your existing toolchain?

* You must provide a valid cookie for each request.
* You can check if your cookie is valid using the
  [cookie status API](cookie_status_api.md).  If this API tells you that your
  cookie expired, you have to re-run this program to retrieve a new one and try
  your request again.

If you use *wget* to download files, add `--load-cookies /path/to/cookie_file
--max-redirect 0` to your invokation of wget. `--max-redirects 0` disable
following redirects and wget will return a non-successfull exit code as an
indicator that you should retrieve a new cookie.

If you use *curl* to download files, add `--cookie $(cat /path/to/cookie_file)`
to your invokation of wget and remove `-L` (short option of `--location`) to
ignore redirects.

Example:

```sh
curl -b 'gf_download_oauth="login|2018-04-12|OuXe89NBSnaI57CZvxdha575IsKkO3xUO5wr4JsLm9imk7oHi6Kqx69RbfgCYmNvNX4BacDUOfFKgmD2ixdFDDd9Csh82t6WIf8pv1C3EWVtuLMxqdpeoxrZurgO6QEdUzTtR97GmIWdbiYBw4aBmhKQJRzD1TEl0-AlrEylTnmh-9ge0KvzVCHVwv3_U_2Ya-if5mm-g_-mmLr_EOHM1SHclvtysF6f2V2G8UrJ8N8kgyXAtt38NzZxNJ0490JMJu_Byb1EJs9yB_izRg=="' https://osm-internal.download.geofabrik.de/seychelles-latest-internal.osm.pbf
```
