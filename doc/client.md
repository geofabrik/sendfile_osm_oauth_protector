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
`https://PROTECTED_WEBSITE/get_cookie?action=get_access_token_cookie` to
retrieve the cookie to be used.

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
* If the server responds with HTTP status code 302 and redirects you to
  `www.openstreetmap.org/authorize`, your cookie is not valid any more. You
  have to re-run this program to retrieve a new one and try your request again.

If you use *wget* to download files, add `--load-cookies /path/to/cookie_file
--max-redirect 0` to your invokation of wget. `--max-redirects 0` disable
following redirects and wget will return a non-successfull exit code as an
indicator that you should retrieve a new cookie.

If you use *curl* to download files, add `--cookie $(cat /path/to/cookie_file)`
to your invokation of wget and remove `-L` (short option of `--location`) to
ignore redirects.
