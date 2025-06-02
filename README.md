# sendfile-osm-oauth-protector

This tool is designed as an drop-in replacement for websites whose content is
served as static files (not generated dynamically by a PHP, Node.JS, Python or whatever software)
by Apache and which should only be accessible to OpenStreetMap contributors.

The OpenStreetMap contributor is asked to authorize read access to the user's
OpenStreetMap settings.  Sendfile-osm-oauth-protector will use the granted
access to verify that an OpenStreetMap contributor.  If the verification
succeeds, the contributor gets a cookie. The cookie contains the encrypted and
signed access token granted to Sendfile-osm-oauth-protector.

This repository also contains a client program written in Python to retrieve
automate the authentication and OAuth authorization process to make it possible
to access the protected ressources without human interaction.

## Requirements

### Client

The client requires Python 3 and the Requets library.

Debian/Ubuntu: `apt install python3 python3-requets`

Pip: `pip install requests`


### Server

This tool is suitable for statically served websites only using Apache.

Requirements:

* Apache
* mod_xsendfile
* mod_wsgi or any other WSGI server


## Documentation

### For users

This repository contains a [client programme written in Python](oauth_cookie_client.py) to retrieve cookies without user interaction. The [client documentation](doc/client.md) explains its usage.

There is a [cookie status API](doc/cookie_status_api.md) telling you whether your cookie is still valid. Depending on server settings, cookies are valid for a few hours only (default: 48 hours).

If you are interested how things work, have a look at the [desription](doc/cookie.md) what information the cookie contains.


### For admins

If you want to put a static website behind a OSM authentication, read the [setup documentation](doc/setup.md) and [how this tool works](doc/cookie.md).


## License

See [LICENSE.md](LICENSE.md)
