# sendfile-osm-oauth-protector

This tool is designed as an drop-in replacement for websites whose content is
served as static files (not generated dynamically by a PHP, Node.JS, Python or whatever software)
by Apache and which should only be accessible to OpenStreetMap contributors.

This repository also contains a client program written in Python to retrieve
automate the authentication and OAuth authorization process to make it possible
to access the protected ressources without human interaction.

## Requirements

* Your website is a static website, nothing is generated dynamically.
* You use Apache to serve files.

## Documentation

* [how this tool works](doc/cookie.md) and its usage of cookies and their content
* [setup](doc/setup.md)
* [client documentation](doc/client.md) explaining the usage of protected ressources using scripts
* [cookie status API](doc/cookie_status_api.md)

## Example configuration for Geofabrik download

Open `oauth_cookie_client.py` and change the `default=` values for the settings:
```
parser.add_argument("-o", "--output", default="cookie.txt", .....
parser.add_argument("-u", "--user", default="OSMUsername", ....
parser.add_argument("-p", "--password", default="OSMPassword", ...
parser.add_argument("-s", "--settings", default=None, ...
parser.add_argument("-c", "--consumer-url", default="https://osm-internal.download.geofabrik.de/get_cookie", ....
parser.add_argument("-f", "--format", default="netscape", h...
parser.add_argument("--osm-host", default="https://www.openstreetmap.org/", ....
```
or provide it by command line option:

`python3 oauth_cookie_client.py --output cookie.txt --user OSMUsername --password OSMPassword --consumer-url https://osm-internal.download.geofabrik.de/get_cookie --format netscape --osm-host https://www.openstreetmap.org/`

Username and password are optional. You will be prompted for if one or both are not provide in the file or by the respective command line option.
The cookie will be stored in cookie.txt as defined in the `--output` and you can use it with `curl` or `wget` to download files with metadata as follows:

`curl -b ./cookie.txt https://osm-internal.download.geofabrik.de/europe/germany/baden-wuerttemberg/stuttgart-regbez.poly`

`wget --load-cookies ./cookie.txt --max-redirect 0 https://osm-internal.download.geofabrik.de/europe/germany/baden-wuerttemberg/stuttgart-regbez.poly`

## License

See [LICENSE.md](LICENSE.md)
