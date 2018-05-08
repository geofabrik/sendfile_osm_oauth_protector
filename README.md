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

## License

See [LICENSE.md](LICENSE.md)
