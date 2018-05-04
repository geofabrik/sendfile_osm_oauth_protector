# Setup

## Dependencies

* Install Python3 and some dependencies:

```sh
sudo apt install python3-cryptography python3-requests python3-requests-oauthlib python3-nacl python3-oauthlib python3-xdg python3-jinja2
```

* Install and enable `mod_wsgi` (Python 3) and `mod_sendfile`. On Debian and Ubuntu do

```sh
sudo apt install libapache2-mod-wsgi-py3 libapache2-mod-xsendfile
sudo a2enmod wsgi
sudo a2enmod xsendfile
```

* Clone this repository to `/srv/osm-internal-auth/`


## Configuration

* Create a key store and the keys by executing the following command. Select any key name you like. You will have to enter the name of the key and the location of the key store in the configuration (see next step).

```sh
/srv/osm-internal-auth/generate_nacl_keys.py firstCookieKey /var/lib/osm-internal-auth/keys/
```

* Configure it by coping `/srv/osm-internal-auth/sendfile_osm_oauth_protector/config.py.sample` to `/srv/osm-internal-auth/sendfile_osm_oauth_protector/config.py`
and editing it.

* Configure the virtual host to be protected with an OAuth login. 

```apache
# You must add the location where the repository has been cloned to the Python search path
WSGIPythonPath /srv/osm-internal-auth/

# use `<VirtualHost *:443` for SSL
<VirtualHost *:80>
    ServerName protected.example.com

    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/protected_website/

    # PyNaCl < 1.1.0 does not support multithreading and will throw
    # CryptoError("Could not initialize sodium") if the C function
    # sodium_init() is returns 1 because it has been called already.
    # That's why we configure two separate daemon processes, one for
    # all WSGI scripts which don't require PyNaCl, one for the other ones.
    WSGIDaemonProcess no_nacl python-path=/srv/osm-internal-auth/
    # You can increase processes but threads must be 1.
    WSGIDaemonProcess with_nacl processes=3 threads=1 python-path=/srv/osm-internal-auth/

    # You can replace the two WSGIDaemonProcess directives by one directive if
    # you have PyNaCl >= 1.1.0 and use multithreading instead of
    # multiprocessing:
    WSGIDaemonProcess processes=1 threads=3

    # location of the Python script with the WSGI entry points
    WSGIScriptAlias /logout/ /srv/osm-internal-auth/logout.py
    WSGIScriptAlias /show_cookie /srv/osm-internal-auth/show_cookie.py
    WSGIScriptAlias /get_cookie /srv/osm-internal-auth/get_cookie.py
    WSGIScriptAlias / /srv/osm-internal-auth/check_access.py

    # The following WSGIProcessGroup directives are only necessary with PyNaCl < 1.1.0:
    <Location /show_cookie>
        WSGIProcessGroup no_nacl
    </Location>
    <Location /get_cookie>
        WSGIProcessGroup with_nacl
    </Location>
    <Location /logout>
        WSGIProcessGroup no_nacl
    </Location>
    <Location />
        WSGIProcessGroup with_nacl
    </Location>
    WSGIApplicationGroup %{GLOBAL}

    # All following directives are always required (your PyNaCl version does not matter):
    <Directory /srv/osm-internal-auth/>
            Require all granted
    </Directory>

    # enable mod_xsendfile for this virtual host
    XSendFile On

    # Set search path.
    # All paths in the X-Sendfile header will be append to this path
    # This means if `X-Senfile: /subpage/index.html` is requested,
    # Apache will deliver `/var/www/protected_website/subpage/index.html`.
    XSendFilePath /var/www/protected_website/

    # grant read permissions for files in the document root
    <Location />
            Require all granted
    </Location>

    # insert SSL settings here (out of scope for this setup documentation)

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```

* Restart Apache using `sudo systemctl restart apache2`
