# Setup

## Dependencies

* Install Python3 and some dependencies:

```sh
sudo apt install python3-cryptography python3-requests python3-requests-oauthlib python3-nacl
```

* Install and enable `mod_wsgi` and `mod_sendfile`. On Debian and Ubuntu do

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

    # location of the Python script with the WSGI entry point
    WSGIScriptAlias /logout/ /srv/osm-internal-auth/logout.py
    WSGIScriptAlias /show_cookie /srv/osm-internal-auth/show_cookie.py
    WSGIScriptAlias / /srv/osm-internal-auth/check_access.py

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
