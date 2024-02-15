# Usage of cookies

This application uses cookies to store OAuth access tokens and access token secrets without
a persistent storage or session management on server side.

## Structure of the cookie

The cookies consists of three parts separated by a `|` character.

```
<login status>|<key name>|<encrypted and signed tokens>
```

*login status* is either the string `login` or `logout`. If logout is set, any other part may be empty and further parsing can be skipped. However, logout cookies must contain all three parts but the second and third part may be empty.

*key name* is the name of the key being used to encrypt and sign the tokens. This part is necessary because the service provide might want to change keys in future but wants to be able to read and verify old cookies.

*encrypted and signed tokens* is a concatenation of the access token, access token secret and the date when the authorization of these tokens has to be rechecked. These tokens are encrypted using the [PyNaCl](https://pynacl.readthedocs.io/en/stable/#) module (`nacl.public` for encryption, `nacl.signing` for the signature).


## Structure of the encrypted and signed content of the cookie

If you decrypt the encrypted message, you will get another string consisting of three parts which are separated by `|` characters:


```
<access token>|oauth2|<valid until>
```

*access token* is the OAuth 2 access token used to request a protected resource from the OSM API.
An usal OAuth 2 implementation would store this token on the server in some kind of session management database. However, we don't run any session managment and implement the OAuth authorization procedure as stateless as possible. That's why we use the client's cookie to store everything which has to be stored.

`oauth2` is a hardcoded keyword. When we used OAuth1, this part was used for the "access token secret". However, that does not exist in OAuth2. In order to avoid changing the cookie syntax, we just replaced it by a hard-coded string.

*valid_until* is the date when the authorization will be checked by requesting a protected resource from the OSM API. The date uses following format: `%Y-%m-%d:%H:%M:%S`

The application will perform a check only in a certain interval. This is a compromise between performance and security. On the one hand, it is possible to use revoked access tokens for a certain time but it will fail when the next check is done. On the other hand, the application can (currently not implemented) suspend the check for a certain time if the OSM API is not accessible (e.g. down or responding with code 500 or similar).

If the such a check is done, valid_until will be set to the date and time when the next check is necessary. This date will be signed (and encrypted) and attackers have to break the digital signature to circumvent a recheck. 

**It is recommended to disable the checking and force users to request a new access token.** Otherwise cookies published by users who want to "circumvent" the authentication "chicane" can be used until their owner revokes the access token which probably never happens. Forcing re-authentication in a certain interval, limits the usage such published cookies work until the nex authentication and authorization is necessary.


## Logout

Users can delete the cookie by calling `/logout` which sets a cookie which has the content `logout||`. Any later requests to any resource other than `/logout` will be redirected to the authorization form of openstreetmap.org.
