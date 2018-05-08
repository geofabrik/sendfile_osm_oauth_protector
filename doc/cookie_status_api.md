# Cookie Status API

The cookie status API helps users who access the server using programs and
scripts to check if their cookie is still valid.

Request URL: `/cookie_status`


## Requirements

* Cookie must be sent as normal cookie, e.g. using `curl -b <COOKIE>`


## Response

The API returns some JSON and uses HTTP status codes to indicate the result.
You can decide what you prefer to use.

```json
{
  "cookie_status": "expired",
  "http_status_code": "401 Unauthorized",
  "description": "Your cookie is expired or invalid."
}
```

The JSON payload contains following properties. `cookie_status` and `description`
have the same meaning.

* `cookie_status`: short status description
* `description`: explanation for humans
* `http_status_code`: the HTTP status code
* `expires`: date of expiry of the cookie, the format is `%Y-%m-%dT%H:%M:%SZ`,
  e.g. `2018-05-08T13:51:12Z`. This property is `null` if it is not applyable
  (e.g. no cookie provided, errors).

Values of `cookie_status` (associated HTTP status code in braces):

* `valid`: Your cookie is valid. (200)
* `expired`: Your cookie expired, you have to retrieve a new one. (401)
* `no_cookie_provided`: You did not provide a cookie. (400)
* `cookie_verification_failed`: Your cookie was encrypted and signed with a
  different key (in most cases on a different server). (400)
* `access_token_use_failed`: This code is returned by servers which recheck
  your OSM authorization when the cookies expires instead of forcing you to
  retrieve a new cookie. This code is returned if you revoked the access token on
  osm.org or if your account was deleted. It might be returned for blocked user
  accounts, too. (403)
* `unknown`: unknown error, all checks failed. Your cookie is invalid. (400)
