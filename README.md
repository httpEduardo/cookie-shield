# cookie-shield

Reviews `Set-Cookie` headers and points out missing or weak security attributes, with severity adjusted to how sensitive each cookie looks.

Session cookies are the keys to a user's account. A single missing attribute can let them leak over plain HTTP, be read by injected JavaScript, or ride along on cross-site requests. cookie-shield takes headers copied from browser dev tools, `curl -I`, or a proxy log and tells you which ones need fixing.

## Checks

- **Secure** missing — the cookie can be sent over unencrypted HTTP
- **HttpOnly** missing — JavaScript (and therefore XSS) can read it
- **SameSite** missing, invalid, or `None` without `Secure`; `None` on a sensitive cookie is called out as a CSRF exposure
- **Domain** set — the cookie is shared with every subdomain (a leading dot makes no difference in modern browsers)
- **Cookie prefixes** — `__Secure-` and `__Host-` cookies that break the rules those prefixes require
- **Long-lived credentials** — sensitive cookies kept for more than 30 days

Cookies whose name suggests a session or credential (`session`, `auth`, `token`, `jwt`, `sid`, `remember`, …) get higher severities, since a missing flag matters much more there than on a theme preference.

## Usage

Requires Python 3.9+, no dependencies.

```bash
python cookie_shield.py --input cookies.txt
```

```text
session_id: ok
auth:
  [HIGH  ] missing Secure: cookie is sent over plain HTTP
  [LOW   ] missing SameSite: relies on the browser default (Lax in most browsers)
pref:
  [LOW   ] missing HttpOnly
  [LOW   ] Domain=.example.com shares the cookie with every subdomain
...
6 cookie(s) analyzed, 5 with warnings, 2 high-severity issue(s)
```

The input has one header per line. The `Set-Cookie:` prefix is optional, and blank lines or `#` comments are ignored.

Exit codes: `0` no high-severity issues, `1` at least one, `2` the file couldn't be read.

## Tests

```bash
python -m unittest
```

## License

[MIT](LICENSE)
