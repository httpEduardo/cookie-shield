# Cookie Shield

Cookie Shield reviews `Set-Cookie` headers and flags weak security attributes.

## Quick start

```bash
python cookie_shield.py --input cookies.txt
```

## What it checks

- Missing `Secure` or `HttpOnly`.
- Missing or lax `SameSite` values.
- Cookies scoped to parent domains.

## Output

Each cookie is listed with warnings and a summary at the end.
