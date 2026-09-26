"""Review Set-Cookie headers for missing or weak security attributes."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field

HEADER_RE = re.compile(r"^\s*set-cookie\s*:\s*(.+)$", re.IGNORECASE)

# Cookie names that usually carry a session or credential.
SENSITIVE_NAME = re.compile(r"(sess|auth|token|jwt|sid|login|remember|csrf|xsrf)", re.IGNORECASE)

ONE_DAY = 86_400
LONG_LIVED = 30 * ONE_DAY


@dataclass
class Cookie:
    name: str
    value: str
    attrs: dict[str, str] = field(default_factory=dict)

    @property
    def sensitive(self) -> bool:
        return bool(SENSITIVE_NAME.search(self.name)) or self.name.startswith(("__Host-", "__Secure-"))


@dataclass
class Warning:
    severity: str  # "high", "medium" or "low"
    message: str


def parse_set_cookie(header: str) -> Cookie | None:
    """Parse the value of a Set-Cookie header (without the header name)."""
    parts = [p.strip() for p in header.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name, value = parts[0].split("=", 1)
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        if not part:
            continue
        key, _, val = part.partition("=")
        attrs[key.strip().lower()] = val.strip()
    return Cookie(name.strip(), value.strip(), attrs)


def analyze(cookie: Cookie) -> list[Warning]:
    a = cookie.attrs
    high_if_sensitive = "high" if cookie.sensitive else "medium"
    out: list[Warning] = []

    if "secure" not in a:
        out.append(Warning(high_if_sensitive, "missing Secure: cookie is sent over plain HTTP"))
    if "httponly" not in a and cookie.sensitive:
        out.append(Warning("high", "missing HttpOnly: readable from JavaScript, so XSS can steal it"))
    elif "httponly" not in a:
        out.append(Warning("low", "missing HttpOnly"))

    samesite = a.get("samesite", "").lower()
    if not samesite:
        out.append(Warning("low", "missing SameSite: relies on the browser default (Lax in most browsers)"))
    elif samesite not in {"lax", "strict", "none"}:
        out.append(Warning("medium", f"invalid SameSite value {a['samesite']!r}"))
    elif samesite == "none":
        if "secure" not in a:
            out.append(Warning("high", "SameSite=None without Secure is rejected by modern browsers"))
        elif cookie.sensitive:
            out.append(Warning("medium", "SameSite=None sends this cookie on cross-site requests (CSRF exposure)"))

    if "domain" in a:
        out.append(Warning("low", f"Domain={a['domain']} shares the cookie with every subdomain"))

    if cookie.name.startswith("__Secure-") and "secure" not in a:
        out.append(Warning("high", "__Secure- prefix requires the Secure attribute"))
    if cookie.name.startswith("__Host-"):
        if "secure" not in a or "domain" in a or a.get("path") != "/":
            out.append(Warning("high", "__Host- prefix requires Secure, Path=/ and no Domain"))

    max_age = a.get("max-age", "")
    try:
        max_age_seconds = int(max_age)
    except ValueError:
        max_age_seconds = None
    if cookie.sensitive and max_age_seconds is not None and max_age_seconds > LONG_LIVED:
        out.append(Warning("low", f"long-lived credential (Max-Age {max_age_seconds // ONE_DAY} days)"))

    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Review Set-Cookie headers for security gaps.")
    parser.add_argument("--input", "-i", required=True, help="file with Set-Cookie headers, one per line")
    args = parser.parse_args(argv)

    try:
        with open(args.input, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        print(f"error: cannot read {args.input}: {exc}", file=sys.stderr)
        return 2

    total = flagged = high = 0
    for number, line in enumerate(lines, start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = HEADER_RE.match(line)
        cookie = parse_set_cookie(match.group(1) if match else line)
        if cookie is None:
            print(f"line {number}: skipped, not a Set-Cookie header", file=sys.stderr)
            continue

        total += 1
        warnings = sorted(analyze(cookie), key=lambda w: ["high", "medium", "low"].index(w.severity))
        if not warnings:
            print(f"{cookie.name}: ok")
            continue
        flagged += 1
        high += sum(w.severity == "high" for w in warnings)
        print(f"{cookie.name}:")
        for w in warnings:
            print(f"  [{w.severity.upper():<6}] {w.message}")

    print(f"\n{total} cookie(s) analyzed, {flagged} with warnings, {high} high-severity issue(s)")
    return 1 if high else 0


if __name__ == "__main__":
    raise SystemExit(main())
