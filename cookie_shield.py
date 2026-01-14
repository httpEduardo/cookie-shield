import argparse
import re
import sys

COOKIE_RE = re.compile(r"^set-cookie:\s*(.+)$", re.IGNORECASE)


def parse_cookie(line: str) -> dict[str, str]:
    parts = [part.strip() for part in line.split(";") if part.strip()]
    attrs = {}
    if parts:
        name_value = parts[0]
        attrs["name"] = name_value.split("=")[0]
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            attrs[key.lower()] = value
        else:
            attrs[part.lower()] = "true"
    return attrs


def analyze_cookie(attrs: dict[str, str]) -> list[str]:
    warnings = []
    if "secure" not in attrs:
        warnings.append("missing Secure")
    if "httponly" not in attrs:
        warnings.append("missing HttpOnly")
    samesite = attrs.get("samesite", "").lower()
    if not samesite:
        warnings.append("missing SameSite")
    elif samesite not in {"lax", "strict", "none"}:
        warnings.append(f"unexpected SameSite={attrs.get('samesite')}")
    if samesite == "none" and "secure" not in attrs:
        warnings.append("SameSite=None without Secure")
    if "domain" in attrs and attrs["domain"].startswith("."):
        warnings.append("scoped to parent domain")
    return warnings


def main() -> int:
    parser = argparse.ArgumentParser(description="Review Set-Cookie headers for security gaps.")
    parser.add_argument("--input", required=True, help="File with Set-Cookie headers")
    args = parser.parse_args()

    try:
        with open(args.input, "r", encoding="utf-8") as handle:
            lines = [line.strip() for line in handle if line.strip()]
    except OSError as exc:
        print(f"Failed to read {args.input}: {exc}", file=sys.stderr)
        return 1

    total = 0
    warn_count = 0
    for line in lines:
        match = COOKIE_RE.match(line)
        if not match:
            continue
        total += 1
        attrs = parse_cookie(match.group(1))
        warnings = analyze_cookie(attrs)
        name = attrs.get("name", "unknown")
        if warnings:
            warn_count += 1
            print(f"{name}: {', '.join(warnings)}")
        else:
            print(f"{name}: ok")

    print(f"\nCookies analyzed: {total}")
    print(f"Cookies with warnings: {warn_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
