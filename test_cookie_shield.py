import unittest

from cookie_shield import analyze, parse_set_cookie


def messages(header):
    return [w.message for w in analyze(parse_set_cookie(header))]


def severities(header):
    return {w.severity for w in analyze(parse_set_cookie(header))}


class CookieTests(unittest.TestCase):
    def test_hardened_session_cookie(self):
        self.assertEqual(messages("session_id=1; Path=/; HttpOnly; Secure; SameSite=Lax"), [])

    def test_sensitive_cookie_without_flags_is_high(self):
        self.assertIn("high", severities("auth=x; Path=/"))

    def test_non_sensitive_cookie_is_lower_severity(self):
        self.assertNotIn("high", severities("theme=dark; Path=/"))

    def test_samesite_none_needs_secure(self):
        self.assertTrue(any("rejected" in m for m in messages("a=1; SameSite=None")))

    def test_host_prefix_rules(self):
        self.assertTrue(any("__Host-" in m for m in messages("__Host-id=1; Secure; Path=/app")))
        self.assertEqual(messages("__Host-id=1; Secure; HttpOnly; Path=/; SameSite=Strict"), [])

    def test_any_domain_attribute_widens_scope(self):
        self.assertTrue(any("subdomain" in m for m in messages("a=1; Domain=example.com; Secure; HttpOnly; SameSite=Lax")))

    def test_values_may_contain_equals(self):
        self.assertEqual(parse_set_cookie("jwt=a.b=c; Secure").value, "a.b=c")

    def test_invalid_header(self):
        self.assertIsNone(parse_set_cookie("no equals sign here"))


if __name__ == "__main__":
    unittest.main()
