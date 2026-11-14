import unittest
from datetime import datetime, timedelta, timezone
from headercheck import analyze_headers, analyze_cert

ALL = {
    "Strict-Transport-Security": "max-age=63072000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

class TestHeaders(unittest.TestCase):
    def test_full_set_grades_a(self):
        score, grade, _ = analyze_headers(ALL)
        self.assertEqual(grade, "A")
        self.assertGreaterEqual(score, 90)

    def test_empty_grades_f(self):
        score, grade, findings = analyze_headers({})
        self.assertEqual(grade, "F")
        self.assertTrue(all(f["status"] == "missing" for f in findings))

    def test_case_insensitive(self):
        score, _, _ = analyze_headers({"STRICT-TRANSPORT-SECURITY": "max-age=1"})
        self.assertGreater(score, 0)

    def test_cookie_flags(self):
        h = dict(ALL)
        h["Set-Cookie"] = "sid=abc"
        _, _, f = analyze_headers(h)
        cookie = [x for x in f if x["header"] == "set-cookie"][0]
        self.assertEqual(cookie["status"], "weak")
        h["Set-Cookie"] = "sid=abc; Secure; HttpOnly; SameSite=Lax"
        _, _, f2 = analyze_headers(h)
        self.assertEqual([x for x in f2 if x["header"] == "set-cookie"][0]["status"], "present")

class TestCert(unittest.TestCase):
    NOW = datetime(2026, 11, 14, tzinfo=timezone.utc)

    def test_valid_cert(self):
        future = (self.NOW + timedelta(days=200)).strftime("%b %d %H:%M:%S %Y GMT")
        out = analyze_cert(future, "TLSv1.3", now=self.NOW)
        self.assertTrue(all(o["status"] == "ok" for o in out))

    def test_expired(self):
        past = (self.NOW - timedelta(days=3)).strftime("%b %d %H:%M:%S %Y GMT")
        out = analyze_cert(past, "TLSv1.3", now=self.NOW)
        self.assertTrue(any(o["status"] == "bad" and "EXPIRED" in o["detail"] for o in out))

    def test_old_tls(self):
        future = (self.NOW + timedelta(days=200)).strftime("%b %d %H:%M:%S %Y GMT")
        out = analyze_cert(future, "TLSv1.1", now=self.NOW)
        self.assertTrue(any("old protocol" in o["detail"] for o in out))

    def test_expiring_soon_warns(self):
        soon = (self.NOW + timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")
        out = analyze_cert(soon, "TLSv1.2", now=self.NOW)
        self.assertTrue(any(o["status"] == "warn" for o in out))

if __name__ == "__main__":
    unittest.main()
