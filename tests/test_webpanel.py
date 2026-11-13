"""Smoke tests for web/webpanel.py against a fixture RAGNAR_DIR.

Starts the real server (plain HTTP - the fixture has no certs) on a
scratch port and drives it with urllib: login flow, dashboard, user
create/list over HTTP, and the Xray links page.
"""
import http.cookiejar
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
import urllib.error

ROOT = os.path.join(os.path.dirname(__file__), "..")
PORT = 18099
BASE_URL = f"http://127.0.0.1:{PORT}"


class WebPanelSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="ragnar-web-")
        env = dict(os.environ, RAGNAR_DIR=cls.tmp,
                   RAGNAR_WEB_PORT=str(PORT),
                   RAGNAR_HOST="203.0.113.7", RAGNAR_DOMAIN="example.com")
        # seed fixture users through the core itself
        seed = subprocess.run(
            [sys.executable, "-c", """
import sys; sys.path.insert(0, 'core')
import ragnar
ragnar.ssh_add('webuser', 'pw123456', 30, 0, 0)
ragnar.xray_add('xuser', 30, 0, 0)
"""], cwd=ROOT, env=env, capture_output=True, text=True)
        assert seed.returncode == 0, seed.stderr
        subprocess.run([sys.executable, os.path.join(ROOT, "web", "webpanel.py"),
                        "--set-password", "admin", "testpass123"],
                       env=env, capture_output=True, text=True, check=True)
        cls.proc = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "web", "webpanel.py")],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        for _ in range(50):
            try:
                urllib.request.urlopen(BASE_URL + "/login", timeout=1)
                break
            except Exception:
                time.sleep(0.2)
        else:
            raise RuntimeError("web panel did not start: "
                               + cls.proc.stdout.read())

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=5)

    def opener(self):
        cj = http.cookiejar.CookieJar()
        return urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj))

    def login(self, op):
        data = urllib.parse.urlencode(
            {"username": "admin", "password": "testpass123"}).encode()
        return op.open(BASE_URL + "/login", data=data)

    def test_login_flow_and_pages(self):
        import urllib.parse
        op = self.opener()
        # dashboard redirects to login when unauthenticated
        page = op.open(BASE_URL + "/login").read().decode()
        self.assertIn("RAGNAR", page)
        # wrong password rejected
        bad = urllib.parse.urlencode(
            {"username": "admin", "password": "nope"}).encode()
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            op.open(BASE_URL + "/login", data=bad)
        self.assertEqual(ctx.exception.code, 401)
        # right password -> dashboard
        self.login(op)
        dash = op.open(BASE_URL + "/").read().decode()
        self.assertIn("Dashboard", dash)
        self.assertIn("Bandwidth today", dash)
        # seeded users visible
        ssh_page = op.open(BASE_URL + "/ssh").read().decode()
        self.assertIn("webuser", ssh_page)
        # create a user over HTTP (needs the CSRF token from the form)
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', ssh_page).group(1)
        form = urllib.parse.urlencode(
            {"csrf": csrf, "op": "create", "user": "made-by-web",
             "password": "pw999999", "days": "15", "quota": "0",
             "iplimit": "0"}).encode()
        op.open(BASE_URL + "/ssh/action", data=form)
        ssh_page = op.open(BASE_URL + "/ssh").read().decode()
        self.assertIn("made-by-web", ssh_page)
        # xray links page carries real URIs
        links = op.open(BASE_URL + "/xray/links?u=xuser").read().decode()
        self.assertIn("vless://", links)
        self.assertIn("anytls://", links)


if __name__ == "__main__":
    unittest.main()
