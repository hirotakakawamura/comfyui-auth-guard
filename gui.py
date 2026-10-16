"""Cookie-session GUI login for comfyui-auth-guard (stdlib only)."""
import base64
import hashlib
import hmac
import html
import logging
import secrets
import threading
import time
from urllib.parse import urlsplit, quote

from aiohttp import web

log = logging.getLogger("comfyui-auth-guard")

COOKIE = "comfy_auth_session"
LOGIN_PATH = "/auth/login"
LOGOUT_PATH = "/auth/logout"
UNSAFE_METHODS = {"POST", "PUT", "DELETE", "PATCH"}
GUI_PREFIXES = ("/assets/", "/extensions/", "/templates/", "/fonts/", "/docs/", "/scripts/", "/lib/")
GUI_EXT = (".html", ".js", ".mjs", ".css", ".map", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".webmanifest")


# ---------------------------------------------------------------- password hash
def make_hash(password: str, n=2 ** 15, r=8, p=1) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, maxmem=128 * 1024 * 1024, dklen=32)
    e = lambda b: base64.b64encode(b).decode()
    return f"scrypt${n}${r}${p}${e(salt)}${e(dk)}"


def parse_hash(s: str):
    parts = s.split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        raise ValueError("format")
    n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
    if n < 2 ** 14 or n & (n - 1) or r < 1 or p < 1:
        raise ValueError("params too weak")
    salt, dk = base64.b64decode(parts[4]), base64.b64decode(parts[5])
    if len(salt) < 16 or len(dk) < 16:
        raise ValueError("salt/hash too short")
    return n, r, p, salt, dk


def verify_password(password: str, parsed) -> bool:
    n, r, p, salt, dk = parsed
    got = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, maxmem=256 * 1024 * 1024, dklen=len(dk))
    return hmac.compare_digest(got, dk)


# ---------------------------------------------------------------- helpers
def is_gui_path(path: str) -> bool:
    if path.startswith("/api/"):
        return False
    return path in ("/", "/index.html") or path.startswith(GUI_PREFIXES) or path.lower().endswith(GUI_EXT)


def safe_next(nxt) -> str:
    """Only same-site relative paths: '/x', not '//x', '/\\x', 'http:', control chars."""
    if not nxt or not isinstance(nxt, str) or len(nxt) > 2000:
        return "/"
    if not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt:
        return "/"
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in nxt):
        return "/"
    sp = urlsplit(nxt)
    if sp.scheme or sp.netloc:
        return "/"
    if sp.path.startswith((LOGIN_PATH, LOGOUT_PATH)):
        return "/"
    return nxt


def is_https(request) -> bool:
    return request.secure or request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower() == "https"


def origin_ok(request, allowed: set) -> bool:
    o = request.headers.get("Origin")
    if not o or o == "null":
        ref = request.headers.get("Referer")
        if not ref:
            return False
        sp = urlsplit(ref)
        o = f"{sp.scheme}://{sp.netloc}"
    o = o.rstrip("/").lower()
    host = request.headers.get("Host", "").lower()
    own = {f"http://{host}", f"https://{host}"} if host else set()
    return o in own or o in allowed


def client_ip(request, trust_cf: bool) -> str:
    if trust_cf and request.headers.get("CF-Connecting-IP"):
        return request.headers["CF-Connecting-IP"].strip()
    return request.remote or "?"


# ---------------------------------------------------------------- rate limiting
class LoginLimiter:
    """Per-IP: after `free` failures, lockout doubles (2,4,8.. s, max `max_lock`).
    Global: more than `global_max` failures within `window` s -> all logins locked for `window` s."""
    def __init__(self, free=5, max_lock=900, global_max=50, window=60, max_ips=10000):
        self.free, self.max_lock, self.global_max, self.window, self.max_ips = free, max_lock, global_max, window, max_ips
        self.ips = {}           # ip -> [fails, locked_until, last]
        self.glob = []          # timestamps
        self.glob_lock_until = 0
        self.lock = threading.Lock()

    def retry_after(self, ip):
        now = time.time()
        with self.lock:
            if now < self.glob_lock_until:
                return int(self.glob_lock_until - now) + 1
            e = self.ips.get(ip)
            if e and now < e[1]:
                return int(e[1] - now) + 1
        return 0

    def fail(self, ip):
        now = time.time()
        with self.lock:
            if len(self.ips) >= self.max_ips:
                for k in [k for k, v in self.ips.items() if now - v[2] > self.max_lock and now > v[1]]:
                    del self.ips[k]
                if len(self.ips) >= self.max_ips:          # still full: global lock (fail closed)
                    self.glob_lock_until = now + self.window
            e = self.ips.setdefault(ip, [0, 0, now])
            e[0] += 1; e[2] = now
            if e[0] > self.free:
                e[1] = now + min(self.max_lock, 2 ** (e[0] - self.free))
            self.glob = [t for t in self.glob if now - t < self.window] + [now]
            if len(self.glob) > self.global_max:
                self.glob_lock_until = now + self.window

    def success(self, ip):
        with self.lock:
            self.ips.pop(ip, None)


# ---------------------------------------------------------------- sessions
class Sessions:
    def __init__(self, secret: bytes, ttl: int, max_sessions=1000):
        self.secret, self.ttl, self.max = secret, ttl, max_sessions
        self.store = {}         # sid -> exp
        self.lock = threading.Lock()

    def _sig(self, payload: str) -> str:
        return base64.urlsafe_b64encode(hmac.new(self.secret, payload.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()

    def create(self):
        now = int(time.time())
        sid = secrets.token_urlsafe(24)
        exp = now + self.ttl
        with self.lock:
            for k in [k for k, e in self.store.items() if e < now]:
                del self.store[k]
            if len(self.store) >= self.max:
                return None
            self.store[sid] = exp
        payload = f"{sid}.{now}.{exp}"
        return sid, f"{payload}.{self._sig(payload)}"

    def validate(self, value):
        if not value or value.count(".") != 3:
            return None
        sid, iat, exp, sig = value.split(".")
        if not hmac.compare_digest(sig, self._sig(f"{sid}.{iat}.{exp}")):
            return None
        try:
            if int(exp) < time.time():
                return None
        except ValueError:
            return None
        with self.lock:
            e = self.store.get(sid)
        if e is None or e < time.time() or str(e) != exp:
            return None
        return sid

    def revoke(self, sid):
        with self.lock:
            self.store.pop(sid, None)


LOGIN_HTML = """<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ComfyUI login</title>
<style>body{{font-family:sans-serif;display:flex;justify-content:center;margin-top:15vh}}
form{{display:flex;flex-direction:column;gap:.6em;width:16em}}.e{{color:#c00}}</style></head>
<body><form method="post" action="/auth/login"><h2>ComfyUI</h2>{msg}
<input type="hidden" name="next" value="{next}">
<input type="password" name="password" placeholder="Password" autocomplete="current-password" required autofocus>
<button type="submit">Login</button></form></body></html>"""


def login_page(nxt="/", msg="", status=200):
    m = f'<p class="e">{html.escape(msg)}</p>' if msg else ""
    return web.Response(text=LOGIN_HTML.format(msg=m, next=html.escape(safe_next(nxt), quote=True)),
                        content_type="text/html", status=status,
                        headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY",
                                 "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
                                 "Referrer-Policy": "same-origin"})


def redirect_to_login(request):
    nxt = safe_next(request.path_qs)
    return web.Response(status=302, headers={"Location": f"{LOGIN_PATH}?next={quote(nxt, safe='')}",
                                             "Cache-Control": "no-store"})
