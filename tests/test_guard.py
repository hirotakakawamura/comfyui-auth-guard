import json, os, sys, time, threading, http.server, pathlib
import pytest, jwt
from aiohttp import web, WSMsgType
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from auth_guard import load_config, install

TOKEN = "t" * 40
AUD = "test-aud-123"
TEAM = "myteam"
ISS = "https://myteam.cloudflareaccess.com"

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_jwk = json.loads(RSAAlgorithm.to_jwk(KEY.public_key())); _jwk.update(kid="k1", alg="RS256", use="sig")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser
ED = Ed25519PrivateKey.generate(); ED2 = Ed25519PrivateKey.generate()
PUB = ED.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo).decode()
JENV = {"COMFY_AUTH_PUBKEY": PUB, "COMFY_AUTH_JWT_AUD": "comfyui"}
JWKS = json.dumps({"keys": [_jwk]}).encode()


@pytest.fixture(scope="module")
def jwks_url():
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(JWKS)
        def log_message(self, *a): pass
    s = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{s.server_port}/cdn-cgi/access/certs"
    s.shutdown()


def mkjwt(key=KEY, aud=AUD, iss=ISS, exp_in=300):
    now = int(time.time())
    return jwt.encode({"aud": [aud], "iss": iss, "iat": now, "exp": now + exp_in, "email": "a@example.com",
                       "sub": "u1"}, key, algorithm="RS256", headers={"kid": "k1"})


def make_app(env):
    """Minimal app mimicking PromptServer: middlewares list given at construction, routes added later."""
    async def stats(r): return web.json_response({"ok": True, "user": r.get("auth_user")})
    async def ws(r):
        w = web.WebSocketResponse(); await w.prepare(r); await w.send_str("hello"); await w.close(); return w
    app = web.Application(middlewares=[])
    install(app, load_config(env))
    app.router.add_get("/system_stats", stats)
    app.router.add_get("/api/system_stats", stats)
    app.router.add_get("/ws", ws)
    return app


async def test_token_mode(aiohttp_client):
    c = await aiohttp_client(make_app({"COMFY_AUTH_TOKEN": TOKEN}))
    assert (await c.get("/system_stats")).status == 401
    assert (await c.get("/system_stats", headers={"Authorization": "Bearer wrong"})).status == 401
    assert (await c.get("/system_stats", headers={"Authorization": "Bearer " + TOKEN})).status == 200
    assert (await c.get("/api/system_stats", headers={"X-ComfyUI-Token": TOKEN})).status == 200
    r = await c.get("/system_stats"); assert (await r.json()) == {"error": "unauthorized"}
    assert (await c.get("/system_stats?token=" + TOKEN)).status == 401


async def test_ws(aiohttp_client):
    c0 = await aiohttp_client(make_app({"COMFY_AUTH_TOKEN": TOKEN}))  # ?token= off by default
    with pytest.raises(Exception):
        await c0.ws_connect("/ws?token=" + TOKEN)
    c = await aiohttp_client(make_app({"COMFY_AUTH_TOKEN": TOKEN, "COMFY_AUTH_ALLOW_QUERY_TOKEN": "1"}))
    with pytest.raises(Exception):
        await c.ws_connect("/ws")
    with pytest.raises(Exception):
        await c.ws_connect("/ws?token=wrong")
    for kw in ({"path": "/ws", "headers": {"Authorization": "Bearer " + TOKEN}}, {"path": "/ws?token=" + TOKEN}):
        w = await c.ws_connect(kw.pop("path"), **kw)
        m = await w.receive(); assert m.type == WSMsgType.TEXT and m.data == "hello"; await w.close()


async def test_fail_closed(aiohttp_client):
    for env in ({}, {"COMFY_AUTH_TOKEN": "short"}, {"COMFY_AUTH_CF_TEAM": TEAM},
                {"COMFY_AUTH_PUBKEY": PUB}, {"COMFY_AUTH_PUBKEY": "garbage", "COMFY_AUTH_JWT_AUD": "x"},
                {"COMFY_AUTH_PUBKEY_PATH": "/nonexistent.pem", "COMFY_AUTH_JWT_AUD": "x"},
                {"COMFY_AUTH_TOKEN": TOKEN, "COMFY_AUTH_MODE": "jwt"}):
        c = await aiohttp_client(make_app(env))
        assert (await c.get("/system_stats", headers={"Authorization": "Bearer short"})).status == 503


async def test_disabled_and_allowlist(aiohttp_client):
    c = await aiohttp_client(make_app({"COMFY_AUTH_DISABLED": "1"}))
    assert (await c.get("/system_stats")).status == 200
    c = await aiohttp_client(make_app({"COMFY_AUTH_TOKEN": TOKEN, "COMFY_AUTH_ALLOWLIST": "/system_stats"}))
    assert (await c.get("/system_stats")).status == 200
    assert (await c.get("/api/system_stats")).status == 401


async def test_cf_jwt(aiohttp_client, jwks_url):
    env = {"COMFY_AUTH_CF_TEAM": TEAM, "COMFY_AUTH_CF_AUD": AUD, "COMFY_AUTH_CF_JWKS_URL": jwks_url}
    c = await aiohttp_client(make_app(env))
    H = "Cf-Access-Jwt-Assertion"
    assert (await c.get("/system_stats")).status == 401
    r = await c.get("/system_stats", headers={H: mkjwt()}); assert r.status == 200
    assert (await r.json())["user"] == "cf:a@example.com"
    for bad in (mkjwt(key=OTHER), mkjwt(aud="other"), mkjwt(iss="https://evil.cloudflareaccess.com"),
                mkjwt(exp_in=-120), "garbage"):
        assert (await c.get("/system_stats", headers={H: bad})).status == 401
    w = await c.ws_connect("/ws", headers={H: mkjwt()}); await w.close()


async def test_all_mode(aiohttp_client, jwks_url):
    env = {"COMFY_AUTH_TOKEN": TOKEN, "COMFY_AUTH_CF_TEAM": TEAM, "COMFY_AUTH_CF_AUD": AUD,
           "COMFY_AUTH_CF_JWKS_URL": jwks_url}
    c = await aiohttp_client(make_app(env))  # auto -> all
    B = {"Authorization": "Bearer " + TOKEN}
    assert (await c.get("/system_stats", headers=B)).status == 401
    assert (await c.get("/system_stats", headers={"Cf-Access-Jwt-Assertion": mkjwt()})).status == 401
    assert (await c.get("/system_stats", headers={**B, "Cf-Access-Jwt-Assertion": mkjwt()})).status == 200
    c = await aiohttp_client(make_app({**env, "COMFY_AUTH_MODE": "any"}))
    assert (await c.get("/system_stats", headers=B)).status == 200


def test_no_secret_in_logs(caplog):
    import logging; caplog.set_level(logging.DEBUG)
    install(web.Application(), load_config({"COMFY_AUTH_TOKEN": TOKEN}))
    install(web.Application(), load_config({"COMFY_AUTH_TOKEN": "s3cretshort"}))
    assert TOKEN not in caplog.text and "s3cretshort" not in caplog.text


import base64, uuid
def ed(key=ED, aud="comfyui", ttl=60, iat_off=0, jti=None, alg="EdDSA", **extra):
    now = int(time.time()) + iat_off
    c = {"aud": aud, "sub": "alice", "iat": now, "exp": now + ttl, "jti": jti or uuid.uuid4().hex, **extra}
    return jwt.encode(c, key, algorithm=alg)

def B(t): return {"Authorization": "Bearer " + t}

def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


async def test_ed25519_jwt(aiohttp_client):
    c = await aiohttp_client(make_app(JENV))
    assert (await c.get("/system_stats")).status == 401
    assert (await c.get("/system_stats", headers=B(ed(scope="generate")))).status == 200      # valid
    assert (await c.get("/system_stats", headers={"X-ComfyUI-JWT": ed()})).status == 200
    assert (await c.get("/system_stats", headers=B(ed(iat_off=-400, ttl=60)))).status == 401  # expired
    assert (await c.get("/system_stats", headers=B(ed(ttl=301)))).status == 401              # ttl too long
    assert (await c.get("/system_stats", headers=B(ed(key=ED2)))).status == 401              # wrong key
    assert (await c.get("/system_stats", headers=B(ed(aud="other")))).status == 401          # wrong aud
    assert (await c.get("/system_stats", headers=B(ed(iat_off=120)))).status == 401          # future iat
    # alg confusion: HS256 signed with the public key PEM as HMAC secret, and alg=none
    now = int(time.time()); cl = {"aud": "comfyui", "iat": now, "exp": now + 60, "jti": "x1"}
    import hmac as h, hashlib
    hdr = b64({"alg": "HS256", "typ": "JWT"}) + "." + b64(cl)
    sig = base64.urlsafe_b64encode(h.new(PUB.encode(), hdr.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    assert (await c.get("/system_stats", headers=B(hdr + "." + sig))).status == 401
    assert (await c.get("/system_stats", headers=B(b64({"alg": "none"}) + "." + b64({**cl, "jti": "x2"}) + "."))).status == 401
    assert (await c.get("/system_stats", headers=B(jwt.encode({**cl, "jti": ""}, ED, algorithm="EdDSA")))).status == 401
    # missing jti
    nojti = jwt.encode({"aud": "comfyui", "iat": now, "exp": now + 60}, ED, algorithm="EdDSA")
    assert (await c.get("/system_stats", headers=B(nojti))).status == 401


async def test_iss_required(aiohttp_client):
    c = await aiohttp_client(make_app({**JENV, "COMFY_AUTH_JWT_ISS": "webapp"}))
    assert (await c.get("/system_stats", headers=B(ed()))).status == 401
    assert (await c.get("/system_stats", headers=B(ed(iss="evil")))).status == 401
    assert (await c.get("/system_stats", headers=B(ed(iss="webapp")))).status == 200


async def test_replay_and_store_full(aiohttp_client):
    c = await aiohttp_client(make_app(JENV))
    t = ed()
    assert (await c.get("/system_stats", headers=B(t))).status == 200
    assert (await c.get("/system_stats", headers=B(t))).status == 401        # replay
    c = await aiohttp_client(make_app({**JENV, "COMFY_AUTH_JTI_MAX": "2"}))
    assert (await c.get("/system_stats", headers=B(ed()))).status == 200
    assert (await c.get("/system_stats", headers=B(ed()))).status == 200
    assert (await c.get("/system_stats", headers=B(ed()))).status == 401     # full -> fail closed


async def test_ws_ticket(aiohttp_client):
    import auth_guard
    c = await aiohttp_client(make_app(JENV))
    assert (await c.post("/auth/ws-ticket")).status == 401                   # needs auth
    assert (await c.get("/auth/ws-ticket", headers=B(ed()))).status == 405
    r = await c.post("/auth/ws-ticket", headers=B(ed())); assert r.status == 200
    t = (await r.json())["ticket"]
    assert (await c.get("/system_stats?ticket=" + t)).status == 401           # not for plain HTTP
    w = await c.ws_connect("/ws?ticket=" + t); m = await w.receive(); assert m.data == "hello"; await w.close()
    with pytest.raises(Exception):
        await c.ws_connect("/ws?ticket=" + t)                                 # single use
    with pytest.raises(Exception):
        await c.ws_connect("/ws?ticket=bogus")
    with pytest.raises(Exception):
        await c.ws_connect("/ws")                                             # no ticket, no auth
    r = await c.post("/auth/ws-ticket", headers=B(ed())); t2 = (await r.json())["ticket"]
    real = time.time
    try:
        auth_guard.time.time = lambda: real() + 31                            # expiry
        with pytest.raises(Exception):
            await c.ws_connect("/ws?ticket=" + t2)
    finally:
        auth_guard.time.time = real


async def test_ws_ticket_subject_binding(aiohttp_client, jwks_url):
    env = {"COMFY_AUTH_CF_TEAM": TEAM, "COMFY_AUTH_CF_AUD": AUD, "COMFY_AUTH_CF_JWKS_URL": jwks_url}
    c = await aiohttp_client(make_app(env))
    H = "Cf-Access-Jwt-Assertion"
    t = (await (await c.post("/auth/ws-ticket", headers={H: mkjwt()})).json())["ticket"]
    other = jwt.encode({"aud": [AUD], "iss": ISS, "iat": int(time.time()), "exp": int(time.time()) + 60,
                        "email": "b@example.com"}, KEY, algorithm="RS256", headers={"kid": "k1"})
    with pytest.raises(Exception):
        await c.ws_connect("/ws?ticket=" + t, headers={H: other})
    t = (await (await c.post("/auth/ws-ticket", headers={H: mkjwt()})).json())["ticket"]
    w = await c.ws_connect("/ws?ticket=" + t, headers={H: mkjwt()}); await w.close()


async def test_token_plus_jwt_all(aiohttp_client):
    c = await aiohttp_client(make_app({**JENV, "COMFY_AUTH_TOKEN": TOKEN}))   # auto -> all
    assert (await c.get("/system_stats", headers=B(ed()))).status == 401
    assert (await c.get("/system_stats", headers={"X-ComfyUI-Token": TOKEN})).status == 401
    assert (await c.get("/system_stats", headers={"X-ComfyUI-Token": TOKEN, **B(ed())})).status == 200


def test_issue_token_tool(tmp_path):
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
    import issue_token
    issue_token.keygen(str(tmp_path))
    assert oct((tmp_path / "private.pem").stat().st_mode & 0o777) == "0o600"
    t = issue_token.issue(str(tmp_path / "private.pem"), "comfyui", "bob", 60, "generate")
    c = jwt.decode(t, (tmp_path / "public.pem").read_text(), algorithms=["EdDSA"], audience="comfyui")
    assert c["sub"] == "bob" and c["scope"] == "generate" and jwt.get_unverified_header(t)["alg"] == "EdDSA"


def test_no_secret_in_logs_jwt(caplog):
    import logging; caplog.set_level(logging.DEBUG)
    install(web.Application(), load_config({"COMFY_AUTH_PUBKEY": "garbage-secretish", "COMFY_AUTH_JWT_AUD": "a"}))
    assert "garbage-secretish" not in caplog.text


# ======================= GUI cookie login =======================
import gui as G
PW = "correct horse battery"
HASH = G.make_hash(PW, n=2 ** 14)
GENV = {**JENV, "COMFY_AUTH_GUI": "login", "COMFY_AUTH_GUI_PASSWORD_HASH": HASH}


def make_gui_app(env):
    app = make_app(env)
    async def root(r): return web.Response(text="<html>gui</html>", content_type="text/html")
    async def prompt(r): return web.json_response({"queued": True})
    app.router.add_get("/", root)
    app.router.add_get("/assets/app.js", root)
    app.router.add_post("/prompt", prompt)
    return app


def origin(c):
    u = c.make_url("/"); return f"{u.scheme}://{u.host}:{u.port}"


async def login(c, pw=PW, nxt="/", hdrs=None):
    h = {"Origin": origin(c)} if hdrs is None else hdrs
    return await c.post("/auth/login", data={"password": pw, "next": nxt}, headers=h, allow_redirects=False)


async def test_gui_off_default(aiohttp_client):
    c = await aiohttp_client(make_gui_app(JENV))
    assert (await c.get("/auth/login")).status == 404
    assert (await c.post("/auth/login", data={"password": PW})).status == 404
    r = await c.get("/", headers={"Accept": "text/html"}, allow_redirects=False)
    assert r.status == 401                                                     # no redirect in off
    assert (await c.get("/", headers=B(ed()))).status == 200                  # header auth still works
    # a forged/valid-looking cookie is ignored in off mode
    g = make_gui_app(GENV)
    assert (await c.get("/system_stats", cookies={G.COOKIE: "a.1.2.x"})).status == 401


async def test_gui_deny(aiohttp_client):
    c = await aiohttp_client(make_gui_app({**JENV, "COMFY_AUTH_GUI": "deny"}))
    for p in ("/", "/assets/app.js", "/index.html"):
        assert (await c.get(p, headers=B(ed()))).status == 403
    assert (await c.get("/system_stats", headers=B(ed()))).status == 200
    assert (await c.get("/auth/login")).status == 404


async def test_gui_fail_closed(aiohttp_client):
    for env in ({**JENV, "COMFY_AUTH_GUI": "login"},
                {**JENV, "COMFY_AUTH_GUI": "login", "COMFY_AUTH_GUI_PASSWORD_HASH": "plainpassword"},
                {**JENV, "COMFY_AUTH_GUI": "login", "COMFY_AUTH_GUI_PASSWORD_HASH": "scrypt$1024$8$1$AAAA$AAAA"},
                {**GENV, "COMFY_AUTH_SESSION_SECRET": "short"},
                {**JENV, "COMFY_AUTH_GUI": "maybe"}):
        c = await aiohttp_client(make_gui_app(env))
        assert (await c.get("/auth/login")).status == 503
        assert (await c.get("/system_stats", headers=B(ed()))).status == 503


async def test_gui_login_flow(aiohttp_client):
    c = await aiohttp_client(make_gui_app(GENV))
    r = await c.get("/?a=1", headers={"Accept": "text/html"}, allow_redirects=False)
    assert r.status == 302 and r.headers["Location"] == "/auth/login?next=%2F%3Fa%3D1"
    assert (await c.get("/system_stats", allow_redirects=False)).status == 401   # non-HTML -> 401 JSON
    r = await c.get("/auth/login?next=/x"); assert r.status == 200 and 'value="/x"' in await r.text()
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    r = await login(c, "wrong"); assert r.status == 401 and G.COOKIE not in r.cookies
    r = await login(c, nxt="/?a=1"); assert r.status == 303 and r.headers["Location"] == "/?a=1"
    sc = r.headers["Set-Cookie"]
    assert "HttpOnly" in sc and "SameSite=Strict" in sc and "Path=/" in sc and "Secure" not in sc
    assert (await c.get("/")).status == 200
    assert (await c.get("/system_stats")).status == 200
    assert (await c.post("/prompt", headers={"Origin": origin(c)})).status == 200
    w = await c.ws_connect("/ws", headers={"Origin": origin(c)}); await w.close()
    # logout revokes server-side
    cookie = c.session.cookie_jar.filter_cookies(c.make_url("/"))[G.COOKIE].value
    r = await c.post("/auth/logout", headers={"Origin": origin(c)}, allow_redirects=False); assert r.status == 303
    assert (await c.get("/system_stats", cookies={G.COOKIE: cookie})).status == 401
    r = await c.get("/", headers={"Accept": "text/html"}, cookies={G.COOKIE: cookie}, allow_redirects=False)
    assert r.status == 302


async def test_gui_cookie_secure(aiohttp_client):
    c = await aiohttp_client(make_gui_app(GENV))
    r = await login(c, hdrs={"Origin": origin(c), "X-Forwarded-Proto": "https"})
    assert "Secure" in r.headers["Set-Cookie"]
    c = await aiohttp_client(make_gui_app({**GENV, "COMFY_AUTH_COOKIE_SECURE": "1"}))
    assert "Secure" in (await login(c)).headers["Set-Cookie"]


async def test_gui_session_regenerated(aiohttp_client):
    c = await aiohttp_client(make_gui_app(GENV))
    await login(c)
    old = c.session.cookie_jar.filter_cookies(c.make_url("/"))[G.COOKIE].value
    await login(c)
    new = c.session.cookie_jar.filter_cookies(c.make_url("/"))[G.COOKIE].value
    assert old != new
    assert (await c.get("/system_stats", cookies={G.COOKIE: old})).status == 401


async def test_gui_tampered_expired_cookie(aiohttp_client):
    import auth_guard
    c = await aiohttp_client(make_gui_app({**GENV, "COMFY_AUTH_SESSION_TTL": "60"}))
    await login(c)
    v = c.session.cookie_jar.filter_cookies(c.make_url("/"))[G.COOKIE].value
    sid, iat, exp, sig = v.split(".")
    c.session.cookie_jar.clear()
    for bad in (f"{sid}.{iat}.{int(exp)+9999}.{sig}", f"{sid}.{iat}.{exp}.{sig[:-2]}AA", "garbage", ""):
        assert (await c.get("/system_stats", cookies={G.COOKIE: bad})).status == 401
    # cookie signed with another process secret
    other = G.Sessions(b"y" * 32, 60); _, forged = other.create()
    assert (await c.get("/system_stats", cookies={G.COOKIE: forged})).status == 401
    assert (await c.get("/system_stats", cookies={G.COOKIE: v})).status == 200
    real = time.time
    try:
        G.time.time = lambda: real() + 61
        assert (await c.get("/system_stats", cookies={G.COOKIE: v})).status == 401
    finally:
        G.time.time = real


async def test_gui_open_redirect():
    for bad in ("//evil.com", "/\\evil.com", "https://evil.com", "evil.com", "/\r\nX: y", "javascript:alert(1)",
                "/auth/login", "\\\\evil", ""):
        assert G.safe_next(bad) == "/", bad
    assert G.safe_next("/view?x=1") == "/view?x=1"


async def test_gui_open_redirect_flow(aiohttp_client):
    c = await aiohttp_client(make_gui_app(GENV))
    r = await login(c, nxt="//evil.com/x"); assert r.headers["Location"] == "/"


async def test_gui_csrf(aiohttp_client):
    c = await aiohttp_client(make_gui_app(GENV))
    assert (await login(c, hdrs={})).status == 403                               # no Origin/Referer
    assert (await login(c, hdrs={"Origin": "https://evil.com"})).status == 403
    assert (await login(c, hdrs={"Referer": origin(c) + "/auth/login"})).status == 303   # Referer fallback ok
    for h in ({}, {"Origin": "https://evil.com"}, {"Origin": "null"}):
        assert (await c.post("/prompt", headers=h)).status == 403
    assert (await c.get("/system_stats")).status == 200                          # GET without Origin ok
    with pytest.raises(Exception):
        await c.ws_connect("/ws", headers={"Origin": "https://evil.com"})
    with pytest.raises(Exception):
        await c.ws_connect("/ws")
    assert (await c.post("/auth/logout", headers={"Origin": "https://evil.com"})).status == 403
    c2 = await aiohttp_client(make_gui_app({**GENV, "COMFY_AUTH_ALLOWED_ORIGINS": "https://comfy.example.com"}))
    assert (await login(c2, hdrs={"Origin": "https://comfy.example.com"})).status == 303
    # header-auth (non-cookie) POST does not need Origin
    assert (await c2.post("/prompt", headers=B(ed()))).status == 200


async def test_gui_lockout(aiohttp_client):
    c = await aiohttp_client(make_gui_app(GENV))
    for _ in range(6):
        assert (await login(c, "nope")).status == 401
    r = await login(c)                                       # correct pw but locked
    assert r.status == 429 and int(r.headers["Retry-After"]) >= 1
    # CF-Connecting-IP is ignored unless trusted
    assert (await login(c, hdrs={"Origin": origin(c), "CF-Connecting-IP": "1.2.3.4"})).status == 429
    c2 = await aiohttp_client(make_gui_app({**GENV, "COMFY_AUTH_TRUST_CF_IP": "1"}))
    for _ in range(6):
        await login(c2, "nope", hdrs={"Origin": origin(c2), "CF-Connecting-IP": "1.2.3.4"})
    assert (await login(c2, hdrs={"Origin": origin(c2), "CF-Connecting-IP": "1.2.3.4"})).status == 429
    assert (await login(c2, hdrs={"Origin": origin(c2), "CF-Connecting-IP": "5.6.7.8"})).status == 303


def test_global_limiter():
    l = G.LoginLimiter(global_max=3, window=60)
    for i in range(4):
        l.fail(f"10.0.0.{i}")
    assert l.retry_after("10.9.9.9") > 0


def test_gui_no_secrets_in_logs(caplog):
    import logging; caplog.set_level(logging.DEBUG)
    install(web.Application(), load_config({**JENV, "COMFY_AUTH_GUI": "login",
                                            "COMFY_AUTH_GUI_PASSWORD_HASH": "scrypt$x$secretvalue"}))
    assert "secretvalue" not in caplog.text


async def test_gui_logs_clean(aiohttp_client, caplog):
    import logging; caplog.set_level(logging.DEBUG)
    c = await aiohttp_client(make_gui_app(GENV))
    await login(c, "wrong-pass-xyz"); await login(c)
    v = c.session.cookie_jar.filter_cookies(c.make_url("/"))[G.COOKIE].value
    await c.get("/system_stats")
    for s in ("wrong-pass-xyz", PW, v, HASH):
        assert s not in caplog.text


# ---- final-review regression tests ------------------------------------------
@pytest.mark.parametrize("name", ["COMFY_AUTH_MAX_TTL", "COMFY_AUTH_LEEWAY", "COMFY_AUTH_JTI_MAX",
                                  "COMFY_AUTH_TICKET_TTL", "COMFY_AUTH_MIN_TOKEN_LEN"])
async def test_bad_int_env_fails_closed_not_crash(aiohttp_client, name):
    env = {"COMFY_AUTH_TOKEN": TOKEN, name: "abc"}
    cfg = load_config(env)              # must not raise (a raise = node import fails = ComfyUI runs open)
    assert any(name in e for e in cfg.errors)
    c = await aiohttp_client(make_app(env))
    assert (await c.get("/system_stats", headers={"Authorization": "Bearer " + TOKEN})).status == 503


def test_bad_session_ttl_and_negative_values():
    assert load_config({"COMFY_AUTH_TOKEN": TOKEN, "COMFY_AUTH_GUI": "login",
                        "COMFY_AUTH_SESSION_TTL": "x"}).errors
    assert load_config({"COMFY_AUTH_TOKEN": TOKEN, "COMFY_AUTH_TICKET_TTL": "0"}).errors
    assert load_config({"COMFY_AUTH_TOKEN": TOKEN, "COMFY_AUTH_LEEWAY": "-1"}).errors
    assert not load_config({"COMFY_AUTH_TOKEN": TOKEN, "COMFY_AUTH_MAX_TTL": " 120 "}).errors


async def test_allowlist_rejects_encoded_slash(aiohttp_client):
    app = make_app({"COMFY_AUTH_TOKEN": TOKEN, "COMFY_AUTH_ALLOWLIST": "/api/system_stats"})
    c = await aiohttp_client(app)
    assert (await c.get("/api/system_stats")).status == 200
    assert (await c.get("/api%2Fsystem_stats")).status == 401
    assert (await c.get("/system_stats")).status == 401      # no implicit /api aliasing


async def test_deny_all_fallback_middleware(aiohttp_client):
    from auth_guard import deny_all_middleware
    async def h(r): return web.Response(text="open")
    app = web.Application(middlewares=[deny_all_middleware]); app.router.add_get("/", h)
    c = await aiohttp_client(app)
    assert (await c.get("/")).status == 503


def test_keygen_refuses_overwrite(tmp_path):
    import subprocess
    tool = pathlib.Path(__file__).resolve().parents[1] / "tools" / "issue_token.py"
    r1 = subprocess.run([sys.executable, str(tool), "keygen", "--out", str(tmp_path)], capture_output=True)
    assert r1.returncode == 0
    if os.name == "posix":
        assert (tmp_path / "private.pem").stat().st_mode & 0o077 == 0
    r2 = subprocess.run([sys.executable, str(tool), "keygen", "--out", str(tmp_path)], capture_output=True)
    assert r2.returncode != 0


# ---- logging ------------------------------------------------------------------
import logging as _logging
import auth_guard as _ag


def _jwt_tok(scope="generate"):
    now = int(time.time())
    return jwt.encode({"aud": "comfyui", "sub": "localui", "iat": now, "exp": now + 60,
                       "jti": os.urandom(8).hex(), "scope": scope}, ED, algorithm="EdDSA")


async def test_success_not_logged_at_info(aiohttp_client, caplog):
    _ag.apply_log_level({})
    c = await aiohttp_client(make_app(JENV))
    with caplog.at_level(_logging.INFO, logger="comfyui-auth-guard"):
        for _ in range(3):
            r = await c.get("/system_stats", headers={"Authorization": "Bearer " + _jwt_tok()})
            assert r.status == 200
    assert not [m for m in caplog.messages if "jwt sub=" in m]
    with caplog.at_level(_logging.DEBUG, logger="comfyui-auth-guard"):
        await c.get("/system_stats", headers={"Authorization": "Bearer " + _jwt_tok()})
    assert any("jwt sub=localui" in m for m in caplog.messages)


def test_rate_limited_log(caplog):
    t = [0.0]
    lg = _logging.getLogger("comfyui-auth-guard.test-rl"); lg.setLevel(_logging.INFO)
    rl = _ag.RateLimitedLog(lg, interval=60, clock=lambda: t[0])
    with caplog.at_level(_logging.INFO, logger=lg.name):
        for i in range(100):
            rl(_logging.INFO, "denied", "denied %s", i)
        rl(_logging.INFO, "other", "other reason")
        assert [r.getMessage() for r in caplog.records] == ["denied 0", "other reason"]
        t[0] = 61
        rl(_logging.INFO, "denied", "denied %s", "late")
    assert caplog.records[-1].getMessage() == "denied late (+99 similar suppressed in last 60s)"


async def test_denials_not_flooding(aiohttp_client, caplog):
    _ag.rlog.state.clear()
    c = await aiohttp_client(make_app({"COMFY_AUTH_TOKEN": TOKEN}))
    with caplog.at_level(_logging.INFO, logger="comfyui-auth-guard"):
        for _ in range(20):
            assert (await c.get("/system_stats")).status == 401
    assert len([m for m in caplog.messages if "denied GET" in m]) == 1


@pytest.mark.parametrize("val,expect", [("", "INFO"), ("debug", "DEBUG"), ("WARNING", "WARNING"),
                                        ("ERROR", "ERROR"), ("loud", "INFO")])
def test_log_level_env(val, expect, caplog):
    root_before = _logging.getLogger().level
    with caplog.at_level(_logging.WARNING, logger="comfyui-auth-guard"):
        assert _ag.apply_log_level({"COMFY_AUTH_LOG_LEVEL": val}) == expect
        assert _logging.getLogger("comfyui-auth-guard").level == getattr(_logging, expect)
    assert _logging.getLogger().level == root_before            # ComfyUI root logger untouched
    assert not _logging.getLogger("comfyui-auth-guard").handlers  # propagate only: no double print
    if val == "loud":
        assert any("invalid COMFY_AUTH_LOG_LEVEL" in m for m in caplog.messages)
    _ag.apply_log_level({})
