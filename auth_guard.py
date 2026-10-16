"""ComfyUI Auth Guard core: aiohttp middleware (no ComfyUI imports, testable standalone)."""
import asyncio
import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass, field

from aiohttp import web

try:
    from . import gui as G
except ImportError:
    import gui as G

log = logging.getLogger("comfyui-auth-guard")
# No handler is attached here: records propagate to ComfyUI's root handler (no double printing).
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")


class RateLimitedLog:
    """At most one line per reason key per `interval` s; the next line reports how many were suppressed.
    Keys are a small fixed set of reasons (never client-controlled), so memory stays bounded."""
    def __init__(self, logger, interval=60.0, clock=time.monotonic):
        self.logger, self.interval, self.clock = logger, interval, clock
        self.state = {}         # key -> [last_emit, suppressed]
        self.lock = threading.Lock()

    def __call__(self, level, key, msg, *args):
        if not self.logger.isEnabledFor(level):
            return
        now = self.clock()
        with self.lock:
            st = self.state.get(key)
            if st is not None and now - st[0] < self.interval:
                st[1] += 1
                return
            suppressed = st[1] if st else 0
            self.state[key] = [now, 0]
        if suppressed:
            msg += " (+%d similar suppressed in last %ds)"
            args = args + (suppressed, int(self.interval))
        self.logger.log(level, msg, *args)


rlog = RateLimitedLog(log)


def apply_log_level(env=None):
    """COMFY_AUTH_LOG_LEVEL on this module's logger only. Invalid -> warning + INFO (not security relevant)."""
    env = os.environ if env is None else env
    raw = env.get("COMFY_AUTH_LOG_LEVEL", "").strip().upper()
    level = raw if raw in LOG_LEVELS else "INFO"
    log.setLevel(level)
    if raw and raw not in LOG_LEVELS:
        log.warning("[auth-guard] invalid COMFY_AUTH_LOG_LEVEL=%r, using INFO", raw[:20])
    return level

try:
    import jwt  # PyJWT
    from jwt import PyJWKClient
    HAVE_JWT = True
except Exception:  # pragma: no cover
    HAVE_JWT = False

TRUE = {"1", "true", "yes", "on"}
METHODS = ("token", "cf", "jwt")
TICKET_PATH = "/auth/ws-ticket"


@dataclass
class Config:
    disabled: bool = False
    token: str = ""
    min_token_len: int = 32
    cf_team: str = ""
    cf_aud: str = ""
    cf_jwks_url: str = ""
    pubkey_pem: str = ""        # Ed25519 public key (PEM)
    jwt_aud: str = ""
    jwt_iss: str = ""           # optional
    max_ttl: int = 300
    leeway: int = 10
    jti_max: int = 10000
    ticket_ttl: int = 30
    ticket_max: int = 10000
    mode: str = "auto"          # auto | token | cf | jwt | any | all
    allow_query_token: bool = False
    allowlist: set = field(default_factory=set)
    gui: str = "off"            # off | deny | login
    gui_hash: object = None     # parsed scrypt hash
    session_secret: bytes = b""
    session_ttl: int = 43200
    cookie_secure: str = "auto" # auto | 1 | 0
    allowed_origins: set = field(default_factory=set)
    trust_cf_ip: bool = False
    errors: list = field(default_factory=list)
    methods: tuple = ()         # methods taking part (resolved)

    @property
    def cf_issuer(self):
        t = self.cf_team.strip().rstrip("/").removeprefix("https://")
        if not t.endswith(".cloudflareaccess.com"):
            t += ".cloudflareaccess.com"
        return "https://" + t

    def configured(self, m):
        return {"token": bool(self.token), "cf": bool(self.cf_team and self.cf_aud),
                "jwt": bool(self.pubkey_pem)}[m]


def _int(env, name, default, errors):
    raw = env.get(name, "")
    if raw.strip() == "":
        return default
    try:
        return int(raw.strip())
    except ValueError:
        errors.append(f"{name} must be an integer")
        return default


def load_config(env=None) -> Config:
    env = os.environ if env is None else env
    errs = []
    c = Config(
        disabled=env.get("COMFY_AUTH_DISABLED", "").lower() in TRUE,
        token=env.get("COMFY_AUTH_TOKEN", ""),
        min_token_len=_int(env, "COMFY_AUTH_MIN_TOKEN_LEN", 32, errs),
        cf_team=env.get("COMFY_AUTH_CF_TEAM", ""),
        cf_aud=env.get("COMFY_AUTH_CF_AUD", ""),
        cf_jwks_url=env.get("COMFY_AUTH_CF_JWKS_URL", ""),
        pubkey_pem=env.get("COMFY_AUTH_PUBKEY", ""),
        jwt_aud=env.get("COMFY_AUTH_JWT_AUD", ""),
        jwt_iss=env.get("COMFY_AUTH_JWT_ISS", ""),
        max_ttl=_int(env, "COMFY_AUTH_MAX_TTL", 300, errs),
        leeway=_int(env, "COMFY_AUTH_LEEWAY", 10, errs),
        jti_max=_int(env, "COMFY_AUTH_JTI_MAX", 10000, errs),
        ticket_ttl=_int(env, "COMFY_AUTH_TICKET_TTL", 30, errs),
        mode=env.get("COMFY_AUTH_MODE", "auto").lower(),
        allow_query_token=env.get("COMFY_AUTH_ALLOW_QUERY_TOKEN", "0").lower() in TRUE,
        allowlist={p.strip() for p in env.get("COMFY_AUTH_ALLOWLIST", "").split(",") if p.strip()},
    )
    c.errors.extend(errs)
    if c.disabled:
        return c
    c.gui = env.get("COMFY_AUTH_GUI", "off").lower()
    c.session_ttl = _int(env, "COMFY_AUTH_SESSION_TTL", 43200, c.errors)
    c.cookie_secure = env.get("COMFY_AUTH_COOKIE_SECURE", "auto").lower()
    c.allowed_origins = {o.strip().rstrip("/").lower() for o in env.get("COMFY_AUTH_ALLOWED_ORIGINS", "").split(",") if o.strip()}
    c.trust_cf_ip = env.get("COMFY_AUTH_TRUST_CF_IP", "").lower() in TRUE
    if c.gui not in ("off", "deny", "login"):
        c.errors.append(f"invalid COMFY_AUTH_GUI: {c.gui}")
    if c.gui == "login":
        try:
            c.gui_hash = G.parse_hash(env.get("COMFY_AUTH_GUI_PASSWORD_HASH", ""))
        except Exception as e:
            c.errors.append(f"COMFY_AUTH_GUI=login requires a valid COMFY_AUTH_GUI_PASSWORD_HASH ({type(e).__name__})")
        sec = env.get("COMFY_AUTH_SESSION_SECRET", "")
        if sec and len(sec.encode()) < 32:
            c.errors.append("COMFY_AUTH_SESSION_SECRET must be at least 32 bytes")
        c.session_secret = sec.encode() if sec else secrets.token_bytes(32)
        if c.session_ttl <= 0:
            c.errors.append("COMFY_AUTH_SESSION_TTL must be positive")
        if c.cookie_secure not in ("auto", "0", "1"):
            c.errors.append("COMFY_AUTH_COOKIE_SECURE must be auto, 0 or 1")
    p = env.get("COMFY_AUTH_PUBKEY_PATH", "")
    if p and not c.pubkey_pem:
        try:
            with open(p, "r", encoding="utf-8") as f:
                c.pubkey_pem = f.read()
        except OSError as e:
            c.errors.append(f"cannot read COMFY_AUTH_PUBKEY_PATH ({type(e).__name__})")
    if c.token and len(c.token) < c.min_token_len:
        c.errors.append(f"COMFY_AUTH_TOKEN is shorter than {c.min_token_len} chars")
    if bool(c.cf_team) != bool(c.cf_aud):
        c.errors.append("COMFY_AUTH_CF_TEAM and COMFY_AUTH_CF_AUD must both be set")
    if c.pubkey_pem and not c.jwt_aud:
        c.errors.append("COMFY_AUTH_JWT_AUD is required with an Ed25519 public key")
    if (c.cf_team or c.pubkey_pem) and not HAVE_JWT:
        c.errors.append("JWT verification requested but PyJWT[crypto] is not installed")
    if c.pubkey_pem and HAVE_JWT:
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            k = load_pem_public_key(c.pubkey_pem.encode())
            if not isinstance(k, Ed25519PublicKey):
                c.errors.append("COMFY_AUTH_PUBKEY is not an Ed25519 public key")
        except Exception as e:
            c.errors.append(f"invalid Ed25519 public key ({type(e).__name__})")
    if c.max_ttl <= 0 or c.jti_max <= 0:
        c.errors.append("COMFY_AUTH_MAX_TTL and COMFY_AUTH_JTI_MAX must be positive")
    if c.ticket_ttl <= 0 or c.leeway < 0 or c.min_token_len < 0:
        c.errors.append("COMFY_AUTH_TICKET_TTL must be positive, COMFY_AUTH_LEEWAY/MIN_TOKEN_LEN non-negative")

    configured = tuple(m for m in METHODS if c.configured(m))
    if c.mode in METHODS:
        c.methods = (c.mode,)
    elif c.mode in ("auto", "all", "any"):
        c.methods = configured
        if c.mode == "auto":
            c.mode = "all"   # auto = every configured method is required
    else:
        c.errors.append(f"invalid COMFY_AUTH_MODE: {c.mode}")
    if not c.methods:
        c.errors.append("no authentication method configured")
    for m in c.methods:
        if not c.configured(m):
            c.errors.append(f"mode requires method '{m}' but it is not configured")
    return c


def _deny(reason="unauthorized", status=401):
    return web.json_response({"error": reason}, status=status,
                             headers={"WWW-Authenticate": 'Bearer realm="comfyui"'})


def _is_ws(request):
    return request.headers.get("Upgrade", "").lower() == "websocket"


class ExpiringSet:
    """Bounded {key: (exp, value)} store. When full (after evicting expired) -> refuse."""
    def __init__(self, max_size):
        self.max = max_size
        self.d = {}
        self.lock = threading.Lock()

    def _evict(self, now):
        for k in [k for k, (e, _) in self.d.items() if e < now]:
            del self.d[k]

    def add_new(self, key, exp, value=None):
        """True if inserted; False if key already present or store full."""
        now = time.time()
        with self.lock:
            if key in self.d and self.d[key][0] >= now:
                return False
            if len(self.d) >= self.max:
                self._evict(now)
                if len(self.d) >= self.max:
                    return False
            self.d[key] = (exp, value)
            return True

    def pop_valid(self, key):
        now = time.time()
        with self.lock:
            item = self.d.pop(key, None)
        if item is None or item[0] < now:
            return None
        return item


class Guard:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._jwk_client = None
        self.seen_jti = ExpiringSet(cfg.jti_max)
        self.tickets = ExpiringSet(cfg.ticket_max)
        self.sessions = G.Sessions(cfg.session_secret or b"x" * 32, cfg.session_ttl)
        self.limiter = G.LoginLimiter()
        if cfg.configured("cf") and HAVE_JWT and not cfg.errors:
            url = cfg.cf_jwks_url or cfg.cf_issuer + "/cdn-cgi/access/certs"
            self._jwk_client = PyJWKClient(url, cache_keys=True, lifespan=3600)

    # --- checks: each returns an identity string or None --------------------
    def check_token(self, request):
        auth = request.headers.get("Authorization", "")
        cands = [request.headers.get("X-ComfyUI-Token")]
        if auth[:7].lower() == "bearer ":
            cands.append(auth[7:].strip())
        if self.cfg.allow_query_token and _is_ws(request):
            cands.append(request.query.get("token"))
        ok = False
        for p in cands:
            if p:
                ok |= hmac.compare_digest(p.encode(), self.cfg.token.encode())
        return "static-token" if ok else None

    async def check_cf(self, request):
        tok = request.headers.get("Cf-Access-Jwt-Assertion")
        if not tok:
            return None
        try:
            key = await asyncio.to_thread(self._jwk_client.get_signing_key_from_jwt, tok)
            c = jwt.decode(tok, key.key, algorithms=["RS256"], audience=self.cfg.cf_aud,
                           issuer=self.cfg.cf_issuer,
                           options={"require": ["exp", "iat", "iss", "aud"]}, leeway=30)
            return "cf:" + str(c.get("email") or c.get("common_name") or c.get("sub"))
        except Exception as e:  # never log the token itself
            rlog(logging.WARNING, "cf:" + type(e).__name__, "[auth-guard] CF Access JWT rejected: %s", type(e).__name__)
            return None

    def check_jwt(self, request):
        """Ed25519 short-lived token: `Authorization: Bearer <jwt>` or `X-ComfyUI-JWT`."""
        cfg = self.cfg
        tok = request.headers.get("X-ComfyUI-JWT")
        auth = request.headers.get("Authorization", "")
        if not tok and auth[:7].lower() == "bearer " and auth.count(".") == 2:
            tok = auth[7:].strip()
        if not tok:
            return None
        try:
            if jwt.get_unverified_header(tok).get("alg") != "EdDSA":
                raise jwt.InvalidAlgorithmError("alg")
            opts = {"require": ["exp", "iat", "jti", "aud"] + (["iss"] if cfg.jwt_iss else [])}
            c = jwt.decode(tok, cfg.pubkey_pem, algorithms=["EdDSA"], audience=cfg.jwt_aud,
                           issuer=cfg.jwt_iss or None, options=opts, leeway=cfg.leeway)
            if not isinstance(c["exp"], int) or not isinstance(c["iat"], int):
                raise jwt.InvalidTokenError("exp/iat type")
            if c["exp"] - c["iat"] > cfg.max_ttl:
                raise jwt.InvalidTokenError("ttl too long")
            if c["iat"] > time.time() + cfg.leeway:
                raise jwt.ImmatureSignatureError("iat in future")
            jti = str(c["jti"])
            if not jti or not self.seen_jti.add_new(jti, c["exp"] + cfg.leeway):
                raise jwt.InvalidTokenError("replay or jti store full")
        except Exception as e:
            why = (e.args[0] if isinstance(e, jwt.InvalidTokenError) and e.args and
                   e.args[0] in ("ttl too long", "replay or jti store full", "alg", "iat in future") else "-")
            rlog(logging.WARNING, "jwt:%s:%s" % (type(e).__name__, why), "[auth-guard] signed JWT rejected: %s (%s)", type(e).__name__, why)
            return None
        sub = str(c.get("sub", ""))
        if "scope" in c:
            request["auth_scope"] = c["scope"]
            log.debug("[auth-guard] jwt sub=%s scope=%s", sub, c["scope"])
        return "jwt:" + sub

    async def authenticate(self, request):
        """Returns identity (str) or None according to mode."""
        cfg = self.cfg
        ids = []
        for m in cfg.methods:
            if m == "token":
                i = self.check_token(request)
            elif m == "cf":
                i = await self.check_cf(request)
            else:
                i = self.check_jwt(request)
            if i and cfg.mode == "any":
                return i
            if not i and cfg.mode != "any":
                return None
            if i:
                ids.append(i)
        return "|".join(ids) if ids else None

    # --- ws tickets --------------------------------------------------------
    @staticmethod
    def _tkey(ticket):
        return hashlib.sha256(ticket.encode()).hexdigest()  # lookup by hash: no timing on secret

    def issue_ticket(self, subject):
        t = secrets.token_urlsafe(32)
        if not self.tickets.add_new(self._tkey(t), time.time() + self.cfg.ticket_ttl, subject):
            return None
        return t

    def redeem_ticket(self, ticket):
        item = self.tickets.pop_valid(self._tkey(ticket))   # single use: removed even if expired
        return item[1] if item else None

    # --- middleware ----------------------------------------------------------
    @web.middleware
    async def middleware(self, request, handler):
        cfg = self.cfg
        if cfg.disabled:
            return await handler(request)
        if cfg.errors:
            return _deny("auth guard misconfigured (fail closed)", status=503)
        if request.path in (G.LOGIN_PATH, G.LOGOUT_PATH):
            if cfg.gui != "login":
                return web.json_response({"error": "not found"}, status=404)
            return await (self.handle_login(request) if request.path == G.LOGIN_PATH else self.handle_logout(request))
        if request.path in cfg.allowlist and "%2f" not in request.raw_path.split("?", 1)[0].lower():
            return await handler(request)
        if cfg.gui == "deny" and G.is_gui_path(request.path):
            return web.json_response({"error": "GUI disabled"}, status=403)

        ticket = request.query.get("ticket")
        if ticket is not None:
            if not (_is_ws(request) and request.path in ("/ws", "/api/ws")):
                return _deny("ticket only valid for websocket")
            subject = self.redeem_ticket(ticket)
            if subject is None:
                rlog(logging.INFO, "ws-ticket", "[auth-guard] denied ws ticket from %s", request.remote)
                return _deny()
            # bound to subject: if the request carries a CF identity it must match
            if "cf" in cfg.methods and request.headers.get("Cf-Access-Jwt-Assertion"):
                cf_id = await self.check_cf(request)
                if not cf_id or cf_id not in subject.split("|"):
                    rlog(logging.WARNING, "ws-mismatch", "[auth-guard] ws ticket subject mismatch")
                    return _deny()
            request["auth_user"] = subject
            return await handler(request)

        identity = None
        bad_origin = False
        if cfg.gui == "login":
            sid = self.sessions.validate(request.cookies.get(G.COOKIE))
            if sid:
                if (request.method in G.UNSAFE_METHODS or _is_ws(request)) and not G.origin_ok(request, cfg.allowed_origins):
                    bad_origin = True       # cookie not usable; header auth may still apply
                else:
                    identity = "gui-session"
        if not identity:
            identity = await self.authenticate(request)
        if not identity and bad_origin:
            rlog(logging.WARNING, "cookie-origin", "[auth-guard] cookie request with bad origin: %s %s", request.method, request.path)
            return web.json_response({"error": "origin check failed"}, status=403)
        if not identity:
            rlog(logging.INFO, "denied", "[auth-guard] denied %s %s from %s", request.method, request.path, request.remote)
            if (cfg.gui == "login" and request.method == "GET" and not _is_ws(request)
                    and "text/html" in request.headers.get("Accept", "")):
                return G.redirect_to_login(request)
            return _deny()
        request["auth_user"] = identity

        if request.path in (TICKET_PATH, "/api" + TICKET_PATH):
            if request.method != "POST":
                return _deny("method not allowed", status=405)
            t = self.issue_ticket(identity)
            if t is None:
                return _deny("ticket store full", status=503)
            return web.json_response({"ticket": t, "expires_in": cfg.ticket_ttl},
                                     headers={"Cache-Control": "no-store"})
        return await handler(request)


async def _handle_login(self, request):
    cfg = self.cfg
    if request.method == "GET":
        return G.login_page(request.query.get("next", "/"))
    if request.method != "POST":
        return web.json_response({"error": "method not allowed"}, status=405)
    if not G.origin_ok(request, cfg.allowed_origins):
        rlog(logging.WARNING, "login-origin", "[auth-guard] login with bad origin from %s", request.remote)
        return web.json_response({"error": "origin check failed"}, status=403)
    ip = G.client_ip(request, cfg.trust_cf_ip)
    wait = self.limiter.retry_after(ip)
    if wait:
        log.warning("[auth-guard] login locked out for %s (%ss)", ip, wait)
        r = G.login_page("/", "試行回数が多すぎます。しばらく待ってください。", status=429)
        r.headers["Retry-After"] = str(wait)
        return r
    form = await request.post()
    pw = form.get("password", "")
    nxt = G.safe_next(form.get("next", "/"))
    if not isinstance(pw, str) or len(pw) > 1024:
        pw = ""
    ok = await asyncio.to_thread(G.verify_password, pw, cfg.gui_hash)
    if not ok:
        self.limiter.fail(ip)
        rlog(logging.WARNING, "login-failed", "[auth-guard] GUI login failed from %s", ip)
        return G.login_page(nxt, "パスワードが違います。", status=401)
    self.limiter.success(ip)
    old = self.sessions.validate(request.cookies.get(G.COOKIE))
    if old:
        self.sessions.revoke(old)             # regenerate session id on login
    created = self.sessions.create()
    if not created:
        return _deny("session store full", status=503)
    _, value = created
    secure = cfg.cookie_secure == "1" or (cfg.cookie_secure == "auto" and G.is_https(request))
    r = web.Response(status=303, headers={"Location": nxt, "Cache-Control": "no-store"})
    r.set_cookie(G.COOKIE, value, max_age=cfg.session_ttl, path="/", httponly=True,
                 samesite="Strict", secure=secure)
    log.info("[auth-guard] GUI login ok from %s", ip)
    return r


async def _handle_logout(self, request):
    if request.method != "POST":
        return web.json_response({"error": "method not allowed"}, status=405)
    if not G.origin_ok(request, self.cfg.allowed_origins):
        return web.json_response({"error": "origin check failed"}, status=403)
    sid = self.sessions.validate(request.cookies.get(G.COOKIE))
    if sid:
        self.sessions.revoke(sid)
    r = web.Response(status=303, headers={"Location": G.LOGIN_PATH, "Cache-Control": "no-store"})
    r.del_cookie(G.COOKIE, path="/")
    return r


Guard.handle_login = _handle_login
Guard.handle_logout = _handle_logout


@web.middleware
async def deny_all_middleware(request, handler):
    """Installed by __init__ when the guard itself fails to initialise (fail closed)."""
    return _deny("auth guard failed to initialise (fail closed)", status=503)


def install(app: web.Application, cfg: Config = None) -> Guard:
    """Insert the guard as the OUTERMOST middleware. Must run before the app is frozen."""
    apply_log_level()
    cfg = cfg or load_config()
    guard = Guard(cfg)
    if cfg.disabled:
        log.warning("[auth-guard] COMFY_AUTH_DISABLED is set: authentication is OFF")
    elif cfg.errors:
        for e in cfg.errors:
            log.error("[auth-guard] config error: %s -> refusing ALL requests (fail closed)", e)
    else:
        log.info("[auth-guard] enabled: mode=%s methods=%s gui=%s cf=%s query_token=%s allowlist=%s",
                 cfg.mode, ",".join(cfg.methods), cfg.gui, cfg.cf_issuer if cfg.configured("cf") else "off",
                 cfg.allow_query_token, sorted(cfg.allowlist))
    if app.frozen:
        raise RuntimeError("aiohttp app already frozen; auth guard cannot be installed")
    app.middlewares.insert(0, guard.middleware)
    return guard
