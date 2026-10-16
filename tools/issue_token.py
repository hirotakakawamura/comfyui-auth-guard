#!/usr/bin/env python3
"""Web-app side helper for comfyui-auth-guard Ed25519 tokens.

  python issue_token.py keygen --out keys/            # writes private.pem (keep secret) + public.pem
  python issue_token.py gui-hash                      # prompts, prints COMFY_AUTH_GUI_PASSWORD_HASH
  python issue_token.py issue --key keys/private.pem --aud comfyui --sub alice [--ttl 60] [--scope generate] [--iss my-backend]
"""
import argparse, os, secrets, sys, time
# PyJWT/cryptography are imported lazily so that `gui-hash` works with the stdlib only.


def keygen(out):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    os.makedirs(out, exist_ok=True)
    k = Ed25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.PEM,
                                      serialization.PublicFormat.SubjectPublicKeyInfo)
    p = os.path.join(out, "private.pem")
    if os.path.exists(p):
        sys.exit(f"{p} already exists; refusing to overwrite an existing private key")
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # 0600 on POSIX; on Windows ACLs are inherited
    with os.fdopen(fd, "wb") as f:
        f.write(priv)
    with open(os.path.join(out, "public.pem"), "wb") as f:
        f.write(pub)
    print(f"wrote {p} (secret: keep it on the client/backend only) and {os.path.join(out, 'public.pem')} (ComfyUI)", file=sys.stderr)


def issue(key_path, aud, sub, ttl=60, scope=None, iss=None):
    import jwt
    from cryptography.hazmat.primitives import serialization
    with open(key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    now = int(time.time())
    claims = {"aud": aud, "sub": sub, "iat": now, "exp": now + ttl, "jti": secrets.token_urlsafe(16)}
    if scope:
        claims["scope"] = scope
    if iss:
        claims["iss"] = iss
    return jwt.encode(claims, key, algorithm="EdDSA")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    g = sp.add_parser("keygen"); g.add_argument("--out", default="keys")
    i = sp.add_parser("issue")
    i.add_argument("--key", required=True); i.add_argument("--aud", required=True)
    i.add_argument("--sub", required=True); i.add_argument("--ttl", type=int, default=60)
    i.add_argument("--scope"); i.add_argument("--iss")
    sp.add_parser("gui-hash")
    a = ap.parse_args()
    if a.cmd == "gui-hash":
        import getpass
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
        from gui import make_hash
        pw = getpass.getpass("GUI password: ")
        if len(pw) < 12:
            sys.exit("password must be at least 12 characters")
        if pw != getpass.getpass("again: "):
            sys.exit("passwords do not match")
        print(make_hash(pw))
    elif a.cmd == "keygen":
        keygen(a.out)
    else:
        print(issue(a.key, a.aud, a.sub, a.ttl, a.scope, a.iss))
