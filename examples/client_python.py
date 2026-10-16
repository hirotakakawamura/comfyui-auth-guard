"""comfyui-auth-guard client example (Python): JWT(Ed25519) + ws-ticket + typical ComfyUI flow.
pip install requests websocket-client "pyjwt[crypto]"
env: COMFY_URL (default http://127.0.0.1:8188), COMFY_PRIVKEY (private.pem), COMFY_AUD (default comfyui), INPUT_IMAGE
"""
import json, os, secrets, time, uuid
import jwt, requests, websocket
from cryptography.hazmat.primitives import serialization

URL = os.environ.get("COMFY_URL", "http://127.0.0.1:8188")
AUD = os.environ.get("COMFY_AUD", "comfyui")
with open(os.environ.get("COMFY_PRIVKEY", "keys/private.pem"), "rb") as f:
    KEY = serialization.load_pem_private_key(f.read(), password=None)


def auth():
    """New token for EVERY request (jti is single-use)."""
    now = int(time.time())
    tok = jwt.encode({"aud": AUD, "sub": "webapp-user-1", "iat": now, "exp": now + 60,
                      "jti": secrets.token_urlsafe(16), "scope": "generate"}, KEY, algorithm="EdDSA")
    return {"Authorization": f"Bearer {tok}"}


def check(r):
    if r.status_code >= 400:
        raise RuntimeError(f"{r.request.method} {r.url} -> {r.status_code} {r.text}")
    return r


print("system_stats:", check(requests.get(f"{URL}/system_stats", headers=auth())).status_code)

# 1) upload an input image
with open(os.environ.get("INPUT_IMAGE", "input.png"), "rb") as f:
    up = check(requests.post(f"{URL}/upload/image", headers=auth(),
                             files={"image": ("auth_guard_test.png", f, "image/png")},
                             data={"overwrite": "true"})).json()
print("uploaded:", up)

# 2) one-time ticket -> websocket (browsers can't send headers; servers could also send the header directly)
ticket = check(requests.post(f"{URL}/auth/ws-ticket", headers=auth())).json()["ticket"]
client_id = str(uuid.uuid4())
ws = websocket.create_connection(f"{URL.replace('http', 'ws', 1)}/ws?clientId={client_id}&ticket={ticket}")

# 3) queue a workflow (API format). LoadImage -> SaveImage needs no model.
workflow = {"1": {"class_type": "LoadImage", "inputs": {"image": up["name"]}},
            "2": {"class_type": "SaveImage", "inputs": {"images": ["1", 0], "filename_prefix": "authguard"}}}
pid = check(requests.post(f"{URL}/prompt", headers=auth(),
                          json={"prompt": workflow, "client_id": client_id})).json()["prompt_id"]
print("prompt_id:", pid)

# 4) wait for completion over websocket
while True:
    msg = ws.recv()
    if isinstance(msg, str):
        m = json.loads(msg)
        if m["type"] == "executing" and m["data"].get("node") is None and m["data"].get("prompt_id") == pid:
            break
        if m["type"] == "execution_error":
            raise RuntimeError(m)
ws.close()

# 5) history -> 6) view
hist = check(requests.get(f"{URL}/history/{pid}", headers=auth())).json()[pid]
img = hist["outputs"]["2"]["images"][0]
r = check(requests.get(f"{URL}/view", headers=auth(), params=img))
print("view:", r.status_code, r.headers.get("Content-Type"), len(r.content), "bytes")
