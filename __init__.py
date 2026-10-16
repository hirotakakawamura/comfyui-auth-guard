"""ComfyUI Auth Guard - defense-in-depth auth for ComfyUI HTTP API and WebSocket.

ComfyUI (main.py) creates PromptServer -> imports custom nodes -> add_routes() -> AppRunner.setup()
(which freezes app.middlewares). So inserting into app.middlewares at import time is effective.
"""
import logging

NODE_CLASS_MAPPINGS = {}
NODE_DISPLAY_NAME_MAPPINGS = {}
__all__ = ["NODE_CLASS_MAPPINGS", "NODE_DISPLAY_NAME_MAPPINGS"]

try:
    from .auth_guard import install
except ImportError:  # loaded outside a package
    from auth_guard import install

try:
    import server
    _app = server.PromptServer.instance.app
except Exception as e:  # pragma: no cover
    logging.getLogger("comfyui-auth-guard").error("[auth-guard] PromptServer not available: %s", e)
    raise  # make load failure visible in ComfyUI's import log
try:
    GUARD = install(_app)
except Exception as e:  # unexpected init failure: refuse everything rather than run open
    logging.getLogger("comfyui-auth-guard").exception("[auth-guard] init failed -> refusing ALL requests: %s", type(e).__name__)
    GUARD = None
    if not _app.frozen:
        try:
            from .auth_guard import deny_all_middleware
        except ImportError:
            from auth_guard import deny_all_middleware
        _app.middlewares.insert(0, deny_all_middleware)
    else:
        raise
