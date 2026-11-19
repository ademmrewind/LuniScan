from urllib.parse import urlsplit

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

MAX_BODY_BYTES = 16_384
MUTATIONS = {"POST", "PUT", "PATCH", "DELETE"}


class LocalAPIProtection:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope["path"].startswith("/api/"):
            await self.app(scope, receive, send)
            return

        async def secure_send(message):
            if message["type"] == "http.response.start":
                response_headers = MutableHeaders(scope=message)
                response_headers["Cache-Control"] = "no-store"
                response_headers["X-Content-Type-Options"] = "nosniff"
            await send(message)

        async def reject(status: int, detail: str) -> None:
            await JSONResponse({"detail": detail}, status_code=status)(
                scope, receive, secure_send
            )

        headers = Headers(scope=scope)
        method = scope["method"]
        if method in MUTATIONS:
            origin = headers.get("origin")
            try:
                expected = f"{scope['scheme']}://{headers.get('host', '')}"
                invalid_origin = origin is not None and (
                    origin != expected
                    or urlsplit(origin).scheme not in {"http", "https"}
                )
            except ValueError:
                invalid_origin = True
            if invalid_origin or headers.get("sec-fetch-site") == "cross-site":
                await reject(403, "Cross-origin API mutations are forbidden.")
                return

        lengths = headers.getlist("content-length")
        if lengths:
            length = lengths[0]
            if (
                len(lengths) != 1
                or not length.isascii()
                or not length.isdecimal()
                or len(length) > 18
            ):
                await reject(400, "Invalid Content-Length.")
                return
            if int(length) > MAX_BODY_BYTES:
                await reject(413, "Request body exceeds 16 KiB.")
                return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > MAX_BODY_BYTES:
                await reject(413, "Request body exceeds 16 KiB.")
                return
            body.extend(chunk)
            if not message.get("more_body"):
                break
        if (
            method in MUTATIONS
            and body
            and headers.get("content-type", "").partition(";")[0].strip().lower()
            != "application/json"
        ):
            await reject(415, "Use application/json for request bodies.")
            return

        async def replay():
            nonlocal body
            if body is None:
                return await receive()
            data, body = bytes(body), None
            return {"type": "http.request", "body": data, "more_body": False}

        await self.app(scope, replay, secure_send)
