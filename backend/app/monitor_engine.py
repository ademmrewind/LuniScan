import asyncio
import math
import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from time import monotonic
from typing import Literal

import h11
from pydantic import BaseModel

from app.scope import Address

Protocol = Literal["tcp", "http", "https", "tls"]
Health = Literal["healthy", "degraded", "unreachable", "unknown"]
CertificateState = Literal[
    "valid",
    "expiring_soon",
    "expired",
    "untrusted",
    "hostname_mismatch",
    "inconclusive",
]
MAX_BODY = 8192
MAX_WIRE = 16384
ASSESSMENT_HEADERS = {
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "x-frame-options",
    "permissions-policy",
}


@dataclass
class ResponseEvidence:
    headers: dict[str, list[str]] = field(default_factory=dict)
    tls_version: str | None = None
    tls_cipher: str | None = None

    def capture(self, headers) -> None:
        for key, value in headers:
            name = key.decode("ascii")
            if name in ASSESSMENT_HEADERS:
                self.headers.setdefault(name, []).append(value.decode("latin-1"))


class Certificate(BaseModel):
    state: CertificateState
    subject: str | None = None
    issuer: str | None = None
    valid_from: datetime | None = None
    expires_at: datetime | None = None
    days_remaining: int | None = None
    verified: bool | None = None
    hostname_valid: bool | None = None
    inspected_at: datetime


class Outcome(BaseModel):
    health: Health
    duration_ms: float
    error: str | None = None
    outcome: Literal["connected", "refused", "timeout", "tls_failed", "network_error"]
    http_status: int | None = None
    expected_status: bool | None = None
    content_match: bool | None = None
    certificate: Certificate | None = None


@dataclass(frozen=True)
class CheckTarget:
    protocol: Protocol
    port: int
    hostname: str | None
    timeout_ms: int
    path: str
    status_min: int
    status_max: int
    expected_content: str | None


def certificate_info(cert: dict, checked: datetime, warning_days: int) -> Certificate:
    def name(key: str) -> str | None:
        parts = [
            f"{field}={value}" for group in cert.get(key, ()) for field, value in group
        ]
        printable = "".join(char for char in ", ".join(parts) if char.isprintable())
        return " ".join(printable.split())[:300] or None

    def timestamp(key: str) -> datetime | None:
        try:
            return datetime.fromtimestamp(ssl.cert_time_to_seconds(cert[key]), UTC)
        except (KeyError, ValueError, OverflowError):
            return None

    start, expires = timestamp("notBefore"), timestamp("notAfter")
    days = math.floor((expires - checked).total_seconds() / 86400) if expires else None
    state = "inconclusive"
    if days is not None:
        state = (
            "expired"
            if expires <= checked
            else "expiring_soon"
            if expires - checked <= timedelta(days=warning_days)
            else "valid"
        )
    return Certificate(
        state=state,
        subject=name("subject"),
        issuer=name("issuer"),
        valid_from=start,
        expires_at=expires,
        days_remaining=days,
        verified=True,
        hostname_valid=True,
        inspected_at=checked,
    )


def verification_failure(code: int | None, checked: datetime) -> Certificate:
    state = (
        "expired"
        if code == 10
        else "hostname_mismatch"
        if code in (62, 64)
        else "untrusted"
    )
    return Certificate(
        state=state,
        verified=False,
        hostname_valid=False if state == "hostname_mismatch" else None,
        inspected_at=checked,
    )


async def read_health(
    reader,
    writer,
    target: CheckTarget,
    host: str,
    evidence: ResponseEvidence | None = None,
):
    protocol = h11.Connection(h11.CLIENT, max_incomplete_event_size=8192)
    writer.write(
        protocol.send(
            h11.Request(
                method="GET",
                target=target.path,
                headers=[
                    ("Host", host),
                    ("Connection", "close"),
                    ("Accept-Encoding", "identity"),
                ],
            )
        )
    )
    writer.write(protocol.send(h11.EndOfMessage()))
    await writer.drain()
    wire = 0
    status = None
    body = bytearray()
    marker = target.expected_content.encode() if target.expected_content else None
    while True:
        event = protocol.next_event()
        if event is h11.NEED_DATA:
            if wire >= MAX_WIRE:
                if status is None:
                    raise h11.RemoteProtocolError("Header limit")
                return status, None
            chunk = await reader.read(min(2048, MAX_WIRE - wire))
            wire += len(chunk)
            protocol.receive_data(chunk)
        elif isinstance(event, h11.Response):
            status = event.status_code
            if evidence is not None:
                evidence.capture(event.headers)
            if 300 <= status < 400 or marker is None:
                return status, None
        elif isinstance(event, h11.Data):
            body.extend(event.data[: MAX_BODY - len(body)])
            if marker in body:
                return status, True
            if len(body) >= MAX_BODY:
                return status, None
        elif isinstance(event, h11.EndOfMessage):
            return status, False if marker is not None else None
        elif event is h11.PAUSED or isinstance(event, h11.ConnectionClosed):
            raise h11.RemoteProtocolError("Incomplete response")


async def observe(
    address: Address,
    target: CheckTarget,
    warning_days: int,
    evidence: ResponseEvidence | None = None,
) -> Outcome:
    started = monotonic()
    writer = None
    tls = target.protocol in ("https", "tls")
    cert = None
    connected = False

    def result(health: Health, connection: str, **fields) -> Outcome:
        return Outcome(
            health=health,
            outcome=connection,
            duration_ms=round((monotonic() - started) * 1000, 3),
            certificate=cert,
            **fields,
        )

    try:
        async with asyncio.timeout(target.timeout_ms / 1000):
            context = None
            if tls:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.load_default_certs()
            reader, writer = await asyncio.open_connection(
                str(address),
                target.port,
                family=socket.AF_INET if address.version == 4 else socket.AF_INET6,
                flags=socket.AI_NUMERICHOST,
                ssl=context,
                server_hostname=(target.hostname or str(address)) if tls else None,
                limit=8192,
            )
            connected = True
            if tls:
                connection = writer.get_extra_info("ssl_object")
                cert = certificate_info(
                    connection.getpeercert(),
                    datetime.now(UTC),
                    warning_days,
                )
                if evidence is not None:
                    evidence.tls_version = connection.version()
                    selected = connection.cipher()
                    evidence.tls_cipher = selected[0] if selected else None
            if target.protocol in ("tcp", "tls"):
                return result("healthy", "connected")
            host = target.hostname or (
                f"[{address}]" if address.version == 6 else str(address)
            )
            status, matched = await read_health(
                reader, writer, target, f"{host}:{target.port}", evidence
            )
            if 300 <= status < 400:
                return result(
                    "degraded",
                    "connected",
                    http_status=status,
                    expected_status=False,
                    error="redirect_blocked",
                )
            expected = target.status_min <= status <= target.status_max
            healthy = expected and (not target.expected_content or matched is True)
            error = (
                None
                if healthy
                else (
                    "unexpected_status"
                    if not expected
                    else "content_mismatch"
                    if matched is False
                    else "content_inconclusive"
                )
            )
            return result(
                "healthy" if healthy else "degraded",
                "connected",
                http_status=status,
                expected_status=expected,
                content_match=matched,
                error=error,
            )
    except ssl.SSLCertVerificationError as error:
        cert = verification_failure(
            getattr(error, "verify_code", None), datetime.now(UTC)
        )
        return result("degraded", "tls_failed", error="certificate_verification")
    except ssl.SSLError:
        return result("degraded", "tls_failed", error="tls_handshake")
    except TimeoutError:
        return result(
            "degraded" if connected else "unreachable", "timeout", error="timeout"
        )
    except ConnectionRefusedError:
        return result("unreachable", "refused", error="refused")
    except h11.RemoteProtocolError:
        return result("degraded", "connected", error="invalid_response")
    except OSError:
        return result("unknown", "network_error", error="socket_error")
    finally:
        if writer is not None:
            writer.close()
            try:
                async with asyncio.timeout(0.15):
                    await writer.wait_closed()
            except (OSError, TimeoutError):
                pass
