import socket
from collections.abc import Callable
from contextlib import contextmanager
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from threading import Lock
from time import monotonic, sleep
from typing import Literal

from fastapi import HTTPException

Address = IPv4Address | IPv6Address
Availability = Literal["reachable", "unreachable", "unknown"]
ProbeError = Literal[
    "timeout", "refused", "socket_error", "approval_changed", "scope_denied"
]
LAB_NETWORKS = tuple(
    map(
        ip_network,
        (
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "::1/128",
            "fc00::/7",
        ),
    )
)


def parse_address(value: str) -> Address:
    address = ip_address(value)
    if "%" in value or (isinstance(address, IPv6Address) and address.ipv4_mapped):
        raise ValueError("Use an unscoped IPv4 or IPv6 literal.")
    return address


def probe_tcp_details(
    address: Address, port: int
) -> tuple[Availability, ProbeError | None]:
    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    try:
        with socket.socket(family, socket.SOCK_STREAM) as transport:
            transport.settimeout(0.75)
            transport.connect((str(address), port))
    except TimeoutError:
        return "unreachable", "timeout"
    except ConnectionRefusedError:
        return "unreachable", "refused"
    except OSError:
        return "unknown", "socket_error"
    return "reachable", None


class Scope:
    def __init__(self, entries: list[str], port: int, discovery_limit: int):
        self.networks = tuple(ip_network(entry, strict=True) for entry in entries)
        if not self.networks or any(
            not any(
                network.version == lab.version and network.subnet_of(lab)
                for lab in LAB_NETWORKS
            )
            or "%" in str(network)
            for network in self.networks
        ):
            raise ValueError(
                "Approved scope must contain loopback or private laboratory ranges."
            )
        self.port = port
        self.discovery_limit = discovery_limit
        self._lock = Lock()
        self._next_probe = 0.0

    def allows(self, address: Address) -> bool:
        matching = [network for network in self.networks if address in network]
        if not isinstance(address, IPv4Address):
            return bool(matching)
        containing = matching + [
            network for network in LAB_NETWORKS if address in network
        ]
        return bool(matching) and not any(
            network.prefixlen < 31
            and address in (network.network_address, network.broadcast_address)
            for network in containing
        )

    def require(self, value: str) -> Address:
        try:
            address = parse_address(value)
        except ValueError:
            raise HTTPException(422, "Enter a supported IP address.") from None
        if not self.allows(address):
            raise HTTPException(403, "IP address is outside the approved scope.")
        return address

    @contextmanager
    def operation(self, *, wait_for_cooldown: bool = False):
        if not self._lock.acquire(blocking=False):
            raise HTTPException(429, "A network operation is already running.")
        try:
            if not wait_for_cooldown and monotonic() < self._next_probe:
                raise HTTPException(
                    429, "Wait before starting another network operation."
                )
            yield
        finally:
            self._lock.release()

    def _prepare_probe(
        self, value: str, before: Callable[[], None] | None = None
    ) -> Address:
        sleep(max(0, self._next_probe - monotonic()))
        if before is not None:
            before()
        return self.reserve(value)

    def reserve(self, value: str) -> Address:
        """Validate the literal and reserve a connection while holding the operation lock."""
        address = self.require(value)
        self._next_probe = monotonic() + 1
        return address

    def cooldown_remaining(self) -> float:
        return max(0.0, self._next_probe - monotonic())

    def probe_service(
        self, value: str, port: int, before: Callable[[], None] | None = None
    ) -> tuple[Availability, ProbeError | None, float]:
        address = self._prepare_probe(value, before)
        started = monotonic()
        status, category = probe_tcp_details(address, port)
        return status, category, round(max(0, monotonic() - started) * 1000, 3)
