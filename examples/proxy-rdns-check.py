"""Self-contained integration check for the WHOIS proxy ``rdns`` option.

No Internet connection or real proxy is required. The script starts a minimal
local SOCKS5 server, makes two WHOIS queries, and prints the destination that
the proxy received in each case.
"""

import socket
import struct
import threading
from typing import Optional

from asyncwhois.query import Query


DESTINATION_HOST = "localhost"
DESTINATION_PORT = 43
WHOIS_RESPONSE = b"Domain Name: EXAMPLE.TEST\r\n"


def recv_exact(connection: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise ConnectionError("SOCKS5 client closed the connection")
        result.extend(chunk)
    return bytes(result)


class RecordingSocks5Proxy:
    """Minimal SOCKS5 server that records CONNECT destinations."""

    def __init__(self, expected_connections: int):
        self.destinations: list[tuple[str, str, int]] = []
        self.error: Optional[BaseException] = None
        self.expected_connections = expected_connections
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen()
        self.server.settimeout(5)
        self.port = self.server.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.thread.join(timeout=6)
        self.server.close()
        if self.thread.is_alive():
            raise RuntimeError("The local SOCKS5 server did not stop")
        if self.error is not None:
            raise self.error

    def _serve(self) -> None:
        try:
            for _ in range(self.expected_connections):
                connection, _ = self.server.accept()
                with connection:
                    self._handle_connection(connection)
        except BaseException as error:
            self.error = error

    def _handle_connection(self, connection: socket.socket) -> None:
        version, method_count = recv_exact(connection, 2)
        if version != 5:
            raise ValueError(f"Expected SOCKS5, received version {version}")
        recv_exact(connection, method_count)
        connection.sendall(b"\x05\x00")  # SOCKS5, no authentication

        version, command, _, address_type = recv_exact(connection, 4)
        if version != 5 or command != 1:
            raise ValueError("Expected a SOCKS5 CONNECT request")

        if address_type == 1:
            host = socket.inet_ntop(socket.AF_INET, recv_exact(connection, 4))
            address_kind = "IPv4"
        elif address_type == 3:
            length = recv_exact(connection, 1)[0]
            host = recv_exact(connection, length).decode("idna")
            address_kind = "DOMAIN"
        elif address_type == 4:
            host = socket.inet_ntop(socket.AF_INET6, recv_exact(connection, 16))
            address_kind = "IPv6"
        else:
            raise ValueError(f"Unknown SOCKS5 address type: {address_type}")

        port = struct.unpack("!H", recv_exact(connection, 2))[0]
        self.destinations.append((address_kind, host, port))

        # Report a successful CONNECT, then behave like the requested WHOIS server.
        connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
        request = bytearray()
        while not request.endswith(b"\r\n"):
            chunk = connection.recv(1024)
            if not chunk:
                raise ConnectionError("WHOIS client closed before sending a query")
            request.extend(chunk)
        connection.sendall(WHOIS_RESPONSE)


def query_through(proxy_url: str, rdns: bool) -> str:
    query = Query(
        proxy_url=proxy_url,
        find_authoritative_server=False,
        rdns=rdns,
    )
    return query.run("example.test", server=DESTINATION_HOST)[0]


def main() -> None:
    with RecordingSocks5Proxy(expected_connections=2) as proxy:
        proxy_url = f"socks5://127.0.0.1:{proxy.port}"
        remote_response = query_through(proxy_url, rdns=True)
        local_response = query_through(proxy_url, rdns=False)

    remote_destination, local_destination = proxy.destinations
    print(
        "rdns=True  -> proxy received "
        f"{remote_destination[0]} {remote_destination[1]}:{remote_destination[2]}"
    )
    print(
        "rdns=False -> proxy received "
        f"{local_destination[0]} {local_destination[1]}:{local_destination[2]}"
    )

    remote_dns_works = remote_destination == (
        "DOMAIN",
        DESTINATION_HOST,
        DESTINATION_PORT,
    )
    local_dns_works = (
        local_destination[0] in {"IPv4", "IPv6"}
        and local_destination[2] == DESTINATION_PORT
    )
    responses_work = remote_response == local_response == WHOIS_RESPONSE.decode()

    if not (remote_dns_works and local_dns_works and responses_work):
        raise SystemExit("FAIL: rdns behavior did not match expectations")
    print("PASS: remote and local DNS modes both work as expected")


if __name__ == "__main__":
    main()
