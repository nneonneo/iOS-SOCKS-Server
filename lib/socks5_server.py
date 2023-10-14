#!python3
# Asynchronous SOCKS5 proxy server with multi-homing support.
# Asyncified from https://github.com/rushter/socks5/blob/master/server.py by @nneonneo
# IPv6 support by @philrosenthal

import asyncio
import logging
import socket
import struct
from enum import IntEnum
from io import BytesIO
from typing import Any, BinaryIO, Callable, Coroutine

from . import status
from .proxy_server import (
    AsyncProxyHandler,
    AsyncProxyServer,
    SocketAddress,
    Socks5AddressType,
)

logger = logging.getLogger("socks5")


SOCKS_VERSION = 5


class Socks5Status(IntEnum):
    SUCCEEDED = 0  # succeeded
    ERROR = 1  # general SOCKS server failure
    EPERM = 2  # connection not allowed by ruleset
    ENETDOWN = 3  # Network unreachable
    EHOSTUNREACH = 4  # Host unreachable
    ECONNREFUSED = 5  # Connection refused
    ETIMEDOUT = 6  # TTL expired
    ENOTSUP = 7  # Command not supported
    EAFNOSUPPORT = 8  # Address type not supported


def encode_address(sockaddr: SocketAddress | None = None) -> bytes:
    # encode sockaddr as SOCKS5 address
    if sockaddr is None:
        return struct.pack("!BIH", Socks5AddressType.IPV4, 0, 0)

    address, port = sockaddr
    try:
        addrbytes = socket.inet_pton(socket.AF_INET, address)
        return struct.pack("!B4sH", Socks5AddressType.IPV4, addrbytes, port)
    except Exception:
        addrbytes = socket.inet_pton(socket.AF_INET6, address)
        return struct.pack("!B16sH", Socks5AddressType.IPV6, addrbytes, port)


class UdpForwarderProtocol(asyncio.DatagramProtocol):
    def __init__(
        self,
        method: Callable[
            [asyncio.DatagramTransport, bytes, SocketAddress],
            Coroutine[None, None, None],
        ],
    ):
        self.method = method
        self.loop = asyncio.get_running_loop()

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: SocketAddress) -> None:
        self.loop.create_task(self.method(self.transport, data, addr[:2]))


class UdpForwarder:
    def __init__(self, log_tag: str, server: "AsyncProxyServer", local_address: str):
        self.log_tag = log_tag + " [udp]"
        self.server = server
        self.local_address = local_address
        self.server_conn_ipv4: asyncio.DatagramTransport | None = None
        self.server_conn_ipv6: asyncio.DatagramTransport | None = None
        self.connections: dict[
            tuple[asyncio.DatagramTransport, SocketAddress], SocketAddress
        ] = {}

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self.client_conn, _ = await loop.create_datagram_endpoint(
            lambda: UdpForwarderProtocol(self.on_client_datagram),
            local_addr=(self.local_address, 0),
        )

        connect_host_ipv4 = self.server.connect_host_ipv4
        connect_host_ipv6 = self.server.connect_host_ipv6

        if connect_host_ipv4 is None and connect_host_ipv6 is None:
            connect_host_ipv4 = "0.0.0.0"
            connect_host_ipv6 = "::"

        if connect_host_ipv4 is not None:
            self.server_conn_ipv4, _ = await loop.create_datagram_endpoint(
                lambda: UdpForwarderProtocol(self.on_server_datagram),
                local_addr=(connect_host_ipv4, 0),
            )

        if connect_host_ipv6 is not None:
            self.server_conn_ipv6, _ = await loop.create_datagram_endpoint(
                lambda: UdpForwarderProtocol(self.on_server_datagram),
                local_addr=(connect_host_ipv6, 0),
            )

    async def on_client_datagram(
        self,
        transport: asyncio.DatagramTransport,
        data: bytes,
        client_addr: SocketAddress,
    ) -> None:
        sockfile = BytesIO(data)
        try:
            # decode header
            _, frag, address_type = self.readstruct(sockfile, "!HBB")
            assert frag == 0, "UDP fragmentation is not supported"
            address = self.read_addrport(address_type, sockfile)
            assert address is not None, "Address type is not supported"
            payload = sockfile.read()
            self.server.traffic_stats.add_outbound(len(payload))

            resolved = await self.server.resolve_address(address_type, address)
            if resolved.ipv6 and self.server_conn_ipv6:
                self.connections[self.server_conn_ipv6, resolved.ipv6] = client_addr
                self.server_conn_ipv6.sendto(payload, resolved.ipv6)
            elif resolved.ipv4 and self.server_conn_ipv4:
                self.connections[self.server_conn_ipv4, resolved.ipv4] = client_addr
                self.server_conn_ipv4.sendto(payload, resolved.ipv4)
            else:
                logging.info(
                    "%s: unable to send UDP packet to %s", self.log_tag, address
                )
        except Exception as e:
            logging.info("%s: malformed udp packet: %s", self.log_tag, e)

    async def on_server_datagram(
        self, transport: asyncio.DatagramTransport, data: bytes, addr: SocketAddress
    ) -> None:
        self.server.traffic_stats.add_inbound(len(data))

        client_addr = self.connections.get((transport, addr), None)
        if client_addr is None:
            logging.warning(
                "%s: got packet from unknown sender %s", self.log_tag, *addr
            )
            return

        header = struct.pack("!HB", 0, 0) + encode_address(addr)
        self.client_conn.sendto(header + data, client_addr)

    def readall(self, f: BinaryIO, n: int) -> bytes:
        res = bytearray()
        while len(res) < n:
            chunk = f.read(n - len(res))
            if not chunk:
                raise EOFError()
            res += chunk
        return bytes(res)

    def readstruct(self, f: BinaryIO, fmt: str) -> tuple[Any, ...]:
        return struct.unpack(fmt, self.readall(f, struct.calcsize(fmt)))

    def read_addrport(self, address_type: int, sockf: BinaryIO) -> SocketAddress | None:
        if address_type == Socks5AddressType.IPV4:
            address = socket.inet_ntop(socket.AF_INET, self.readall(sockf, 4))
        elif address_type == Socks5AddressType.DOMAIN:
            domain_length = ord(self.readall(sockf, 1))
            address = self.readall(sockf, domain_length).decode()
        elif address_type == Socks5AddressType.IPV6:
            address = socket.inet_ntop(socket.AF_INET6, self.readall(sockf, 16))
        else:
            return None
        (port,) = self.readstruct(sockf, "!H")
        return address, port

    def close(self) -> None:
        self.client_conn.close()
        if self.server_conn_ipv4:
            self.server_conn_ipv4.close()
        if self.server_conn_ipv6:
            self.server_conn_ipv6.close()


class AsyncSocks5Handler(AsyncProxyHandler):
    def send_reply(
        self, status: Socks5Status, bindaddr: tuple[str, int] | None = None
    ) -> None:
        reply = struct.pack("!BBB", SOCKS_VERSION, status, 0)
        reply += encode_address(bindaddr)
        self.writer.write(reply)

    async def readstruct(self, fmt: str) -> tuple[Any, ...]:
        data = await self.reader.readexactly(struct.calcsize(fmt))
        return struct.unpack(fmt, data)

    async def _handle(self) -> None:
        # receive client's auth methods
        version, nmethods = await self.readstruct("!BB")
        if version != SOCKS_VERSION:
            raise Exception(
                "Invalid version %r (not configured as unencrypted SOCKS proxy?)"
                % chr(version)
            )

        # get available methods
        methods = await self.reader.readexactly(nmethods)

        # accept only NONE auth
        if 0 not in methods:
            # no acceptable methods - fail with method 255
            self.writer.write(struct.pack("!BB", SOCKS_VERSION, 0xFF))
            raise Exception("Unsupported auth methods %s" % str(methods))

        # send welcome with auth method 0=NONE
        self.writer.write(struct.pack("!BB", SOCKS_VERSION, 0))
        version, cmd, _, address_type = await self.readstruct("!BBBB")
        if version != SOCKS_VERSION:
            raise Exception("Invalid version %r after auth" % chr(version))

        address = await self.read_addrport(address_type)
        if address is None:
            self.send_reply(Socks5Status.EAFNOSUPPORT)
            raise Exception("Unsupported address type %d" % address_type)

        # reply
        if cmd == 1:  # CONNECT
            await self.handle_connect(address_type, address)
        elif cmd == 3:  # UDP ASSOCIATE
            # ignore the request host: the client might not actually know
            # its own address
            client_address = self.writer.get_extra_info("peername")
            if client_address:
                address = (client_address[0], address[1])
            await self.handle_udp(address)
        else:
            self.send_reply(Socks5Status.ENOTSUP)
            raise Exception("Command %d unsupported" % cmd)

    async def handle(self) -> None:
        try:
            await self._handle()
        except Exception as e:
            logger.error("%s: %s: %s", self.log_tag, type(e).__name__, e)
        finally:
            if not self.writer.is_closing():
                self.writer.close()
                await self.writer.wait_closed()

    async def read_addrport(self, address_type: int) -> SocketAddress | None:
        if address_type == Socks5AddressType.IPV4:
            ip = await self.reader.readexactly(4)
            address = socket.inet_ntop(socket.AF_INET, ip)
        elif address_type == Socks5AddressType.DOMAIN:
            domain_length = ord(await self.reader.readexactly(1))
            address = (await self.reader.readexactly(domain_length)).decode()
        elif address_type == Socks5AddressType.IPV6:
            ip = await self.reader.readexactly(16)
            address = socket.inet_ntop(socket.AF_INET6, ip)
        else:
            return None

        (port,) = await self.readstruct("!H")
        return address, port

    async def handle_connect(self, address_type: int, address: SocketAddress) -> None:
        try:
            connection = await self.server.tcp_connect(address_type, address)
        except Exception as e:
            self.send_reply(Socks5Status.EHOSTUNREACH)
            raise e

        self.send_reply(Socks5Status.SUCCEEDED)
        await self.tcp_forward(connection)

    async def handle_udp(self, client_address: SocketAddress) -> None:
        csock_addr = self.writer.get_extra_info("sockname")[0]

        # TODO: restrict incoming packets to client address
        try:
            udp_forwarder = UdpForwarder(self.log_tag, self.server, csock_addr)
            await udp_forwarder.start()
        except Exception as e:
            self.send_reply(Socks5Status.ERROR)
            raise e

        csock_port = udp_forwarder.client_conn.get_extra_info("sockname")[1]

        self.send_reply(Socks5Status.SUCCEEDED, (csock_addr, csock_port))
        try:
            while True:
                chunk = await self.reader.read(4096)
                if not chunk:
                    break
        finally:
            udp_forwarder.close()


if __name__ == "__main__":
    # Testing purposes only
    stats = status.StatusMonitor("SOCKS5 Server", interval=1)
    logging.getLogger().addHandler(stats)

    async def main() -> None:
        server = AsyncProxyServer(AsyncSocks5Handler, traffic_stats=stats)
        asyncio.create_task(server.run())
        await stats.render_forever()

    asyncio.run(main())
