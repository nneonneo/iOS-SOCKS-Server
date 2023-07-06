#!python3
# Asynchronous SOCKS5 server with multi-homing support.
# Asyncified from https://github.com/rushter/socks5/blob/master/server.py by @nneonneo
# IPv6 support by @philrosenthal

import asyncio
import logging
import random
import socket
import struct
from asyncio.staggered import staggered_race
from dataclasses import dataclass
from enum import IntEnum
from io import BytesIO
from typing import Sequence

from . import status
from dns.asyncresolver import Resolver
from dns.inet import af_for_address

logger = logging.getLogger("socks5")


SOCKS_VERSION = 5
HAPPY_EYEBALLS_DELAY = 0.05  # seconds
CONNECT_TIMEOUT = 75  # seconds


@dataclass
class GenericAddress:
    ipv4: str | None = None
    ipv6: str | None = None


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


class Socks5AddressType(IntEnum):
    IPV4 = 1
    DOMAIN = 3
    IPV6 = 4


def encode_address(sockaddr=None):
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


async def forwarder_loop(reader, writer, stat_fn):
    while 1:
        buf = await reader.read(65536)
        if not buf:
            break
        stat_fn(len(buf))
        writer.write(buf)
        await writer.drain()
    writer.close()
    await writer.wait_closed()


class UdpForwarderProtocol(asyncio.DatagramProtocol):
    def __init__(self, method):
        self.method = method
        self.loop = asyncio.get_running_loop()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.loop.create_task(self.method(self.transport, data, addr))


class UdpForwarder:
    client_conn: asyncio.DatagramTransport
    server_conn_ipv4: asyncio.DatagramTransport | None
    server_conn_ipv6: asyncio.DatagramTransport | None
    server: "AsyncSocks5Server"
    connections: dict

    def __init__(self, log_tag: str, server: "AsyncSocks5Server", local_address: str):
        self.log_tag = log_tag + " [udp]"
        self.server = server
        self.local_address = local_address
        self.server_conn_ipv4 = None
        self.server_conn_ipv6 = None
        self.connections = {}

    async def start(self):
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

    async def on_client_datagram(self, transport, data, client_addr):
        sockfile = BytesIO(data)
        try:
            # decode header
            _, frag, address_type = self.readstruct(sockfile, "!HBB")
            assert frag == 0, "UDP fragmentation is not supported"
            address, port = self.read_addrport(address_type, sockfile)
            assert address is not None, "Address type is not supported"
            payload = sockfile.read()
            self.server.traffic_stats.add_outbound(len(payload))

            resolved = await self.server.resolve_address(address_type, address)
            if resolved.ipv6 and self.server_conn_ipv6:
                self.connections[
                    self.server_conn_ipv6, (resolved.ipv6, port)
                ] = client_addr
                self.server_conn_ipv6.sendto(payload, (resolved.ipv6, port))
            elif resolved.ipv4 and self.server_conn_ipv4:
                self.connections[
                    self.server_conn_ipv4, (resolved.ipv4, port)
                ] = client_addr
                self.server_conn_ipv4.sendto(payload, (resolved.ipv4, port))
            else:
                logging.info(
                    "%s: unable to send UDP packet to %s", self.log_tag, address
                )
        except Exception as e:
            logging.info("%s: malformed udp packet: %s", self.log_tag, e)

    async def on_server_datagram(self, transport, data, addr):
        self.server.traffic_stats.add_inbound(len(data))

        client_addr = self.connections.get((transport, addr[:2]), None)
        if client_addr is None:
            logging.warning(
                "%s: got packet from unknown sender %s", self.log_tag, *addr
            )
            return

        header = struct.pack("!HB", 0, 0) + encode_address(addr)
        self.client_conn.sendto(header + data, client_addr)

    def readall(self, f, n):
        res = bytearray()
        while len(res) < n:
            chunk = f.read(n - len(res))
            if not chunk:
                raise EOFError()
            res += chunk
        return bytes(res)

    def readstruct(self, f, fmt):
        return struct.unpack(fmt, self.readall(f, struct.calcsize(fmt)))

    def read_addrport(self, address_type, sockf):
        if address_type == Socks5AddressType.IPV4:
            address = socket.inet_ntop(socket.AF_INET, self.readall(sockf, 4))
        elif address_type == Socks5AddressType.DOMAIN:
            domain_length = ord(self.readall(sockf, 1))
            address = self.readall(sockf, domain_length).decode()
        elif address_type == Socks5AddressType.IPV6:
            address = socket.inet_ntop(socket.AF_INET6, self.readall(sockf, 16))
        else:
            return None, None
        (port,) = self.readstruct(sockf, "!H")
        return address, port

    def close(self):
        self.client_conn.close()
        if self.server_conn_ipv4:
            self.server_conn_ipv4.close()
        if self.server_conn_ipv6:
            self.server_conn_ipv6.close()


class AsyncSocks5Handler:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    server: "AsyncSocks5Server"
    log_tag: str

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        server: "AsyncSocks5Server",
    ):
        self.reader = reader
        self.writer = writer
        self.server = server

        peer_addr = writer.get_extra_info("peername")
        if peer_addr is None:
            self.log_tag = "<unknown>"
        elif len(peer_addr) == 2:
            # IPv4
            self.log_tag = "%s:%s" % peer_addr
        elif len(peer_addr) == 4:
            # IPv6
            self.log_tag = "[%s]:%s" % peer_addr[:2]
        else:
            self.log_tag = "[%s]" % (peer_addr,)

    def send_reply(self, status: Socks5Status, bindaddr=None):
        reply = struct.pack("!BBB", SOCKS_VERSION, status, 0)
        reply += encode_address(bindaddr)
        self.writer.write(reply)

    async def readstruct(self, fmt: str) -> tuple:
        data = await self.reader.readexactly(struct.calcsize(fmt))
        return struct.unpack(fmt, data)

    async def _handle(self):
        # receive client's auth methods
        version, nmethods = await self.readstruct("!BB")
        if version != SOCKS_VERSION:
            raise Exception(
                "Invalid version %r (not configured as SOCKS proxy?)" % chr(version)
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

        address, port = await self.read_addrport(address_type)
        if address is None:
            self.send_reply(Socks5Status.EAFNOSUPPORT)
            raise Exception("Unsupported address type %d" % address_type)

        # reply
        if cmd == 1:  # CONNECT
            await self.handle_connect(address_type, address, port)
        elif cmd == 3:  # UDP ASSOCIATE
            # ignore the request host: the client might not actually know
            # its own address
            client_address = self.writer.get_extra_info("peername")
            if client_address:
                await self.handle_udp(client_address[0], port)
            else:
                await self.handle_udp(address, port)
        else:
            self.send_reply(Socks5Status.ENOTSUP)
            raise Exception("Command %d unsupported" % cmd)

    async def handle(self):
        try:
            await self._handle()
        except Exception as e:
            logger.error("%s: %s: %s", self.log_tag, type(e).__name__, e)
        finally:
            if not self.writer.is_closing():
                self.writer.close()
                await self.writer.wait_closed()

    async def read_addrport(self, address_type: int) -> tuple[str | None, int | None]:
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
            return None, None

        (port,) = await self.readstruct("!H")
        return address, port

    async def handle_connect(self, address_type, address, port):
        resolved = await self.server.resolve_address(address_type, address)

        try:
            if resolved.ipv4 is not None and resolved.ipv6 is not None:
                # happy eyeballs
                result, result_index, exceptions = await staggered_race(
                    [
                        lambda: self.server.ipv6_connect(resolved.ipv6, port),
                        lambda: self.server.ipv4_connect(resolved.ipv4, port),
                    ],
                    delay=HAPPY_EYEBALLS_DELAY,
                )
                if not result:
                    raise exceptions[0]
                connection = result
            elif resolved.ipv4 is not None:
                connection = await self.server.ipv4_connect(resolved.ipv4, port)
            elif resolved.ipv6 is not None:
                connection = await self.server.ipv6_connect(resolved.ipv6, port)
            else:
                raise Exception("Host %s could not be resolved" % address)
        except Exception as e:
            self.send_reply(Socks5Status.EHOSTUNREACH)
            raise e

        self.send_reply(Socks5Status.SUCCEEDED)

        s_reader, s_writer = connection
        await asyncio.gather(
            forwarder_loop(
                s_reader, self.writer, self.server.traffic_stats.add_inbound
            ),
            forwarder_loop(
                self.reader, s_writer, self.server.traffic_stats.add_outbound
            ),
            return_exceptions=True,
        )

    async def handle_udp(self, address, port):
        csock_addr = self.writer.get_extra_info("sockname")[0]

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


class AsyncSocks5Server:
    listen_hosts: str | Sequence[str]
    listen_port: int
    traffic_stats: status.TrafficStats
    resolver: Resolver
    resolver_source: str | None
    connect_host_ipv4: str | None
    connect_host_ipv6: str | None

    def __init__(
        self,
        listen_hosts: str | Sequence[str] = ("::", "0.0.0.0"),
        listen_port: int = 9876,
        traffic_stats: status.TrafficStats | None = None,
        resolver: Resolver | None = None,
        connect_host_ipv4: str | None = None,
        connect_host_ipv6: str | None = None,
    ):
        self.listen_hosts = listen_hosts
        self.listen_port = listen_port
        self.traffic_stats = traffic_stats or status.SimpleTrafficStats()
        self.resolver = resolver or Resolver()
        self.connect_host_ipv4 = connect_host_ipv4
        self.connect_host_ipv6 = connect_host_ipv6
        if self.connect_host_ipv4 is not None or self.connect_host_ipv6 is not None:
            resolver_afs = [af_for_address(ns) for ns in self.resolver.nameservers]
            if (
                any(af == socket.AF_INET for af in resolver_afs)
                and self.connect_host_ipv4 is not None
            ):
                self.resolver_source = self.connect_host_ipv4
                self.resolver.nameservers = [
                    ns
                    for ns in self.resolver.nameservers
                    if af_for_address(ns) == socket.AF_INET
                ]
            elif (
                any(af == socket.AF_INET6 for af in resolver_afs)
                and self.connect_host_ipv6 is not None
            ):
                self.resolver_source = self.connect_host_ipv4
                self.resolver.nameservers = [
                    ns
                    for ns in self.resolver.nameservers
                    if af_for_address(ns) == socket.AF_INET6
                ]
            else:
                raise Exception("Resolver does not have any suitable nameservers!")
        else:
            self.resolver_source = None

    async def run(self):
        server = await asyncio.start_server(
            self.client_connected,
            host=self.listen_hosts,
            port=self.listen_port,
            reuse_address=True,
        )
        await server.serve_forever()

    async def client_connected(self, reader, writer):
        handler = AsyncSocks5Handler(reader, writer, server=self)
        self.traffic_stats.add_connection()
        try:
            await handler.handle()
        finally:
            self.traffic_stats.remove_connection()

    async def ipv4_connect(self, address, port):
        local_addr = (
            (self.connect_host_ipv4, 0) if self.connect_host_ipv4 is not None else None
        )
        return await asyncio.wait_for(
            asyncio.open_connection(address, port, local_addr=local_addr),
            timeout=CONNECT_TIMEOUT,
        )

    async def ipv6_connect(self, address, port):
        local_addr = (
            (self.connect_host_ipv6, 0) if self.connect_host_ipv6 is not None else None
        )
        return await asyncio.wait_for(
            asyncio.open_connection(address, port, local_addr=local_addr),
            timeout=CONNECT_TIMEOUT,
        )

    async def _resolve_domain(self, address: str) -> GenericAddress:
        result = GenericAddress()
        try:
            socket.inet_pton(socket.AF_INET, address)
            result.ipv4 = address
            return result
        except Exception:
            pass

        try:
            socket.inet_pton(socket.AF_INET6, address)
            result.ipv6 = address
            return result
        except Exception:
            pass

        ipv4, ipv6 = await asyncio.gather(
            self.resolver.resolve(address, "A", source=self.resolver_source),
            self.resolver.resolve(address, "AAAA", source=self.resolver_source),
            return_exceptions=True,
        )
        if not isinstance(ipv4, BaseException) and ipv4:
            result.ipv4 = random.choice(ipv4).address
        if not isinstance(ipv6, BaseException) and ipv6:
            result.ipv6 = random.choice(ipv6).address
        return result

    async def resolve_address(self, address_type: int, address: str) -> GenericAddress:
        if address_type == Socks5AddressType.IPV4:
            result = GenericAddress(ipv4=address)
        elif address_type == Socks5AddressType.DOMAIN:
            result = await self._resolve_domain(address)
        elif address_type == Socks5AddressType.IPV6:
            result = GenericAddress(ipv6=address)

        if self.connect_host_ipv4 is None and self.connect_host_ipv6 is not None:
            result.ipv4 = None
        elif self.connect_host_ipv4 is not None and self.connect_host_ipv6 is None:
            result.ipv6 = None

        return result


if __name__ == "__main__":

    stats = status.StatusMonitor("SOCKS5 Server", interval=1)
    logging.getLogger().addHandler(stats)

    async def main():
        server = AsyncSocks5Server(traffic_stats=stats)
        asyncio.create_task(server.run())
        await stats.render_forever()

    asyncio.run(main())
