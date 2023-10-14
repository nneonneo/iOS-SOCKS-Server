""" General base class for proxies """

import asyncio
import random
import socket
from asyncio.staggered import staggered_race
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Sequence, Type

from dns.asyncresolver import Resolver
from dns.inet import af_for_address

from . import status

SocketAddress = tuple[str, int]
Connection = tuple[asyncio.StreamReader, asyncio.StreamWriter]


@dataclass
class GenericAddress:
    ipv4: SocketAddress | None = None
    ipv6: SocketAddress | None = None


HAPPY_EYEBALLS_DELAY = 0.05  # seconds
CONNECT_TIMEOUT = 75  # seconds


async def forwarder_loop(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    stat_fn: Callable[[int], None],
) -> None:
    try:
        while 1:
            buf = await reader.read(65536)
            if not buf:
                break
            stat_fn(len(buf))
            writer.write(buf)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


# XXX: should make this a more generic address type enum and convert from socks5
class Socks5AddressType(IntEnum):
    IPV4 = 1
    DOMAIN = 3
    IPV6 = 4


class AsyncProxyHandler:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        server: "AsyncProxyServer",
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

    async def tcp_forward(self, connection: Connection) -> None:
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

    async def handle(self) -> None:
        pass


class AsyncProxyServer:
    def __init__(
        self,
        handler_class: Type[AsyncProxyHandler],
        listen_hosts: str | Sequence[str] = ("::", "0.0.0.0"),
        listen_port: int = 9876,
        traffic_stats: status.TrafficStats | None = None,
        resolver: Resolver | None = None,
        connect_host_ipv4: str | None = None,
        connect_host_ipv6: str | None = None,
    ):
        self.handler_class = handler_class
        self.listen_hosts = listen_hosts
        self.listen_port = listen_port
        self.traffic_stats = traffic_stats or status.SimpleTrafficStats()
        self.resolver = resolver or Resolver()
        self.connect_host_ipv4 = connect_host_ipv4
        self.connect_host_ipv6 = connect_host_ipv6
        self.resolver_source: str | None = None
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
                self.resolver_source = self.connect_host_ipv6
                self.resolver.nameservers = [
                    ns
                    for ns in self.resolver.nameservers
                    if af_for_address(ns) == socket.AF_INET6
                ]
            else:
                raise Exception("Resolver does not have any suitable nameservers!")

    async def run(self) -> None:
        server = await asyncio.start_server(
            self.client_connected,
            host=self.listen_hosts,
            port=self.listen_port,
            reuse_address=True,
        )
        await server.serve_forever()

    async def client_connected(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        handler = self.handler_class(reader, writer, server=self)
        self.traffic_stats.add_connection()
        try:
            await handler.handle()
        finally:
            self.traffic_stats.remove_connection()

    async def ipv4_connect(self, address: SocketAddress) -> Connection:
        local_addr = (
            (self.connect_host_ipv4, 0) if self.connect_host_ipv4 is not None else None
        )
        return await asyncio.wait_for(
            asyncio.open_connection(address[0], address[1], local_addr=local_addr),
            timeout=CONNECT_TIMEOUT,
        )

    async def ipv6_connect(self, address: SocketAddress) -> Connection:
        local_addr = (
            (self.connect_host_ipv6, 0) if self.connect_host_ipv6 is not None else None
        )
        return await asyncio.wait_for(
            asyncio.open_connection(address[0], address[1], local_addr=local_addr),
            timeout=CONNECT_TIMEOUT,
        )

    async def tcp_connect(
        self, address_type: int, address: SocketAddress
    ) -> Connection:
        resolved = await self.resolve_address(address_type, address)

        if resolved.ipv4 is not None and resolved.ipv6 is not None:
            ipv6_addr = resolved.ipv6
            ipv4_addr = resolved.ipv4
            # happy eyeballs
            result, result_index, exceptions = await staggered_race(
                [
                    lambda: self.ipv6_connect(ipv6_addr),
                    lambda: self.ipv4_connect(ipv4_addr),
                ],
                delay=HAPPY_EYEBALLS_DELAY,
            )
            if not result:
                raise exceptions[0]
            return result
        elif resolved.ipv4 is not None:
            return await self.ipv4_connect(resolved.ipv4)
        elif resolved.ipv6 is not None:
            return await self.ipv6_connect(resolved.ipv6)
        else:
            raise Exception("Host %s could not be resolved" % (address,))

    async def dummy_resolve(self):
        raise Exception("address family not supported")

    async def _resolve_domain(self, address: SocketAddress) -> GenericAddress:
        domain, port = address

        result = GenericAddress()
        try:
            socket.inet_pton(socket.AF_INET, domain)
            result.ipv4 = address
            return result
        except Exception:
            pass

        try:
            socket.inet_pton(socket.AF_INET6, domain)
            result.ipv6 = address
            return result
        except Exception:
            pass

        if self.connect_host_ipv4 is None and self.connect_host_ipv6 is not None:
            ipv4_resolver = self.dummy_resolve()
        else:
            ipv4_resolver = self.resolver.resolve(
                domain, "A", source=self.resolver_source
            )

        if self.connect_host_ipv4 is not None and self.connect_host_ipv6 is None:
            ipv6_resolver = self.dummy_resolve()
        else:
            ipv6_resolver = self.resolver.resolve(
                domain, "AAAA", source=self.resolver_source
            )

        ipv4, ipv6 = await asyncio.gather(
            ipv4_resolver,
            ipv6_resolver,
            return_exceptions=True,
        )
        if not isinstance(ipv4, BaseException) and ipv4:
            result.ipv4 = (random.choice(ipv4).address, port)
        if not isinstance(ipv6, BaseException) and ipv6:
            result.ipv6 = (random.choice(ipv6).address, port)
        return result

    async def resolve_address(
        self, address_type: int, address: SocketAddress
    ) -> GenericAddress:
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
