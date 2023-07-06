#!python3
# Original from https://github.com/rushter/socks5/blob/master/server.py
# Modified for Pythonista by @nneonneo
# Pretty statistics view and IPv6 support added by @philrosenthal

from io import BytesIO
import logging
from select import select
import socket
import struct
import threading
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
import concurrent.futures
import time
from datetime import datetime
import sys
import ipaddress
import errno
if 'Pythonista' in sys.executable:
    import console
from lib.status import StatusMonitor
from lib.socks5_server import AsyncSocks5Server

logging.basicConfig(level=logging.ERROR)

# IP over which the proxy will be available (probably WiFi IP)
PROXY_HOST = "172.20.10.1"
# IP over which the proxy will attempt to connect to the Internet
CONNECT_HOST_IPV4 = None
CONNECT_HOST_IPV6 = None
# Time out connections after being idle for this long (in seconds)
IDLE_TIMEOUT = 1800

SOCKS_HOST = '0.0.0.0'
SOCKS_PORT = 9876
WPAD_PORT = 80

# Try to keep the screen from turning off (iOS)
try:
    import console
    from objc_util import on_main_thread
    on_main_thread(console.set_idle_timer_disabled)(True)
except ImportError:
    pass

def is_globally_routable(ipv6_address):
    non_routable_networks = [
        "ff00::/8",         # Multicast address range
        "fe80::/10",        # Link-local address range
        "fc00::/7",         # Unique local address range
        "::/8",             # Unspecified address range
        "2001:db8::/32",    # Documentation address range
        "2001::/32",        # Teredo address range
        "2002::/16",        # 6to4 address range
        "ff02::/16",        # Link-local multicast address range
    ]
    for network in non_routable_networks:
        if ipaddress.ip_address(ipv6_address) in ipaddress.ip_network(network):
            return False
    return True

try:
    # TODO: configurable DNS (or find a way to use the cell network's own DNS)
    import dns.asyncresolver
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers += ['1.0.0.1', '1.1.1.1', '8.8.8.8', "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8844"]
except ImportError:
    # pip install dnspython
    print("Warning: dnspython not available; falling back to system DNS")
    resolver = None

try:
    # We want the WiFi address so that clients know what IP to use.
    # We want the non-WiFi (cellular?) address so that we can force network
    #  traffic to go over that network. This allows the proxy to correctly
    #  forward traffic to the cell network even when the WiFi network is
    #  internet-enabled but limited (e.g. firewalled)

    from lib import ifaddrs
    from collections import defaultdict
    initial_output = ''
    ipv4_output = ''
    ipv6_output = ''

    interfaces = ifaddrs.get_interfaces()
    iftypes = defaultdict(list)
    for iface in interfaces:
        if not iface.addr:
            continue
        if iface.name.startswith('lo'):
            continue
        # XXX implement better classification of interfaces
        if iface.name.startswith('en'):
            iftypes['en'].append(iface)
        elif iface.name.startswith('bridge'):
            iftypes['bridge'].append(iface)
        else:
            iftypes['cell'].append(iface)

    if iftypes['bridge']:
        iface = next((iface for iface in iftypes['bridge'] if iface.addr.family == socket.AF_INET), None)
        if iface:
            initial_output = "Assuming proxy will be accessed over hotspot (%s) at %s\n" % (iface.name, iface.addr.address)
            PROXY_HOST = iface.addr.address
    elif iftypes['en']:
        iface = next((iface for iface in iftypes['en'] if iface.addr.family == socket.AF_INET), None)
        if iface:
            initial_output += "Assuming proxy will be accessed over WiFi (%s) at %s\n" % (iface.name, iface.addr.address)
            PROXY_HOST = iface.addr.address
    else:
        initial_output += 'Warning: could not get WiFi address; assuming %s\n' % PROXY_HOST

    if iftypes['cell']:
        iface_ipv4 = next((iface for iface in iftypes['cell'] if iface.addr.family == socket.AF_INET), None)
        iface_ipv6 = None

        if iface_ipv4:
            iface_ipv4.addr.address
            ipv4_output += "Will connect to IPv4 servers over interface %s at %s\n" % (iface_ipv4.name, iface_ipv4.addr.address)
            CONNECT_HOST_IPV4 = iface_ipv4.addr.address

            # Create a list of all IPv6 addresse that are globally routable and match the IPv4 interface
            iface_ipv6_list = [iface for iface in iftypes['cell'] if iface.addr.family == socket.AF_INET6 and iface.addr.address and is_globally_routable(iface.addr.address) and iface.name == iface_ipv4.name]

            # Select the last IPv6 address to select the temporary address for reduced tracking
            iface_ipv6 = iface_ipv6_list[-1] if iface_ipv6_list else None

        if iface_ipv6 is None:
            # Create a list of all IPv6 addresses that are globally routable
            iface_ipv6_list = [iface for iface in iftypes['cell'] if iface.addr.family == socket.AF_INET6 and iface.addr.address and is_globally_routable(iface.addr.address)]

            # Select the last IPv6 address to select the temporary address for reduced tracking
            iface_ipv6 = iface_ipv6_list[-1] if iface_ipv6_list else None

        if iface_ipv6:
            iface_ipv6.addr.address
            ipv6_output += "Will connect to IPv6 servers over interface %s at %s\n" % (iface_ipv6.name, iface_ipv6.addr.address)
            # Test IPv6 connectivity
            try:
                test_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                test_socket.settimeout(5)
                test_socket.bind((iface_ipv6.addr.address, 0))
                test_socket.connect(("2606:4700:4700::1111", 80))
                test_socket.close()
                CONNECT_HOST_IPV6 = iface_ipv6.addr.address
            except Exception as e:
                ipv6_output += "Failed to connect to 2606:4700:4700::1111 over IPv6 due to: %s\n" % str(e)
                CONNECT_HOST_IPV6 = None
            finally:
                test_socket.close()

    initial_output += ipv4_output + ipv6_output
    print(initial_output)
except Exception as e:
    logging.error("Address detection failed: %s: %s", (type(e).__name__, e))
    import traceback
    traceback.print_exc()

    interfaces = None


def create_wpad_server(hhost, hport, phost, pport):
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class HTTPHandler(BaseHTTPRequestHandler):
        def do_HEAD(s):
            s.send_response(200)
            s.send_header("Content-type", "application/x-ns-proxy-autoconfig")
            s.end_headers()

        def do_GET(s):
            s.send_response(200)
            s.send_header("Content-type", "application/x-ns-proxy-autoconfig")
            s.end_headers()
            s.wfile.write(("""
function FindProxyForURL(url, host)
{
   if (isInNet(host, "192.168.0.0", "255.255.0.0")) {
      return "DIRECT";
   } else if (isInNet(host, "172.16.0.0", "255.240.0.0")) {
      return "DIRECT";
   } else if (isInNet(host, "10.0.0.0", "255.0.0.0")) {
      return "DIRECT";
   } else {
      return "SOCKS5 %s:%d; SOCKS %s:%d";
   }
}
""" % (phost, pport, phost, pport)).lstrip().encode())

    HTTPServer.allow_reuse_address = True
    server = HTTPServer((hhost, hport), HTTPHandler)
    return server


def run_wpad_server(server):
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    import asyncio

    wpad_server = create_wpad_server(
        SOCKS_HOST, WPAD_PORT, PROXY_HOST, SOCKS_PORT
    )

    initial_output += "PAC URL: http://{}:{}/wpad.dat\n".format(PROXY_HOST, WPAD_PORT)
    initial_output += "SOCKS Address: {}:{}\n".format(PROXY_HOST or SOCKS_HOST, SOCKS_PORT)
    stats = StatusMonitor(initial_output)
    logging.getLogger().addHandler(stats)

    thread = threading.Thread(target=run_wpad_server, args=(wpad_server,))
    thread.daemon = True
    thread.start()

    async def main():
        server = AsyncSocks5Server(listen_hosts=SOCKS_HOST, listen_port=SOCKS_PORT, traffic_stats=stats, resolver=resolver, connect_host_ipv4=CONNECT_HOST_IPV4, connect_host_ipv6=CONNECT_HOST_IPV6)
        asyncio.create_task(server.run())
        await stats.render_forever()

    try:
        asyncio.run(main())
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down.")
        wpad_server.shutdown()
