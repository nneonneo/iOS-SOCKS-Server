#!python3
# Original from https://github.com/rushter/socks5/blob/master/server.py
# Modified for Pythonista by @nneonneo

import logging
import select
import socket
import struct
import threading
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler

# IP over which the proxy will be available
PROXY_HOST = "172.20.10.1"
CONNECT_HOST = None

# Try to keep the screen from turning off (iOS)
try:
    import console
    from objc_util import on_main_thread
    on_main_thread(console.set_idle_timer_disabled)(True)
except ImportError:
    pass

try:
    # We want the WiFi address so that clients know what IP to use.
    # We want the non-WiFi (cellular?) address so that we can force network
    #  traffic to go over that network. This allows the proxy to correctly
    #  forward traffic to the cell network even when the WiFi network is
    #  internet-enabled but limited (e.g. firewalled)

    import ifaddrs
    from collections import defaultdict
    interfaces = ifaddrs.get_interfaces()
    iftypes = defaultdict(list)
    for iface in interfaces:
        if not iface.addr:
            continue
        if iface.name.startswith('lo'):
            continue
        # TODO IPv6 support someday
        if iface.addr.family != socket.AF_INET:
            continue
        # XXX implement better classification of interfaces
        if iface.name.startswith('en'):
            iftypes['en'].append(iface)
        elif iface.name.startswith('bridge'):
            iftypes['bridge'].append(iface)
        else:
            iftypes['cell'].append(iface)

    if iftypes['bridge']:
        iface = iftypes['bridge'][0]
        print("Assuming proxy will be accessed over hotspot bridge interface %s at %s" %
              (iface.name, iface.addr.address))
        PROXY_HOST = iface.addr.address
    elif iftypes['en']:
        iface = iftypes['en'][0]
        print("Assuming proxy will be accessed over WiFi interface %s at %s" %
              (iface.name, iface.addr.address))
        PROXY_HOST = iface.addr.address
    else:
        print('Warning: could not get WiFi address; assuming %s' % PROXY_HOST)

    if iftypes['cell']:
        iface = iftypes['cell'][0]
        print("Will connect to servers over interface %s at %s" %
              (iface.name, iface.addr.address))
        CONNECT_HOST = iface.addr.address
except Exception as e:
    print(e)
    interfaces = None

try:
    # TODO: configurable DNS (or find a way to use the cell network's own DNS)
    # TODO support IPv6 which is increasingly common on cell networks
    import dns.resolver
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers += ['1.0.0.1', '1.1.1.1', '8.8.8.8']
    # random is used to load-balance among multiple A records
    import random
except ImportError:
    # pip install dnspython
    print("Warning: dnspython not available; falling back to system DNS")
    resolver = None

logging.basicConfig(level=logging.DEBUG)
SOCKS_VERSION = 5
SOCKS_HOST = '0.0.0.0'
SOCKS_PORT = 9876
WPAD_PORT = 80


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True


def recvall(sock, n):
    res = bytearray()
    while len(res) < n:
        chunk = sock.recv(n - len(res))
        if not chunk:
            raise EOFError()
        res += chunk
    return res


def sendall(sock, data):
    b = memoryview(data)
    n = 0
    while n < len(b):
        res = sock.send(b[n:])
        if res <= 0:
            raise EOFError()
        n += res


class SocksProxy(StreamRequestHandler):
    def handle(self):
        log_tag = '%s:%s' % self.client_address

        logging.info('%s: new connection', log_tag)

        # receive client's auth methods
        version, nmethods = struct.unpack("!BB", recvall(self.connection, 2))
        assert version == SOCKS_VERSION

        # get available methods
        methods = recvall(self.connection, nmethods)

        # accept only NONE auth
        if 0 not in methods:
            # no acceptable methods - fail with method 255
            sendall(self.connection, struct.pack("!BB", SOCKS_VERSION, 0xff))
            self.server.close_request(self.request)
            return

        # send welcome with auth method 0=NONE
        sendall(self.connection, struct.pack("!BB", SOCKS_VERSION, 0))

        # request
        req = recvall(self.connection, 4)
        version, cmd, _, address_type = req
        assert version == SOCKS_VERSION

        if address_type == 1:  # IPv4
            address = socket.inet_ntoa(recvall(self.connection, 4))
            status = 0
        elif address_type == 3:  # Domain name
            domain_length = ord(recvall(self.connection, 1))
            address = recvall(self.connection, domain_length).decode()
            status = 0
            if resolver:
                logging.debug('%s: resolving address %s', log_tag, address)
                addrs = resolver.query(address, 'A', source=CONNECT_HOST)
                if addrs:
                    address = random.choice(addrs).address
        else:
            status = 8  # Address type not supported

        port, = struct.unpack('!H', recvall(self.connection, 2))

        # reply
        if status == 0:
            try:
                if cmd == 1:  # CONNECT
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    if CONNECT_HOST:
                        remote.bind((CONNECT_HOST, 0))
                    remote.connect((address, port))
                    logging.info('%s: connected to %s:%s', log_tag, address, port)
                    status = 0  # Succeeded
                else:
                    logging.info('%s: command %d unsupported', log_tag, cmd)
                    status = 7  # Command not supported

            except Exception as err:
                logging.error('%s: connect error %s', log_tag, err)
                # return connection refused error
                status = 5

        reply = struct.pack("!BBBBIH", SOCKS_VERSION, status, 0, 1, 0, 0)  # ATYP=IPV4

        sendall(self.connection, reply)

        # establish data exchange
        if status == 0:
            try:
                self.exchange_loop(self.connection, remote)
            except Exception as e:
                logging.error('%s: forwarding error: %s', log_tag, e)

        logging.info('%s: shutting down', log_tag)
        self.server.close_request(self.request)

    def exchange_loop(self, client, remote):
        while True:
            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(4096)
                if not data:
                    break
                sendall(remote, data)

            if remote in r:
                data = remote.recv(4096)
                if not data:
                    break
                sendall(client, data)


def start_wpad_server(hhost, hport, phost, pport):
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
""" % (phost, pport, phost, pport)).strip().encode())

    HTTPServer.allow_reuse_address = True
    server = HTTPServer((hhost, hport), HTTPHandler)
    threading.Thread(target=server.serve_forever).start()

if __name__ == '__main__':
    start_wpad_server(SOCKS_HOST, WPAD_PORT, PROXY_HOST, SOCKS_PORT)
    print("PAC URL: http://{}:{}/wpad.dat".format(PROXY_HOST, WPAD_PORT))
    print("SOCKS Address: {}:{}".format(PROXY_HOST or SOCKS_HOST, SOCKS_PORT))

    with ThreadingTCPServer((SOCKS_HOST, SOCKS_PORT), SocksProxy) as server:
        server.serve_forever()
