#!python3
# Original from https://github.com/rushter/socks5/blob/master/server.py
# Modified for Pythonista by @nneonneo

from io import BytesIO
import logging
from select import select
import socket
import ui
import struct
import threading
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler

# IP over which the proxy will be available (probably WiFi IP)
PROXY_HOST = "172.20.10.1"
# IP over which the proxy will attempt to connect to the Internet
CONNECT_HOST = None
# Time out connections after being idle for this long (in seconds)
IDLE_TIMEOUT = 1800

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
        print("Assuming proxy will be accessed over hotspot (%s) at %s" %
              (iface.name, iface.addr.address))
        PROXY_HOST = iface.addr.address
    elif iftypes['en']:
        iface = iftypes['en'][0]
        print("Assuming proxy will be accessed over WiFi (%s) at %s" %
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
    daemon_threads = True
    allow_reuse_address = True


def readall(f, n):
    res = bytearray()
    while len(res) < n:
        chunk = f.read(n - len(res))
        if not chunk:
            raise EOFError()
        res += chunk
    return bytes(res)


def readstruct(f, fmt):
    return struct.unpack(fmt, readall(f, struct.calcsize(fmt)))


class SocksProxy(StreamRequestHandler):
    STATUS_SUCCEEDED = 0     # succeeded
    STATUS_ERROR = 1         # general SOCKS server failure
    STATUS_EPERM = 2         # connection not allowed by ruleset
    STATUS_ENETDOWN = 3      # Network unreachable
    STATUS_EHOSTUNREACH = 4  # Host unreachable
    STATUS_ECONNREFUSED = 5  # Connection refused
    STATUS_ETIMEDOUT = 6     # TTL expired
    STATUS_ENOTSUP = 7       # Command not supported
    STATUS_EAFNOSUPPORT = 8  # Address type not supported

    ATYP_IPV4 = 1
    ATYP_DOMAIN = 3
    ATYP_IPV6 = 4

    def encode_address(self, sockaddr=None):
        if sockaddr is None:
            return struct.pack("!BIH", self.ATYP_IPV4, 0, 0)

        address, port = sockaddr
        try:
            addrbytes = socket.inet_pton(socket.AF_INET, address)
            return struct.pack("!B4sH", self.ATYP_IPV4, addrbytes, port)
        except Exception:
            addrbytes = socket.inet_pton(socket.AF_INET6, address)
            return struct.pack("!B16sH", self.ATYP_IPV6, addrbytes, port)

    def send_reply(self, status, bindaddr=None):
        reply = struct.pack("!BBB", SOCKS_VERSION, status, 0)
        reply += self.encode_address(bindaddr)
        self.connection.sendall(reply)

    def handle(self):
        log_tag = '%s:%s' % self.client_address

        logging.info('%s: new connection', log_tag)

        sockfile = self.connection.makefile('rb')

        # receive client's auth methods
        version, nmethods = readstruct(sockfile, "!BB")
        assert version == SOCKS_VERSION

        # get available methods
        methods = readstruct(sockfile, "!%dB" % nmethods)

        # accept only NONE auth
        if 0 not in methods:
            # no acceptable methods - fail with method 255
            self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 0xff))
            logging.error('%s: unsupported auth methods %s', log_tag, methods)
            self.server.close_request(self.request)
            return

        # send welcome with auth method 0=NONE
        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 0))

        # request
        version, cmd, _, address_type = readstruct(sockfile, "!BBBB")
        assert version == SOCKS_VERSION

        address, port = self.read_addrport(address_type, sockfile)
        if address is None:
            logging.error('%s: bad address type %d', log_tag, address_type)
            self.send_reply(self.STATUS_EAFNOSUPPORT)
            self.server.close_request(self.request)
            return

        # reply
        if cmd == 1:  # CONNECT
            if address_type == self.ATYP_DOMAIN:
                address = self.resolve_address(address)
            self.handle_connect(address, port)
        elif cmd == 3:  # UDP ASSOCIATE
            # ignore the request host: the client might not actually know
            # its own address
            self.handle_udp(self.client_address[0], port)
        else:
            logging.info('%s: command %d unsupported', log_tag, cmd)
            self.send_reply(self.STATUS_ENOTSUP)
            self.server.close_request(self.request)

    def resolve_address(self, address, force=False):
        log_tag = '%s:%s' % self.client_address
        if resolver:
            logging.debug('%s: resolving address %s', log_tag, address)
            addrs = resolver.query(address, 'A', source=CONNECT_HOST)
            if addrs:
                return random.choice(addrs).address
        if force:
            return socket.gethostbyname(address)
        return address

    def read_addrport(self, address_type, sockfile):
        if address_type == self.ATYP_IPV4:
            address = socket.inet_ntop(socket.AF_INET, readall(sockfile, 4))
        elif address_type == self.ATYP_DOMAIN:
            domain_length = ord(readall(sockfile, 1))
            address = readall(sockfile, domain_length).decode()
        elif address_type == self.ATYP_IPV6:
            address = socket.inet_ntop(socket.AF_INET6, readall(sockfile, 16))
        else:
            return None, None
        port, = readstruct(sockfile, "!H")
        return address, port

    def tcp_loop(self, sock1, sock2):
        while True:
            # wait until client or remote is available for read
            r, _, _ = select([sock1, sock2], [], [], IDLE_TIMEOUT)
            if not r:
                raise socket.timeout()

            if sock1 in r:
                data = sock1.recv(4096)
                if not data:
                    break
                sock2.sendall(data)

            if sock2 in r:
                data = sock2.recv(4096)
                if not data:
                    break
                sock1.sendall(data)

    def handle_connect(self, address, port):
        log_tag = '%s:%s -> %s:%s' % (self.client_address + (address, port))
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if CONNECT_HOST:
                remote.bind((CONNECT_HOST, 0))
            remote.connect((address, port))
            logging.info('%s: connected', log_tag)
        except Exception as err:
            logging.error('%s: connect error %s', log_tag, err)
            self.send_reply(self.STATUS_ECONNREFUSED)
            self.server.close_request(self.request)
            return

        self.send_reply(self.STATUS_SUCCEEDED)

        try:
            self.tcp_loop(self.connection, remote)
        except socket.timeout:
            logging.error('%s: connection timed out', log_tag)
        except Exception as e:
            logging.error('%s: forwarding error: %s', log_tag, e)

        try:
            remote.close()
        except Exception:
            pass

        logging.info('%s: shutting down', log_tag)
        self.server.close_request(self.request)

    def udp_loop(self, controlsock, csock, ssock):
        log_tag = '%s:%s [udp]' % self.client_address
        connections = {}

        while True:
            r, _, _ = select([controlsock, csock, ssock], [], [], IDLE_TIMEOUT)
            if not r:
                raise socket.timeout()

            # Shut down the UDP association when the TCP connection breaks
            if controlsock in r:
                data = controlsock.recv(4096)
                if not data:
                    break

            if csock in r:
                data, addr = csock.recvfrom(4096)
                sockfile = BytesIO(data)
                try:
                    # decode header
                    _, frag, address_type = readstruct(sockfile, "!HBB")
                    assert frag == 0, "UDP fragmentation is not supported"
                    address, port = self.read_addrport(address_type, sockfile)
                    assert address is not None, "Address type is not supported"
                    if address_type == self.ATYP_DOMAIN:
                        address = self.resolve_address(address, force=True)
                    if (address, port) not in connections:
                        logging.info(
                            '%s: new connection to %s:%s',
                            log_tag, address, port
                        )
                    connections[address, port] = addr
                    # strip header and send to target host
                    ssock.sendto(sockfile.read(), (address, port))
                except Exception as e:
                    logging.info('%s: malformed packet: %s', log_tag, e)
                    pass

            if ssock in r:
                data, addr = ssock.recvfrom(4096)
                if not data:
                    break
                if addr not in connections:
                    logging.warning(
                        '%s: got packet from unknown sender %s:%s',
                        log_tag, *addr
                    )
                    continue
                header = struct.pack("!HB", 0, 0) + self.encode_address(addr)
                csock.sendto(header + data, connections[addr])

    def handle_udp(self, address, port):
        log_tag = '%s:%s [udp]' % (self.client_address)

        try:
            # client-side socket
            csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            csock.bind((SOCKS_HOST, 0))
            # remote-side socket
            ssock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if CONNECT_HOST:
                ssock.bind((CONNECT_HOST, 0))
            logging.info('%s: udp association established', log_tag)
        except Exception as err:
            logging.error('%s: udp association error %s', log_tag, err)
            self.send_reply(self.STATUS_ERROR)
            self.server.close_request(self.request)
            return

        _, cport = csock.getsockname()
        self.send_reply(self.STATUS_SUCCEEDED, (PROXY_HOST, cport))

        try:
            self.udp_loop(self.connection, csock, ssock)
        except socket.timeout:
            logging.error('%s: connection timed out', log_tag)
        except Exception as e:
            logging.error('%s: forwarding error: %s', log_tag, e)

        try:
            csock.close()
        except Exception:
            pass

        try:
            ssock.close()
        except Exception:
            pass

        logging.info('%s: shutting down', log_tag)
        self.server.close_request(self.request)


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


# Handler for full screen button to render a full screen window.
# Use a two-finger "slide down" gesture to close.
def full_screen_handler(sender):
    fs_view = ui.View()
    fs_view.name = "Full screen"
    fs_view.background_color = 'black'
    fs_view.present(style='popover', hide_title_bar=True)

def run_wpad_server(server):
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    wpad_server = create_wpad_server(
        SOCKS_HOST, WPAD_PORT, PROXY_HOST, SOCKS_PORT
    )

    print("PAC URL: http://{}:{}/wpad.dat".format(PROXY_HOST, WPAD_PORT))
    print("SOCKS Address: {}:{}".format(PROXY_HOST or SOCKS_HOST, SOCKS_PORT))

    thread = threading.Thread(target=run_wpad_server, args=(wpad_server,))
    thread.daemon = True
    thread.start()

    server = ThreadingTCPServer((SOCKS_HOST, SOCKS_PORT), SocksProxy)

    # Create side panel UI component to enter full screen
    view = ui.View()
    view.name = "SOCKS"
    view.background_color = 'black'
    view.flex = 'WH'
    # Add simple button to show full screen popover
    fs_button = ui.Button(title="Enter full screen")
    fs_button.action = full_screen_handler

    # Render main UI and full screen button
    view.add_subview(fs_button)
    view.present(style='panel', hide_title_bar=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down.")
        server.shutdown()
        wpad_server.shutdown()
