#!/usr/bin/env python3
import socket
import socketserver
import threading
import time
from collections import defaultdict, deque

# sudo iptables -t nat -A PREROUTING -p udp -m iprange --dst-range 66.70.160.240-66.70.160.243 --dport 7777 -m string --algo bm --string "SAMP" -j REDIRECT --to-port 7778

SERVER_PORT = 7777
PROXY_PORT = 7778

SAMP_SERVER_ADDRESSES = [
    "66.70.160.240",
    "66.70.160.241",
    "66.70.160.242",
    "66.70.160.243",
]
SAMP_SERVER_ADDRESS_BYTES_LIST = [socket.inet_aton(ip) for ip in SAMP_SERVER_ADDRESSES]

SAMP_SERVER_LOCALHOST = "127.0.0.1"
QUERY_TIMEOUT = 7

MAX_PACKET_SIZE = 4096
RATE_LIMIT_WINDOW = 5
RATE_LIMIT_MAX = 300
BLACKLIST_TIME = 60  # segundos de bloqueo temporal

_rate_buckets = defaultdict(deque)
_blacklist = {}

info = b""
rules = b""
clients = b""
detail = b""
isonline = False
_lock = threading.Lock()


def allowed_rate(ip):
    """Límite de velocidad + blacklist temporal"""
    now = time.time()
    if ip in _blacklist and now < _blacklist[ip]:
        return False
    dq = _rate_buckets[ip]
    while dq and dq[0] <= now - RATE_LIMIT_WINDOW:
        dq.popleft()
    if len(dq) >= RATE_LIMIT_MAX:
        _blacklist[ip] = now + BLACKLIST_TIME
        dq.clear()
        print(f"[SEC] {ip} añadido a blacklist por flood ({BLACKLIST_TIME}s)")
        return False
    dq.append(now)
    return True


def create_handler(func):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                func(self)
            except Exception as e:
                print(f"[ERROR] {e}")
    return Handler


class UDPServer:
    def __init__(self, bind_address, target_address, timeout=0.5):
        self.target_address = target_address
        self.timeout = timeout
        self.server = socketserver.UDPServer(bind_address, create_handler(self.handle_external_packet))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(QUERY_TIMEOUT)

    def start(self):
        self.server.socket.settimeout(self.timeout)
        threading.Thread(target=self.querythread, daemon=True).start()
        threading.Thread(target=self.watchdog, daemon=True).start()
        print(f"SA-MP Query Cache iniciado | Activo en {bind_address[0]}:{bind_address[1]} → {SAMP_SERVER_LOCALHOST}:{SERVER_PORT}")
        self.server.serve_forever()

    def assemblePacket(self, opcode):
        ip_bytes = SAMP_SERVER_ADDRESS_BYTES_LIST[0]
        port_bytes = SERVER_PORT.to_bytes(2, "little")
        return b"SAMP" + ip_bytes + port_bytes + bytes(opcode, "utf-8")

    def ping(self):
        pack = self.assemblePacket("p0101")
        try:
            self.sock.sendto(pack, (SAMP_SERVER_ADDRESSES[0], SERVER_PORT))
            reply = self.sock.recv(1024)[10:]
            return reply == b"p0101"
        except socket.timeout:
            return False
        except Exception as e:
            print(f"[WARN] Ping error: {e}")
            return False

    def querythread(self):
        global info, rules, clients, detail, isonline
        while True:
            if self.ping():
                isonline = True
                try:
                    for opcode, varname in [("i", "info"), ("r", "rules"), ("d", "detail"), ("c", "clients")]:
                        packet = self.assemblePacket(opcode)
                        self.sock.sendto(packet, (SAMP_SERVER_ADDRESSES[0], SERVER_PORT))
                        data = self.sock.recv(1024)[11:]
                        with _lock:
                            globals()[varname] = data
                        time.sleep(QUERY_TIMEOUT)
                except Exception as e:
                    print(f"[WARN] Error durante consulta: {e}")
                    time.sleep(QUERY_TIMEOUT)
            else:
                isonline = False
                print("[WARN] Servidor no responde al ping. Reintentando...")
                time.sleep(QUERY_TIMEOUT)

    def watchdog(self):
        """Reinicia el socket si el servidor deja de responder mucho tiempo."""
        while True:
            time.sleep(30)
            if not isonline:
                try:
                    print("[WATCHDOG] Reiniciando socket...")
                    self.sock.close()
                    self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self.sock.settimeout(QUERY_TIMEOUT)
                except Exception as e:
                    print(f"[WATCHDOG] Error al reiniciar socket: {e}")

    def handle_external_packet(self, handler):
        payload, _ = handler.request
        client_addr = handler.client_address
        client_ip = client_addr[0]

        if len(payload) < 11 or len(payload) > MAX_PACKET_SIZE:
            return
        if payload[:4] != b"SAMP":
            return
        if payload[4:8] not in SAMP_SERVER_ADDRESS_BYTES_LIST:
            return
        if not allowed_rate(client_ip):
            print(f"[SEC] Bloqueado por rate-limit {client_ip}")
            return
        if not isonline:
            return

        opcode = payload[10:11]
        if opcode not in b"pirdc":
            return

        if opcode == b"p":
            self.server.socket.sendto(payload, client_addr)
            return

        with _lock:
            data_map = {b"i": info, b"r": rules, b"d": detail, b"c": clients}
            data = data_map.get(opcode, b"")
        if data:
            if len(data) + len(payload) <= MAX_PACKET_SIZE:
                self.server.socket.sendto(payload + data, client_addr)
            else:
                print(f"[SEC] Respuesta truncada para {client_ip} (demasiado grande)")


if __name__ == "__main__":
    bind_address = ("0.0.0.0", PROXY_PORT)
    target_address = (SAMP_SERVER_LOCALHOST, SERVER_PORT)
    proxy = UDPServer(bind_address, target_address)
    proxy.start()
