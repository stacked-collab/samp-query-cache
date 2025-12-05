#!/usr/bin/env python3
import socket
import socketserver
import threading
import time
from collections import defaultdict, deque
from typing import Optional, Sequence

# sudo iptables -t nat -A PREROUTING -p udp -m iprange --dst-range 66.70.160.240-66.70.160.243 --dport 7777 -m string --algo bm --string "SAMP" -j REDIRECT --to-port 7778
# sudo iptables -t nat -A PREROUTING -p udp --dport 7777 -m iprange --dst-range 66.70.160.240-66.70.160.243 -m u32 --u32 "28=0x53414d50 && 38&0xFF=0x6F" -j REDIRECT --to-ports 7778

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
BLACKLIST_TIME = 300  # segundos de bloqueo temporal

_rate_buckets = defaultdict(deque)
_blacklist = {}

info = b""
rules = b""
clients = b""
detail = b""
omp = b""
isonline = False
_lock = threading.Lock()


def allowed_rate(ip):
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


def patch_rules_packet(
    data: bytes,
    replacements: dict[str, str],
    remove: Optional[Sequence[str]] = None,
    order: Optional[Sequence[str]] = None
) -> bytes:
    """
    Modifica, agrega, elimina y ordena reglas en el paquete 'rules' de SA:MP.
    - replacements: {nombre: valor} para modificar o añadir reglas.
    - remove: lista de nombres de reglas a eliminar por completo.
    - order: orden final deseado (opcional).
    """
    try:
        if len(data) < 2:
            return data

        buf = bytearray(data)
        offset = 0
        if offset + 2 > len(buf):
            return data
        rules_count = buf[offset] | (buf[offset + 1] << 8)
        offset += 2

        existing = []
        for _ in range(rules_count):
            if offset >= len(buf):
                break
            if offset + 1 > len(buf):
                break
            name_len = buf[offset]
            offset += 1
            if offset + name_len > len(buf):
                break
            name = buf[offset:offset + name_len].decode("latin-1", errors="ignore")
            offset += name_len

            if offset + 1 > len(buf):
                break
            value_len = buf[offset]
            offset += 1
            if offset + value_len > len(buf):
                break
            value = buf[offset:offset + value_len].decode("latin-1", errors="ignore")
            offset += value_len
            existing.append((name, value))

        # Aplicar eliminaciones
        result = []
        remove_set = set(remove or [])
        for n, v in existing:
            if n not in remove_set:
                if n in replacements:
                    result.append((n, replacements[n]))
                else:
                    result.append((n, v))

        # Agregar reglas nuevas
        for key, value in replacements.items():
            if key not in [n for n, _ in result]:
                result.append((key, value))

        # Aplicar orden si se define
        if order:
            ordered_rules = []
            added = set()
            for key in order:
                for n, v in result:
                    if n == key and n not in added:
                        ordered_rules.append((n, v))
                        added.add(n)
            for n, v in result:
                if n not in added:
                    ordered_rules.append((n, v))
            final_rules = ordered_rules
        else:
            final_rules = result

        # Reconstruir buffer usando latin-1 para compatibilidad con tildes/ñ
        rebuilt = bytearray()
        rebuilt += (len(final_rules)).to_bytes(2, "little")
        for name, value in final_rules:
            name_bytes = name.encode("latin-1", errors="replace")
            value_bytes = value.encode("latin-1", errors="replace")

            if len(name_bytes) > 255:
                name_bytes = name_bytes[:255]
            if len(value_bytes) > 255:
                value_bytes = value_bytes[:255]

            rebuilt.append(len(name_bytes))
            rebuilt += name_bytes
            rebuilt.append(len(value_bytes))
            rebuilt += value_bytes

        return bytes(rebuilt)
    except Exception as e:
        print(f"[WARN] patch_rules_packet error: {e}")
        return data


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
        global info, rules, clients, detail, isonline, omp
        while True:
            if self.ping():
                isonline = True
                try:
                    for opcode, varname in [("o", "omp"), ("i", "info"), ("r", "rules"), ("d", "detail"), ("c", "clients")]:
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
            return

        if not isonline:
            return

        opcode = payload[10:11]

        if opcode in (b"c", b"d"):
            return
            
        if opcode not in (b"p", b"o", b"i", b"r", b"d", b"c"):
            return

        if opcode == b"p":
            self.server.socket.sendto(payload, client_addr)
            return

        if opcode == b"o":
            with _lock:
                data = omp
            if data:
                self.server.socket.sendto(payload + data, client_addr)
            return

        with _lock:
            data_map = {b"i": info, b"r": rules, b"d": detail, b"c": clients}
            data = data_map.get(opcode, b"")

        if opcode == b"r" and data:
            replacements = {}
            remove = []
            order = [
                "allowed_clients",
                "artwork",
                "lagcomp",
                "mapname",
                "version",
                "weather",
                "weburl",
                "worldtime",
            ]
            data = patch_rules_packet(data, replacements, remove=remove, order=order)

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
