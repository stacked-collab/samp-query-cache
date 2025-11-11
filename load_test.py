#!/usr/bin/env python3
"""
load_test.py

Simula N clientes SA-MP enviando queries 'p' (ping) e 'i' (info) a un servidor.

Uso: python3 load_test.py --target 66.70.160.240 --clients 100 --duration 60 --interval 1
"""
import socket, threading, time, argparse, random

def make_packet(target_ip, target_port, opcode_str):
    # SAMP + 4 bytes IP + 2 bytes port little-endian + opcode (string)
    ip_bytes = socket.inet_aton(target_ip)
    port_bytes = int(target_port).to_bytes(2, "little")
    return b"SAMP" + ip_bytes + port_bytes + opcode_str.encode("utf-8")

def client_thread(name, target_ip, target_port, duration, interval, mix=0.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    pkt_p = make_packet(target_ip, target_port, "p0101")  # ping
    pkt_i = make_packet(target_ip, target_port, "i")      # info
    end = time.time() + duration
    sent = 0
    recv = 0
    while time.time() < end:
        if random.random() < mix:
            pkt = pkt_p
        else:
            pkt = pkt_i
        try:
            s.sendto(pkt, (target_ip, int(target_port)))
            sent += 1
            try:
                data, addr = s.recvfrom(4096)
                recv += 1
            except socket.timeout:
                pass
        except Exception:
            pass
        time.sleep(interval * (0.8 + random.random()*0.4))  # jitter
    s.close()
    print(f"[{name}] sent={sent} recv={recv}")

def run_test(target, clients, duration, interval, mix):
    t_ip, t_port = target.split(":") if ":" in target else (target, "7777")
    threads = []
    for i in range(clients):
        th = threading.Thread(target=client_thread, args=(f"c{i+1}", t_ip, t_port, duration, interval, mix), daemon=True)
        threads.append(th)
        th.start()
        time.sleep(0.01)  # ramp-up
    for th in threads:
        th.join()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True, help="IP[:port] del servidor (ej. 66.70.160.240:7777)")
    p.add_argument("--clients", type=int, default=50, help="número de clientes concurrentes")
    p.add_argument("--duration", type=int, default=30, help="duración en segundos")
    p.add_argument("--interval", type=float, default=1.0, help="intervalo medio entre paquetes por cliente (s)")
    p.add_argument("--mix", type=float, default=0.5, help="proporción de pings vs info (0..1), 0.5 = mitad p")
    args = p.parse_args()
    print(f"Test → target={args.target} clients={args.clients} dur={args.duration}s int={args.interval}s mix={args.mix}")
    run_test(args.target, args.clients, args.duration, args.interval, args.mix)
