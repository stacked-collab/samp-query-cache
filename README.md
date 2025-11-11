# SA-MP Query Cache

Un script en Python que ayuda a servidores SA-MP (San Andreas Multiplayer) a **mostrarse en línea** incluso bajo cargas de consultas UDP (floods).  
Incluye protección básica: **rate limiting por IP**, **blacklist temporal**, validación de paquetes y caching de respuestas de consulta.

> Propósito: reducir la carga de consultas repetidas (i, r, d, c) y evitar que sondas/floods hagan que el servidor aparezca offline.

## Diagrama

```
+-----------------------+     +-------------------+     +-----------------------+
|                       |     |                   |     |                       |
|     SA-MP Client      |<--->|    UDP Proxy      |<--->|     SA-MP Server      |
| (Game/Query Client)   |     |  (pack_scan.py)   |     |  (Game/Query Server)  |
|                       |     |                   |     |                       |
+-----------------------+     +-------------------+     +-----------------------+
          |                             |                          |
          |                             |                          |
          v                             v                          v
     Sends Game/                   Filters and                 Accepts/
    Query Requests               Forwards Requests          Sends Responses
```

---

## Características principales

- Redirige y responde consultas SA-MP (`SAMP` query packets) desde múltiples IP públicas.
- Cachea respuestas `i` (info), `r` (rules), `d` (detail) y `c` (clients).
- Rate limiting por IP (ventana configurable + límite de consultas).
- Blacklist temporal tras exceder el límite.
- Validación simple de paquetes (`SAMP` header y IP destino en la cabecera).
- Protección por tamaño de paquete y truncamiento seguro.
- Watchdog que reinicia el socket si el servidor deja de responder.
- Fácil integración con `iptables` (DNAT/REDIRECT).

---

## Instalación

1. Copiar el script `pack_scan.py` al servidor donde corre SA-MP o en el proxy.
2. Ajustar variables del script (encabezado `CONFIGURACIÓN`):
   - `SAMP_SERVER_ADDRESSES`: lista de IPs públicas asociadas.
   - `SAMP_SERVER_LOCALHOST`: IP local donde responde el servidor SA-MP (`127.0.0.1` si corre en la misma máquina).
   - `SERVER_PORT` y `PROXY_PORT`.

3. Instalar reglas `iptables` para redirigir queries:
```bash

# ejemplo: redirigir rango 66.70.160.240-243 a proxy local 7778 si contienen "SAMP"
sudo iptables -t nat -A PREROUTING -p udp -m iprange --dst-range 66.70.160.240-66.70.160.243 --dport 7777 -m string --algo bm --string "SAMP" -j REDIRECT --to-port 7778

# si sólo utilizas una dirección IP, la regla se vería así para redirigir al proxy local 7778 si contienen "SAMP"
sudo iptables -t nat -A PREROUTING -p udp --dport 7777 -m string --algo bm --string "SAMP" -j REDIRECT --to-port 7778

# permitir entrada local al puerto 7778 si usas firewall local
sudo iptables -I INPUT -p udp --dport 7778 -j ACCEPT