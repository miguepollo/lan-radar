#!/usr/bin/env python3
"""
📡 LAN RADAR v2.0 — Escanea tu red local y te enseña qué hay conectado.

Niveles:
  1. Auto-detecta TODAS las redes + ping sweep + boost TCP→ARP (caza 5G/IoT que ignoran ping)
  2. Hostname + latencia + diff entre escaneos
  3. TUI hacker bonita — iconos, colores, historial, auto-refresh 5s
  4. Alerta NEW DEVICE + historial persistente + gráfica 24h
  5. Fingerprint: hostname multi-fuente (PTR + getent + mDNS + NetBIOS),
     tipo por puertos TCP + TTL + OUI + gateway
  6. Nombres v2: DNS directo al router (evita Cloudflare/1.1.1.1 que no sabe
     tu LAN) + mDNS/LLMNR/NBNS nativos en Python puro (sin depender de que
     systemd tenga mDNS/LLMNR activados) + SSDP/UPnP friendlyName
     ("Salón TV") + avahi-browse. Multi-red: 2.4GHz + 5GHz + ethernet
     comparten subred, pero si tu router las aísla o usa VLANs, se escanean
     todas a la vez.

Stack: Python + Rich (pip install rich)
Uso:
  python lan_radar.py              # TUI interactiva
  python lan_radar.py --once       # un solo escaneo y salir
  python lan_radar.py --range 192.168.1.0/24
  python lan_radar.py --range 192.168.1.0/24 --range 192.168.2.0/24
  python lan_radar.py --interval 5
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import itertools
import json
import os
import random
import re
import select
import socket
import struct
import subprocess
import sys
import time
import urllib.request
from concurrent import futures
from dataclasses import asdict, dataclass, field
from pathlib import Path

try:
    import termios
    import tty

    HAS_TTY = True
except ImportError:  # Windows: sin termios, modo degradado
    tty = termios = None
    HAS_TTY = False

try:
    from rich import box
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("❌ Falta 'rich'. Instala con: pip install rich")
    sys.exit(1)

VERSION = "v2.0"
DEFAULT_INTERVAL = 5
DEFAULT_PING_TIMEOUT = 1
MAX_WORKERS = 100
DNS_WORKERS = 30
DNS_BUDGET = 8.0  # segundos totales para resolución de hostnames por escaneo
MAX_HOSTS = 512
MDNS_TIMEOUT = 1.0  # avahi-resolve-address cuelga si no hay registro mDNS
NMB_TIMEOUT = 1.0  # nmblookup -A a hosts sin NetBIOS tarda en dar timeout
PORT_TIMEOUT = 0.35  # por puerto; todos los (ip, puerto) van en paralelo
PORT_WORKERS = 100
# Timeouts de los resolvers nativos (multicast-respuestas llegan en ms)
GWDNS_TIMEOUT = 1.0  # PTR directo al router por IP
NATIVE_MDNS_TIMEOUT = 0.9  # mDNS reverso 224.0.0.251:5353
NATIVE_LLMNR_TIMEOUT = 0.9  # LLMNR reverso 224.0.0.252:5355
NATIVE_NBNS_TIMEOUT = 0.9  # NetBIOS NBSTAT directo UDP/137
SSDP_TIMEOUT = 3.0  # un M-SEARCH caza TVs/altavoces/NAS de golpe
SSDP_FETCH_TIMEOUT = 2.0  # descarga del XML de descripción UPnP
BROWSE_TIMEOUT = 4  # techo para avahi-browse -r (se aprovecha salida parcial)
# Puertos para el "knock" TCP que fuerza al kernel a resolver ARP.
# Solo se prueban en IPs que NO respondieron al ping: así aparecen móviles
# en reposo (5GHz) e IoTs baratos que ignoran ICMP pero contestan ARP.
TCP_ARP_PORTS = (80, 443, 445, 22)
TCP_ARP_TIMEOUT = 0.25
TCP_ARP_WORKERS = 100

DATA_DIR = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "lan-radar"
DATA_DIR.mkdir(parents=True, exist_ok=True)
HISTORY_FILE = DATA_DIR / "history.json"
SNAPSHOTS_FILE = DATA_DIR / "snapshots.json"
KNOWN_FILE = DATA_DIR / "known_devices.json"

console = Console()


# ── Modelos ──────────────────────────────────────────────────────────────────


@dataclass
class Device:
    ip: str
    hostname: str = "unknown"
    latency_ms: float | None = None
    mac: str | None = None
    icon: str = "👽"
    device_type: str = "Desconoc"
    vendor: str = ""
    os_hint: str = ""
    open_ports: list = field(default_factory=list)
    ttl: int | None = None


@dataclass
class HistoryEvent:
    time: str = ""
    iso: str = ""
    ip: str = ""
    hostname: str = "unknown"
    action: str = "joined"  # "joined" | "left"


# ── Helpers genéricos ────────────────────────────────────────────────────────


def _read_json(path, default):
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def _esc(s):
    """Escapa markup de Rich (hostnames podrían traer [])."""
    return (s or "").replace("[", "\\[")


def _lat(ms):
    """Latencia coloreada según umbrales."""
    if ms is None:
        return "[dim]—[/dim]"
    c = "bright_green" if ms < 5 else "green" if ms < 30 else "yellow" if ms < 100 else "red"
    return f"[{c}]{ms:.1f} ms[/{c}]"


def num_hosts(net):
    if net.prefixlen >= 31:
        return net.num_addresses
    return max(net.num_addresses - 2, 1)


# ── Red: detección de rango, IP propia, MACs ─────────────────────────────────

SKIP_IFACE = (
    "lo",
    "docker",
    "br-",
    "veth",
    "tailscale",
    "wg",
    "tun",
    "tap",
    "virbr",
    "zt",
)


def _parse_cidr_list(cidr_overrides):
    """Normaliza --range (repetible y/o separado por comas) a lista de redes."""
    if isinstance(cidr_overrides, str):
        cidr_overrides = [c for c in re.split(r"[,\s]+", cidr_overrides) if c]
    nets = []
    for cidr in cidr_overrides or []:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError as e:
            console.print(f"[red]CIDR inválido {cidr}: {e}[/red]")
            sys.exit(1)
    return nets


def _collect_route_candidates():
    """Candidatas (iface, red) vía ip route + ip addr. Sin filtrar."""
    cands = []
    try:
        out = subprocess.check_output(["ip", "route"], text=True, timeout=3)
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)\s+dev\s+(\S+)", line)
            if m:
                try:
                    cands.append((m.group(2), ipaddress.ip_network(m.group(1), strict=False)))
                except ValueError:
                    pass
    except Exception:
        pass
    try:
        out = subprocess.check_output(["ip", "-o", "-4", "addr", "show"], text=True, timeout=3)
        for line in out.splitlines():
            m = re.search(r"^\d+:\s+(\S+).*?\binet\s+(\S+)", line)
            if m:
                try:
                    cands.append((m.group(1), ipaddress.ip_interface(m.group(2)).network))
                except ValueError:
                    pass
    except Exception:
        pass
    return cands


def get_all_local_networks(cidr_overrides=None):
    """Todas las redes LAN locales.

    2.4GHz, 5GHz y ethernet normalmente comparten la misma subred (el router
    las puentea), así que un solo /24 ya las ve a todas. PERO si el router
    aísla bandas, usa VLANs o red de invitados, cada segmento es una subred
    distinta: por eso se escanean TODAS las interfaces privadas a la vez.
    Con --range se escanean solo las indicadas.
    """
    explicit = _parse_cidr_list(cidr_overrides)
    if explicit:
        # dedup manteniendo orden
        seen, nets = set(), []
        for n in explicit:
            if str(n) not in seen:
                seen.add(str(n))
                nets.append(n)
        return nets

    usable = [
        n
        for iface, n in _collect_route_candidates()
        if not iface.startswith(SKIP_IFACE) and n.is_private and not n.is_loopback and n.prefixlen >= 16
    ]
    # dedup + preferidas primero (192.168.x > 10.x > resto)
    seen, nets = set(), []
    for n in sorted(
        usable,
        key=lambda n: (
            0 if str(n).startswith("192.168.") else 1 if str(n).startswith("10.") else 2,
            n.prefixlen,
        ),
    ):
        if str(n) not in seen:
            seen.add(str(n))
            nets.append(n)
    if nets:
        return nets

    ip = get_own_ip()
    if ip:
        try:
            return [ipaddress.ip_network(f"{ip}/24", strict=False)]
        except ValueError:
            pass
    console.print("[yellow]⚠️  No se pudo detectar red, usando 192.168.1.0/24[/yellow]")
    return [ipaddress.ip_network("192.168.1.0/24")]


def get_local_network(cidr_override=None):
    """Compat: primera red de get_all_local_networks()."""
    nets = get_all_local_networks([cidr_override] if cidr_override else None)
    return nets[0]


def nets_label(networks):
    if len(networks) == 1:
        return str(networks[0])
    return f"{len(networks)} redes ({', '.join(str(n) for n in networks)})"


def total_hosts(networks):
    return sum(num_hosts(n) for n in networks)


def get_own_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return None


_gateway_cache = "unset"


def get_default_gateway():
    """IP del gateway (ip route show default). Se cachea: no cambia mid-scan."""
    global _gateway_cache
    if _gateway_cache != "unset":
        return _gateway_cache
    _gateway_cache = None
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True, timeout=2)
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            _gateway_cache = m.group(1)
    except Exception:
        pass
    return _gateway_cache


def get_arp_table():
    """Tabla ARP con estado: {ip: (mac, STATE)}. Sin FAILED/INCOMPLETE.

    El kernel rellena esta tabla con TODO lo que habla en L2 (2.4GHz, 5GHz
    y ethernet por igual), responda o no al ping. Es la red de seguridad
    para cazar móviles en reposo e IoTs que ignoran ICMP.
    """
    table = {}
    try:
        out = subprocess.check_output(["ip", "neigh"], text=True, timeout=3)
        for line in out.splitlines():
            m = re.search(
                r"^(\d+\.\d+\.\d+\.\d+).*?lladdr\s+([0-9a-f:]{17})\s+(\S+)",
                line,
                re.IGNORECASE,
            )
            if m:
                state = m.group(3).upper()
                if state in ("FAILED", "INCOMPLETE"):
                    continue
                table[m.group(1)] = (m.group(2).lower(), state)
    except Exception:
        pass
    return table


def get_mac_table():
    """Tabla ARP (ip neigh) para enriquecer con MAC sin root."""
    return {ip: mac for ip, (mac, _state) in get_arp_table().items()}


def tcp_knock(ip, timeout=TCP_ARP_TIMEOUT):
    """Intenta conectar a puertos comunes. Retorna lista de abiertos.

    Efecto lateral buscado: aunque todo esté cerrado, el SYN obliga al
    kernel a resolver ARP, así ip neigh registra al host. Sin root.
    """
    open_ports = []
    for port in TCP_ARP_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append(port)
        except Exception:
            continue
    return open_ports


def tcp_arp_boost(missed_ips, timeout=TCP_ARP_TIMEOUT):
    """Fuerza resolución ARP en IPs que no respondieron al ping.

    Retorna {ip: [puertos abiertos]}. Quien abra algo está vivo seguro;
    quien no abra nada pero deje entrada ARP fresca también cuenta
    (se comprueba releyendo ip neigh después del knock).
    """
    found = {}
    if not missed_ips:
        return found
    with futures.ThreadPoolExecutor(max_workers=TCP_ARP_WORKERS) as ex:
        futs = {ex.submit(tcp_knock, ip, timeout): ip for ip in missed_ips}
        for fut in futures.as_completed(futs):
            try:
                found[futs[fut]] = fut.result()
            except Exception:
                found[futs[fut]] = []
    return found


# ── Ping, TTL & hostname multi-fuente ────────────────────────────────────────

PING_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)
TTL_RE = re.compile(r"ttl[=:]\s*(\d+)", re.IGNORECASE)


def ping_host(ip, timeout=DEFAULT_PING_TIMEOUT):
    """Retorna (online, latency_ms, ttl). El TTL orienta sobre el SO/tipo."""
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout + 1,
            check=False,
        )
        m = PING_RE.search(r.stdout)
        t = TTL_RE.search(r.stdout)
        ttl = int(t.group(1)) if t else None
        if r.returncode == 0 or m:
            return True, float(m.group(1)) if m else None, ttl
        return False, None, None
    except Exception:
        return False, None, None


def _clean_hostname(raw, ip=None):
    """Normaliza un candidato: primera etiqueta, sin basura DHCP/numérica."""
    if not raw:
        return None
    raw = raw.strip()
    if ip and raw == ip:
        return None
    name = raw.split(".")[0].strip().rstrip("-_")
    if not name or name.lower() in ("unknown", "localhost"):
        return None
    if name.isdigit():  # resto de una IP literal ("192" de "192.168.1.5")
        return None
    if re.fullmatch(r"\d+-\d+-\d+-\d+", name):  # 192-168-1-5 genérico
        return None
    if re.fullmatch(r"(dhcp|ip|host)[\-_]?\d+", name, re.IGNORECASE):
        return None
    return name[:32] or None


def _ptr_lookup(ip):
    """Reverse DNS clásico. Rápido, pero muchos routers caseros no tienen zona."""
    try:
        return _clean_hostname(socket.gethostbyaddr(ip)[0], ip)
    except Exception:
        return None


def _cmd_out(cmd, timeout):
    """Ejecuta comando y devuelve stdout ('' si falla)."""
    try:
        r = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
        )
        return r.stdout
    except Exception:
        return ""


def _getent_lookup(ip):
    """Vía NSS (files/dns/systemd). Casi instantáneo; pilla _gateway, etc."""
    parts = _cmd_out(["getent", "hosts", ip], 1.0).split()
    return _clean_hostname(parts[1], ip) if len(parts) >= 2 else None


def _mdns_lookup(ip):
    """mDNS/Bonjour (avahi). Oro para portátiles, móviles, impresoras y TVs
    que publican <nombre>.local pero no tienen PTR en el router."""
    parts = _cmd_out(["avahi-resolve-address", ip], MDNS_TIMEOUT).split()
    return _clean_hostname(parts[1], ip) if len(parts) >= 2 else None


def _netbios_lookup(ip):
    """NetBIOS (nmblookup -A). Último recurso: aún delata nombres Windows."""
    for line in _cmd_out(["nmblookup", "-A", ip], NMB_TIMEOUT).splitlines():
        m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9\-_]{0,14})\s+<00>", line)
        if m:
            name = _clean_hostname(m.group(1), ip)
            if name:
                return name
    return None


# ── Resolvers nativos en Python puro (sin root, sin depender del sistema) ────
# Por qué existen: en muchas máquinas el DNS del sistema es Cloudflare/Quad9
# (1.1.1.1) o el stub de systemd, que NO conoce los nombres DHCP de tu LAN;
# y systemd suele llevar LLMNR y mDNS desactivados en el enlace WiFi.
# Preguntar al router + multicast directo evita todo eso.

def _dns_build_query(qname, qtype=12, txid=None, flags=0x0100):
    txid = random.randint(0, 0xFFFF) if txid is None else txid
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname.split(".")) + b"\x00"
    return txid, header + q + struct.pack(">HH", qtype, 1)


def _dns_decode_name(pkt, off):
    """Decodifica nombre DNS con punteros de compresión. Retorna (nombre, off')."""
    labels, seen = [], set()
    jumped, orig_off = False, off
    for _ in range(32):  # techo anti-bucles
        if off >= len(pkt):
            raise ValueError("truncated")
        ln = pkt[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(pkt):
                raise ValueError("truncated")
            ptr = ((ln & 0x3F) << 8) | pkt[off + 1]
            if ptr in seen:
                raise ValueError("loop")
            seen.add(ptr)
            if not jumped:
                orig_off = off + 2
            off, jumped = ptr, True
        else:
            off += 1
            labels.append(pkt[off : off + ln].decode("utf-8", "replace"))
            off += ln
    else:
        raise ValueError("loop")
    return ".".join(labels), (orig_off if jumped else off)


def _dns_first_ptr(pkt, txid=None):
    """Primera respuesta PTR del paquete, o None. txid=None → no verifica."""
    if len(pkt) < 12:
        return None
    rid, _flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", pkt[:12])
    if txid is not None and rid != txid:
        return None
    if an == 0:
        return None
    off = 12
    try:
        for _ in range(qd):  # saltar preguntas
            _name, off = _dns_decode_name(pkt, off)
            off += 4
        for _ in range(an):
            _name, off = _dns_decode_name(pkt, off)
            if off + 10 > len(pkt):
                return None
            rtype, _class, _ttl, rdlen = struct.unpack(">HHIH", pkt[off : off + 10])
            off += 10
            rdata = pkt[off : off + rdlen]
            roff = off
            off += rdlen
            if rtype == 12 and rdlen:  # PTR
                name, _ = _dns_decode_name(pkt, roff)
                if name:
                    return name
    except Exception:
        return None
    return None


def _reverse_arpa(ip):
    try:
        return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    except Exception:
        return ""


def dns_ptr_at_server(ip, server, timeout=GWDNS_TIMEOUT):
    """PTR preguntando a un servidor concreto (el router lo sabe TODO: DHCP
    de 2.4GHz, 5GHz y ethernet). Retorna hostname corto o None."""
    try:
        qname = _reverse_arpa(ip)
        if not qname or not server:
            return None
        txid, pkt = _dns_build_query(qname)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(pkt, (server, 53))
            data, _ = s.recvfrom(2048)
        finally:
            s.close()
        return _clean_hostname(_dns_first_ptr(data, txid), ip)
    except Exception:
        return None


def mdns_ptr_lookup(ip, timeout=NATIVE_MDNS_TIMEOUT):
    """mDNS reverso nativo (224.0.0.251:5353). Pilla <nombre>.local de
    portátiles, móviles, impresoras y TVs sin necesitar avahi ni systemd."""
    try:
        qname = _reverse_arpa(ip)
        if not qname:
            return None
        _txid, pkt = _dns_build_query(qname, txid=0, flags=0x0000)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            s.settimeout(timeout)
            s.sendto(pkt, ("224.0.0.251", 5353))
            end = time.time() + timeout
            while True:
                s.settimeout(max(0.05, end - time.time()))
                try:
                    data, _ = s.recvfrom(2048)
                except socket.timeout:
                    return None
                name = _clean_hostname(_dns_first_ptr(data), ip)
                if name:
                    return name
                if time.time() >= end:
                    return None
        finally:
            s.close()
    except Exception:
        return None


def llmnr_ptr_lookup(ip, timeout=NATIVE_LLMNR_TIMEOUT):
    """LLMNR reverso nativo (224.0.0.252:5355, RFC 4795). El que delata a
    los Windows que no publican mDNS."""
    try:
        qname = _reverse_arpa(ip)
        if not qname:
            return None
        txid, pkt = _dns_build_query(qname, flags=0x0000)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            s.sendto(pkt, ("224.0.0.252", 5355))
            end = time.time() + timeout
            while True:
                s.settimeout(max(0.05, end - time.time()))
                try:
                    data, _ = s.recvfrom(2048)
                except socket.timeout:
                    return None
                name = _clean_hostname(_dns_first_ptr(data, txid), ip)
                if name:
                    return name
                if time.time() >= end:
                    return None
        finally:
            s.close()
    except Exception:
        return None


def nbns_lookup(ip, timeout=NATIVE_NBNS_TIMEOUT):
    """NetBIOS NBSTAT directo (UDP/137, sin samba). Pregunta '*<00>' y lee
    los nombres registrados. Los Windows viejos y cacharros SMB contestan."""
    try:
        txid = random.randint(1, 0xFFFF)
        # '*' (0x2A) → 'CK' + padding 'AA'*15 (15 bytes × 2 chars)
        qname = b"\x20" + b"CK" + b"AA" * 15 + b"\x00"
        pkt = struct.pack(">HHHHHH", txid, 0x0010, 1, 0, 0, 0) + qname + struct.pack(">HH", 0x21, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(pkt, (ip, 137))
            data, _ = s.recvfrom(2048)
        finally:
            s.close()
        if len(data) < 12:
            return None
        rid, _fl, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
        if rid != txid or an == 0:
            return None
        off = 12
        for _ in range(qd):
            _n, off = _dns_decode_name(data, off)
            off += 4
        fallback = None
        for _ in range(an):
            _n, off = _dns_decode_name(data, off)
            if off + 10 > len(data):
                return None
            rtype, _cl, _ttl, rdlen = struct.unpack(">HHIH", data[off : off + 10])
            off += 10
            if rtype != 0x21 or rdlen < 1 or off + rdlen > len(data):
                off += rdlen
                continue
            count = data[off]
            p = off + 1
            for _i in range(min(count, 32)):
                if p + 18 > len(data):
                    break
                raw, suffix = data[p : p + 15], data[p + 15]
                flags = struct.unpack(">H", data[p + 16 : p + 18])[0]
                p += 18
                name = raw.split(b"\x00")[0].strip().decode("ascii", "replace")
                clean = _clean_hostname(name, ip)
                if not clean:
                    continue
                if not (flags & 0x8000):  # nombre único > grupo
                    if suffix == 0x00:
                        return clean  # workstation: el mejor
                    fallback = fallback or clean
                elif fallback is None:
                    fallback = clean
            return fallback
    except Exception:
        return None
    return None


# ── SSDP/UPnP: nombres "humanos" (friendlyName) ──────────────────────────────

SSDP_STS = ("ssdp:all", "upnp:rootdevice")
_FRIENDLY_RE = re.compile(r"<friendlyName\s*>(.*?)</friendlyName\s*>", re.IGNORECASE | re.DOTALL)
_MANUF_RE = re.compile(r"<manufacturer\s*>(.*?)</manufacturer\s*>", re.IGNORECASE | re.DOTALL)
_LOC_RE = re.compile(r"^\s*location\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)


def _clean_friendly(raw):
    """Nombre humano UPnP ('Salón TV'). Permite espacios, corta a 32."""
    if not raw:
        return None
    name = re.sub(r"\s+", " ", raw).strip()[:32].strip()
    if not name or len(name) < 2:
        return None
    low = name.lower()
    if "uuid" in low or low in ("unknown", "localhost"):
        return None
    if name.replace(".", "").replace("-", "").replace(":", "").isdigit():
        return None
    return name


def _fetch_upnp_name(location):
    try:
        req = urllib.request.Request(location, headers={"User-Agent": "lan-radar/2.0"})
        with urllib.request.urlopen(req, timeout=SSDP_FETCH_TIMEOUT) as r:
            if (r.headers.get_content_type() or "").split(";")[0] not in (
                "text/xml",
                "application/xml",
                "text/plain",
            ) and "xml" not in (r.headers.get_content_type() or ""):
                pass  # algunos equipos mienten el content-type: parsear igual
            xml = r.read(65536).decode("utf-8", "replace")
        m = _FRIENDLY_RE.search(xml)
        manu = _MANUF_RE.search(xml)
        return (
            _clean_friendly(m.group(1)) if m else None,
            manu.group(1).strip()[:24] if manu else "",
        )
    except Exception:
        return None, ""


def ssdp_sweep(timeout=SSDP_TIMEOUT):
    """Un M-SEARCH caza de golpe TVs, altavoces, NAS, routers e impresoras
    UPnP y devuelve {ip: {'name': friendlyName, 'vendor': manufacturer}}."""
    found = {}  # location -> sender ip
    for st in SSDP_STS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(timeout / len(SSDP_STS))
            msg = (
                "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                f'MAN: "ns=01;"\r\nMX: 2\r\nST: {st}\r\nUSER-AGENT: lan-radar/2.0\r\n\r\n'
            ).encode()
            try:
                s.sendto(msg, ("239.255.255.250", 1900))
            except Exception:
                s.close()
                continue
            end = time.time() + timeout / len(SSDP_STS)
            while True:
                s.settimeout(max(0.05, end - time.time()))
                try:
                    data, addr = s.recvfrom(8192)
                except socket.timeout:
                    break
                m = _LOC_RE.search(data.decode("utf-8", "replace"))
                if m and addr and addr[0]:
                    found.setdefault(m.group(1).strip(), addr[0])
                if time.time() >= end:
                    break
            s.close()
        except Exception:
            continue
    if not found:
        return {}
    out = {}
    with futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(_fetch_upnp_name, loc): (loc, ip) for loc, ip in found.items()}
        for fut in futures.as_completed(futs):
            loc, ip = futs[fut]
            try:
                name, vendor = fut.result()
            except Exception:
                continue
            if name and ip not in out:
                out[ip] = {"name": name, "vendor": vendor}
    return out


def avahi_browse_map(timeout=BROWSE_TIMEOUT):
    """`avahi-browse -a -t -r --parsable` → {ip: hostname}. Caza servicios
    anunciados (impresoras, Chromecasts, _smb, _airplay…) aunque el reverso falle.
    Con techo duro: si avahi se entretiene resolviendo, nos quedamos lo parcial."""
    mapping = {}
    out = ""
    try:
        p = subprocess.Popen(
            ["avahi-browse", "-a", "-t", "-r", "-p"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            out, _ = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                p.kill()
                out, _ = p.communicate(timeout=2)
            except Exception:
                out = out or ""
    except Exception:
        return mapping
    for line in (out or "").splitlines():
        if not line.startswith("="):
            continue
        parts = line.split(";")
        if len(parts) < 8:
            continue
        host, addr = parts[6].strip(), parts[7].strip()
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", addr) and host:
            clean = _clean_hostname(host, addr)
            if clean and addr not in mapping:
                mapping[addr] = clean
    return mapping


def resolve_hostname(ip, dns_servers=(), extra_names=None):
    """Cascada v2. Primera que dé nombre válido gana:
    getent → DNS directo al router → mDNS nativo → LLMNR nativo →
    NBNS nativo → SSDP/avahi-browse → avahi CLI → nmblookup → PTR sistema.
    """
    quick = _getent_lookup(ip)
    if quick:
        return quick
    for srv in dns_servers or ():
        try:
            name = dns_ptr_at_server(ip, srv)
        except Exception:
            name = None
        if name:
            return name
    for fn in (mdns_ptr_lookup, llmnr_ptr_lookup, nbns_lookup):
        try:
            name = fn(ip)
        except Exception:
            name = None
        if name:
            return name
    if extra_names and ip in extra_names:
        return extra_names[ip]
    for fn in (_mdns_lookup, _netbios_lookup, _ptr_lookup):
        try:
            name = fn(ip)
        except Exception:
            name = None
        if name:
            return name
    return "unknown"


# ── Fingerprint de tipo: hostname + puertos + TTL + OUI + gateway ────────────
# Orden de señales: gateway > keywords de hostname > puertos TCP > OUI > TTL.

# (keywords en hostname, etiqueta TIPO, icono). De específico a genérico.
TYPE_RULES = [
    (
        ("router", "gateway", "modem", "ont", "fibra", "livebox", "fritz",
         "movistar", "vodafone", "orange", "jazztel", "digi", "masmovil",
         "technicolor", "arcadyan", "askey", "mitra", "repeater", "extender"),
        "Router", "🛰️",
    ),
    (
        ("nintendo", "switch", "playstation", "ps5", "ps4", "ps3", "psp",
         "vita", "xbox", "xboxone", "steam-deck", "steamdeck"),
        "Consola", "🎮",
    ),
    (("chromecast",), "Cast", "📺"),
    (
        ("tv", "television", "smart-tv", "bravia", "webos", "tizen", "roku",
         "firetv", "appletv", "androidtv", "googletv", "shield-tv", "mi-tv",
         "cctv", "dvr", "nvr"),
        "TV", "📺",
    ),
    (("iphone",), "Móvil", "📱"),
    (("ipad", "tablet", "tab-"), "Tablet", "📱"),
    (
        ("android", "pixel", "galaxy", "samsung", "xiaomi", "redmi", "poco",
         "oneplus", "huawei", "honor", "oppo", "realme", "vivo", "motorola",
         "nokia", "phone", "mobile", "movil", "smartphone"),
        "Móvil", "📱",
    ),
    (("macbook", "imac", "mac-mini", "mac-"), "Mac", "🍎"),
    (
        ("raspberry", "rpi", "pihole", "octopi", "homeassistant", "hass",
         "dietpi", "proxmox"),
        "Mini-PC", "🍓",
    ),
    (
        ("printer", "impresora", "epson", "canon", "brother", "xerox",
         "laserjet", "officejet", "deskjet", "inkjet", "jetdirect", "npi"),
        "Impresora", "🖨️",
    ),
    (
        ("nas", "synology", "qnap", "truenas", "unraid", "plex", "jellyfin"),
        "NAS", "🗄️",
    ),
    (
        ("camera", "camara", "ipcam", "webcam", "mycam", "tapo", "reolink",
         "dahua", "hikvision", "wyze", "doorbell", "ring"),
        "Cámara", "🎥",
    ),
    (
        ("echo", "alexa", "sonos", "googlehome", "nest-audio", "homepod",
         "altavoz", "speaker"),
        "Altavoz", "🔊",
    ),
    (
        ("esp", "espressif", "tasmota", "shelly", "hue", "tuya", "smartplug",
         "smartbulb", "nest", "thermostat"),
        "IoT", "💡",
    ),
    (
        ("laptop", "notebook", "thinkpad", "ideapad", "pavilion", "envy",
         "zenbook", "vivobook", "legion", "nitro", "victus", "omen",
         "spectre", "elitebook", "probook", "swift", "aspire",
         "surface", "portatil"),
        "Portátil", "💻",
    ),
    (("server", "nuc", "mini-pc", "minipc"), "Servidor", "🖥️"),
    (
        ("vmware", "virtualbox", "vbox", "kvm", "qemu", "hyper-v", "hyperv",
         "xen", "parallels", "utm-", "virtual-machine", "vm-"),
        "VM", "📦",
    ),
    (("windows", "win-", "desktop", "tower", "workstation",
       "-pc", "_pc", " pc", "pc-", "pc_"), "PC", "🖥️"),
]

# OUI (3 primeros bytes MAC) → (marca, tipo, icono). Solo entradas fiables;
# lo dudoso se muestra como prefijo OUI sin inventar marca.
OUI_DB = {
    "b8:27:eb": ("Raspberry Pi", "Mini-PC", "🍓"),
    "dc:a6:32": ("Raspberry Pi", "Mini-PC", "🍓"),
    "d8:3a:dd": ("Raspberry Pi", "Mini-PC", "🍓"),
    "e4:5f:01": ("Raspberry Pi", "Mini-PC", "🍓"),
    "24:0a:c4": ("Espressif", "IoT", "💡"),
    "24:6f:28": ("Espressif", "IoT", "💡"),
    "30:ae:a4": ("Espressif", "IoT", "💡"),
    "3c:71:bf": ("Espressif", "IoT", "💡"),
    "a4:cf:12": ("Espressif", "IoT", "💡"),
    "18:b4:30": ("Nest", "IoT", "💡"),
    "00:80:77": ("Brother", "Impresora", "🖨️"),
    "fc:a1:83": ("Xiaomi", "Móvil", "📱"),
    "64:16:66": ("Samsung", "Móvil", "📱"),
    # Consolas: silenciosas (sin mDNS/NetBIOS/SSDP, 0 puertos TCP, ignoran
    # ping). El OUI es la única señal fiable sin root (verificado en red
    # real: Switch 20:1c:3a sin ping ni puertos → solo el OUI la delata).
    # Nintendo Co.,Ltd (Switch/WiiU/3DS; 20:1c:3a verificado en vivo):
    "20:1c:3a": ("Nintendo", "Consola", "🎮"),
    "20:0b:cf": ("Nintendo", "Consola", "🎮"),
    "28:cf:51": ("Nintendo", "Consola", "🎮"),
    "2c:10:c1": ("Nintendo", "Consola", "🎮"),
    "1c:45:86": ("Nintendo", "Consola", "🎮"),
    "04:03:d6": ("Nintendo", "Consola", "🎮"),
    "60:1a:c7": ("Nintendo", "Consola", "🎮"),
    "60:6b:ff": ("Nintendo", "Consola", "🎮"),
    "bc:9e:bb": ("Nintendo", "Consola", "🎮"),
    "cc:5b:31": ("Nintendo", "Consola", "🎮"),
    "40:d2:8a": ("Nintendo", "Consola", "🎮"),
    "48:f1:eb": ("Nintendo", "Consola", "🎮"),
    "58:b0:3e": ("Nintendo", "Consola", "🎮"),
    "34:2f:bd": ("Nintendo", "Consola", "🎮"),
    "00:1f:32": ("Nintendo", "Consola", "🎮"),
    "00:22:aa": ("Nintendo", "Consola", "🎮"),
    # Sony Interactive Entertainment (solo PlayStation, no TVs/móviles):
    "00:04:1f": ("PlayStation", "Consola", "🎮"),
    "00:13:15": ("PlayStation", "Consola", "🎮"),
    "00:15:c1": ("PlayStation", "Consola", "🎮"),
    "00:19:c5": ("PlayStation", "Consola", "🎮"),
    "00:1d:0d": ("PlayStation", "Consola", "🎮"),
    "00:1f:a7": ("PlayStation", "Consola", "🎮"),
    "04:f7:78": ("PlayStation", "Consola", "🎮"),
    "60:5b:b4": ("PlayStation", "Consola", "🎮"),
    "70:9e:29": ("PlayStation", "Consola", "🎮"),
    "78:c8:81": ("PlayStation", "Consola", "🎮"),
    "1c:98:c1": ("PlayStation", "Consola", "🎮"),
    "5c:84:3c": ("PlayStation", "Consola", "🎮"),
    "70:66:2a": ("PlayStation", "Consola", "🎮"),
    "ac:89:95": ("PlayStation", "Consola", "🎮"),
    "b4:0a:d8": ("PlayStation", "Consola", "🎮"),
    "c8:4a:a0": ("PlayStation", "Consola", "🎮"),
    "e8:6e:3a": ("PlayStation", "Consola", "🎮"),
    "f8:46:1c": ("PlayStation", "Consola", "🎮"),
    "f8:d0:ac": ("PlayStation", "Consola", "🎮"),
    "fc:0f:e6": ("PlayStation", "Consola", "🎮"),
    # NOTA: Xbox usa OUIs genéricos de Microsoft (compartidos con Surface),
    # así que no se mapea por OUI: se detecta por hostname (xbox*) y por el
    # puerto TCP 3074 (Xbox Live) en type_from_ports().
    # Hipervisores: las VMs en puente aparecen como un host más, con OUI virtual
    "08:00:27": ("VirtualBox", "VM", "📦"),
    "00:0c:29": ("VMware", "VM", "📦"),
    "00:50:56": ("VMware", "VM", "📦"),
    "00:05:69": ("VMware", "VM", "📦"),
    "00:15:5d": ("Hyper-V", "VM", "📦"),
    "52:54:00": ("QEMU/KVM", "VM", "📦"),
    "00:16:3e": ("Xen", "VM", "📦"),
    "00:1c:42": ("Parallels", "VM", "📦"),
}

# Puertos a sondear (TCP connect, sin root ni nmap). Elegidos porque delatan tipo.
# Incluye 3074 (Xbox Live) y 3478/3479/3480/3658 (PlayStation Network).
PORT_PROBES = [
    21, 22, 23, 53, 80, 139, 443, 445, 515, 548, 554, 631, 1883, 3000,
    3074, 3478, 3479, 3480, 3658, 5000, 5001, 5357, 8000, 8008, 8009,
    8080, 8883, 9100, 32400, 62078,
]
WEB_PORTS = {80, 443, 3000, 5000, 8000, 8080}


def vendor_of(mac):
    """Marca corta por OUI, o '' si no se sabe (no inventar)."""
    if not mac:
        return ""
    info = OUI_DB.get(mac[:8].lower())
    return info[0] if info else ""


def short_mac(mac):
    if not mac:
        return "—"
    return vendor_of(mac) or mac[:8].upper()


def _check_port(args):
    ip, port, timeout = args
    for _ in range(2):  # reintento: los IoT lentos a veces pierden el primer SYN
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return ip, port
        except Exception:
            continue
    return ip, None


def probe_all_ports(ips, timeout=PORT_TIMEOUT):
    """Sondeo TCP paralelo: todos los (ip, puerto) a la vez. ~0.5-1s total."""
    found = {ip: [] for ip in ips}
    if not ips:
        return found
    with futures.ThreadPoolExecutor(max_workers=PORT_WORKERS) as ex:
        futs = [ex.submit(_check_port, (ip, p, timeout)) for ip in ips for p in PORT_PROBES]
        try:
            for fut in futures.as_completed(futs, timeout=timeout * 4 + 2):
                try:
                    ip, port = fut.result()
                except Exception:
                    continue
                if port:
                    found[ip].append(port)
        except Exception:
            pass  # presupuesto agotado: nos quedamos con lo hallado
    return {ip: sorted(ps) for ip, ps in found.items()}


def type_from_ports(ports, ttl=None):
    """Deduce tipo desde puertos abiertos. Retorna (tipo, icono) o None."""
    s = set(ports or [])
    if not s:
        return None
    if s & {8008, 8009}:  # Chromecast / Google Home / Android TV
        return "Cast", "📺"
    if 3074 in s:  # Xbox Live (TCP 3074): la Xbox despierta sí lo abre
        return "Consola", "🎮"
    if s & {3478, 3479, 3480, 3658}:  # PlayStation Network
        return "Consola", "🎮"
    if s & {9100, 515, 631}:  # JetDirect / LPD / IPP
        return "Impresora", "🖨️"
    if 554 in s:  # RTSP
        return "Cámara", "🎥"
    if s & {1883, 8883}:  # MQTT
        return "IoT", "💡"
    if s & {548, 62078}:  # AFP / sync iPhone
        return "Apple", "🍎"
    if s & {5001, 32400}:  # Synology HTTPS / Plex
        return "NAS", "🗄️"
    if s & {445, 139}:  # SMB: Windows si TTL 128, si no NAS/Samba
        return ("PC", "🖥️") if ttl == 128 else ("NAS", "🗄️")
    if 53 in s:  # DNS en LAN ≈ router o Pi-hole
        return "Router", "🛰️"
    if 23 in s and 22 not in s:  # telnet sin ssh ≈ router viejo
        return "Router", "🛰️"
    if 22 in s:
        if s & (WEB_PORTS | {21, 23, 53}):
            return "Servidor", "🖥️"
        return ("Linux", "🐧") if len(s) == 1 else ("Servidor", "🖥️")
    if s <= WEB_PORTS | {5357}:  # solo web ≈ cacharro IoT/cámara básica
        return "IoT", "💡"
    return "Servidor", "🖥️"


def classify_device(hostname="", ip="", mac=None, ttl=None, ports=(), is_gateway=False):
    """Combina señales → (device_type, icon). gateway > nombre > puertos > OUI > TTL."""
    h = (hostname or "").lower()
    if is_gateway or (ip and (ip.endswith(".1") or ip.endswith(".254"))):
        return "Router", "🛰️"
    for keys, dtype, icon in TYPE_RULES:
        if any(k in h for k in keys):
            return dtype, icon
    pt = type_from_ports(ports, ttl)
    if pt:
        return pt
    if mac:
        info = OUI_DB.get(mac[:8].lower())
        if info:
            return info[1], info[2]
    if ttl == 128:  # stack Windows
        return "PC", "🖥️"
    if h and h != "unknown":
        return "Equipo", "💻"
    return "Desconoc", "👽"


def guess_os(hostname="", ttl=None, ports=()):
    """Pista de SO para el JSON/alerta. Conservador: '' si no está claro."""
    h = (hostname or "").lower()
    s = set(ports or [])
    if ttl == 128 or "windows" in h or h.startswith("win-") or "surface" in h:
        return "Windows"
    if s & {548, 62078} or "macbook" in h or "imac" in h or "iphone" in h or "ipad" in h:
        return "Apple"
    if "android" in h or "pixel" in h or "galaxy" in h:
        return "Android"
    if ttl == 64 and (22 in s or "linux" in h or "ubuntu" in h or "debian" in h):
        return "Linux"
    if ttl is not None and ttl >= 200:
        return "Firmware"
    return ""


# ── Scanner ──────────────────────────────────────────────────────────────────


class Scanner:
    def __init__(self, networks, timeout=DEFAULT_PING_TIMEOUT, do_ports=True,
                 do_tcp_arp=True, do_ssdp=True):
        self.networks = [networks] if isinstance(networks, (str, ipaddress.IPv4Network)) else list(networks)
        # por si llega un string suelto dentro de la lista
        fixed = []
        for n in self.networks:
            fixed.append(ipaddress.ip_network(n, strict=False) if isinstance(n, str) else n)
        self.networks = fixed
        self.timeout = timeout
        self.do_ports = do_ports
        self.do_tcp_arp = do_tcp_arp
        self.do_ssdp = do_ssdp
        self.own_ip = get_own_ip()

    @property
    def network(self):
        return self.networks[0]

    def _all_hosts(self):
        hosts = []
        for net in self.networks:
            hosts.extend(str(ip) for ip in itertools.islice(net.hosts(), MAX_HOSTS))
        if total_hosts(self.networks) > MAX_HOSTS:
            console.print(
                f"[yellow]⚠️  Redes grandes ({nets_label(self.networks)}),"
                f" limitando a {MAX_HOSTS} hosts[/yellow]"
            )
        # dedup manteniendo orden
        return list(dict.fromkeys(hosts))

    def _dns_servers(self):
        """Servidores a preguntar PTR directo: gateway + .1 de cada red."""
        servers = []
        gw = get_default_gateway()
        if gw:
            servers.append(gw)
        for net in self.networks:
            try:
                first = str(net.network_address + 1)
                if first not in servers:
                    servers.append(first)
            except Exception:
                pass
        return servers

    def scan(self, progress_cb=None):
        """Ping sweep + boost TCP→ARP. Retorna Devices online ordenados por IP."""
        hosts = self._all_hosts()

        ping_results = {}
        with futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {ex.submit(ping_host, ip, self.timeout): ip for ip in hosts}
            for done, fut in enumerate(futures.as_completed(futs), 1):
                try:
                    ping_results[futs[fut]] = fut.result()
                except Exception:
                    ping_results[futs[fut]] = (False, None, None)
                if progress_cb:
                    progress_cb(done, len(hosts))

        online_ips = [ip for ip, (on, _, _) in ping_results.items() if on]
        lat_map = {ip: lat for ip, (_on, lat, _t) in ping_results.items()}
        ttl_map = {ip: ttl for ip, (_on, _l, ttl) in ping_results.items()}

        # ── Boost: IPs mudas al ping pero vivas en ARP/TCP (típico 5GHz/IoT)
        # Solo promociona con prueba fresca (evita fantasmas STALE de ayer):
        #   - el knock abrió ≥1 puerto TCP → vivo seguro, o
        #   - ip neigh lo marca REACHABLE/DELAY/PERMANENT tras el knock
        #     (el SYN obliga al kernel a revalidar ARP; lo muerto cae a
        #     FAILED/INCOMPLETE y se filtra solo).
        post_arp = {}
        if self.do_tcp_arp:
            missed = [ip for ip in hosts if ip not in online_ips and ip != self.own_ip]
            knock = tcp_arp_boost(missed)
            time.sleep(0.5)  # deja que el kernel complete la resolución ARP
            post_arp = get_arp_table()  # ARPs frescos post-knock
            for ip in missed:
                if ip in online_ips:
                    continue
                if knock.get(ip):  # abrió puerto → vivo seguro
                    online_ips.append(ip)
                elif post_arp.get(ip, (None, ""))[1] in ("REACHABLE", "DELAY", "PERMANENT"):
                    online_ips.append(ip)
        else:
            post_arp = get_arp_table()

        if self.own_ip and self.own_ip not in online_ips:
            try:
                if any(ipaddress.ip_address(self.own_ip) in n for n in self.networks):
                    online_ips.append(self.own_ip)
                    lat_map.setdefault(self.own_ip, None)
                    ttl_map.setdefault(self.own_ip, None)
            except ValueError:
                pass

        hostname_map = {}
        # Puertos, SSDP y hostnames son independientes: se resuelven en paralelo.
        ports_future = ssdp_future = browse_future = None
        bg = futures.ThreadPoolExecutor(max_workers=3)
        if self.do_ports and online_ips:
            ports_future = bg.submit(probe_all_ports, online_ips)
        if self.do_ssdp:
            ssdp_future = bg.submit(ssdp_sweep)
            browse_future = bg.submit(avahi_browse_map)
        dns_servers = self._dns_servers()
        if online_ips:
            # SSDP/browse alimentan la cascada: esperarlos con techo.
            extra_names = {}
            if ssdp_future:
                try:
                    self._ssdp_info = ssdp_future.result(timeout=SSDP_TIMEOUT + 3)
                    for ip, info in self._ssdp_info.items():
                        extra_names.setdefault(ip, info["name"])
                except Exception:
                    self._ssdp_info = {}
            else:
                self._ssdp_info = {}
            if browse_future:
                try:
                    for ip, name in browse_future.result(timeout=BROWSE_TIMEOUT + 2).items():
                        extra_names.setdefault(ip, name)
                except Exception:
                    pass
            ex = futures.ThreadPoolExecutor(max_workers=DNS_WORKERS)
            futs = {ex.submit(resolve_hostname, ip, dns_servers, extra_names): ip for ip in online_ips}
            try:
                for fut in futures.as_completed(futs, timeout=DNS_BUDGET):
                    hostname_map[futs[fut]] = fut.result()
            except Exception:
                pass  # presupuesto agotado: el resto queda "unknown"
            for ip in online_ips:
                hostname_map.setdefault(ip, "unknown")
            ex.shutdown(wait=False, cancel_futures=True)
        else:
            self._ssdp_info = {}

        ports_map = ports_future.result() if ports_future else {}
        bg.shutdown(wait=False, cancel_futures=True)

        mac_table = {ip: mac for ip, (mac, _st) in post_arp.items()}
        gateway = get_default_gateway()
        own_host = socket.gethostname().split(".")[0] or "this-device"
        devices = []
        for ip in online_ips:
            hostname = hostname_map.get(ip, "unknown")
            if ip == self.own_ip and hostname == "unknown":
                hostname = own_host
            mac = mac_table.get(ip)
            lat = lat_map.get(ip)
            ttl = ttl_map.get(ip)
            ports = ports_map.get(ip, [])
            dtype, icon = classify_device(hostname, ip, mac, ttl, ports, is_gateway=(gateway is not None and ip == gateway))
            if ip == self.own_ip:
                icon = "⭐"
            vendor = vendor_of(mac)
            if not vendor and ip in self._ssdp_info:
                vendor = self._ssdp_info[ip].get("vendor", "")
            devices.append(
                Device(ip, hostname, lat, mac, icon, dtype, vendor, guess_os(hostname, ttl, ports), ports, ttl)
            )
        devices.sort(key=lambda d: int(ipaddress.ip_address(d.ip)))
        return devices


# ── Historial persistente ────────────────────────────────────────────────────


def _prune_snapshots(snaps, now):
    """Solo últimas 24h, máx 288 snapshots."""
    cutoff = (now - dt.timedelta(hours=24)).isoformat()
    return [s for s in snaps if s["iso"] >= cutoff][-288:]


class HistoryManager:
    def __init__(self):
        self.events = []
        for d in _read_json(HISTORY_FILE, [])[-200:]:
            if isinstance(d, dict) and d.get("ip"):
                self.events.append(
                    HistoryEvent(
                        d.get("time", ""),
                        d.get("iso", ""),
                        d["ip"],
                        d.get("hostname", "unknown"),
                        d.get("action", "joined"),
                    )
                )
        self.snapshots = [
            s for s in _read_json(SNAPSHOTS_FILE, []) if isinstance(s, dict) and "iso" in s and "count" in s
        ]
        self.snapshots = _prune_snapshots(self.snapshots, dt.datetime.now())
        self.known = _read_json(KNOWN_FILE, {})
        if not isinstance(self.known, dict):
            self.known = {}

    def save(self):
        try:
            HISTORY_FILE.write_text(json.dumps([asdict(e) for e in self.events], ensure_ascii=False))
            SNAPSHOTS_FILE.write_text(json.dumps(self.snapshots))
            KNOWN_FILE.write_text(json.dumps(self.known, ensure_ascii=False))
        except Exception as e:
            console.print(f"[dim]No se pudo guardar historial: {e}[/dim]")

    def record(self, devices, joined=(), left=()):
        """Una sola escritura por escaneo: eventos + known + snapshot."""
        by_ip = {d.ip: d for d in devices}
        now = dt.datetime.now()
        stamp = (now.strftime("%H:%M:%S"), now.isoformat())
        for ip in joined:
            if ip in by_ip:
                self.events.append(HistoryEvent(stamp[0], stamp[1], ip, by_ip[ip].hostname, "joined"))
        for ip in left:
            self.events.append(
                HistoryEvent(
                    stamp[0],
                    stamp[1],
                    ip,
                    self.known.get(ip, {}).get("hostname", "unknown"),
                    "left",
                )
            )
        del self.events[:-100]
        for d in devices:
            self.known.setdefault(d.ip, {"first_seen": now.isoformat()})
            self.known[d.ip].update(
                last_seen=now.isoformat(),
                hostname=d.hostname,
                icon=d.icon,
                device_type=d.device_type,
                vendor=d.vendor,
            )
        self.snapshots.append(
            {
                "iso": now.isoformat(),
                "time": now.strftime("%H:%M"),
                "count": len(devices),
            }
        )
        self.snapshots = _prune_snapshots(self.snapshots, now)
        self.save()

    def recent(self, n=6):
        return list(reversed(self.events[-n:]))


# ── UI ───────────────────────────────────────────────────────────────────────


def _panel(content, title):
    """Panel estándar de la TUI (mismo box/borde/padding en ESTADO/HISTORIAL/GRÁFICA)."""
    return Panel(content, title=title, box=box.ROUNDED, border_style="bright_black", padding=(0, 1))


def _avg_lat(devices):
    """Latencia media formateada (usada en ESTADO y en --once)."""
    lats = [d.latency_ms for d in devices if d.latency_ms is not None]
    return _lat(sum(lats) / len(lats)) if lats else "[dim]—[/dim]"


def render_table(devices, own_ip):
    table = Table(
        box=box.HEAVY,
        show_header=True,
        header_style="bold bright_cyan",
        border_style="bright_black",
        expand=True,
        padding=(0, 1),
        collapse_padding=True,
    )
    # 3+15+12+8+8+8+9 + bordes/padding ≈ 78 cols (cabe en 80)
    table.add_column(" ", width=3, justify="center", no_wrap=True, overflow="fold")
    table.add_column("IP", style="bold white", no_wrap=True, width=15, overflow="fold")
    table.add_column(
        "HOSTNAME",
        style="cyan",
        no_wrap=False,
        width=12,
        overflow="ellipsis",
        min_width=8,
    )
    table.add_column("TIPO", style="yellow", no_wrap=True, width=8, overflow="ellipsis")
    table.add_column("MAC", style="dim", no_wrap=True, width=8, overflow="fold")
    table.add_column("LATENCIA", justify="right", width=8, overflow="fold")
    table.add_column("ESTADO", justify="center", width=9, overflow="fold")

    if not devices:
        table.add_row("—", "[dim]—[/dim]", "[dim]sin dispositivos[/dim]", "—", "—", "—", "[dim]—[/dim]")
        return table
    for d in devices:
        host = _esc(d.hostname) + (" [dim](tú)[/dim]" if d.ip == own_ip else "")
        table.add_row(
            d.icon,
            d.ip,
            host,
            _esc(d.device_type),
            short_mac(d.mac),
            _lat(d.latency_ms),
            "[bright_green]🟢 ONLINE[/bright_green]",
        )
    return table


def render_header(networks, interval, scan_count):
    if isinstance(networks, (str, ipaddress.IPv4Network)):
        networks = [networks]
    title = Text(
        f" 📡  LAN RADAR  {VERSION} ",
        style="bold black on bright_green",
        justify="center",
    )
    subtitle = Text(
        f"{nets_label(networks)}  •  escaneo #{scan_count}  •  cada {interval}s"
        f"  •  {dt.datetime.now().strftime('%H:%M:%S')}",
        style="dim",
        justify="center",
    )
    grid = Table.grid(expand=True)
    grid.add_column(justify="center")
    grid.add_row(title)
    grid.add_row(subtitle)
    return Panel(grid, box=box.HEAVY, border_style="bright_green", padding=(0, 0))


def render_stats(devices, last_scan, networks):
    if isinstance(networks, (str, ipaddress.IPv4Network)):
        networks = [networks]
    total = total_hosts(networks)
    avg = _avg_lat(devices)
    pct = len(devices) / total * 100 if total else 0
    filled = int(12 * len(devices) / max(total, 1))
    bar = "█" * filled + "░" * (12 - filled)
    bar_c = "bright_green" if pct < 50 else "yellow" if pct < 80 else "red"
    t = Table.grid(padding=(0, 2))
    t.add_column(style="dim")
    t.add_column(style="bold white")
    t.add_row(
        "Dispositivos:",
        f"[bright_cyan]{len(devices)}[/bright_cyan] / {total}  [{bar_c}]{bar}[/{bar_c}] {pct:.0f}%",
    )
    t.add_row("Latencia media:", avg)
    t.add_row("Último escaneo:", f"[white]{last_scan}[/white]")
    t.add_row("Rango:", f"[dim]{nets_label(networks)}[/dim]")
    return _panel(t, "[bold bright_green]▣ ESTADO[/bold bright_green]")


def render_history(events):
    if not events:
        return _panel(
            Text("  sin eventos aún — deja el radar corriendo", style="dim italic"),
            "[bold yellow]◷ HISTORIAL[/bold yellow]",
        )
    t = Table.grid(padding=(0, 1))
    t.add_column(width=8, style="dim", no_wrap=True)
    t.add_column(width=2, justify="center", no_wrap=True)
    t.add_column(width=13, no_wrap=True, overflow="fold")
    t.add_column(no_wrap=False, overflow="ellipsis")
    for ev in events:
        joined = ev.action == "joined"
        icon = "[bright_green]🟢[/bright_green]" if joined else "[red]🔴[/red]"
        action = f"[bright_green]{ev.action}[/bright_green]" if joined else f"[red]{ev.action}[/red]"
        t.add_row(ev.time, icon, ev.ip, f"{_esc(ev.hostname)} {action}")
    return _panel(t, "[bold yellow]◷ HISTORIAL[/bold yellow]")


BLOCKS = " ▁▂▃▄▅▆▇█"


def render_graph(snapshots):
    if len(snapshots) < 2:
        return _panel(
            Text("  recopilando datos para gráfica 24h…", style="dim italic"),
            "[bold magenta]▅ GRÁFICA 24H[/bold magenta]",
        )
    counts = [s["count"] for s in snapshots]
    lo, hi = min(counts), max(counts)
    spark = "▅" * len(counts) if hi == lo else "".join(BLOCKS[int((c - lo) / (hi - lo) * 8)] for c in counts)
    info = Table.grid(expand=True)
    info.add_column(justify="left", style="dim")
    info.add_column(justify="center", style="dim")
    info.add_column(justify="right", style="dim")
    mid = snapshots[len(snapshots) // 2]["time"] if len(snapshots) > 2 else ""
    info.add_row(snapshots[0]["time"], mid, snapshots[-1]["time"])
    grid = Table.grid(expand=True)
    grid.add_column()
    grid.add_row(Text(spark, style="bright_magenta"))
    grid.add_row(info)
    grid.add_row(
        Text(
            f"  min {lo}  •  max {hi}  •  ahora {counts[-1]} dispositivos",
            style="dim",
            justify="center",
        )
    )
    return _panel(grid, "[bold magenta]▅ GRÁFICA 24H[/bold magenta]")


def render_new_device_alert(device):
    ports = ", ".join(map(str, device.open_ports)) if device.open_ports else "—"
    t = Table.grid(expand=True, padding=(0, 1))
    t.add_column(style="dim", width=12)
    t.add_column(style="bold white")
    t.add_row("IP:", f"[bright_cyan]{device.ip}[/bright_cyan]")
    t.add_row("Hostname:", f"[white]{_esc(device.hostname)}[/white]")
    t.add_row("Tipo:", f"[yellow]{_esc(device.device_type)}[/yellow]")
    t.add_row("Marca:", f"[white]{_esc(device.vendor) or '—'}[/white]")
    t.add_row("Latencia:", _lat(device.latency_ms))
    t.add_row("MAC:", f"[dim]{device.mac or '—'}[/dim]")
    t.add_row("Puertos:", f"[dim]{ports}[/dim]")
    t.add_row("Icono:", device.icon)
    inner = Table.grid(expand=True)
    inner.add_column(justify="center")
    inner.add_row(Text("🚨  NEW DEVICE DETECTED  🚨", style="bold white on red", justify="center"))
    inner.add_row(Text(""))
    inner.add_row(t)
    inner.add_row(Text(""))
    inner.add_row(Text("[ENTER] para reconocer  •  [q] salir", style="dim italic", justify="center"))
    return Panel(
        inner,
        box=box.HEAVY,
        border_style="red",
        padding=(1, 2),
        title="[bold red]⚠ ALERTA[/bold red]",
    )


# ── Teclado ──────────────────────────────────────────────────────────────────


def _raw():
    """Pone stdin en cbreak. Devuelve old para restaurar, o None si no hay TTY."""
    if not HAS_TTY or not sys.stdin.isatty():
        return None
    try:
        old = termios.tcgetattr(sys.stdin)
        tty.setcbreak(sys.stdin.fileno())
        return old
    except Exception:
        return None


def _restore(old):
    if old is not None:
        try:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
        except Exception:
            pass


def _read_key(timeout):
    """Tecla sin bloqueo (bytes en minúsculas) o b'' si no hay nada."""
    try:
        r, _, _ = select.select([sys.stdin], [], [], timeout)
        if r:
            return os.read(sys.stdin.fileno(), 10).lower()
    except Exception:
        pass
    return b""


def _wait_key():
    """Espera ENTER (ack) o q. Retorna 'enter' | 'q'."""
    old = _raw()
    if old is None:
        try:
            input()
        except Exception:
            pass
        return "enter"
    try:
        while True:
            ch = _read_key(0.2)
            if not ch:
                continue
            if b"q" in ch or b"\x03" in ch:  # q o Ctrl+C
                return "q"
            if b"\r" in ch or b"\n" in ch:
                return "enter"
    except Exception:
        return "enter"
    finally:
        _restore(old)


# ── App ──────────────────────────────────────────────────────────────────────


class LANRadarApp:
    def __init__(self, networks, interval, timeout, do_ports=True, do_tcp_arp=True, do_ssdp=True):
        self.networks = [networks] if isinstance(networks, (str, ipaddress.IPv4Network)) else list(networks)
        self.interval = interval
        self.scanner = Scanner(networks, timeout, do_ports, do_tcp_arp, do_ssdp)
        self.history = HistoryManager()
        self.devices = []
        self.prev_ips = set()
        self.scan_count = 0
        self.last_scan_str = "—"
        self.own_ip = get_own_ip()

    @property
    def network(self):
        return self.networks[0]

    def diff_and_record(self, devs):
        new = {d.ip for d in devs}
        joined, left = new - self.prev_ips, self.prev_ips - new
        if self.scan_count <= 1:  # primer escaneo: registra sin spamear eventos
            self.history.record(devs)
            return joined, left, []
        fresh = [d for d in devs if d.ip in joined and d.ip not in self.history.known]
        self.history.record(devs, joined, left)
        return joined, left, fresh

    def build_renderable(self):
        header = render_header(self.networks, self.interval, self.scan_count)
        table = render_table(self.devices, self.own_ip)
        stats = render_stats(self.devices, self.last_scan_str, self.networks)
        hist = render_history(self.history.recent())
        graph = render_graph(self.history.snapshots)
        body = Table.grid(expand=True, padding=(0, 0))
        body.add_column()
        body.add_row(header)
        body.add_row(table)
        wide = console.size.width >= 100
        if wide:
            footer = Table.grid(expand=True, padding=(1, 1))
            footer.add_column(ratio=1)
            footer.add_column(ratio=1)
            footer.add_row(stats, hist)
            body.add_row(footer)
        else:
            body.add_row(stats)
            body.add_row(hist)
        body.add_row(graph)
        hint = Text(
            " [q] salir  •  [r] rescan  •  [c] limpiar historial  •  deja el radar corriendo",
            style="dim italic",
            justify="center",
        )
        body.add_row(Panel(hint, box=box.MINIMAL, padding=(0, 0), border_style="dim"))
        return body

    def run_once(self):
        self.scan_count += 1
        devs = self.scanner.scan()
        self.devices = devs
        self.last_scan_str = dt.datetime.now().strftime("%H:%M:%S")
        out = self.diff_and_record(devs)
        self.prev_ips = {d.ip for d in devs}
        return devs, *out

    def run_tui(self):
        console.clear()
        console.print(
            f"[bright_green]📡 LAN RADAR {VERSION}[/bright_green]"
            f" [dim]• {nets_label(self.networks)} • cada {self.interval}s[/dim]"
        )
        console.print(f"[dim]Escaneando {total_hosts(self.networks)} hosts — tu IP {self.own_ip or '?'}[/dim]\n")
        self.run_once()  # ya registra known + snapshot inicial

        old = _raw()

        pending = []
        try:
            with Live(
                self.build_renderable(),
                console=console,
                refresh_per_second=2,
                screen=True,
            ) as live:
                next_scan = time.time() + self.interval
                while True:
                    if old is None:
                        time.sleep(0.05)
                    else:
                        ch = _read_key(0.05)
                        if b"q" in ch or b"\x03" in ch:
                            break
                        if b"r" in ch:
                            next_scan = time.time()
                        if b"c" in ch:
                            self.history.events.clear()
                            self.history.snapshots.clear()
                            self.history.save()

                    if pending:
                        dev = pending.pop(0)
                        live.stop()
                        _restore(old)
                        console.clear()
                        console.print(render_new_device_alert(dev))
                        console.print()
                        quit_ = _wait_key() == "q"
                        old = _raw() or old
                        if quit_:
                            break
                        live.start()
                        next_scan = time.time() + self.interval
                        continue

                    if time.time() >= next_scan:
                        _, _, _, fresh = self.run_once()
                        pending.extend(fresh)
                        live.update(self.build_renderable())
                        next_scan = time.time() + self.interval
                    else:
                        live.update(self.build_renderable())
                        time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            _restore(old)
            console.clear()
            console.print(
                f"[bright_green]📡 LAN RADAR detenido[/bright_green]"
                f" [dim]— {self.scan_count} escaneos, {len(self.history.events)} eventos[/dim]"
            )
            console.print(f"[dim]Historial guardado en {HISTORY_FILE}[/dim]")
            if self.devices:
                console.print(render_table(self.devices, self.own_ip))
            if self.history.events:
                console.print(render_history(self.history.recent(10)))


# ── CLI ──────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="📡 LAN RADAR — escanea tu red local (2.4GHz + 5GHz + ethernet)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Ejemplos:\n  python lan_radar.py\n  python lan_radar.py --once\n"
        "  python lan_radar.py --range 192.168.0.0/24 --interval 10\n"
        "  python lan_radar.py --range 192.168.1.0/24 --range 192.168.2.0/24\n",
    )
    parser.add_argument(
        "--range",
        dest="range",
        action="append",
        default=None,
        help="CIDR a escanear (ej: 192.168.1.0/24). Repetible. Sin esto escanea TODAS las redes locales",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL,
        help=f"Intervalo entre escaneos en segundos (default {DEFAULT_INTERVAL})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_PING_TIMEOUT,
        help=f"Timeout ping en segundos (default {DEFAULT_PING_TIMEOUT})",
    )
    parser.add_argument("--once", action="store_true", help="Hace un solo escaneo y sale (sin TUI)")
    parser.add_argument("--json", action="store_true", help="En modo --once, salida en JSON")
    parser.add_argument("--no-color", action="store_true", help="Desactiva colores")
    parser.add_argument(
        "--no-ports",
        action="store_true",
        help="Omite el sondeo de puertos (escaneo más rápido y sigiloso, pero peor detección de tipo)",
    )
    parser.add_argument(
        "--no-tcp-arp",
        action="store_true",
        help="Omite el boost TCP→ARP (no caza dispositivos que ignoran ping: móviles en reposo, IoT)",
    )
    parser.add_argument(
        "--no-ssdp",
        action="store_true",
        help="Omite SSDP/UPnP + avahi-browse (nombres 'Salón TV' de teles/altavoces/NAS)",
    )
    args = parser.parse_args()

    if args.json and not args.once:
        args.once = True
    if args.no_color:
        console.no_color = True
    if args.interval < 1 or args.timeout < 1:
        console.print("[red]--interval y --timeout deben ser >= 1[/red]")
        sys.exit(1)

    networks = get_all_local_networks(args.range)

    if args.once:
        scanner = Scanner(
            networks, args.timeout, do_ports=not args.no_ports,
            do_tcp_arp=not args.no_tcp_arp, do_ssdp=not args.no_ssdp,
        )
        if args.json:
            print(json.dumps([asdict(d) for d in scanner.scan()], indent=2, ensure_ascii=False))
            return
        total = total_hosts(networks)
        console.print(f"[dim]Escaneando {nets_label(networks)} ({total} hosts)...[/dim]")
        console.print("[dim]Ping + TCP→ARP (mudos) + nombres (router/mDNS/UPnP)...[/dim]")
        start = time.time()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
            console=console,
            transient=True,
        ) as prog:
            task = prog.add_task(f"ping {nets_label(networks)}", total=total)
            devices = scanner.scan(progress_cb=lambda done, _t: prog.update(task, completed=done))
        elapsed = time.time() - start
        console.print(render_table(devices, scanner.own_ip))
        avg = _avg_lat(devices)
        console.print(
            f"\n[bold]Dispositivos:[/bold] {len(devices)}  [dim]•[/dim]"
            f"  [bold]Latencia media:[/bold] {avg}  [dim]•[/dim]"
            f"  [bold]Tiempo:[/bold] {elapsed:.1f}s  [dim]•[/dim]  [bold]Rango:[/bold] {nets_label(networks)}"
        )
        console.print(
            f"[dim]Último escaneo: {dt.datetime.now().strftime('%H:%M:%S')}"
            f"  •  tu IP: {scanner.own_ip or '?'}[/dim]"
        )
        return

    LANRadarApp(
        networks, args.interval, args.timeout, do_ports=not args.no_ports,
        do_tcp_arp=not args.no_tcp_arp, do_ssdp=not args.no_ssdp,
    ).run_tui()


if __name__ == "__main__":
    main()
