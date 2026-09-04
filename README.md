# 📡 LAN RADAR v2.0

> Tu propio Fing en una hora. Escanea tu red local y te enseña qué hay conectado — absurdamente bonito.

```text
╔════════════════════════════════════════════════════════════╗
║                📡 LAN RADAR v1.1                          ║
╠════════════════════════════════════════════════════════════╣
║  IP             HOSTNAME      TIPO      MAC       LAT      ║
║  192.168.1.1    _gateway      Router    60:A4:B7  1.5ms 🟢 ║
║  192.168.1.191  omarchy (tú)  Equipo    —         0.0ms 🟢 ║
║  192.168.1.219  pantherlake   Linux     84:47:09  0.8ms 🟢 ║
╚════════════════════════════════════════════════════════════╝
Dispositivos: 7 • Latencia media: 6.5ms • Último escaneo: 10:16:48
```

## 🔥 Niveles

**Nivel 1 — 15 min**
- Detecta automáticamente tu rango (`ip route` + `ip addr` + socket fallback)
- Ping sweep paralelo (50 workers) a todo el `/24`
- Muestra quién responde

**Nivel 2 — 20 min**
- Hostname multi-fuente en cascada: reverse DNS → `getent hosts` → mDNS (`avahi-resolve-address`, pilla `*.local` que el router no sabe) → NetBIOS (`nmblookup -A`)
- Latencia real parseando `ping -c 1 -W 1` (+ TTL para pista de SO)
- Diff entre escaneos → detecta joins/leaves

**Nivel 6 — nombres v2 + todas las bandas 💀**
- El problema: si tu DNS es Cloudflare/1.1.1.1 o el stub de systemd, el reverse-DNS **nunca** sabe los nombres DHCP de tu LAN; y systemd suele llevar mDNS/LLMNR desactivados en el WiFi. Resultado: todo "unknown".
- La solución, en Python puro y sin root: **PTR directo al router** (su dnsmasq sí sabe los nombres DHCP de 2.4GHz, 5GHz y ethernet) → **mDNS reverso nativo** (224.0.0.251:5353, `*.local` sin avahi) → **LLMNR nativo** (224.0.0.252:5355, Windows) → **NBNS directo** (UDP/137, sin samba) → **SSDP/UPnP** (`friendlyName` real: "Salón TV") + `avahi-browse` → fallbacks clásicos.
- **2.4GHz + 5GHz + ethernet**: normalmente comparten subred, así que ya se veían… salvo los que **ignoran el ping** (móviles en reposo, IoT barato) o si el router aísla bandas/VLANs. Ahora: se escanean **todas las redes locales a la vez** (`--range` repetible) + **boost TCP→ARP**: knock a (80, 443, 445, 22) en las IPs mudas para forzar al kernel a resolver ARP y releer `ip neigh`. Solo promociona con prueba fresca (puerto abierto o REACHABLE/DELAY), sin fantasmas STALE.
- En una red real: de 6 dispositivos con 4 "unknown" → **9 dispositivos con 2 "unknown"** (cazó un POCO en 5G y un portátil HP que ni ping respondían).

**Nivel 3 — 20 min (absurdamente bonito)**
- TUI hacker con Rich: `box.HEAVY`, verde `#00ff41`, bordes neon
- Columna TIPO + iconos por dispositivo: 🛰️ Router, 📱 Móvil, 🍎 Mac/Apple, 🍓 Mini-PC, 🖨️ Impresora, 📺 TV/Cast, 🎮 Consola (Nintendo/PlayStation/Xbox por OUI, hostname o puertos 3074/3478-3480/3658), 🖥️ PC/Servidor, 📦 VM (VirtualBox/VMware/Hyper-V/KVM/Xen/Parallels por OUI o nombre), 🐧 Linux, 🎥 Cámara, 🔊 Altavoz, 💡 IoT, 🗄️ NAS, 👽 desconocido, ⭐ tú
- Historial últimos eventos + refresco auto cada 5s
- Adaptado a 80 columnas (Omarchy terminal)

**Nivel 4 — jefe final 💀**
- 🚨 `NEW DEVICE DETECTED` modal que pausa el Live y espera `[ENTER]`
- Historial persistente en `~/.local/share/lan-radar/` (`history.json`, `snapshots.json`, `known_devices.json`)
- Gráfica 24h con bloques `▁▂▃▄▅▆▇█` (288 snapshots, 1 cada 5 min)

**Nivel 5 — fingerprint sin root 💀**
- Tipo por combinación de señales: gateway real (`ip route`) > keywords de hostname > **puertos TCP abiertos** (sin nmap, puro `connect()`) > OUI de la MAC > TTL del ping
- Huellas: 8008/8009 → Cast, 9100/515/631 → impresora, 554 → cámara, 1883/8883 → IoT/MQTT, 548/62078 → Apple, 3074 → Xbox, 3478/3479/3480/3658 → PlayStation, 445+TTL128 → Windows, 53 → router/DNS, 22 solo → Linux. Las consolas dormidas (0 puertos, sin ping: típico Switch) se cazan por OUI (Nintendo + Sony Interactive Entertainment)
- El JSON incluye `device_type`, `vendor`, `os_hint`, `open_ports` y `ttl` por dispositivo

## 🛠️ Instalación

```bash
# Omarchy / Arch
pip install rich
# o
pip install -r requirements.txt

# Opcional pero recomendado (mejoran el hostname; si faltan se omite esa fuente):
sudo pacman -S avahi samba  # avahi-resolve-address + nmblookup

chmod +x lan_radar.py
```

## 🚀 Uso

```bash
# TUI interactiva (recomendado) — deja corriendo
python lan_radar.py
# o
./lan_radar.py

# Un solo escaneo
python lan_radar.py --once

# JSON para scripts
python lan_radar.py --once --json | jq

# Rango custom (sin fingerprint de puertos: más rápido y sigiloso)
python lan_radar.py --range 192.168.0.0/24 --interval 10 --no-ports

# Varias redes a la vez (bandas aisladas, VLANs, invitados)
python lan_radar.py --range 192.168.1.0/24 --range 192.168.2.0/24

# Modo rápido (~1s en /29): sin puertos, sin TCP→ARP, sin SSDP
python lan_radar.py --once --no-ports --no-tcp-arp --no-ssdp

# Sin colores (para logs)
python lan_radar.py --once --no-color
```

### Controles TUI

| Tecla | Acción |
|-------|--------|
| `q` | salir |
| `r` | forzar rescan |
| `c` | limpiar historial |
| `ENTER` | reconocer alerta NEW DEVICE |

### Dónde se guarda el historial

```
~/.local/share/lan-radar/history.json      # eventos joined/left
~/.local/share/lan-radar/snapshots.json    # gráfica 24h
~/.local/share/lan-radar/known_devices.json # dispositivos conocidos
```

Ejemplo `history.json`:

```json
[
  {
    "time": "10:02:00",
    "iso": "2026-09-03T10:02:00",
    "ip": "192.168.1.23",
    "hostname": "migue-PC",
    "action": "joined"
  }
]
```

## 📺 Captura TUI

```
┏━━━━━━━━━━━━━━━━━━ 📡 LAN RADAR v1.1 ━━━━━━━━━━━━━━━━━━┓
┃ 192.168.1.0/24 • escaneo #42 • cada 5s • 10:16:58      ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
┏━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━┓
┃      ┃IP             ┃HOSTNAME     ┃TIPO    ┃MAC     ┃LATENCIA ┃ ESTADO   ┃
┣━━━━━━╋━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━╋━━━━━━━━╋━━━━━━━━╋━━━━━━━━━╋━━━━━━━━━━┫
┃  🛰️  ┃192.168.1.1    ┃_gateway     ┃Router  ┃60:A4:B7┃  1.5 ms ┃🟢 ONLINE ┃
┃  ⭐  ┃192.168.1.191  ┃omarchy (tú) ┃Equipo  ┃—       ┃  0.0 ms ┃🟢 ONLINE ┃
┗━━━━━━┻━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━┻━━━━━━━━┻━━━━━━━━┻━━━━━━━━━┻━━━━━━━━━━┛
╭────────── ▣ ESTADO ──────────╮╭────────── ◷ HISTORIAL ──────────╮
│ Dispositivos: 7 / 254  ██░░ 3% ││ 10:07 🟢 192.168.1.73 joined     │
│ Latencia media: 6.5 ms        ││ 10:04 🔴 192.168.1.42 left       │
╰───────────────────────────────╯╰────────────────────────────────╯
╭─────────────────────── ▅ GRÁFICA 24H ───────────────────────╮
│ ▁▂▃▄▅▆▇█▅▃▁  min 2 • max 7 • ahora 7 dispositivos            │
│ 09:00              21:00              10:16                  │
╰──────────────────────────────────────────────────────────────╯
```

### Alerta NEW DEVICE

```
╭──────────────────────── ⚠ ALERTA ────────────────────────╮
│                                                          │
│              🚨  NEW DEVICE DETECTED  🚨                 │
│                                                          │
│   IP:       192.168.1.73                                 │
│   Hostname: iphone-de-alguien                            │
│   Tipo:     Móvil                                        │
│   Marca:    Apple                                        │
│   Latencia: 12.0 ms                                      │
│   MAC:      aa:bb:cc:dd:ee:ff                            │
│   Puertos:  62078                                        │
│                                                          │
│         [ENTER] para reconocer  •  [q] salir             │
╰──────────────────────────────────────────────────────────╯
```

## 🧪 Stack

- **Python 3.10+** + **Rich 13+** (única dependencia)
- `ping` del sistema (no necesita root ni nmap)
- `ip neigh` para MACs; hostnames vía PTR directo al router + `getent` + mDNS/LLMNR/NBNS nativos (multicast, Python puro) + SSDP/UPnP + `avahi-browse`/`avahi-resolve-address` + `nmblookup`
- Descubrimiento multi-red con boost TCP→ARP para los que ignoran ICMP
- Fingerprint de puertos con `socket.create_connection` (25 puertos, paralelo, ~1s)
- `ThreadPoolExecutor` 50 workers, timeouts controlados

## ⚡ Performance

- `/24` (254 hosts) en ~15s con sweep completo (ping + TCP→ARP + router-DNS + mDNS/LLMNR/NBNS + SSDP + puertos, todo en paralelo)
- `/16` limitado a 512 hosts para no saturar WiFi
- Hostnames en paralelo (30 workers, presupuesto total 8s por escaneo)
- `--no-ports --no-tcp-arp --no-ssdp` para ir rápido y sigiloso

## 🐛 Troubleshooting

```bash
# ¿De dónde sale tu DNS? Si es 1.1.1.1/8.8.8.8, el sistema JAMÁS sabrá los
# nombres LAN (por eso v2.0 pregunta al router directamente):
resolvectl status | grep -A3 "Current DNS"

# No ves dispositivos de la 5GHz:
# 1. Normalmente comparten subred con 2.4G/ethernet: el radar ya los barre.
#    Si faltan es que ignoran ping (móviles/IoT) → el boost TCP→ARP los caza.
# 2. Si tu router aísla bandas ("Isolate 2.4GHz and 5GHz") o usa VLANs/
#    red de invitados, son subredes distintas: escanea todas con --range.
# 3. Comprueba qué ve el kernel en L2: ip neigh

# No detecta rango
python lan_radar.py --range 192.168.1.0/24 --once --json

# Probar ping manual
ping -c 1 -W 1 192.168.1.1

# Ver vecinos ARP
ip neigh

# Muchos "unknown": instala avahi para mDNS (portátiles/móviles/TVs)
sudo pacman -S avahi && sudo systemctl enable --now avahi-daemon
avahi-resolve-address 192.168.1.X  # prueba manual

# Ver qué ve el fingerprint de un host
python -c "import socket; [print(p, 'OPEN' if (lambda s: (s.settimeout(0.5), s.connect_ex(('192.168.1.X', p)) == 0)[1])(socket.socket()) else 'closed') for p in (22,80,443,445,554,631,8008,8009)]"

# Ver historial
cat ~/.local/share/lan-radar/history.json | jq
```

## 📜 Licencia

MIT — Haz lo que quieras, pero deja el radar corriendo y di "hostia, esto sí lo uso" 😎
