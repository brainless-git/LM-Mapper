"""Aruba parsers: ArubaOS-Switch / HP ProCurve, and AOS-CX."""
from __future__ import annotations

import re

from ..models import Port, SwitchConfig, compress_vlans, expand_vlan_list, natural_key


# --------------------------------------------------------------------------
# ArubaOS-Switch / ProCurve
# --------------------------------------------------------------------------

def detect_procurve(text: str) -> bool:
    if re.search(r"^; \S+ Configuration Editor", text, re.M):
        return True
    return bool(re.search(r'^hostname "', text, re.M)
                and re.search(r"^\s+(untagged|tagged) \S", text, re.M))


def expand_procurve_ports(spec: str) -> list[str]:
    """'1-3,A1-A2,1/5-1/6,Trk1' -> ['1','2','3','A1','A2','1/5','1/6','Trk1']."""
    out: list[str] = []
    for tok in spec.split(","):
        tok = tok.strip()
        if not tok:
            continue
        m = re.fullmatch(r"((?:\d+/)?[A-Za-z]?)(\d+)-\1(\d+)", tok)
        if m:
            prefix = m.group(1)
            out.extend(f"{prefix}{i}" for i in range(int(m.group(2)), int(m.group(3)) + 1))
        else:
            out.append(tok)
    return out


def parse_procurve(text: str, source_file: str) -> list[SwitchConfig]:
    hostname = ""
    vlans: dict[str, str] = {}
    ports: dict[str, Port] = {}
    untagged: dict[str, str] = {}
    tagged: dict[str, list[str]] = {}
    lags: dict[str, str] = {}
    block, cur_name, cur_vlan = None, None, None

    def port(name: str) -> Port:
        if name not in ports:
            ports[name] = Port(name=name)
        return ports[name]

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith(";"):
            continue
        if not line.startswith(" "):
            block = None
            m = re.match(r'^hostname "?([^"]+)"?', line)
            if m:
                hostname = m.group(1)
                continue
            m = re.match(r"^interface (\S+)", line)
            if m:
                block, cur_name = "interface", m.group(1)
                port(cur_name)
                continue
            m = re.match(r"^vlan (\d+)", line)
            if m:
                block, cur_vlan = "vlan", m.group(1)
                vlans.setdefault(cur_vlan, "")
                continue
            m = re.match(r"^trunk (\S+) (\S+)", line)
            if m:
                for p in expand_procurve_ports(m.group(1)):
                    lags[p] = m.group(2).capitalize()
            continue

        s = line.strip()
        if s == "exit":
            block = None
            continue
        if block == "interface":
            p = port(cur_name)
            m = re.match(r'^name "?(.*?)"?$', s)
            if m:
                p.description = m.group(1)
            elif s == "disable":
                p.admin_down = True
            elif s == "enable":
                p.admin_down = False
        elif block == "vlan":
            m = re.match(r'^name "?(.*?)"?$', s)
            if m:
                vlans[cur_vlan] = m.group(1)
            elif s.startswith("untagged "):
                for p in expand_procurve_ports(s[9:]):
                    untagged[p] = cur_vlan
            elif s.startswith("tagged "):
                for p in expand_procurve_ports(s[7:]):
                    tagged.setdefault(p, []).append(cur_vlan)
            elif s.startswith("no untagged "):
                for p in expand_procurve_ports(s[12:]):
                    if untagged.get(p) == cur_vlan:
                        untagged.pop(p)

    for name in sorted(set(untagged) | set(tagged) | set(lags), key=natural_key):
        if not name.lower().startswith("trk"):
            port(name)

    for name, p in ports.items():
        if name in lags:
            p.lag = lags[name]
        # ProCurve puts VLAN membership on the Trk interface, not its members
        src = lags.get(name, name)
        t = tagged.get(src, [])
        u = untagged.get(src)
        if t:
            p.mode = "trunk"
            p.native_vlan = u
            p.allowed_vlans = compress_vlans(t)
        elif u:
            p.mode = "access"
            p.access_vlan = u

    return [SwitchConfig(hostname=hostname or source_file, vendor="aruba_procurve",
                         source_file=source_file, vlans=vlans,
                         ports=sorted(ports.values(), key=lambda p: natural_key(p.name)))]


# --------------------------------------------------------------------------
# AOS-CX
# --------------------------------------------------------------------------

def detect_aoscx(text: str) -> bool:
    if re.search(r"^!Version ArubaOS-CX", text, re.M):
        return True
    return bool(re.search(r"^interface \d+/\d+/\d+", text, re.M)
                and re.search(r"^\s+vlan (access|trunk) ", text, re.M))


def parse_aoscx(text: str, source_file: str) -> list[SwitchConfig]:
    hostname = ""
    vlans: dict[str, str] = {}
    ports: list[Port] = []
    lag_cfg: dict[str, Port] = {}
    block, cur, cur_vlan = None, None, None

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("!"):
            continue
        if not line.startswith(" "):
            block, cur = None, None
            m = re.match(r"^hostname (\S+)", line)
            if m:
                hostname = m.group(1)
                continue
            m = re.match(r"^vlan (\d+)$", line)
            if m:
                block, cur_vlan = "vlan", m.group(1)
                vlans.setdefault(cur_vlan, "")
                continue
            m = re.match(r"^interface (\d+/\d+/\d+)$", line)
            if m:
                block, cur = "interface", Port(name=m.group(1))
                ports.append(cur)
                continue
            m = re.match(r"^interface lag (\d+)", line)
            if m:
                block, cur = "interface", Port(name=f"lag{m.group(1)}", kind="logical")
                lag_cfg[cur.name] = cur
                continue
            continue

        s = line.strip()
        if block == "vlan" and s.startswith("name "):
            vlans[cur_vlan] = s[5:].strip().strip('"')
        elif block == "interface" and cur is not None:
            if s.startswith("description "):
                cur.description = s[12:].strip()
            elif s == "shutdown":
                cur.admin_down = True
            elif s == "no shutdown":
                cur.admin_down = False
            elif s.startswith("vlan access "):
                cur.mode, cur.access_vlan = "access", s.split()[-1]
            elif s.startswith("vlan trunk native "):
                cur.mode, cur.native_vlan = "trunk", s.split()[3]
            elif s.startswith("vlan trunk allowed "):
                cur.mode = "trunk"
                vals = expand_vlan_list(s[len("vlan trunk allowed "):])
                existing = expand_vlan_list(cur.allowed_vlans) if cur.allowed_vlans else []
                cur.allowed_vlans = compress_vlans(existing + vals)
            elif s == "routing" or s.startswith("ip address "):
                cur.mode = "routed"
            elif s.startswith("lag "):
                cur.lag = f"lag{s.split()[1]}"

    # Members inherit VLAN settings from their LAG interface
    for p in ports:
        if p.lag and p.lag in lag_cfg:
            lag = lag_cfg[p.lag]
            p.mode = lag.mode if lag.mode != "unknown" else p.mode
            p.access_vlan = p.access_vlan or lag.access_vlan
            p.native_vlan = p.native_vlan or lag.native_vlan
            p.allowed_vlans = p.allowed_vlans or lag.allowed_vlans
            p.description = p.description or lag.description
    return [SwitchConfig(hostname=hostname or source_file, vendor="aruba_aoscx",
                         source_file=source_file, ports=ports + list(lag_cfg.values()), vlans=vlans)]
