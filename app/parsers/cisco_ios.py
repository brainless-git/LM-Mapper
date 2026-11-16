"""Cisco IOS / IOS-XE running-config parser."""
from __future__ import annotations

import re

from ..models import Port, SwitchConfig, compress_vlans, expand_vlan_list

SKIP_PREFIXES = ("vlan", "loopback", "null", "tunnel", "bdi", "nve")


def detect(text: str) -> bool:
    return bool(re.search(r"^interface (Gigabit|FastEthernet|TenGigabit|TwentyFive|Ethernet|Port-channel)", text, re.M)
                and re.search(r"^(version \d|hostname \S)", text, re.M))


def parse(text: str, source_file: str) -> list[SwitchConfig]:
    hostname = ""
    vlans: dict[str, str] = {}
    ports: list[Port] = []
    block: str | None = None
    current: Port | None = None
    current_vlan: str | None = None
    allowed: list[str] = []

    def close_interface():
        nonlocal current, allowed
        if current is not None:
            if allowed:
                current.allowed_vlans = compress_vlans(allowed)
            elif current.mode == "trunk":
                current.allowed_vlans = "all"
            ports.append(current)
        current, allowed = None, []

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("!"):
            if line.startswith("!"):
                close_interface()
                block = None
            continue

        if not line.startswith(" "):           # top-level statement
            close_interface()
            block = None
            m = re.match(r"^hostname (\S+)", line)
            if m:
                hostname = m.group(1)
                continue
            m = re.match(r"^vlan (\d+)$", line)
            if m:
                block, current_vlan = "vlan", m.group(1)
                vlans.setdefault(current_vlan, "")
                continue
            m = re.match(r"^interface (\S+)", line)
            if m:
                name = m.group(1)
                if name.lower().startswith(SKIP_PREFIXES):
                    block = "skip"
                else:
                    block = "interface"
                    current = Port(name=name)
                    if name.lower().startswith(("port-channel", "po")):
                        current.kind = "logical"
            continue

        s = line.strip()
        if block == "vlan" and s.startswith("name "):
            vlans[current_vlan] = s[5:].strip()
        elif block == "interface" and current is not None:
            _apply_interface_line(current, s, allowed)

    close_interface()
    return [SwitchConfig(hostname=hostname or source_file, vendor="cisco_ios",
                         source_file=source_file, ports=ports, vlans=vlans)]


def _apply_interface_line(p: Port, s: str, allowed: list[str]) -> None:
    if s.startswith("description "):
        p.description = s[12:].strip()
    elif s == "shutdown":
        p.admin_down = True
    elif s == "no shutdown":
        p.admin_down = False
    elif s == "switchport mode access":
        p.mode = "access"
    elif s == "switchport mode trunk":
        p.mode = "trunk"
    elif s == "no switchport":
        p.mode = "routed"
    elif s.startswith("ip address ") and len(s.split()) >= 4:
        p.mode = "routed"
        p.ip = _cidr(s.split()[2], s.split()[3])
    elif s.startswith("switchport access vlan "):
        p.access_vlan = s.split()[-1]
        if p.mode == "unknown":
            p.mode = "access"
    elif s.startswith("switchport voice vlan "):
        p.voice_vlan = s.split()[-1]
    elif s.startswith("switchport trunk native vlan "):
        p.native_vlan = s.split()[-1]
    elif s.startswith("switchport trunk allowed vlan add "):
        allowed.extend(expand_vlan_list(s[len("switchport trunk allowed vlan add "):]))
    elif s.startswith("switchport trunk allowed vlan remove "):
        rm = set(expand_vlan_list(s[len("switchport trunk allowed vlan remove "):]))
        allowed[:] = [v for v in allowed if v not in rm]
    elif s.startswith("switchport trunk allowed vlan "):
        allowed[:] = expand_vlan_list(s[len("switchport trunk allowed vlan "):])
    elif s.startswith("channel-group "):
        p.lag = "Po" + s.split()[1]


def _cidr(ip: str, mask: str) -> str:
    try:
        bits = sum(bin(int(o)).count("1") for o in mask.split("."))
        return f"{ip}/{bits}"
    except ValueError:
        return ip
