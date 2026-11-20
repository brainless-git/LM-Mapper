"""Cisco IOS / IOS-XE running-config parser."""
from __future__ import annotations

import re

from ..models import Port, SwitchConfig, compress_vlans, expand_vlan_list

SKIP_PREFIXES = ("vlan", "loopback", "null", "tunnel", "bdi", "nve")


IF_RX = (r"^interface\s+(?:gigabitethernet|fastethernet|tengigabitethernet|twentyfivegige|fortygigabitethernet|"
         r"hundredgige|twogigabitethernet|fivegigabitethernet|appgigabitethernet|ethernet|port-channel|"
         r"gi|fa|te|tw|fo|hu|eth|po)\s?\d")


def detect(text: str) -> bool:
    """IOS, IOS-XE, NX-OS and Cisco Business (CBS/SG) running-configs."""
    return bool(re.search(IF_RX, text, re.M | re.I)
                and re.search(r"^\s*(version \d|hostname \S|!command: show running-config|"
                              r"config-file-header|building configuration)", text, re.M | re.I))


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
            m = re.match(r"^hostname \"?([^\"\s]+)", line)
            if m:
                hostname = m.group(1)
                continue
            m = re.match(r"^vlan (\d+)$", line)
            if m:
                block, current_vlan = "vlan", m.group(1)
                vlans.setdefault(current_vlan, "")
                continue
            m = re.match(r"^interface\s+(\S+(?:\s\d\S*)?)", line, re.I)
            if m:
                name = m.group(1).replace(" ", "")
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
        p.description = s[12:].strip().strip('"')
    elif s == "shutdown":
        p.admin_down = True
    elif s == "no shutdown":
        p.admin_down = False
    elif s == "switchport mode access":
        p.mode = "access"
    elif s in ("switchport mode trunk", "switchport mode general"):
        p.mode = "trunk"
    elif s.startswith("switchport general allowed vlan add "):      # Cisco Business: '... add 10,20 tagged'
        rest = s[len("switchport general allowed vlan add "):].split()
        vl = expand_vlan_list(rest[0]) if rest else []
        if len(rest) > 1 and rest[1] == "untagged" and len(vl) == 1:
            p.native_vlan = vl[0]
        else:
            allowed.extend(vl)
    elif s.startswith("switchport general pvid "):
        p.native_vlan = s.split()[-1]
    elif s.startswith("switchport trunk native vlan ") or s.startswith("switchport trunk native-vlan "):
        p.native_vlan = s.split()[-1]
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
    elif s.startswith("switchport trunk allowed vlan add "):
        allowed.extend(expand_vlan_list(s[len("switchport trunk allowed vlan add "):]))
    elif s.startswith("switchport trunk allowed vlan remove "):
        rm = set(expand_vlan_list(s[len("switchport trunk allowed vlan remove "):]))
        allowed[:] = [v for v in allowed if v not in rm]
    elif s.startswith("switchport trunk allowed vlan "):
        allowed[:] = expand_vlan_list(s[len("switchport trunk allowed vlan "):])
    elif s.startswith("channel-group ") and s.split()[1].isdigit():
        p.lag = "Po" + s.split()[1]


def _cidr(ip: str, mask: str) -> str:
    try:
        bits = sum(bin(int(o)).count("1") for o in mask.split("."))
        return f"{ip}/{bits}"
    except ValueError:
        return ip
