"""Normalised data model shared by all config parsers."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class Port:
    name: str                      # interface name as written in the config
    description: str = ""
    mode: str = "unknown"          # access | trunk | routed | lag-member | unknown
    access_vlan: Optional[str] = None
    native_vlan: Optional[str] = None
    allowed_vlans: str = ""        # human readable list, e.g. "10,20,30-40"
    voice_vlan: Optional[str] = None
    admin_down: bool = False
    lag: Optional[str] = None      # port-channel / trunk / LAG membership
    kind: str = "physical"         # physical | logical (LAG, SVI, VLAN subinterface, tunnel)
    ip: str = ""                   # firewall / routed interfaces

    def vlan_set(self) -> tuple[set[str], bool]:
        """VLANs carried by this port and whether it carries 'all' VLANs."""
        vl: set[str] = set()
        for v in (self.access_vlan, self.native_vlan, self.voice_vlan):
            if v:
                vl.add(str(v))
        allowed = expand_vlan_list(self.allowed_vlans) if self.allowed_vlans else []
        all_flag = "all" in [a.lower() for a in allowed]
        vl.update(a for a in allowed if a.lower() != "all")
        return vl, all_flag

    @property
    def key(self) -> str:
        return normalise_ifname(self.name)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["key"] = self.key
        return d


@dataclass
class SwitchConfig:
    hostname: str
    vendor: str
    source_file: str
    serial: Optional[str] = None
    ports: list[Port] = field(default_factory=list)
    vlans: dict[str, str] = field(default_factory=dict)   # vlan id -> name
    role: str = "switch"           # switch | firewall
    site: str = "default"
    meta: dict = field(default_factory=dict)  # vendor specific (FortiLink members, ISL trunks, parent FortiGate)

    @property
    def switch_id(self) -> str:
        return self.serial or self.hostname


# Longest prefixes first so "tengigabitethernet" wins over "gigabitethernet".
_IF_PREFIXES = [
    ("hundredgigabitethernet", "hu"), ("hundredgige", "hu"),
    ("fortygigabitethernet", "fo"), ("fortygige", "fo"),
    ("twentyfivegigabitethernet", "twe"), ("twentyfivegige", "twe"),
    ("tengigabitethernet", "te"), ("tengige", "te"),
    ("fivegigabitethernet", "fi"), ("twogigabitethernet", "tw"),
    ("appgigabitethernet", "ap"),
    ("gigabitethernet", "gi"), ("fastethernet", "fa"),
    ("port-channel", "po"), ("portchannel", "po"),
    ("ethernet", "eth"),
]
_SHORT = {"gig": "gi", "ten": "te", "g": "gi", "f": "fa", "t": "te", "e": "eth"}


def normalise_ifname(name: str) -> str:
    """Return a comparison key so 'GigabitEthernet1/0/1', 'Gi1/0/1' and 'gi1/0/1' match."""
    n = (name or "").strip().strip('"').lower().replace(" ", "")
    for long, short in _IF_PREFIXES:
        if n.startswith(long):
            return short + n[len(long):]
    m = re.match(r"^([a-z\-]+)(\d.*)$", n)
    if m and m.group(1) in _SHORT:
        return _SHORT[m.group(1)] + m.group(2)
    return n


def compress_vlans(vlans: list[str]) -> str:
    """['10','11','12','20'] -> '10-12,20'. Non-numeric entries are appended as-is."""
    nums = sorted({int(v) for v in vlans if str(v).isdigit()})
    other = [v for v in vlans if not str(v).isdigit()]
    out, start, prev = [], None, None
    for v in nums:
        if start is None:
            start = prev = v
        elif v == prev + 1:
            prev = v
        else:
            out.append(f"{start}-{prev}" if start != prev else str(start))
            start = prev = v
    if start is not None:
        out.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(out + sorted(set(other)))


def expand_vlan_list(text: str) -> list[str]:
    """'10,20-22 30' -> ['10','20','21','22','30']. Keywords like 'all' are kept."""
    out: list[str] = []
    for tok in re.split(r"[,\s]+", text.strip()):
        if not tok:
            continue
        m = re.fullmatch(r"(\d+)-(\d+)", tok)
        if m:
            out.extend(str(i) for i in range(int(m.group(1)), int(m.group(2)) + 1))
        else:
            out.append(tok)
    return out


def natural_key(s: str) -> list:
    """Sort 'port2' before 'port10' and '1/1/2' before '1/1/10'."""
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", s or "")]
