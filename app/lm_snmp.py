"""LLDP neighbours and MAC address tables via LogicMonitor collector SNMP walks.

Uses the collector debug facility (POST /debug with '!snmpwalk <host> <oid>'), so the
collector's stored SNMP credentials are used and the app needs no SNMP access itself.
The LM API user needs permission to run collector debug commands.

Per device it walks:
  ifName                 1.3.6.1.2.1.31.1.1.1.1     ifIndex -> port name
  ifPhysAddress          1.3.6.1.2.1.2.2.1.6        own interface MACs
  dot1dBaseBridgeAddress 1.3.6.1.2.1.17.1.1         own bridge MAC
  dot1dBasePortIfIndex   1.3.6.1.2.1.17.1.4.1.2     bridge port -> ifIndex
  dot1qTpFdbPort         1.3.6.1.2.1.17.7.1.2.2.1.2 fdbId.MAC -> bridge port
  dot1dTpFdbPort         1.3.6.1.2.1.17.4.3.1.2     MAC -> bridge port (fallback)
  lldpLocPortId          1.0.8802.1.1.2.1.3.7.1.3   local LLDP port number -> port id
  lldpRemSysName         1.0.8802.1.1.2.1.4.1.1.9   neighbour system name
  lldpRemPortId          1.0.8802.1.1.2.1.4.1.1.7   neighbour port id
  lldpRemPortDesc        1.0.8802.1.1.2.1.4.1.1.8   neighbour port description
Results are cached in DATA_DIR/snmp-cache for SNMP_CACHE_MINUTES.
"""
from __future__ import annotations

import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from .lm_client import LMClient
from .parsers.neighbours import Neighbour

log = logging.getLogger(__name__)

OIDS = {
    "ifName": "1.3.6.1.2.1.31.1.1.1.1",
    "ifPhys": "1.3.6.1.2.1.2.2.1.6",
    "bridgeMac": "1.3.6.1.2.1.17.1.1",
    "basePortIf": "1.3.6.1.2.1.17.1.4.1.2",
    "qFdbPort": "1.3.6.1.2.1.17.7.1.2.2.1.2",
    "dFdbPort": "1.3.6.1.2.1.17.4.3.1.2",
    "lldpLocPortId": "1.0.8802.1.1.2.1.3.7.1.3",
    "lldpRemSysName": "1.0.8802.1.1.2.1.4.1.1.9",
    "lldpRemPortId": "1.0.8802.1.1.2.1.4.1.1.7",
    "lldpRemPortDesc": "1.0.8802.1.1.2.1.4.1.1.8",
}
MAX_MACS_PER_PORT = 200


@dataclass
class DeviceL2:
    device_id: str                       # SwitchConfig.switch_id
    own_macs: set[str] = field(default_factory=set)
    fdb: dict[str, set[str]] = field(default_factory=dict)        # port name -> MACs learned
    lldp: list[tuple[str, str, str]] = field(default_factory=list)  # (local port, remote name, remote port)
    error: str = ""


# --------------------------------------------------------------------------
# parsing helpers
# --------------------------------------------------------------------------

_LINE = re.compile(r"^\s*\.?((?:\d+\.)+\d+)\s*(?:=>|=|:)\s*(.*?)\s*$")


def parse_walk(output: str, base_oid: str) -> dict[str, str]:
    """'1.3.6.1.2.1.31.1.1.1.1.5 => Gi1/0/1' lines -> {'5': 'Gi1/0/1'} (suffix after base OID)."""
    out: dict[str, str] = {}
    base = base_oid.strip(".") + "."
    for line in output.splitlines():
        m = _LINE.match(line)
        if not m:
            continue
        oid, val = m.group(1), m.group(2)
        if oid.startswith(base):
            val = re.sub(r"^(STRING|Hex-STRING|INTEGER|OCTET STRING|Gauge32|Counter32)\s*:\s*", "", val, flags=re.I)
            out[oid[len(base):]] = val.strip().strip('"')
        elif oid == base[:-1]:
            out[""] = val.strip().strip('"')
    return out


def norm_mac(v: str) -> str | None:
    """Accepts '00:11:22:33:44:55', '0011.2233.4455', '00 11 22 33 44 55', '0x001122334455'."""
    if not v:
        return None
    h = re.sub(r"[^0-9a-fA-F]", "", v.lower().removeprefix("0x"))
    if len(h) == 12:
        return ":".join(h[i:i + 2] for i in range(0, 12, 2))
    parts = re.split(r"[:\-\s]", v.strip())
    if len(parts) == 6 and all(re.fullmatch(r"[0-9a-fA-F]{1,2}", p) for p in parts):
        return ":".join(p.zfill(2).lower() for p in parts)
    return None


def mac_from_oid_suffix(suffix: str) -> str | None:
    parts = suffix.split(".")[-6:]
    if len(parts) != 6 or not all(p.isdigit() for p in parts):
        return None
    return ":".join(f"{int(p):02x}" for p in parts)


def build_l2(device_id: str, walks: dict[str, dict[str, str]]) -> DeviceL2:
    l2 = DeviceL2(device_id=device_id)
    if_name = walks.get("ifName", {})
    for v in walks.get("ifPhys", {}).values():
        m = norm_mac(v)
        if m and m != "00:00:00:00:00:00":
            l2.own_macs.add(m)
    for v in walks.get("bridgeMac", {}).values():
        m = norm_mac(v)
        if m:
            l2.own_macs.add(m)

    bp_if = walks.get("basePortIf", {})
    fdb_raw = walks.get("qFdbPort") or walks.get("dFdbPort") or {}
    for suffix, bport in fdb_raw.items():
        mac = mac_from_oid_suffix(suffix)
        if not mac or bport in ("0", ""):
            continue
        port = if_name.get(bp_if.get(bport, bport))
        if not port:
            continue
        s = l2.fdb.setdefault(port, set())
        if len(s) < MAX_MACS_PER_PORT:
            s.add(mac)

    loc = walks.get("lldpLocPortId", {})
    rem_name = walks.get("lldpRemSysName", {})
    rem_port = walks.get("lldpRemPortId", {})
    rem_desc = walks.get("lldpRemPortDesc", {})
    for idx, name in rem_name.items():
        parts = idx.split(".")             # timeMark.localPortNum.remIndex
        if len(parts) < 3 or not name:
            continue
        local_num = parts[-2]
        local = loc.get(local_num) or if_name.get(local_num) or local_num
        rport = rem_port.get(idx, "")
        if norm_mac(rport):                # port id is a MAC: the description is more useful
            rport = rem_desc.get(idx, "") or rport
        l2.lldp.append((local, name, rport or rem_desc.get(idx, "")))
    return l2


# --------------------------------------------------------------------------
# collection
# --------------------------------------------------------------------------

def collect(client: LMClient, targets: list[tuple[str, dict]], data_dir: str,
            cache_minutes: int, workers: int = 4) -> tuple[dict[str, DeviceL2], list[str]]:
    """targets: (switch_id, LM device dict). Returns ({switch_id: DeviceL2}, errors)."""
    cache_dir = Path(data_dir) / "snmp-cache"
    errors: list[str] = []

    def one(item):
        sid, dev = item
        cfile = cache_dir / f"{dev['id']}.json"
        try:
            c = json.loads(cfile.read_text())
            if time.time() - c["ts"] < cache_minutes * 60:
                return sid, c["walks"], None
        except (OSError, ValueError, KeyError):
            pass
        collector = dev.get("currentCollectorId") or dev.get("preferredCollectorId")
        host = dev.get("name")
        if not collector or not host:
            return sid, None, f"{dev.get('displayName')}: no collector or host on LM device"
        walks = {}
        try:
            for key, oid in OIDS.items():
                if key == "dFdbPort" and walks.get("qFdbPort"):
                    continue
                out = client.collector_debug(collector, f"!snmpwalk {host} {oid}")
                walks[key] = parse_walk(out, oid)
        except Exception as exc:
            return sid, None, f"{dev.get('displayName')}: {exc}"
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
            cfile.write_text(json.dumps({"ts": time.time(), "walks": walks}))
        except OSError:
            pass
        return sid, walks, None

    result: dict[str, DeviceL2] = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for sid, walks, err in pool.map(one, targets):
            if err:
                errors.append(err)
                continue
            result[sid] = build_l2(sid, walks)
    return result, errors


# --------------------------------------------------------------------------
# turning L2 data into links
# --------------------------------------------------------------------------

def lldp_neighbours(l2: dict[str, DeviceL2], hostname_of: dict[str, str]) -> list[Neighbour]:
    out = []
    for sid, d in l2.items():
        for local, rname, rport in d.lldp:
            out.append(Neighbour(local=hostname_of.get(sid, sid), local_port=local, remote=rname,
                                 remote_port=rport, protocol="lldp", source_file="LM collector SNMP"))
    return out


def mac_links(l2: dict[str, DeviceL2]) -> list[tuple[str, str, str, str | None]]:
    """Infer direct links from MAC tables.

    port_to(A, B) = the port on A where any of B's own MACs is learned.
    A and B are directly connected if no third switch C sits between them, i.e. there is no C
    with port_to(A, C) == port_to(A, B) whose own port towards A differs from its port towards B.
    Returns (A, A port, B, B port or None)."""
    def port_to(a: DeviceL2, b: DeviceL2) -> str | None:
        hits = [p for p, macs in a.fdb.items() if macs & b.own_macs]
        return hits[0] if len(hits) == 1 else (max(hits, key=lambda p: len(a.fdb[p] & b.own_macs)) if hits else None)

    devs = [d for d in l2.values() if d.own_macs]
    switches = [d for d in devs if d.fdb]
    links = []
    seen = set()
    for a in switches:
        for b in devs:
            if a is b or frozenset((a.device_id, b.device_id)) in seen:
                continue
            pab = port_to(a, b)
            if not pab:
                continue
            between = False
            for c in switches:
                if c in (a, b):
                    continue
                if port_to(a, c) == pab:
                    pca, pcb = port_to(c, a), port_to(c, b)
                    if pca and pcb and pca != pcb:
                        between = True
                        break
            if between:
                continue
            pba = port_to(b, a) if b.fdb else None
            seen.add(frozenset((a.device_id, b.device_id)))
            links.append((a.device_id, pab, b.device_id, pba))
    return links
