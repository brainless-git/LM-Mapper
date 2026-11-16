"""CDP / LLDP neighbour output parser.

Drop neighbour command output next to the configs (any file name). Supported:
  * Cisco  'show cdp neighbors detail'
  * Cisco  'show lldp neighbors detail'
  * ArubaOS-Switch 'show lldp info remote-device detail'
  * AOS-CX 'show lldp neighbor-info detail'
The local switch is taken from the CLI prompt in the file ('CORE-SW01#show cdp ...'),
otherwise from the file name (e.g. 'CORE-SW01.cdp.txt' -> 'CORE-SW01').
The output can also be appended to the end of a config backup.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePath


@dataclass
class Neighbour:
    local: str
    local_port: str
    remote: str
    remote_port: str
    protocol: str
    source_file: str


# Each dialect: (protocol, record-start regex on local port, remote name regex, remote port regex)
DIALECTS = [
    ("cdp", r"^Interface:\s*([^,]+),", r"^Device ID:\s*(\S+)", r"Port ID \(outgoing port\):\s*(\S+)"),
    ("lldp", r"^Local Intf:\s*(\S+)", r"^System Name:\s*(\S+)", r"^Port id:\s*(\S+)"),
    ("lldp", r"^\s*Local Port\s*:\s*(\S+)", r"^\s*SysName\s*:\s*(\S+)", r"^\s*PortId\s*:\s*(\S+)"),
    ("lldp", r"^\s*Port\s*:\s*(\d+/\d+/\d+)", r"^\s*Neighbor System-Name\s*:\s*(\S+)",
     r"^\s*Neighbor Port-ID\s*:\s*(\S+)"),
]


def _split_records(text: str) -> list[str]:
    parts = re.split(r"^-{5,}\s*$|^\s*$\n(?=\s*(?:Local Port|Port\s*:|Device ID|Local Intf))", text, flags=re.M)
    return [p for p in parts if p.strip()]


def parse(text: str, source_file: str) -> list[Neighbour]:
    m = re.search(r"^(\S+?)[#>]\s*sh(?:ow)?\s+(?:cdp|lldp)", text, re.M)
    local = m.group(1) if m else PurePath(source_file).name.split(".")[0]
    out: list[Neighbour] = []
    for record in _split_records(text):
        for proto, rx_local, rx_name, rx_port in DIALECTS:
            lm = re.search(rx_local, record, re.M)
            nm = re.search(rx_name, record, re.M)
            if lm and nm:
                pm = re.search(rx_port, record, re.M)
                out.append(Neighbour(local=local, local_port=lm.group(1).strip(),
                                     remote=nm.group(1).strip(), remote_port=pm.group(1).strip() if pm else "",
                                     protocol=proto, source_file=source_file))
                break
    return out


def looks_like_neighbours(text: str) -> bool:
    return bool(re.search(r"Port ID \(outgoing port\)|^Local Intf:|^\s*SysName\s*:|Neighbor System-Name",
                          text, re.M))
