"""FortiOS parsers.

  * FortiGate backups: one firewall device (physical ports, VLAN subinterfaces,
    aggregates, software/hardware switches) plus one switch device per
    FortiLink-managed FortiSwitch ('config switch-controller managed-switch').
  * Standalone FortiSwitchOS backups ('config switch interface').
"""
from __future__ import annotations

import ipaddress
import re
import shlex

from ..models import Port, SwitchConfig, compress_vlans


def detect(text: str) -> bool:
    return bool(re.search(r"^#config-version=(FGT|FG|FS|FWF)", text, re.M)
                or re.search(r"^config switch-controller managed-switch", text, re.M)
                or re.search(r"^config firewall policy", text, re.M)
                or re.search(r"^config switch (interface|physical-port)", text, re.M))


# --------------------------------------------------------------------------
# Generic FortiOS config tree
# --------------------------------------------------------------------------

class Node(dict):
    """A config section or edit entry. Settings live in .settings, children in the dict."""
    def __init__(self):
        super().__init__()
        self.settings: dict[str, list[str]] = {}

    def __bool__(self) -> bool:      # an entry with settings but no children is still present
        return True

    def val(self, key: str, default: str = "") -> str:
        v = self.settings.get(key)
        return " ".join(v) if v else default


def parse_tree(text: str) -> Node:
    root = Node()
    stack = [root]
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tokens = shlex.split(line, posix=True)
        except ValueError:
            tokens = line.split()
        if not tokens:
            continue
        kw = tokens[0]
        if kw in ("config", "edit"):
            node = stack[-1].setdefault(" ".join(tokens[1:]), Node())
            stack.append(node)
        elif kw in ("next", "end"):
            if len(stack) > 1:
                stack.pop()
        elif kw == "set" and len(tokens) >= 2:
            stack[-1].settings[tokens[1]] = tokens[2:]
        elif kw == "unset" and len(tokens) >= 2:
            stack[-1].settings.pop(tokens[1], None)
    return root


def _is_fortiswitch(text: str, tree: Node) -> bool:
    m = re.search(r"^#config-version=(\w+)", text, re.M)
    if m:
        return m.group(1).upper().startswith("FS")
    return tree.get("firewall policy") is None and tree.get("switch-controller managed-switch") is None \
        and (tree.get("switch interface") is not None or tree.get("switch physical-port") is not None)


def parse(text: str, source_file: str) -> list[SwitchConfig]:
    tree = parse_tree(text)
    if _is_fortiswitch(text, tree):
        return _parse_fortiswitch(tree, source_file)
    return _parse_fortigate(tree, source_file)


# --------------------------------------------------------------------------
# FortiGate firewall + FortiLink managed switches
# --------------------------------------------------------------------------

LOGICAL_TYPES = {"vlan", "aggregate", "redundant", "tunnel", "loopback", "hard-switch",
                 "switch", "vap-switch", "wl-mesh", "fext-wan", "vxlan", "geneve", "emac-vlan",
                 "ssl", "lan-extension"}
VIRTUAL_NAMES = ("ssl.", "naf.", "l2t.", "modem", "npu", "mesh.")


def _ip(node: Node) -> str:
    v = node.settings.get("ip") or []
    if len(v) >= 2 and v[0] != "0.0.0.0":
        try:
            return str(ipaddress.ip_interface(f"{v[0]}/{v[1]}"))
        except ValueError:
            return v[0]
    if len(v) == 1 and "/" in v[0] and not v[0].startswith("0.0.0.0"):
        return v[0]
    return ""


def _parse_fortigate(tree: Node, source_file: str) -> list[SwitchConfig]:
    glob = tree.get("system global") or Node()
    hostname = glob.val("hostname") or source_file
    sysif: Node = tree.get("system interface") or Node()

    vlan_by_ifname: dict[str, str] = {"_default": "1"}
    vlans: dict[str, str] = {}
    for ifname, node in sysif.items():
        vid = node.val("vlanid")
        if vid:
            vlan_by_ifname[ifname] = vid
            vlans.setdefault(vid, node.val("alias") or ifname)

    fw = SwitchConfig(hostname=hostname, vendor="fortigate", role="firewall",
                      source_file=source_file, vlans=dict(vlans))
    ports: dict[str, Port] = {}
    tagged: dict[str, list[str]] = {}
    group_of: dict[str, str] = {}
    fortilink_ifaces: dict[str, list[str]] = {}

    for ifname, node in sysif.items():
        itype = node.val("type")
        vid = node.val("vlanid")
        parent = node.val("interface")
        p = Port(name=ifname, description=node.val("description") or node.val("alias"),
                 ip=_ip(node), admin_down=node.val("status") == "down")
        if vid and parent:
            p.kind, p.mode, p.access_vlan = "logical", "vlan", vid
            tagged.setdefault(parent, []).append(vid)
        elif itype in LOGICAL_TYPES or ifname.startswith(VIRTUAL_NAMES):
            p.kind = "logical"
            p.mode = "routed" if p.ip else itype or "logical"
            for m in node.settings.get("member", []):
                group_of[m] = ifname
        else:
            p.mode = "routed" if p.ip else "unknown"
        if node.val("fortilink") == "enable":
            fortilink_ifaces[ifname] = list(node.settings.get("member", [])) or [ifname]
        ports[ifname] = p

    # Software / hardware switch members
    for section in ("system switch-interface", "system virtual-switch"):
        for swname, sw in (tree.get(section) or {}).items():
            for m in sw.settings.get("member", []):
                group_of[m] = swname
            for m in (sw.get("port") or {}):
                group_of[m] = swname
                ports.setdefault(m, Port(name=m))

    for name, p in ports.items():
        if name in group_of:
            p.lag = group_of[name]
        # VLANs tagged on an aggregate are carried by its members too
        t = tagged.get(name, []) + tagged.get(group_of.get(name, ""), [])
        if t:
            p.mode = "trunk"
            p.allowed_vlans = compress_vlans(t)
    fw.ports = list(ports.values())
    fw.meta["fortilink"] = fortilink_ifaces
    fw.meta["fortilink_vlans"] = sorted(set(
        v for fl in fortilink_ifaces for v in tagged.get(fl, [])) | {"1"}, key=int)

    out = [fw]
    for serial, sw in (tree.get("switch-controller managed-switch") or {}).items():
        out.append(_managed_switch(serial, sw, vlans, vlan_by_ifname, source_file, fw.switch_id))
    return out


def _managed_switch(serial, sw: Node, vlans, vlan_by_ifname, source_file, fw_id) -> SwitchConfig:
    vid = lambda n: vlan_by_ifname.get(n, n)
    name = sw.val("name") or sw.val("description") or serial
    cfg = SwitchConfig(hostname=name, serial=serial, vendor="fortiswitch_managed",
                       source_file=source_file, vlans=dict(vlans))
    lag_of: dict[str, str] = {}
    fortilink_members: list[str] = []
    isl: dict[str, list[str]] = {}
    for pname, pn in (sw.get("ports") or {}).items():
        p = _forti_port(pname, pn, vid)
        members = list(pn.settings.get("members", []))
        if pn.val("type") == "trunk" and members:
            p.kind, p.mode = "logical", "lag"
            for m in members:
                lag_of[m] = pname
            if re.match(r"^__forti\w*link", pname, re.I) or pn.val("fortilink") == "enable":
                fortilink_members = members
            else:
                isl[pname] = members
        cfg.ports.append(p)
    for p in cfg.ports:
        p.lag = lag_of.get(p.name)
    cfg.meta.update(fortigate=fw_id, fortilink_members=fortilink_members, isl=isl)
    return cfg


def _forti_port(name: str, node: Node, vid) -> Port:
    p = Port(name=name, description=node.val("description"))
    p.admin_down = node.val("status") == "down"
    native = node.val("vlan") or node.val("native-vlan")
    allowed = node.settings.get("allowed-vlans", [])
    if node.val("allowed-vlans-all") == "enable":
        allowed = ["all"]
    if native:
        native = vid(native)
    if allowed:
        p.mode = "trunk"
        p.native_vlan = native or None
        p.allowed_vlans = compress_vlans([vid(a) for a in allowed])
    elif native:
        p.mode = "access"
        p.access_vlan = native
    return p


# --------------------------------------------------------------------------
# Standalone FortiSwitchOS
# --------------------------------------------------------------------------

def _parse_fortiswitch(tree: Node, source_file: str) -> list[SwitchConfig]:
    glob = tree.get("system global") or Node()
    hostname = glob.val("hostname") or source_file
    vlans: dict[str, str] = {}
    for ifname, node in (tree.get("system interface") or {}).items():
        if node.val("vlanid"):
            vlans[node.val("vlanid")] = ifname

    phys = tree.get("switch physical-port") or {}
    swif = tree.get("switch interface") or {}
    trunks = tree.get("switch trunk") or {}
    lag_of: dict[str, str] = {}
    for tname, tn in trunks.items():
        for m in tn.settings.get("members", []):
            lag_of[m] = tname

    cfg = SwitchConfig(hostname=hostname, vendor="fortiswitch", source_file=source_file, vlans=vlans)
    names = list(dict.fromkeys(list(phys.keys()) + [n for n in swif.keys() if n not in trunks]))
    for name in names:
        if name.startswith("internal"):
            continue
        si = swif.get(name) or Node()
        ph = phys.get(name) or Node()
        p = Port(name=name, description=si.val("description") or ph.val("description"))
        p.admin_down = ph.val("status") == "down"
        native = si.val("native-vlan")
        allowed = si.settings.get("allowed-vlans", [])
        if allowed:
            p.mode, p.native_vlan = "trunk", native or None
            p.allowed_vlans = compress_vlans([x for a in allowed for x in _expand_forti_range(a)])
        elif native:
            p.mode, p.access_vlan = "access", native
        p.lag = lag_of.get(name)
        cfg.ports.append(p)
    for tname, tn in trunks.items():
        cfg.ports.append(Port(name=tname, kind="logical", mode="lag",
                              description=swif.get(tname, Node()).val("description")))
    return [cfg]


def _expand_forti_range(a: str) -> list[str]:
    m = re.fullmatch(r"(\d+)-(\d+)", a)
    if m:
        return [str(i) for i in range(int(m.group(1)), int(m.group(2)) + 1)]
    return [x for x in a.split(",") if x]
