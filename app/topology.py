"""Link discovery and topology model.

Link sources, highest priority first:
  explicit     mapping.yaml 'links:'
  cdp / lldp   neighbour output files
  fortilink    FortiGate <-> managed FortiSwitch, and auto-ISL trunks between switches
  description  a port description (config or LM ifAlias) naming another device
Links from different sources describing the same connection are merged.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict, deque

from .models import SwitchConfig, normalise_ifname
from .parsers.neighbours import Neighbour

SOURCE_PRIORITY = ["explicit", "cdp", "lldp", "fortilink", "isl", "mac", "description"]

# Categorical palette (validated 8-slot order). Slots go to the most widespread VLANs per site;
# the rest fold to "other". Status colours are kept separate.
PALETTE_LIGHT = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
PALETTE_DARK = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#0ca30c", "#9085e9", "#e66767"]
OTHER_LIGHT, OTHER_DARK = "#a3a29c", "#6b6a64"


FIREWALL_WORDS = r"fortigate|firewall|fgt|utm|fw|palo|sophos|checkpoint|check point|asa"


def _short_aliases(hostname: str) -> set[str]:
    """'SVG-TUR-SW02' -> {'sw02', 'sw2'}: the last name segment with and without zero padding."""
    seg = re.split(r"[-_.\s]+", hostname.strip().lower())[-1]
    m = re.fullmatch(r"([a-z]+)0*(\d+)", seg)
    if not m:
        return {seg} if len(seg) >= 3 else set()
    letters, num = m.group(1), m.group(2)
    return {seg, f"{letters}{num}", f"{letters}{int(num):02d}", f"{letters}{int(num):03d}"}


class DeviceIndex:
    """Resolve free-text names (hostnames, FQDNs, serials, aliases, short site names) to devices."""

    def __init__(self, devices: list[SwitchConfig], aliases: dict[str, list[str]]):
        self.by_id = {d.switch_id: d for d in devices}
        self.names: dict[str, str] = {}
        self.short: dict[str, dict[str, str]] = defaultdict(dict)   # site -> short alias -> device
        self.firewalls: dict[str, list[str]] = defaultdict(list)    # site -> firewall device ids
        for d in devices:
            for n in [d.hostname, d.serial, *aliases.get(d.hostname.lower(), []),
                      *aliases.get((d.serial or "").lower(), [])]:
                if n:
                    self.names.setdefault(n.lower(), d.switch_id)
                    self.names.setdefault(n.lower().split(".")[0], d.switch_id)
            for a in _short_aliases(d.hostname):
                # an alias shared by two devices in one site is ambiguous: drop it
                if a in self.short[d.site] and self.short[d.site][a] != d.switch_id:
                    self.short[d.site][a] = ""
                else:
                    self.short[d.site][a] = d.switch_id
            if d.role == "firewall":
                self.firewalls[d.site].append(d.switch_id)

    def resolve(self, name: str) -> str | None:
        if not name:
            return None
        n = name.strip().lower()
        n = re.sub(r"\(.*\)$", "", n)            # CDP 'SW1(FOC123)'
        return self.names.get(n) or self.names.get(n.split(".")[0])

    @staticmethod
    def _scan(names: dict[str, str], low: str, exclude: str, min_len: int, best):
        for name, dev in names.items():
            if not dev or dev == exclude or len(name) < min_len:
                continue
            for m in re.finditer(r"(?<![a-z0-9])" + re.escape(name) + r"(?![a-z0-9])", low):
                if best is None or len(name) > best[2]:
                    best = (dev, m.end(), len(name))
        return best

    def find_in_text(self, text: str, exclude: str, site: str = "default") -> tuple[str, int] | None:
        """Device named in text -> (device_id, end offset of the match).

        Full hostnames/serials/aliases win; then short names within the same site
        ('SW02', 'SW8'); then firewall words ('FortiGate', 'UTM') if the site has one firewall."""
        low = (text or "").lower()
        if not low.strip():
            return None
        best = self._scan(self.names, low, exclude, 4, None)
        if best is None:
            best = self._scan(self.short.get(site, {}), low, exclude, 3, None)
        if best is None:
            fws = [f for f in self.firewalls.get(site, []) if f != exclude]
            m = re.search(r"(?<![a-z0-9])(" + FIREWALL_WORDS + r")(?![a-z0-9])", low)
            if m and len(fws) == 1:
                best = (fws[0], m.end(), 0)
        return (best[0], best[1]) if best else None


def _port_lookup(dev: SwitchConfig) -> dict:
    return {p.key: p for p in dev.ports}


def _peer_port_from_text(text: str, offset: int, dev: SwitchConfig) -> str | None:
    """Find a port name of dev mentioned after offset in text.

    Handles 'EDGE-SW02 port 25', 'SW02/P47', 'SW3 Gi1/0/1', 'core 1/1/49'."""
    rest = text[offset:].strip()
    keys = _port_lookup(dev)
    cands = re.findall(r"[A-Za-z\-]*\d+(?:/\d+)+", rest)       # slash names first ('1/1/49', 'Gi1/0/1')
    tail = [t for t in re.split(r"[\s,;:/()\[\]]+", rest) if t][:4]
    for i, t in enumerate(tail):
        cands.append(t)
        if i + 1 < len(tail):
            cands.append(t + tail[i + 1])
        m = re.fullmatch(r"(?i)p(?:ort)?[-.#]?(\d+[a-z]?)", t)   # 'P47', 'port25', 'P-3'
        if m:
            cands.append(m.group(1))
            cands.append("port" + m.group(1))
    for c in cands:
        k = normalise_ifname(c)
        if k in keys and keys[k].kind == "physical":
            return keys[k].name
    return None


class LinkSet:
    def __init__(self):
        self.links: list[dict] = []

    def add(self, a: str, a_port: str | None, b: str, b_port: str | None, source: str, detail: str = ""):
        if a == b:
            return
        if (a, a_port or "") > (b, b_port or ""):
            a, a_port, b, b_port = b, b_port, a, a_port
        ka, kb = normalise_ifname(a_port) if a_port else None, normalise_ifname(b_port) if b_port else None
        for L in self.links:
            if L["a"] != a or L["b"] != b:
                continue
            la, lb = L["_ka"], L["_kb"]
            if (la is None or ka is None or la == ka) and (lb is None or kb is None or lb == kb):
                if la is None and ka:
                    L["a_port"], L["_ka"] = a_port, ka
                if lb is None and kb:
                    L["b_port"], L["_kb"] = b_port, kb
                if source not in L["sources"]:
                    L["sources"].append(source)
                if detail:
                    L["details"].append(detail)
                return
        self.links.append({"a": a, "a_port": a_port, "b": b, "b_port": b_port, "_ka": ka, "_kb": kb,
                           "sources": [source], "details": [detail] if detail else []})


def _expand_lag(dev: SwitchConfig, port: str | None) -> list[str | None]:
    """A LAG name ('Trk1', 'Po1', 'lag1') -> its physical member ports; anything else unchanged."""
    if not port:
        return [port]
    k = normalise_ifname(port)
    members = [p.name for p in dev.ports if p.lag and normalise_ifname(p.lag) == k and p.kind == "physical"]
    return members or [port]


def discover_links(devices: list[SwitchConfig], neighbours: list[Neighbour], mapping: dict,
                   lm_alias: dict[tuple[str, str], str],
                   mac_links: list[tuple[str, str, str, str | None]] | None = None) -> list[dict]:
    aliases = {str(k).lower(): [str(x) for x in (v or {}).get("aliases", [])]
               for k, v in (mapping.get("switches") or {}).items()}
    idx = DeviceIndex(devices, aliases)
    ls = LinkSet()

    # 1. explicit
    for e in mapping.get("links") or []:
        a, b = idx.resolve(str(e.get("a", ""))), idx.resolve(str(e.get("b", "")))
        if a and b:
            ls.add(a, e.get("a_port"), b, e.get("b_port"), "explicit")

    # 2. CDP / LLDP
    for n in neighbours:
        a, b = idx.resolve(n.local), idx.resolve(n.remote)
        if a and b:
            a_ports = _expand_lag(idx.by_id[a], _canon_port(idx.by_id[a], n.local_port))
            b_port = _canon_port(idx.by_id[b], n.remote_port) if n.remote_port else None
            for ap in a_ports:
                ls.add(a, ap, b, b_port if len(a_ports) == 1 else None, n.protocol, n.source_file)

    # 3. FortiLink and ISL
    managed = [d for d in devices if d.meta.get("fortigate")]
    serials = {d.serial: d for d in managed if d.serial}
    isl_parent: dict[str, tuple[str, list[str]]] = {}
    for d in managed:
        for tname, members in (d.meta.get("isl") or {}).items():
            peer = _isl_peer(tname, serials, d.serial)
            if peer:
                isl_parent.setdefault(peer.switch_id, (d.switch_id, members))
    for d in managed:
        up = d.meta.get("fortilink_members") or []
        if d.switch_id in isl_parent:
            parent, parent_members = isl_parent[d.switch_id]
            _pair(ls, d.switch_id, up, parent, parent_members, "isl")
        elif d.meta["fortigate"] in idx.by_id:
            fw = idx.by_id[d.meta["fortigate"]]
            fw_members = [m for ms in (fw.meta.get("fortilink") or {}).values() for m in ms]
            _pair(ls, d.switch_id, up, fw.switch_id, fw_members, "fortilink")

    # 3b. MAC address tables (collector SNMP)
    for a, ap, b, bp in mac_links or []:
        if a in idx.by_id and b in idx.by_id:
            aps = _expand_lag(idx.by_id[a], _canon_port(idx.by_id[a], ap))
            bps = _expand_lag(idx.by_id[b], _canon_port(idx.by_id[b], bp)) if bp else [None]
            for i, x in enumerate(aps):
                y = bps[i] if len(bps) == len(aps) else (bps[0] if len(aps) == 1 and len(bps) == 1 else None)
                ls.add(a, x, b, y, "mac", "MAC address table")

    # 4. descriptions (config description, then LM ifAlias)
    for d in devices:
        lags = defaultdict(list)
        for p in d.ports:
            if p.lag:
                lags[normalise_ifname(p.lag)].append(p)
        for p in d.ports:
            for text in (p.description, lm_alias.get((d.switch_id, p.key), "")):
                hit = idx.find_in_text(text, d.switch_id, d.site)
                if not hit:
                    continue
                peer = idx.by_id[hit[0]]
                peer_port = _peer_port_from_text(text, hit[1], peer)
                local = [p] if p.kind == "physical" else lags.get(p.key, [])
                for lp in local:
                    ls.add(d.switch_id, lp.name, peer.switch_id, peer_port if len(local) == 1 else None,
                           "description", f"{d.hostname} {p.name}: {text}")
                break

    _drop_shadowed(ls)
    return ls.links


def _canon_port(dev: SwitchConfig, name: str) -> str:
    p = _port_lookup(dev).get(normalise_ifname(name))
    return p.name if p else name


def _isl_peer(tname: str, serials: dict, own: str | None):
    base = re.sub(r"-\d+$", "", tname)
    for s, dev in serials.items():
        if s == own:
            continue
        if s == base or s.startswith(base) or (len(s) >= 8 and base.startswith(s)):
            return dev
    return None


def _pair(ls: LinkSet, a, a_members, b, b_members, source):
    if not a_members:
        ls.add(a, None, b, None, source)
        return
    for i, m in enumerate(a_members):
        bm = b_members[i] if len(b_members) == len(a_members) else None
        ls.add(a, m, b, bm, source)


def _drop_shadowed(ls: LinkSet):
    """Remove portless links between devices that already have a port-specific link."""
    specific = {(L["a"], L["b"]) for L in ls.links if L["_ka"] or L["_kb"]}
    ls.links = [L for L in ls.links if L["_ka"] or L["_kb"] or (L["a"], L["b"]) not in specific]


# --------------------------------------------------------------------------
# Topology assembly
# --------------------------------------------------------------------------

def _vlans_of(dev: SwitchConfig, port_name: str | None, by_id: dict) -> tuple[set[str], bool] | None:
    if not port_name:
        return None
    p = _port_lookup(dev).get(normalise_ifname(port_name))
    if not p:
        return None
    # FortiLink and ISL trunk members carry every FortiLink VLAN defined on the FortiGate
    fl_trunk = dev.meta.get("fortilink_members") or []
    if dev.meta.get("fortigate") and (p.name in fl_trunk or p.lag in (dev.meta.get("isl") or {})):
        fw = by_id.get(dev.meta["fortigate"])
        return (set(fw.meta.get("fortilink_vlans") or []), False) if fw else (set(), True)
    if dev.role == "firewall" and p.name in [m for ms in (dev.meta.get("fortilink") or {}).values() for m in ms]:
        return set(dev.meta.get("fortilink_vlans") or []), False
    vl, all_flag = p.vlan_set()
    if not vl and not all_flag and p.lag:
        lag = _port_lookup(dev).get(normalise_ifname(p.lag))
        if lag:
            return lag.vlan_set()
    return vl, all_flag


def build_topology(devices: list[SwitchConfig], links: list[dict], rows: list[dict],
                   summaries: list[dict], port_macs: dict | None = None) -> dict:
    by_id = {d.switch_id: d for d in devices}
    row_by_port = {(r["switch_id"], normalise_ifname(r["port"])): r for r in rows if r["in_config"]}
    summ = {s["switch_id"]: s for s in summaries}

    # Link VLANs, status and mismatches
    out_links = []
    for i, L in enumerate(links):
        da, db = by_id[L["a"]], by_id[L["b"]]
        va, vb = _vlans_of(da, L["a_port"], by_id), _vlans_of(db, L["b_port"], by_id)
        issues = []
        if va and vb:
            (sa, alla), (sb, allb) = va, vb
            if alla and allb:
                vlans, all_flag = sa | sb, True
            elif alla or allb:
                vlans, all_flag = (sb if alla else sa), False
            else:
                vlans, all_flag = sa & sb, False
                only_a, only_b = sorted(sa - sb, key=_vkey), sorted(sb - sa, key=_vkey)
                if only_a or only_b:
                    issues.append(f"VLAN mismatch. Only on {da.hostname}: {','.join(only_a) or '-'}; "
                                  f"only on {db.hostname}: {','.join(only_b) or '-'}")
        else:
            vlans, all_flag = (va or vb or (set(), False))
        status = "unknown"
        ends = [row_by_port.get((L["a"], L["_ka"])), row_by_port.get((L["b"], L["_kb"]))]
        if any(e and e["cfg_admin"] == "down" for e in ends):
            status = "disabled"
        elif any(e and e["lm_oper"] in ("down", "lowerLayerDown") for e in ends):
            status = "down"
        elif any(e and e["lm_oper"] == "up" for e in ends):
            status = "up"
        out_links.append({"id": i, "a": L["a"], "a_port": L["a_port"], "b": L["b"], "b_port": L["b_port"],
                          "sources": L["sources"], "details": L["details"][:3],
                          "vlans": sorted(vlans, key=_vkey), "all_vlans": all_flag,
                          "status": status, "issues": issues})

    sites: dict[str, dict] = {}
    for site in sorted({d.site for d in devices}):
        members = {d.switch_id for d in devices if d.site == site}
        site_links = [L for L in out_links if L["a"] in members or L["b"] in members]
        ids = members | {L["a"] for L in site_links} | {L["b"] for L in site_links}
        tiers = _tiers(ids, site_links, by_id)
        vlan_counts: Counter = Counter()
        vlan_names: dict[str, str] = {}
        for did in ids:
            d = by_id[did]
            for k, v in d.vlans.items():
                if v:
                    vlan_names.setdefault(k, v)
            for p in d.ports:
                if p.kind == "physical":
                    vl, _ = p.vlan_set()
                    vlan_counts.update(vl)
        top = sorted([v for v, _ in vlan_counts.most_common(len(PALETTE_LIGHT))], key=_vkey)
        palette = {v: {"light": PALETTE_LIGHT[i], "dark": PALETTE_DARK[i]} for i, v in enumerate(top)}
        sites[site] = {
            "devices": [_device_view(by_id[i], tiers.get(i, 0), i not in members, summ.get(i, {}),
                                     row_by_port, port_macs or {}) for i in sorted(ids)],
            "links": site_links,
            "vlans": [{"id": v, "name": vlan_names.get(v, ""), "ports": vlan_counts[v],
                       "color": palette.get(v)} for v in sorted(vlan_counts, key=_vkey)],
            "other_color": {"light": OTHER_LIGHT, "dark": OTHER_DARK},
        }
    return {"sites": sites}


def _vkey(v: str):
    return (0, int(v), "") if str(v).isdigit() else (1, 0, str(v))


def _tiers(ids: set[str], links: list[dict], by_id) -> dict[str, int]:
    adj = defaultdict(set)
    for L in links:
        adj[L["a"]].add(L["b"])
        adj[L["b"]].add(L["a"])
    tier: dict[str, int] = {}
    remaining = set(ids)
    while remaining:
        comp_roots = [i for i in remaining if by_id[i].role == "firewall"]
        if not comp_roots:
            comp_roots = [max(remaining, key=lambda i: (len(adj[i]), i))]
        q = deque((r, 0) for r in comp_roots)
        for r in comp_roots:
            tier[r] = 0
        while q:
            n, t = q.popleft()
            for m in adj[n]:
                if m not in tier and m in ids:
                    tier[m] = t + 1
                    q.append((m, t + 1))
        newly = {i for i in remaining if i in tier}
        if not newly:
            break
        remaining -= newly
    for i in ids:
        tier.setdefault(i, 0)
    # devices with no links at all go to their own bottom row
    linked = set(adj)
    bottom = max(tier.values(), default=0) + 1
    for i in ids:
        if i not in linked:
            tier[i] = bottom
    return tier


def _device_view(d: SwitchConfig, tier: int, external: bool, summary: dict, row_by_port, port_macs) -> dict:
    ports = []
    for p in d.ports:
        r = row_by_port.get((d.switch_id, p.key), {})
        vl, all_flag = p.vlan_set()
        ports.append({"name": p.name, "kind": p.kind, "mode": p.mode, "description": p.description,
                      "access_vlan": p.access_vlan, "native_vlan": p.native_vlan,
                      "allowed_vlans": p.allowed_vlans, "voice_vlan": p.voice_vlan, "lag": p.lag,
                      "ip": p.ip, "vlans": sorted(vl, key=_vkey), "all_vlans": all_flag,
                      "admin_down": p.admin_down, "lm_oper": r.get("lm_oper"),
                      "lm_alias": r.get("lm_alias", ""),
                      "macs": sorted(port_macs.get((d.switch_id, p.key), [])),
                      "issues": [i["text"] for i in r.get("issues", []) if i["level"] == "warn"]})
    return {"id": d.switch_id, "hostname": d.hostname, "role": d.role, "vendor": d.vendor,
            "serial": d.serial, "tier": tier, "external": external, "site": d.site,
            "lm_device": summary.get("lm_device"), "ports": ports}
