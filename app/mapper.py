"""Join parsed switch configs with LogicMonitor devices and interface instances."""
from __future__ import annotations

import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .lm_client import LMClient
from .lm_configs import fetch_lm_configs
from . import lm_snmp
from .models import SwitchConfig, natural_key, normalise_ifname
from .parsers import Inventory, load_inventory
from .topology import build_topology, discover_links
from .settings import Settings

log = logging.getLogger(__name__)

OPER_STATUS = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant",
               6: "notPresent", 7: "lowerLayerDown"}


@dataclass
class Report:
    generated_at: float = 0.0
    duration_s: float = 0.0
    switches: list[dict] = field(default_factory=list)
    rows: list[dict] = field(default_factory=list)
    parse_errors: list[dict] = field(default_factory=list)
    topology: dict = field(default_factory=dict)
    lm_config_stats: dict = field(default_factory=dict)
    snmp_stats: dict = field(default_factory=dict)
    neighbour_count: int = 0
    lm_errors: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _props(obj: dict, *kinds: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for kind in kinds:
        for p in obj.get(kind) or []:
            if isinstance(p, dict) and "name" in p:
                out[p["name"]] = str(p.get("value", ""))
    return out


def _device_keys(dev: dict) -> list[tuple[int, str]]:
    """(priority, key) pairs used to match a config switch to an LM device."""
    props = _props(dev, "systemProperties", "autoProperties", "customProperties")
    keys = [(0, dev.get("displayName", "")), (1, dev.get("name", "")),
            (1, props.get("system.sysname", "")), (1, props.get("system.hostname", ""))]
    keys += [(2, v) for k, v in props.items() if "serial" in k.lower()]
    out = []
    for prio, k in keys:
        k = (k or "").strip().lower()
        if k:
            out.append((prio, k))
            if "." in k and not re.match(r"^\d+\.\d+\.\d+\.\d+$", k):
                out.append((prio + 1, k.split(".")[0]))   # short hostname
    return out


def _instance_keys(inst: dict, settings: Settings) -> set[str]:
    props = _props(inst, "autoProperties", "customProperties")
    cands = [props.get(p, "") for p in settings.name_properties]
    disp = inst.get("displayName") or ""
    disp = re.sub(r"\s*\[.*?\]\s*$", "", disp)          # drop "[ID:123]" style suffix
    cands += [disp, disp.split(" - ")[0]]
    if ":" in disp:
        cands.append(disp.rsplit(":", 1)[-1])            # "SWITCH:port1" style
    return {normalise_ifname(c) for c in cands if c}


def _norm_text(s: str | None) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().strip('"')).lower()


def _parse_status(data: dict, names: list[str]) -> str | None:
    dps = data.get("dataPoints") or []
    lower = [d.lower() for d in dps]
    idx = next((lower.index(n.lower()) for n in names if n.lower() in lower), None)
    if idx is None:
        return None
    for row in data.get("values") or []:
        try:
            v = row[idx]
        except (IndexError, TypeError):
            continue
        if isinstance(v, (int, float)):
            return OPER_STATUS.get(int(v), str(int(v)))
    return None


# --------------------------------------------------------------------------
# main build
# --------------------------------------------------------------------------

def build_report(settings: Settings, client: LMClient | None) -> Report:
    t0 = time.time()
    settings.load_mapping()
    rep = Report()
    if settings.config_source in ("files", "both"):
        inv = load_inventory(settings.config_dir, settings.vendor_overrides)
    else:
        inv = Inventory()
    rep.parse_errors = inv.errors
    ignore = settings.ignore_ports

    devices: list[dict] = []
    site_by_device: dict[int, str] = {}
    if client is not None:
        try:
            if settings.lm_group_ids:
                seen: dict = {}
                for gid in settings.lm_group_ids:
                    try:
                        gname = client.group(gid).get("name") or str(gid)
                    except Exception:
                        gname = str(gid)
                    for d in client.group_devices(gid, settings.include_subgroups):
                        seen.setdefault(d["id"], d)
                        site_by_device.setdefault(d["id"], gname)
                devices = list(seen.values())
            else:
                devices = client.devices(settings.lm_device_filter)
        except Exception as exc:
            rep.lm_errors.append(f"Device list: {exc}")
    else:
        rep.lm_errors.append("LogicMonitor credentials not set; showing config only")

    # Configs from LogicMonitor ConfigSources replace file configs for the same device
    if client is not None and devices and settings.config_source in ("lm", "both"):
        try:
            lmc = fetch_lm_configs(client, devices, site_by_device, settings)
            rep.lm_config_stats = {"devices": len(lmc.devices), "downloaded": lmc.fetched, "cached": lmc.cached}
            rep.parse_errors.extend(lmc.errors)
            lm_ids = {d.switch_id.lower() for d in lmc.devices} | {d.hostname.lower() for d in lmc.devices}
            inv.devices = [d for d in inv.devices
                           if d.switch_id.lower() not in lm_ids and d.hostname.lower() not in lm_ids] + lmc.devices
            inv.neighbours.extend(lmc.neighbours)
        except Exception as exc:
            log.exception("LM config pull failed")
            rep.lm_errors.append(f"LM configs: {exc}")
    configs = inv.devices
    rep.neighbour_count = len(inv.neighbours)

    index: dict[str, tuple[int, dict]] = {}
    by_id = {d["id"]: d for d in devices}
    for d in devices:
        for prio, k in _device_keys(d):
            if k not in index or prio < index[k][0]:
                index[k] = (prio, d)

    def match_device(sw: SwitchConfig) -> dict | None:
        if sw.meta.get("lm_device_id") in by_id:          # config pulled from this LM device
            return by_id[sw.meta["lm_device_id"]]
        for key in (sw.serial, sw.hostname):
            ov = settings.switch_overrides.get((key or "").lower())
            if ov:
                if ov.get("lm_device_id") in by_id:
                    return by_id[ov["lm_device_id"]]
                if ov.get("lm_device"):
                    hit = index.get(str(ov["lm_device"]).lower())
                    return hit[1] if hit else None
        best = None
        for key in (sw.hostname, sw.serial):
            if not key:
                continue
            for k in (key.lower(), key.lower().split(".")[0]):
                if k in index and (best is None or index[k][0] < best[0]):
                    best = index[k]
        return best[1] if best else None

    def process(sw: SwitchConfig) -> tuple[dict, list[dict]]:
        dev = match_device(sw) if devices else None
        summary = {"switch_id": sw.switch_id, "hostname": sw.hostname, "serial": sw.serial,
                   "vendor": sw.vendor, "source_file": sw.source_file, "role": sw.role, "site": sw.site,
                   "lm_device_id": dev["id"] if dev else None,
                   "lm_device": dev.get("displayName") if dev else None,
                   "lm_datasource": None, "error": None}
        instances: dict[str, dict] = {}
        alerts: dict[str, list[dict]] = {}
        hds_id = None
        if dev:
            try:
                hds = _pick_datasource(client.device_datasources(dev["id"]), settings)
                if hds:
                    hds_id = hds["id"]
                    summary["lm_datasource"] = hds.get("dataSourceName")
                    for inst in client.instances(dev["id"], hds_id):
                        for k in _instance_keys(inst, settings):
                            instances.setdefault(k, inst)
                else:
                    summary["error"] = "No interface DataSource matched on device"
                if settings.fetch_alerts:
                    for a in client.device_alerts(dev["id"]):
                        key = str(a.get("instanceId") or a.get("instanceName") or "")
                        alerts.setdefault(key, []).append(a)
            except Exception as exc:
                summary["error"] = str(exc)

        rows = []
        seen_inst: set[int] = set()
        for p in sorted(sw.ports, key=lambda x: natural_key(x.name)):
            if p.key in ignore or p.name.lower() in ignore:
                continue
            inst = instances.get(p.key)
            if inst:
                seen_inst.add(inst["id"])
            rows.append(_row(sw, summary, p.to_dict(), inst, settings, alerts))

        # LM instances that have no matching port in config
        if dev and instances:
            for inst in {i["id"]: i for i in instances.values()}.values():
                if inst["id"] not in seen_inst:
                    rows.append(_row(sw, summary, None, inst, settings, alerts))

        if dev and hds_id and settings.fetch_status:
            _fill_status(client, dev["id"], hds_id, rows, settings)
        for r in rows:
            r["issues"] = _issues(r, summary)
        summary["port_count"] = sum(1 for r in rows if r["in_config"])
        summary["matched"] = sum(1 for r in rows if r["in_config"] and r["lm_instance_id"])
        summary["issue_count"] = sum(1 for r in rows if any(i["level"] == "warn" for i in r["issues"]))
        return summary, rows

    with ThreadPoolExecutor(max_workers=max(1, settings.max_workers)) as pool:
        results = list(pool.map(process, configs))

    keep = configs
    if settings.hide_unmatched and settings.lm_group_ids and devices:
        matched_ids = {s["switch_id"] for s, _ in results if s["lm_device_id"]}
        results = [(s, r) for s, r in results if s["switch_id"] in matched_ids]
        keep = [c for c in configs if c.switch_id in matched_ids]
    for summary, rows in results:
        rep.switches.append(summary)
        rep.rows.extend(rows)

    # LLDP + MAC tables through the LM collectors
    mac_links, port_macs = [], {}
    if client is not None and settings.collector_snmp:
        targets = [(sm["switch_id"], by_id[sm["lm_device_id"]]) for sm in rep.switches
                   if sm["lm_device_id"] in by_id]
        try:
            l2, errs = lm_snmp.collect(client, targets, settings.data_dir, settings.snmp_cache_minutes)
            rep.lm_errors.extend(f"SNMP: {e}" for e in errs[:10])
            host_of = {c.switch_id: c.hostname for c in keep}
            inv.neighbours.extend(lm_snmp.lldp_neighbours(l2, host_of))
            mac_links = lm_snmp.mac_links(l2)
            for sid, d in l2.items():
                for port, macs in d.fdb.items():
                    port_macs[(sid, normalise_ifname(port))] = macs
            for r in rep.rows:
                macs = port_macs.get((r["switch_id"], normalise_ifname(r["port"])), set())
                r["mac_count"] = len(macs)
                r["macs"] = sorted(macs)[:20]
            rep.snmp_stats = {"devices": len(l2), "lldp_neighbours": sum(len(d.lldp) for d in l2.values()),
                              "macs": sum(len(m) for d in l2.values() for m in d.fdb.values()),
                              "mac_links": len(mac_links), "errors": len(errs)}
        except Exception as exc:
            log.exception("Collector SNMP failed")
            rep.lm_errors.append(f"SNMP: {exc}")

    try:
        lm_alias = {(r["switch_id"], normalise_ifname(r["port"])): r["lm_alias"]
                    for r in rep.rows if r["in_config"] and r["lm_alias"]}
        links = discover_links(keep, inv.neighbours, settings.mapping, lm_alias, mac_links)
        rep.topology = build_topology(keep, links, rep.rows, rep.switches, port_macs)
    except Exception as exc:
        log.exception("Topology build failed")
        rep.lm_errors.append(f"Topology: {exc}")

    rep.switches.sort(key=lambda s: natural_key(s["hostname"]))
    rep.generated_at, rep.duration_s = time.time(), round(time.time() - t0, 1)
    return rep


def _pick_datasource(hds_list: list[dict], settings: Settings) -> dict | None:
    for pattern in settings.interface_datasources:
        rx = re.compile(pattern, re.I)
        hits = [h for h in hds_list if rx.search(h.get("dataSourceName", ""))]
        if hits:
            return max(hits, key=lambda h: h.get("instanceNumber", 0) or 0)
    return None


def _row(sw, summary, port: dict | None, inst: dict | None, settings, alerts) -> dict:
    props = _props(inst, "autoProperties", "customProperties") if inst else {}
    alias = next((props[a] for a in settings.alias_properties if props.get(a)), "")
    if inst and not alias:
        alias = inst.get("description") or ""
    inst_alerts = []
    if inst:
        inst_alerts = alerts.get(str(inst["id"]), []) + alerts.get(inst.get("name", ""), []) \
            + alerts.get(inst.get("displayName", ""), [])
    p = port or {}
    if p.get("mode") == "access":
        vlan = f"{p.get('access_vlan') or ''}" + (f" (voice {p['voice_vlan']})" if p.get("voice_vlan") else "")
    elif p.get("mode") == "trunk":
        vlan = f"native {p.get('native_vlan') or '-'} / allowed {p.get('allowed_vlans') or '-'}"
    else:
        vlan = ""
    return {
        "switch_id": sw.switch_id, "switch": sw.hostname, "lm_device": summary["lm_device"],
        "in_config": port is not None,
        "port": p.get("name") or re.sub(r"\s*\[.*?\]\s*$", "", (inst or {}).get("displayName", "")),
        "description": p.get("description", ""),
        "mode": p.get("mode", ""), "vlan": vlan,
        "access_vlan": p.get("access_vlan"), "native_vlan": p.get("native_vlan"),
        "allowed_vlans": p.get("allowed_vlans", ""), "voice_vlan": p.get("voice_vlan"),
        "lag": p.get("lag"), "kind": p.get("kind", ""), "ip": p.get("ip", ""),
        "cfg_admin": ("down" if p.get("admin_down") else "up") if port else "",
        "lm_instance_id": inst["id"] if inst else None,
        "lm_instance": inst.get("displayName") if inst else "",
        "lm_alias": alias,
        "lm_monitored": (not inst.get("stopMonitoring", False)) if inst else None,
        "lm_oper": None, "mac_count": 0, "macs": [],
        "alerts": [{"severity": a.get("severity"), "datapoint": a.get("dataPointName"),
                    "value": a.get("alertValue")} for a in inst_alerts],
    }


def _fill_status(client, dev_id, hds_id, rows, settings) -> None:
    targets = [r for r in rows if r["lm_instance_id"]]

    def fetch(r):
        try:
            r["lm_oper"] = _parse_status(client.instance_data(dev_id, hds_id, r["lm_instance_id"]),
                                         settings.status_datapoints)
        except Exception as exc:
            log.debug("status fetch failed for %s: %s", r["port"], exc)

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(fetch, targets))


def _issues(r: dict, summary: dict) -> list[dict]:
    out = []
    def add(level, code, text):
        out.append({"level": level, "code": code, "text": text})

    if not summary["lm_device_id"]:
        add("info", "no_lm_device", "Switch not found in LogicMonitor")
        return out
    if not r["in_config"]:
        add("warn", "not_in_config", "LM monitors this interface but it is not in the config")
        return out
    if not r["lm_instance_id"]:
        lvl = "info" if r["cfg_admin"] == "down" or r["mode"] == "lag" or r.get("kind") == "logical" else "warn"
        add(lvl, "no_lm_instance", "No matching LM interface instance (may be filtered by the DataSource)")
        return out
    if _norm_text(r["description"]) != _norm_text(r["lm_alias"]) and (r["description"] or r["lm_alias"]):
        add("warn", "description_mismatch", f"Config '{r['description']}' vs LM '{r['lm_alias']}'")
    if r["cfg_admin"] == "down" and r["lm_oper"] == "up":
        add("warn", "shutdown_but_up", "Shutdown in config but LM reports up (config may be stale)")
    if r["cfg_admin"] == "up" and r["lm_oper"] in ("down", "lowerLayerDown") and r["description"]:
        add("info", "described_but_down", "Port has a description but LM reports it down")
    if r["lm_monitored"] is False:
        add("info", "not_monitored", "Monitoring disabled on this LM instance")
    if r["alerts"]:
        add("warn", "alerting", f"{len(r['alerts'])} active alert(s)")
    return out
