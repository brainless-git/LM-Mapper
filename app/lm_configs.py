"""Pull device configs from LogicMonitor ConfigSources (LM Config).

For each LM device in scope:
  1. list its ConfigSources:   GET /device/devices/{id}/devicedatasources?filter=dataSourceType:"CS"
  2. list their instances and pick the one that holds the running/full config
  3. read the newest version:  GET .../instances/{inst}/config?sort=-version&size=1
Configs are cached under DATA_DIR/lm-configs by version, so unchanged configs cost one
small API call per device instead of a full download.
"""
from __future__ import annotations

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from .lm_client import LMClient
from .models import SwitchConfig
from .parsers import detect_vendor, neighbours, parse_text
from .parsers.neighbours import Neighbour
from .settings import Settings

log = logging.getLogger(__name__)


@dataclass
class LMConfigResult:
    devices: list[SwitchConfig] = field(default_factory=list)
    neighbours: list[Neighbour] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    fetched: int = 0
    cached: int = 0
    diag: list[dict] = field(default_factory=list)   # one entry per LM device in scope


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name or "unnamed")[:120]


def _score(instance_name: str, settings: Settings) -> int:
    n = instance_name.lower()
    if re.search(settings.lm_config_instance_exclude, n, re.I):
        return -1
    return 2 if re.search(settings.lm_config_instance_prefer, n, re.I) else 1


class ConfigCache:
    def __init__(self, data_dir: str):
        self.root = Path(data_dir) / "lm-configs"
        self.index_file = self.root / "index.json"
        try:
            self.index = json.loads(self.index_file.read_text())
        except (OSError, ValueError):
            self.index = {}
        self.writable = True

    def get(self, key: str, version) -> str | None:
        e = self.index.get(key)
        if e and e.get("version") == version:
            try:
                return Path(e["path"]).read_text(encoding="utf-8", errors="replace")
            except OSError:
                return None
        return None

    def put(self, key: str, version, site: str, name: str, text: str) -> None:
        if not self.writable:
            return
        try:
            p = self.root / _safe(site) / f"{_safe(name)}.cfg"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
            self.index[key] = {"version": version, "path": str(p)}
        except OSError as exc:
            log.warning("Config cache not writable: %s", exc)
            self.writable = False

    def save(self) -> None:
        if self.writable:
            try:
                self.root.mkdir(parents=True, exist_ok=True)
                self.index_file.write_text(json.dumps(self.index, indent=1))
            except OSError:
                pass


def fetch_lm_configs(client: LMClient, devices: list[dict], site_by_device: dict[int, str],
                     settings: Settings) -> LMConfigResult:
    res = LMConfigResult()
    cache = ConfigCache(settings.data_dir)
    cs_name_rx = re.compile(settings.lm_configsource_regex, re.I)
    vendor_over = settings.vendor_overrides

    if len(devices) > settings.lm_config_max_devices:
        res.errors.append({"file": "LogicMonitor", "error":
                           f"{len(devices)} devices in scope; only the first {settings.lm_config_max_devices} "
                           "are checked for configs. Narrow the group IDs or raise LM_CONFIG_MAX_DEVICES."})
        devices = devices[:settings.lm_config_max_devices]

    def one(dev: dict):
        name = dev.get("displayName") or dev.get("name") or str(dev["id"])
        site = site_by_device.get(dev["id"], "default")
        diag = {"device": name, "lm_id": dev["id"], "site": site, "configsources": [], "tried": [],
                "used": None, "vendor": None, "outcome": ""}
        out: list[tuple] = []
        try:
            hds_list = list(client.paged(f"/device/devices/{dev['id']}/devicedatasources",
                                         {"filter": 'dataSourceType:"CS"'}))
            candidates = []
            for hds in hds_list:
                cs = {"name": hds.get("dataSourceName", ""), "instances": [], "skipped": ""}
                diag["configsources"].append(cs)
                if not cs_name_rx.search(cs["name"]):
                    cs["skipped"] = "name does not match LM_CONFIGSOURCE_REGEX"
                    continue
                for inst in client.instances(dev["id"], hds["id"]):
                    label = inst.get("displayName") or inst.get("name") or ""
                    sc = _score(label, settings)
                    cs["instances"].append(label + ("" if sc >= 0 else " (excluded)"))
                    if sc >= 0:
                        candidates.append((sc, hds, inst, label))
            candidates.sort(key=lambda c: -c[0])
            for _, hds, inst, label in candidates:
                path = f"/device/devices/{dev['id']}/devicedatasources/{hds['id']}/instances/{inst['id']}/config"
                head = client.get(path, {"sort": "-version", "size": 1, "fields": "id,version,pollTimestamp"})
                items = head.get("items") or []
                attempt = {"configsource": hds.get("dataSourceName"), "instance": label}
                diag["tried"].append(attempt)
                if not items:
                    attempt["result"] = "no config versions stored"
                    continue
                version = items[0].get("version")
                key = f"{dev['id']}:{hds['id']}:{inst['id']}"
                text = cache.get(key, version)
                was_cached = text is not None
                if text is None:
                    full = client.get(path, {"sort": "-version", "size": 1, "fields": "id,version,config"})
                    text = ((full.get("items") or [{}])[0].get("config")) or ""
                    cache.put(key, version, site, f"{name}__{label}", text)
                source = f"LM:{site}/{name}/{hds.get('dataSourceName')}/{label}"
                vendor = vendor_over.get(source) or detect_vendor(text)
                attempt.update(result=f"format: {vendor}" if vendor else "format not recognised",
                               size=len(text), first_line=(text.strip().splitlines() or [""])[0][:80])
                out.append((dev, site, source, text, was_cached))
                if vendor:
                    break        # first parseable config wins; later candidates are fallbacks
            if not hds_list:
                diag["outcome"] = "no ConfigSources applied to this device in LogicMonitor"
            elif not candidates:
                diag["outcome"] = "ConfigSources found, but no usable instance (see names)"
        except Exception as exc:
            diag["outcome"] = f"error: {exc}"
            return dev, [], f"{name}: {exc}", diag
        return dev, out, None, diag

    with ThreadPoolExecutor(max_workers=max(1, settings.max_workers)) as pool:
        results = list(pool.map(one, devices))

    for dev, items, err, diag in results:
        res.diag.append(diag)
        if err:
            res.errors.append({"file": "LogicMonitor", "error": err})
        for d, site, source, text, was_cached in items:
            res.cached += was_cached
            res.fetched += not was_cached
            if neighbours.looks_like_neighbours(text):
                res.neighbours.extend(neighbours.parse(text, source))
            vendor = vendor_over.get(source) or detect_vendor(text)
            if not vendor:
                continue
            try:
                parsed = parse_text(text, source, vendor)
                for sw in parsed:
                    sw.site = site
                    if not sw.meta.get("fortigate"):
                        sw.meta["lm_device_id"] = d["id"]   # managed FortiSwitches are matched normally
                    res.devices.append(sw)
                diag.update(used=source, vendor=vendor,
                            outcome=f"parsed: {sum(len(x.ports) for x in parsed)} ports"
                                    + (f", {len(parsed) - 1} managed switches" if len(parsed) > 1 else ""))
            except Exception as exc:
                res.errors.append({"file": source, "error": str(exc)})
                diag["outcome"] = f"parse error: {exc}"
            break
        else:
            if items:
                diag["outcome"] = "config downloaded but format not recognised"
                res.errors.append({"file": f"LM:{dev.get('displayName')}",
                                   "error": "ConfigSource data found but no supported config format"})
    cache.save()
    return res
