"""Runtime settings.

Precedence: values saved from the Settings page (DATA_DIR/settings.json) override
environment variables, which override built-in defaults.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


def _list(name: str, default: str) -> list[str]:
    return [x.strip() for x in os.getenv(name, default).split(",") if x.strip()]


def _ints(text: str) -> list[int]:
    return [int(x) for x in str(text).replace(";", ",").split(",") if x.strip().isdigit()]


# Fields editable on the Settings page, with their types.
UI_FIELDS = {
    "lm_company": str, "lm_bearer_token": str, "lm_access_id": str, "lm_access_key": str,
    "lm_group_ids": list, "include_subgroups": bool, "hide_unmatched": bool,
    "lm_device_filter": str, "config_source": str, "fetch_status": bool, "fetch_alerts": bool, "refresh_minutes": int,
}
SECRET_FIELDS = {"lm_bearer_token", "lm_access_key"}


@dataclass
class Settings:
    lm_company: str = field(default_factory=lambda: os.getenv("LM_COMPANY", ""))
    lm_access_id: str = field(default_factory=lambda: os.getenv("LM_ACCESS_ID", ""))
    lm_access_key: str = field(default_factory=lambda: os.getenv("LM_ACCESS_KEY", ""))
    lm_bearer_token: str = field(default_factory=lambda: os.getenv("LM_BEARER_TOKEN", ""))
    # Only ingest LM devices in these device group IDs (empty = all devices)
    lm_group_ids: list[int] = field(default_factory=lambda: _ints(os.getenv("LM_GROUP_IDS", "")))
    include_subgroups: bool = field(default_factory=lambda: _bool("LM_INCLUDE_SUBGROUPS", True))
    # Hide config devices that do not match an LM device in the selected groups
    hide_unmatched: bool = field(default_factory=lambda: _bool("HIDE_UNMATCHED", False))
    lm_device_filter: str = field(default_factory=lambda: os.getenv("LM_DEVICE_FILTER", ""))
    # Where configs come from: files (CONFIG_DIR), lm (LogicMonitor ConfigSources) or both
    config_source: str = field(default_factory=lambda: os.getenv("CONFIG_SOURCE", "both").lower())
    lm_configsource_regex: str = field(default_factory=lambda: os.getenv("LM_CONFIGSOURCE_REGEX", ".*"))
    lm_config_instance_prefer: str = field(default_factory=lambda: os.getenv(
        "LM_CONFIG_INSTANCE_PREFER", r"running|full|show.?run|backup|config"))
    lm_config_instance_exclude: str = field(default_factory=lambda: os.getenv(
        "LM_CONFIG_INSTANCE_EXCLUDE", r"startup|version|inventory|licen[cs]e|hardware|log|diff"))
    lm_config_max_devices: int = field(default_factory=lambda: int(os.getenv("LM_CONFIG_MAX_DEVICES", "500")))
    interface_datasources: list[str] = field(default_factory=lambda: _list(
        "LM_INTERFACE_DATASOURCES", r"^SNMP_Network_Interfaces$,^snmp64_If-?$,Interfaces,FortiSwitch.*Port"))
    status_datapoints: list[str] = field(default_factory=lambda: _list(
        "LM_STATUS_DATAPOINTS", "OperStatus,Status,ifOperStatus"))
    alias_properties: list[str] = field(default_factory=lambda: _list(
        "LM_ALIAS_PROPERTIES", "auto.interface.alias,auto.interface.ifalias"))
    name_properties: list[str] = field(default_factory=lambda: _list(
        "LM_NAME_PROPERTIES", "auto.interface.name,auto.interface.description,auto.interface.ifname"))
    fetch_status: bool = field(default_factory=lambda: _bool("LM_FETCH_STATUS", True))
    fetch_alerts: bool = field(default_factory=lambda: _bool("LM_FETCH_ALERTS", True))
    max_workers: int = field(default_factory=lambda: int(os.getenv("LM_MAX_WORKERS", "6")))

    config_dir: str = field(default_factory=lambda: os.getenv("CONFIG_DIR", "/configs"))
    mapping_file: str = field(default_factory=lambda: os.getenv("MAPPING_FILE", "/mapping/mapping.yaml"))
    data_dir: str = field(default_factory=lambda: os.getenv("DATA_DIR", "/data"))
    refresh_minutes: int = field(default_factory=lambda: int(os.getenv("REFRESH_INTERVAL_MINUTES", "0")))
    ui_username: str = field(default_factory=lambda: os.getenv("UI_USERNAME", ""))
    ui_password: str = field(default_factory=lambda: os.getenv("UI_PASSWORD", ""))

    mapping: dict = field(default_factory=dict)

    # -- persisted UI settings ----------------------------------------------

    @property
    def settings_file(self) -> Path:
        return Path(self.data_dir) / "settings.json"

    def load_saved(self) -> None:
        try:
            saved = json.loads(self.settings_file.read_text())
        except (OSError, ValueError):
            return
        for k, v in saved.items():
            if k in UI_FIELDS:
                setattr(self, k, v)

    def save(self, values: dict) -> None:
        """Apply and persist UI values. Empty secret fields keep their current value."""
        for k, typ in UI_FIELDS.items():
            if k not in values:
                continue
            v = values[k]
            if k in SECRET_FIELDS and (v is None or v == ""):
                continue
            if typ is bool:
                v = bool(v)
            elif typ is int:
                v = int(v or 0)
            elif k == "config_source":
                v = str(v).lower() if str(v).lower() in ("files", "lm", "both") else "both"
            elif typ is list:
                v = _ints(",".join(map(str, v)) if isinstance(v, list) else v)
            else:
                v = str(v).strip()
            setattr(self, k, v)
        if values.get("clear_secrets"):
            self.lm_bearer_token = self.lm_access_key = ""
        Path(self.data_dir).mkdir(parents=True, exist_ok=True)
        tmp = self.settings_file.with_suffix(".tmp")
        tmp.write_text(json.dumps({k: getattr(self, k) for k in UI_FIELDS}, indent=2))
        os.chmod(tmp, 0o600)
        tmp.replace(self.settings_file)

    def public(self) -> dict:
        """Settings safe to show in the UI: secrets masked."""
        out = {k: getattr(self, k) for k in UI_FIELDS if k not in SECRET_FIELDS}
        for k in SECRET_FIELDS:
            v = getattr(self, k)
            out[k + "_set"] = bool(v)
            out[k + "_hint"] = ("…" + v[-4:]) if len(v) > 8 else ("set" if v else "")
        return out

    # -- mapping.yaml ---------------------------------------------------------

    def load_mapping(self) -> None:
        p = Path(self.mapping_file)
        self.mapping = (yaml.safe_load(p.read_text()) or {}) if p.is_file() else {}

    @property
    def switch_overrides(self) -> dict:
        return {str(k).lower(): v or {} for k, v in (self.mapping.get("switches") or {}).items()}

    @property
    def vendor_overrides(self) -> dict:
        return {str(k): str(v) for k, v in (self.mapping.get("files") or {}).items()}

    @property
    def ignore_ports(self) -> set[str]:
        return {str(x).lower() for x in (self.mapping.get("ignore_ports") or [])}
