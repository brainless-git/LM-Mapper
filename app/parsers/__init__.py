"""Vendor detection and config loading."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from ..models import SwitchConfig
from . import aruba, cisco_ios, fortios, neighbours
from .neighbours import Neighbour

log = logging.getLogger(__name__)

# Order matters: most specific detectors first.
PARSERS = {
    "fortios": (fortios.detect, fortios.parse),
    "aruba_aoscx": (aruba.detect_aoscx, aruba.parse_aoscx),
    "aruba_procurve": (aruba.detect_procurve, aruba.parse_procurve),
    "cisco_ios": (cisco_ios.detect, cisco_ios.parse),
}

CONFIG_SUFFIXES = {".cfg", ".conf", ".txt", ".config", ".log", ".cdp", ".lldp", ""}


@dataclass
class Inventory:
    devices: list[SwitchConfig] = field(default_factory=list)
    neighbours: list[Neighbour] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)


def detect_vendor(text: str) -> str | None:
    for name, (det, _) in PARSERS.items():
        if det(text):
            return name
    return None


def parse_text(text: str, source_file: str, vendor: str | None = None) -> list[SwitchConfig]:
    vendor = vendor or detect_vendor(text)
    if vendor not in PARSERS:
        raise ValueError(f"Unrecognised config format: {source_file}")
    return PARSERS[vendor][1](text, source_file)


def site_of(rel: str) -> str:
    """configs/<site>/<file> -> <site>; files at the top level go to 'default'."""
    parts = Path(rel).parts
    return parts[0] if len(parts) > 1 else "default"


def load_inventory(path: str | Path, vendor_overrides: dict[str, str] | None = None) -> Inventory:
    vendor_overrides = vendor_overrides or {}
    inv = Inventory()
    root = Path(path)
    if not root.is_dir():
        inv.errors.append({"file": str(root), "error": "Config directory not found"})
        return inv
    for f in sorted(root.rglob("*")):
        if not f.is_file() or f.name.startswith(".") or f.suffix.lower() not in CONFIG_SUFFIXES:
            continue
        rel = str(f.relative_to(root))
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            inv.errors.append({"file": rel, "error": str(exc)})
            continue
        nbrs = neighbours.parse(text, rel) if neighbours.looks_like_neighbours(text) else []
        inv.neighbours.extend(nbrs)
        vendor = vendor_overrides.get(rel) or detect_vendor(text)
        if vendor is None:
            if not nbrs:
                inv.errors.append({"file": rel, "error": "Unrecognised config format"})
            continue
        try:
            for dev in parse_text(text, rel, vendor):
                dev.site = site_of(rel)
                inv.devices.append(dev)
        except Exception as exc:  # keep going; report per-file errors in the UI
            log.warning("Failed to parse %s: %s", rel, exc)
            inv.errors.append({"file": rel, "error": str(exc)})
    return inv


def load_directory(path, vendor_overrides=None) -> tuple[list[SwitchConfig], list[dict]]:
    """Backwards compatible helper: (devices, errors)."""
    inv = load_inventory(path, vendor_overrides)
    return inv.devices, inv.errors
