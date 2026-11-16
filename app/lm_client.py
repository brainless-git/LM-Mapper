"""Read-only LogicMonitor REST API (v3) client.

Only GET requests are issued. Supports LMv1 (access ID/key) or Bearer token auth.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import time
from typing import Any, Iterator

import requests

log = logging.getLogger(__name__)


class LMError(RuntimeError):
    pass


class LMClient:
    def __init__(self, company: str, access_id: str = "", access_key: str = "",
                 bearer_token: str = "", timeout: int = 30, page_size: int = 1000):
        if not company:
            raise LMError("LM_COMPANY is required")
        if not bearer_token and not (access_id and access_key):
            raise LMError("Set LM_BEARER_TOKEN, or LM_ACCESS_ID and LM_ACCESS_KEY")
        self.base = f"https://{company}.logicmonitor.com/santaba/rest"
        self.access_id, self.access_key, self.bearer = access_id, access_key, bearer_token
        self.timeout, self.page_size = timeout, page_size
        self.session = requests.Session()

    # -- transport ---------------------------------------------------------

    def _auth_header(self, verb: str, resource_path: str, body: str = "") -> str:
        if self.bearer:
            return f"Bearer {self.bearer}"
        epoch = str(int(time.time() * 1000))
        msg = (verb + epoch + body + resource_path).encode()
        digest = hmac.new(self.access_key.encode(), msg, hashlib.sha256).hexdigest()
        signature = base64.b64encode(digest.encode()).decode()
        return f"LMv1 {self.access_id}:{signature}:{epoch}"

    def get(self, resource_path: str, params: dict | None = None) -> Any:
        for attempt in range(6):
            headers = {
                "Authorization": self._auth_header("GET", resource_path),
                "X-Version": "3",
                "Accept": "application/json",
            }
            r = self.session.get(self.base + resource_path, params=params,
                                 headers=headers, timeout=self.timeout)
            if r.status_code == 429 or r.status_code >= 500:
                wait = float(r.headers.get("X-Rate-Limit-Window", 0) or 0) or 2 ** attempt
                log.info("LM %s on %s, retrying in %.0fs", r.status_code, resource_path, wait)
                time.sleep(min(wait, 60))
                continue
            if r.status_code != 200:
                raise LMError(f"GET {resource_path} -> HTTP {r.status_code}: {r.text[:300]}")
            return r.json()
        raise LMError(f"GET {resource_path} failed after retries")

    def paged(self, resource_path: str, params: dict | None = None) -> Iterator[dict]:
        params = dict(params or {})
        offset = 0
        while True:
            params.update(size=self.page_size, offset=offset)
            data = self.get(resource_path, params)
            items = data.get("items", [])
            yield from items
            offset += len(items)
            total = data.get("total", 0)
            # total can be negative for some endpoints (meaning "more available")
            if not items or (total >= 0 and offset >= total):
                break

    # -- resources ---------------------------------------------------------

    def devices(self, filter_: str = "") -> list[dict]:
        params: dict = {}
        if filter_:
            params["filter"] = filter_
        return list(self.paged("/device/devices", params))

    def groups(self, query: str = "") -> list[dict]:
        params = {"fields": "id,name,fullPath,numOfHosts,parentId"}
        if query:
            q = query.replace('"', "")
            params["filter"] = f'fullPath~"{q}"' if not q.isdigit() else f"id:{q}"
        return list(self.paged("/device/groups", params))

    def group(self, group_id: int) -> dict:
        return self.get(f"/device/groups/{int(group_id)}")

    def group_devices(self, group_id: int, include_subgroups: bool = True) -> list[dict]:
        """Devices in a group, optionally walking subgroups. De-duplicated by device ID."""
        seen: dict[int, dict] = {}
        todo, visited = [int(group_id)], set()
        while todo:
            gid = todo.pop()
            if gid in visited:
                continue
            visited.add(gid)
            for d in self.paged(f"/device/groups/{gid}/devices"):
                seen.setdefault(d["id"], d)
            if include_subgroups:
                todo.extend(int(g["id"]) for g in (self.group(gid).get("subGroups") or []))
        return list(seen.values())

    def device_datasources(self, device_id: int) -> list[dict]:
        return list(self.paged(f"/device/devices/{device_id}/devicedatasources",
                               {"fields": "id,dataSourceName,dataSourceDisplayName,instanceNumber"}))

    def instances(self, device_id: int, hds_id: int) -> list[dict]:
        return list(self.paged(
            f"/device/devices/{device_id}/devicedatasources/{hds_id}/instances"))

    def instance_data(self, device_id: int, hds_id: int, inst_id: int) -> dict:
        return self.get(
            f"/device/devices/{device_id}/devicedatasources/{hds_id}/instances/{inst_id}/data",
            {"period": 1})

    def device_alerts(self, device_id: int) -> list[dict]:
        return list(self.paged(f"/device/devices/{device_id}/alerts",
                               {"filter": 'cleared:"false"'}))
