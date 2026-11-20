"""FastAPI web UI and JSON/CSV API for the switchport map."""
from __future__ import annotations

import csv
import io
import logging
import os
import secrets
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates

from .lm_client import LMClient, LMError
from .mapper import Report, build_report
from .settings import UI_FIELDS, Settings

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("lm-portmap")

settings = Settings()
settings.load_saved()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.filters["ts"] = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) if t else "never"


class State:
    report: Report = Report()
    refreshing: bool = False
    last_error: str | None = None
    lock = threading.Lock()


state = State()


def make_client(cfg: Settings | None = None) -> LMClient | None:
    cfg = cfg or settings
    try:
        return LMClient(cfg.lm_company, cfg.lm_access_id, cfg.lm_access_key, cfg.lm_bearer_token)
    except LMError as exc:
        log.warning("%s", exc)
        return None


def refresh() -> bool:
    """Rebuild the report. Returns False if a refresh is already running."""
    if not state.lock.acquire(blocking=False):
        return False
    state.refreshing = True
    try:
        log.info("Refresh started")
        state.report = build_report(settings, make_client())
        state.last_error = None
        log.info("Refresh done: %d switches, %d rows in %ss",
                 len(state.report.switches), len(state.report.rows), state.report.duration_s)
    except Exception as exc:
        log.exception("Refresh failed")
        state.last_error = str(exc)
    finally:
        state.refreshing = False
        state.lock.release()
    return True


def _scheduler():
    """Honours refresh_minutes changes made on the Settings page without a restart."""
    while True:
        time.sleep(30)
        mins = settings.refresh_minutes
        if mins > 0 and not state.refreshing and time.time() - state.report.generated_at >= mins * 60:
            refresh()


@asynccontextmanager
async def lifespan(app: FastAPI):
    threading.Thread(target=refresh, daemon=True).start()
    threading.Thread(target=_scheduler, daemon=True).start()
    yield


security = HTTPBasic(auto_error=False)


def auth(creds: HTTPBasicCredentials | None = Depends(security)):
    if not settings.ui_username:
        return
    ok = creds is not None \
        and secrets.compare_digest(creds.username.encode(), settings.ui_username.encode()) \
        and secrets.compare_digest(creds.password.encode(), settings.ui_password.encode())
    if not ok:
        raise HTTPException(401, "Unauthorised", headers={"WWW-Authenticate": "Basic"})


app = FastAPI(title="LM Switchport Map", lifespan=lifespan, dependencies=[Depends(auth)])


def _ctx(request: Request, **kw):
    return {"request": request, "report": state.report, "refreshing": state.refreshing,
            "last_error": state.last_error, "company": settings.lm_company, **kw}


# -- HTML ------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", _ctx(request))


@app.get("/switch/{switch_id}", response_class=HTMLResponse)
def switch_page(request: Request, switch_id: str):
    sw = next((s for s in state.report.switches if s["switch_id"] == switch_id), None)
    if sw is None:
        raise HTTPException(404, "Switch not found")
    rows = [r for r in state.report.rows if r["switch_id"] == switch_id]
    return templates.TemplateResponse(request, "switch.html", _ctx(request, sw=sw, rows=rows))


@app.get("/topology", response_class=HTMLResponse)
def topology_page(request: Request, site: str | None = None):
    sites = sorted((state.report.topology or {}).get("sites", {}).keys())
    site = site if site in sites else (sites[0] if sites else "")
    data = state.report.topology["sites"].get(site) if site else None
    return templates.TemplateResponse(request, "topology.html", _ctx(request, sites=sites, site=site, data=data))


@app.get("/lm-configs", response_class=HTMLResponse)
def lm_configs_page(request: Request):
    return templates.TemplateResponse(request, "lm_configs.html", _ctx(request, diag=state.report.lm_config_diag))


@app.get("/api/lm-configs")
def api_lm_configs():
    return {"generated_at": state.report.generated_at, "devices": state.report.lm_config_diag}


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    return templates.TemplateResponse(request, "settings.html", _ctx(request, s=settings.public()))


# -- API -------------------------------------------------------------------

@app.get("/api/topology")
def api_topology(site: str | None = None):
    sites = (state.report.topology or {}).get("sites", {})
    if site:
        if site not in sites:
            raise HTTPException(404, "Unknown site")
        return sites[site]
    return {"sites": list(sites)}


@app.get("/api/settings")
def api_get_settings():
    return settings.public()


@app.post("/api/settings")
def api_save_settings(values: dict = Body(...)):
    try:
        settings.save(values)
    except (ValueError, OSError) as exc:
        raise HTTPException(400, f"Could not save settings: {exc}")
    if not state.refreshing:
        threading.Thread(target=refresh, daemon=True).start()
    return settings.public()


def _candidate_settings(values: dict) -> Settings:
    """Settings as typed on the page (unsaved), falling back to saved secrets."""
    cfg = Settings(**{k: getattr(settings, k) for k in UI_FIELDS})
    for k in ("lm_company", "lm_access_id"):
        if values.get(k):
            setattr(cfg, k, str(values[k]).strip())
    for k in ("lm_bearer_token", "lm_access_key"):
        if values.get(k):
            setattr(cfg, k, str(values[k]).strip())
    return cfg


@app.post("/api/lm/test")
def api_lm_test(values: dict = Body(default={})):
    client = make_client(_candidate_settings(values))
    if client is None:
        raise HTTPException(400, "Portal and a bearer token (or access ID/key) are required")
    try:
        data = client.get("/device/groups", {"size": 1, "fields": "id"})
    except Exception as exc:
        raise HTTPException(502, str(exc))
    return {"ok": True, "groups": data.get("total", 0)}


@app.post("/api/lm/groups")
def api_lm_groups(values: dict = Body(default={})):
    client = make_client(_candidate_settings(values))
    if client is None:
        raise HTTPException(400, "Portal and a bearer token (or access ID/key) are required")
    try:
        groups = client.groups(str(values.get("q", "")).strip())[:200]
    except Exception as exc:
        raise HTTPException(502, str(exc))
    return {"groups": [{k: g.get(k) for k in ("id", "name", "fullPath", "numOfHosts")} for g in groups]}


@app.get("/healthz")
def healthz():
    return {"ok": True, "generated_at": state.report.generated_at, "refreshing": state.refreshing}


@app.post("/api/refresh")
def api_refresh():
    if state.refreshing:
        return JSONResponse({"started": False, "detail": "Refresh already running"}, 409)
    threading.Thread(target=refresh, daemon=True).start()
    return {"started": True}


@app.get("/api/switches")
def api_switches():
    r = state.report
    return {"generated_at": r.generated_at, "duration_s": r.duration_s, "switches": r.switches,
            "lm_config_stats": r.lm_config_stats, "snmp_stats": r.snmp_stats,
            "parse_errors": r.parse_errors, "lm_errors": r.lm_errors}


@app.get("/api/ports")
def api_ports(switch: str | None = None, issues_only: bool = False):
    rows = state.report.rows
    if switch:
        rows = [r for r in rows if switch.lower() in (r["switch_id"].lower(), r["switch"].lower())]
    if issues_only:
        rows = [r for r in rows if r["issues"]]
    return {"generated_at": state.report.generated_at, "count": len(rows), "ports": rows}


CSV_FIELDS = ["switch", "lm_device", "port", "kind", "ip", "description", "lm_alias", "mode", "access_vlan",
              "native_vlan", "allowed_vlans", "voice_vlan", "lag", "cfg_admin", "lm_oper",
              "lm_instance", "lm_instance_id", "mac_count", "macs", "in_config", "alerts", "issues"]


@app.get("/export.csv")
def export_csv(switch: str | None = None):
    rows = api_ports(switch)["ports"]
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow({**r, "alerts": len(r["alerts"]), "macs": " ".join(r.get("macs", [])),
                    "issues": "; ".join(i["text"] for i in r["issues"])})
    name = f"portmap-{switch or 'all'}-{time.strftime('%Y%m%d-%H%M')}.csv"
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{name}"'})
