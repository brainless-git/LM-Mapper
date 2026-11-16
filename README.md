# LM-Mapper

Read-only web app that parses switch and firewall config backups, maps every port to its
LogicMonitor interface instance, draws the network topology with VLANs in colour, and flags
differences between the config and what LogicMonitor sees.

It only issues **GET** requests to LogicMonitor. It never writes to LM, switches or firewalls.

## Features

- **Devices view:** every switch and firewall, its LM device match and how many ports matched.
- **Port view:** per-port config (description, mode, VLANs, IP, LAG) next to LM data (ifAlias,
  status, alerts) with warnings. CSV and JSON export.
- **Topology view:** per site. Devices are drawn as faceplates (one square per physical port,
  coloured by access or native VLAN, trunks ringed, down ports hatched). Links are drawn with
  one coloured stroke per VLAN carried. Click a VLAN to isolate where it reaches. Links with
  a VLAN mismatch between the two ends are flagged. A links table sits under the diagram.
- **Settings page:** LM portal, Bearer token (or LMv1 ID/key), and the LM device group IDs to
  ingest, with a group search. Saved to `/data/settings.json`.

## Where configs come from

Set on the Settings page (**Config source**) or with `CONFIG_SOURCE`:

- **LogicMonitor ConfigSources** (LM Config). For every LM device in the selected groups the app
  lists its ConfigSources, picks the instance holding the running/full config (names matching
  `running|full|show run|backup|config`, skipping `startup|version|inventory|…`), and reads the
  newest version. Downloads are cached in `/data/lm-configs` by version, so a refresh only
  re-downloads configs that changed. Devices are grouped into sites by the group ID they were
  selected through.
- **Config folder** (`/configs`), one subfolder per site.
- **Both** (default). If a device appears in both, the LogicMonitor config wins.

## Supported configs

| Platform | Detected by | Parsed |
|---|---|---|
| Cisco IOS / IOS-XE | `hostname` + `interface GigabitEthernet…` | access/trunk/voice VLANs, allowed add/remove, channel-group, shutdown, routed IPs |
| Aruba ProCurve / ArubaOS-Switch | `; J####A Configuration Editor` or `hostname "…"` with tagged/untagged VLAN blocks | VLAN membership, `trunk … trkN`, `disable` |
| Aruba AOS-CX | `!Version ArubaOS-CX` or `interface 1/1/1` + `vlan access/trunk` | LAG members inherit VLANs from `interface lag N` |
| FortiGate (firewall) | `#config-version=FGT…` or `config firewall policy` | physical ports, IPs, VLAN subinterfaces (tagged onto the parent port), aggregates, hardware/software switches, FortiLink |
| FortiGate managed FortiSwitches | `config switch-controller managed-switch` | one switch per serial, VLAN names resolved to IDs, FortiLink and ISL trunks |
| FortiSwitchOS standalone | `#config-version=FS…` | native/allowed VLANs, trunks, `status down` |

Other firewall platforms are not parsed yet.

## How links are found

In priority order. Links from several sources that describe the same connection are merged,
and the table shows which sources found each one.

1. **Explicit:** `links:` in `mapping.yaml`.
2. **CDP / LLDP:** neighbour output saved next to the configs, in any file. Supported: Cisco
   `show cdp neighbors detail` and `show lldp neighbors detail`, ArubaOS-Switch
   `show lldp info remote-device detail`, AOS-CX `show lldp neighbor-info detail`. The local
   device comes from the CLI prompt in the file (`CORE-SW01#show cdp …`) or the file name.
3. **FortiLink:** each managed FortiSwitch's FortiLink trunk goes to the FortiGate's FortiLink
   ports. If another switch has an auto-ISL trunk named after this switch's serial, the
   uplink goes to that switch instead (tiered FortiLink).
4. **Descriptions:** a port description (config, or LM ifAlias) containing another device's
   hostname, serial or alias. A port name after the hostname is used as the far-end port,
   e.g. `Uplink EDGE-SW02 port 25`.

## Sites

Put each site's backups in its own folder: `configs/<site>/…`. Files directly under `configs/`
go to the `default` site. The topology view has a site selector.

## Running

### Docker / Compose

```bash
mkdir -p configs mapping data
cp mapping/mapping.example.yaml mapping/mapping.yaml   # optional
docker compose up -d          # pulls ghcr.io/brainless-git/lm-mapper:latest
# http://<host>:8080  ->  Settings: portal, Bearer token, group IDs
```

`docker compose up -d --build` builds locally instead.

### Unraid

Docker tab, **Add Container**:

| Field | Value |
|---|---|
| Repository | `ghcr.io/brainless-git/lm-mapper:latest` |
| Network | bridge |
| Port | container 8080 → host 8080 (or any free port) |
| Path `/configs` | `/mnt/user/appdata/lm-mapper/configs` (read only) |
| Path `/mapping` | `/mnt/user/appdata/lm-mapper/mapping` (read only) |
| Path `/data` | `/mnt/user/appdata/lm-mapper/data` |
| WebUI | `http://[IP]:[PORT:8080]/` |

The app runs as uid 99 / gid 100 (Unraid `nobody:users`). The entrypoint starts as root only to
fix ownership of `/data`, then drops to that user. Set `PUID` / `PGID` to change it.
If the GHCR package is private, either make it public in the package settings on GitHub or
log Unraid in to GHCR with a token that has `read:packages`.

### LM API account

Create an API-only user with a read-only role that can view the target resource groups
(Resources: View) and alerts. Generate a Bearer token and paste it on the Settings page.
Use **Find groups** to look up group IDs by name or path, then **Add**. With
**Include subgroups** on, all devices below the selected groups are ingested.
**Hide unmatched configs** limits the UI to config devices found in those groups.

The token is stored in `/data/settings.json` (mode 600) and is never returned by the API.
Set `UI_USERNAME` / `UI_PASSWORD` to protect the UI with basic auth, and put it behind TLS
(e.g. a reverse proxy or Tailscale) if it is reachable beyond your LAN.

## Environment variables

Settings saved on the Settings page override these.

| Variable | Default | Purpose |
|---|---|---|
| `LM_COMPANY` | | Portal name (`<company>.logicmonitor.com`) |
| `LM_BEARER_TOKEN` | | Bearer token |
| `LM_ACCESS_ID` / `LM_ACCESS_KEY` | | LMv1 alternative |
| `LM_GROUP_IDS` | | Comma separated device group IDs to ingest |
| `LM_INCLUDE_SUBGROUPS` | `true` | Walk subgroups of the selected groups |
| `HIDE_UNMATCHED` | `false` | Hide configs not matched in the selected groups |
| `LM_DEVICE_FILTER` | | LM REST filter, used only when no groups are set |
| `CONFIG_SOURCE` | `both` | `lm`, `files` or `both` |
| `LM_CONFIGSOURCE_REGEX` | `.*` | Only use ConfigSources whose name matches |
| `LM_CONFIG_INSTANCE_PREFER` | `running\|full\|show.?run\|backup\|config` | Preferred ConfigSource instance names |
| `LM_CONFIG_INSTANCE_EXCLUDE` | `startup\|version\|inventory\|licen[cs]e\|hardware\|log\|diff` | Instance names never used |
| `LM_CONFIG_MAX_DEVICES` | `500` | Safety cap on devices checked for configs per refresh |
| `LM_INTERFACE_DATASOURCES` | `^SNMP_Network_Interfaces$,^snmp64_If-?$,Interfaces,FortiSwitch.*Port` | Ordered regexes for the interface DataSource |
| `LM_NAME_PROPERTIES` | `auto.interface.name,auto.interface.description,auto.interface.ifname` | Instance properties holding ifName / ifDescr |
| `LM_ALIAS_PROPERTIES` | `auto.interface.alias,auto.interface.ifalias` | Instance property holding ifAlias |
| `LM_STATUS_DATAPOINTS` | `OperStatus,Status,ifOperStatus` | Datapoint carrying ifOperStatus (1 up, 2 down) |
| `LM_FETCH_STATUS` | `true` | 1 API call per matched port |
| `LM_FETCH_ALERTS` | `true` | Active alerts per device |
| `REFRESH_INTERVAL_MINUTES` | `0` | 0 = startup and manual refresh only |
| `UI_USERNAME` / `UI_PASSWORD` | | Basic auth |
| `CONFIG_DIR` / `MAPPING_FILE` / `DATA_DIR` | `/configs`, `/mapping/mapping.yaml`, `/data` | Paths |

DataSource, property and datapoint names differ between LM versions and custom modules. Check
one interface instance in your portal and adjust these if ports do not match or status shows n/a.

## API

| Path | Purpose |
|---|---|
| `GET /api/switches` | Device summary, parse errors, LM errors |
| `GET /api/ports?switch=X&issues_only=true` | Port rows |
| `GET /api/topology?site=X` | Devices, links and VLAN palette for a site |
| `GET /export.csv[?switch=X]` | CSV export |
| `POST /api/refresh` | Rebuild |
| `GET/POST /api/settings` | Read (secrets masked) / save settings |
| `POST /api/lm/test`, `POST /api/lm/groups` | Connection test, group search |
| `GET /healthz` | Health check |

## Development

```bash
pip install -r requirements.txt pytest httpx
pytest -q
CONFIG_DIR=tests/fixtures DATA_DIR=/tmp/lm-mapper uvicorn app.main:app --reload --port 8080
```

`tests/fixtures` holds sample Cisco, ProCurve, AOS-CX and FortiGate configs plus CDP output.
The tests run the full join, link discovery and topology against a fake LM API.
