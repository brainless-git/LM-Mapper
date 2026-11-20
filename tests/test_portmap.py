import base64
import hashlib
import hmac
from pathlib import Path

import pytest

from app.lm_client import LMClient
from app.mapper import build_report
from app.models import normalise_ifname
from app.parsers import detect_vendor, load_directory
from app.settings import Settings

FIX = Path(__file__).parent / "fixtures"


def sw_by_name(switches, name):
    return next(s for s in switches if s.hostname == name)


# -- parsers -----------------------------------------------------------------

def test_detection():
    expected = {"core-sw01.cfg": "cisco_ios", "edge-procurve.cfg": "aruba_procurve",
                "cx-sw03.cfg": "aruba_aoscx", "site1-fgt.conf": "fortios"}
    for f, v in expected.items():
        assert detect_vendor((FIX / f).read_text()) == v, f


def test_normalise():
    assert normalise_ifname("GigabitEthernet1/0/1") == normalise_ifname("Gi1/0/1") == "gi1/0/1"
    assert normalise_ifname("TenGigabitEthernet1/1/1") == normalise_ifname("Te1/1/1")
    assert normalise_ifname("Port-channel1") == normalise_ifname("Po1")


def test_cisco():
    sws, errs = load_directory(FIX)
    assert not errs
    s = sw_by_name(sws, "CORE-SW01")
    ports = {p.name: p for p in s.ports}
    assert "Vlan99" not in ports
    up = ports["GigabitEthernet1/0/47"]
    assert (up.mode, up.native_vlan, up.allowed_vlans, up.lag) == ("trunk", "99", "10,20,99", "Po1")
    assert ports["GigabitEthernet1/0/1"].voice_vlan == "20"
    assert ports["GigabitEthernet1/0/2"].admin_down


def test_procurve():
    s = sw_by_name(load_directory(FIX)[0], "EDGE-SW02")
    ports = {p.name: p for p in s.ports}
    assert ports["1"].access_vlan == "10" and ports["1"].description == "Desk 1"
    assert (ports["2"].mode, ports["2"].native_vlan, ports["2"].allowed_vlans) == ("trunk", "30", "10")
    assert ports["3"].admin_down and ports["3"].access_vlan == "1"
    assert ports["25"].lag == "Trk1" and ports["25"].allowed_vlans == "10,30"


def test_aoscx():
    s = sw_by_name(load_directory(FIX)[0], "CX-SW03")
    ports = {p.name: p for p in s.ports}
    assert ports["1/1/49"].lag == "lag1" and ports["1/1/49"].native_vlan == "99"
    assert ports["1/1/2"].admin_down


def test_fortigate_managed():
    s = sw_by_name(load_directory(FIX)[0], "SITE1-FSW01")
    assert s.serial == "S124FTF21000001"
    ports = {p.name: p for p in s.ports}
    assert ports["port1"].access_vlan == "10"
    assert (ports["port3"].native_vlan, ports["port3"].allowed_vlans) == ("10", "20")
    assert ports["port25"].lag == "__FoRtI1LiNk0__"


# -- LM client signing -------------------------------------------------------

def test_lmv1_signature(monkeypatch):
    c = LMClient("acme", "id1", "key1")
    monkeypatch.setattr("time.time", lambda: 1700000000.0)
    hdr = c._auth_header("GET", "/device/devices")
    digest = hmac.new(b"key1", b"GET1700000000000/device/devices", hashlib.sha256).hexdigest()
    assert hdr == f"LMv1 id1:{base64.b64encode(digest.encode()).decode()}:1700000000000"


# -- end-to-end with a fake LM -----------------------------------------------

def inst(i, name, alias="", stop=False):
    return {"id": i, "name": f"SNMP_Network_Interfaces-{name}", "displayName": f"{name} [ID:{i}]",
            "stopMonitoring": stop,
            "autoProperties": [{"name": "auto.interface.name", "value": name},
                               {"name": "auto.interface.alias", "value": alias}]}


class FakeLM:
    def devices(self, f=""):
        return [
            {"id": 1, "displayName": "core-sw01.client.local", "name": "10.0.99.2",
             "systemProperties": [{"name": "system.sysname", "value": "CORE-SW01"}]},
            {"id": 2, "displayName": "SITE1-FSW01", "name": "10.1.0.10",
             "autoProperties": [{"name": "auto.fortinet.serial_number", "value": "S124FTF21000001"}]},
        ]

    def device_datasources(self, dev_id):
        return [{"id": 100 + dev_id, "dataSourceName": "SNMP_Network_Interfaces", "instanceNumber": 5},
                {"id": 900, "dataSourceName": "SNMP_HostUptime", "instanceNumber": 1}]

    def instances(self, dev_id, hds):
        if dev_id == 1:
            return [inst(11, "Gi1/0/1", "PC-RECEPTION"), inst(12, "Gi1/0/2", "UNUSED"),
                    inst(13, "Gi1/0/3", "PRINTER-L2"), inst(14, "Gi1/0/47", "UPLINK-FGT"),
                    inst(15, "Gi1/0/46", "MYSTERY")]
        return [inst(21, "port1", "Reception PC"), inst(22, "port3", "Phone")]

    def instance_data(self, dev_id, hds, inst_id):
        status = {11: 1, 12: 1, 13: 2, 14: 1, 15: 1, 21: 1, 22: 2}[inst_id]
        return {"dataPoints": ["InOctets", "OperStatus"], "values": [["No Data", status]]}

    def device_alerts(self, dev_id):
        return [{"instanceId": 14, "severity": 3, "dataPointName": "InErrors", "alertValue": 12}] if dev_id == 1 else []


@pytest.fixture
def report(monkeypatch):
    s = Settings()
    s.config_dir, s.mapping_file = str(FIX), "/nonexistent"
    return build_report(s, FakeLM())


def issues(rep, switch, port):
    r = next(r for r in rep.rows if r["switch"] == switch and r["port"].startswith(port))
    return {i["code"] for i in r["issues"]}, r


def test_device_matching(report):
    sws = {s["hostname"]: s for s in report.switches}
    assert sws["CORE-SW01"]["lm_device_id"] == 1
    assert sws["SITE1-FSW01"]["lm_device_id"] == 2          # matched by serial
    assert sws["EDGE-SW02"]["lm_device_id"] is None
    assert sws["CORE-SW01"]["lm_datasource"] == "SNMP_Network_Interfaces"


def test_issue_detection(report):
    assert issues(report, "CORE-SW01", "GigabitEthernet1/0/1")[0] == set()
    assert "shutdown_but_up" in issues(report, "CORE-SW01", "GigabitEthernet1/0/2")[0]
    codes, row = issues(report, "CORE-SW01", "GigabitEthernet1/0/3")
    assert {"description_mismatch", "described_but_down"} <= codes and row["lm_oper"] == "down"
    assert "alerting" in issues(report, "CORE-SW01", "GigabitEthernet1/0/47")[0]
    assert "not_in_config" in issues(report, "CORE-SW01", "Gi1/0/46")[0]
    assert "no_lm_instance" in issues(report, "CORE-SW01", "TenGigabitEthernet1/1/1")[0]
    assert "no_lm_device" in issues(report, "EDGE-SW02", "1")[0]


def test_web(monkeypatch, report):
    from fastapi.testclient import TestClient
    import app.main as m
    monkeypatch.setattr(m, "refresh", lambda: True)
    m.state.report = report
    with TestClient(m.app) as c:
        assert c.get("/").status_code == 200
        r = c.get("/switch/CORE-SW01")
        assert r.status_code == 200 and "PRINTER-L2" in r.text
        assert c.get("/switch/S124FTF21000001").status_code == 200
        j = c.get("/api/ports", params={"switch": "core-sw01", "issues_only": True}).json()
        assert j["count"] >= 4
        csv_text = c.get("/export.csv").text
        assert csv_text.splitlines()[0].startswith("switch,lm_device,port")


def test_basic_auth(monkeypatch, report):
    from fastapi.testclient import TestClient
    import app.main as m
    monkeypatch.setattr(m, "refresh", lambda: True)
    monkeypatch.setattr(m.settings, "ui_username", "admin")
    monkeypatch.setattr(m.settings, "ui_password", "pw")
    with TestClient(m.app) as c:
        assert c.get("/api/switches").status_code == 401
        assert c.get("/api/switches", auth=("admin", "pw")).status_code == 200


# -- firewall, topology, settings ---------------------------------------------

def test_fortigate_firewall():
    sws = load_directory(FIX)[0]
    fw = sw_by_name(sws, "SITE1-FGT")
    assert fw.role == "firewall"
    ports = {p.name: p for p in fw.ports}
    assert ports["port1"].mode == "trunk" and ports["port1"].allowed_vlans == "10,20,99"
    assert ports["wan1"].ip == "203.0.113.10/29" and ports["wan1"].mode == "routed"
    assert ports["port7"].lag == "fortilink" and ports["core_data"].kind == "logical"
    assert ports["port6"].admin_down
    assert fw.meta["fortilink_vlans"] == ["1", "10", "20"]
    fsw2 = sw_by_name(sws, "SITE1-FSW02")
    assert fsw2.meta["fortilink_members"] == ["port25", "port26"]


def test_topology_links(report):
    topo = report.topology["sites"]["default"]
    names = {d["id"]: d["hostname"] for d in topo["devices"]}
    links = {}
    for l in topo["links"]:
        links[(names[l["a"]], l["a_port"], names[l["b"]], l["b_port"])] = l
        links[(names[l["b"]], l["b_port"], names[l["a"]], l["a_port"])] = l
    cdp = links[("CORE-SW01", "GigabitEthernet1/0/48", "CX-SW03", "1/1/49")]
    assert set(cdp["sources"]) == {"cdp", "description"} and cdp["vlans"] == ["10", "99"]
    assert any("VLAN mismatch" in i for i in cdp["issues"])
    assert links[("CORE-SW01", "GigabitEthernet1/0/47", "SITE1-FGT", "port1")]["vlans"] == ["10", "20", "99"]
    assert ("CORE-SW01", "TenGigabitEthernet1/1/1", "EDGE-SW02", "25") in links
    assert links[("SITE1-FGT", "port7", "SITE1-FSW01", "port25")]["sources"] == ["fortilink"]
    assert links[("SITE1-FSW01", "port23", "SITE1-FSW02", "port25")]["sources"] == ["isl"]
    tiers = {d["hostname"]: d["tier"] for d in topo["devices"]}
    assert tiers["SITE1-FGT"] == 0 and tiers["CORE-SW01"] == 1 and tiers["SITE1-FSW02"] == 2
    assert sum(1 for v in topo["vlans"] if v["color"]) <= 8


def test_explicit_link(tmp_path):
    m = tmp_path / "mapping.yaml"
    m.write_text("links:\n  - {a: EDGE-SW02, a_port: '26', b: CX-SW03, b_port: 1/1/50}\n")
    s = Settings()
    s.config_dir, s.mapping_file = str(FIX), str(m)
    rep = build_report(s, None)
    assert any(l["sources"] == ["explicit"] for l in rep.topology["sites"]["default"]["links"])


def test_settings_persist(tmp_path):
    s = Settings()
    s.data_dir = str(tmp_path)
    s.save({"lm_company": "acme", "lm_bearer_token": "tok-1234567890", "lm_group_ids": "12, 34",
            "include_subgroups": False})
    s.save({"lm_bearer_token": ""})                       # blank keeps the saved token
    s2 = Settings()
    s2.data_dir = str(tmp_path)
    s2.load_saved()
    assert (s2.lm_company, s2.lm_bearer_token, s2.lm_group_ids, s2.include_subgroups) == \
        ("acme", "tok-1234567890", [12, 34], False)
    pub = s2.public()
    assert "lm_bearer_token" not in pub and pub["lm_bearer_token_hint"] == "…7890"


class FakeGroupsLM(FakeLM):
    def group_devices(self, gid, include_subgroups=True):
        return [d for d in self.devices() if d["id"] == gid]


def test_group_scope_hide_unmatched():
    s = Settings()
    s.config_dir, s.mapping_file = str(FIX), "/nonexistent"
    s.lm_group_ids, s.hide_unmatched = [1], True
    rep = build_report(s, FakeGroupsLM())
    assert [x["hostname"] for x in rep.switches] == ["CORE-SW01"]


def test_topology_and_settings_pages(monkeypatch, report, tmp_path):
    from fastapi.testclient import TestClient
    import app.main as m
    monkeypatch.setattr(m, "refresh", lambda: True)
    monkeypatch.setattr(m.settings, "data_dir", str(tmp_path))
    m.state.report = report
    with TestClient(m.app) as c:
        r = c.get("/topology")
        assert r.status_code == 200 and "SITE1-FGT" in r.text
        assert c.get("/api/topology", params={"site": "default"}).json()["links"]
        assert c.get("/settings").status_code == 200
        j = c.post("/api/settings", json={"lm_company": "acme", "lm_bearer_token": "secret-abcd1234",
                                          "lm_group_ids": "5"}).json()
        assert j["lm_group_ids"] == [5] and "secret" not in str(j)


# -- LogicMonitor ConfigSource pull --------------------------------------------

class FakeConfigLM(FakeGroupsLM):
    """Device 3 'EDGE-SW02' with a ProCurve ConfigSource holding running + startup configs."""
    calls = 0

    def __init__(self, text):
        self.text, self.version = text, 7

    def devices(self, f=""):
        return super().devices() + [{"id": 3, "displayName": "edge-sw02.site", "name": "10.0.99.4"}]

    def group(self, gid):
        return {"id": gid, "name": "St Agnes"}

    def group_devices(self, gid, include_subgroups=True):
        return [d for d in self.devices() if d["id"] == 3]

    def paged(self, path, params=None):
        if path.endswith("/devicedatasources") and 'CS' in (params or {}).get("filter", ""):
            return iter([{"id": 300, "dataSourceName": "HP_Switch_Configs", "instanceNumber": 2}])
        raise AssertionError(path)

    def instances(self, dev_id, hds):
        if hds == 300:
            return [{"id": 1, "displayName": "startup-config"}, {"id": 2, "displayName": "running-config"}]
        return super().instances(dev_id, hds)

    def get(self, path, params=None):
        assert path.endswith("/instances/2/config"), path       # startup-config is never read
        FakeConfigLM.calls += 1
        item = {"id": 99, "version": self.version}
        if "config" in params["fields"].split(","):
            item["config"] = self.text
        return {"items": [item]}


def test_pull_configs_from_lm(tmp_path):
    text = (FIX / "edge-procurve.cfg").read_text().replace('"Desk 1"', '"Desk 1 LM"')
    s = Settings()
    s.config_dir, s.mapping_file, s.data_dir = str(FIX), "/nonexistent", str(tmp_path)
    s.lm_group_ids, s.config_source, s.fetch_status, s.fetch_alerts = [3], "both", False, False
    lm = FakeConfigLM(text)
    rep = build_report(s, lm)
    edge = [x for x in rep.switches if x["hostname"] == "EDGE-SW02"]
    assert len(edge) == 1 and edge[0]["source_file"].startswith("LM:St Agnes/")
    assert edge[0]["site"] == "St Agnes" and edge[0]["lm_device_id"] == 3
    assert any(r["description"] == "Desk 1 LM" for r in rep.rows if r["switch"] == "EDGE-SW02")
    assert rep.lm_config_stats == {"devices": 1, "downloaded": 1, "cached": 0, "in_scope": 1}
    assert list((tmp_path / "lm-configs").rglob("*.cfg"))
    # second refresh: same version -> served from cache with only the small version check
    FakeConfigLM.calls = 0
    rep2 = build_report(s, lm)
    assert rep2.lm_config_stats["cached"] == 1 and FakeConfigLM.calls == 1
    # LM only: file configs are ignored
    s.config_source = "lm"
    assert [x["hostname"] for x in build_report(s, lm).switches] == ["EDGE-SW02"]


# -- short-name links (site naming like 'TRUNK SW02/P47') ----------------------

def _procurve(name, ports):
    lines = [f'; J9773A Configuration Editor; Created on release #YA.16.10', f'hostname "{name}"']
    for p, desc in ports.items():
        lines += [f"interface {p}", f'   name "{desc}"', "   exit"]
    lines += ['vlan 1', '   name "DEFAULT_VLAN"', f'   untagged {",".join(ports)}', '   exit',
              'vlan 10', '   name "DATA"', f'   tagged {",".join(ports)}', '   exit']
    return "\n".join(lines) + "\n"


def test_short_name_links(tmp_path):
    site = tmp_path / "Turrella"
    site.mkdir()
    (site / "sw01.cfg").write_text(_procurve("SVG-TUR-SW01", {"47": "UPLINK TO FORTIGATE", "48": "TRUNK SW02/P47"}))
    (site / "sw02.cfg").write_text(_procurve("SVG-TUR-SW02", {"46": "TRUNK SW8/P23", "47": "TRUNK SW1/P48",
                                                              "8": "SVG-TUR-WAP01"}))
    (site / "sw08.cfg").write_text(_procurve("SVG-TUR-SW08", {"23": "TRUNK SW02/P46"}))
    (site / "utm01.conf").write_text("#config-version=FGT60F-7.2.8\nconfig system global\n    set hostname \"SVG-TUR-UTM01\"\nend\n"
                                     "config system interface\n    edit \"internal1\"\n        set type physical\n    next\nend\n"
                                     "config firewall policy\nend\n")
    # same short names at another site must not cross-link
    other = tmp_path / "Other"
    other.mkdir()
    (other / "sw02.cfg").write_text(_procurve("ABC-XYZ-SW02", {"1": "TRUNK SW01/P1"}))
    s = Settings()
    s.config_dir, s.mapping_file, s.data_dir = str(tmp_path), "/nonexistent", str(tmp_path / "d")
    rep = build_report(s, None)
    topo = rep.topology["sites"]["Turrella"]
    names = {d["id"]: d["hostname"] for d in topo["devices"]}
    links = {frozenset([(names[l["a"]], l["a_port"]), (names[l["b"]], l["b_port"])]): l for l in topo["links"]}
    assert frozenset([("SVG-TUR-SW01", "48"), ("SVG-TUR-SW02", "47")]) in links
    assert links[frozenset([("SVG-TUR-SW01", "48"), ("SVG-TUR-SW02", "47")])]["sources"] == ["description"]
    assert frozenset([("SVG-TUR-SW02", "46"), ("SVG-TUR-SW08", "23")]) in links
    assert frozenset([("SVG-TUR-SW01", "47"), ("SVG-TUR-UTM01", None)]) in links
    assert len(topo["links"]) == 3
    assert rep.topology["sites"]["Other"]["links"] == []


# -- collector SNMP: LLDP + MAC tables ------------------------------------------

from app import lm_snmp


def _walk(base, entries):
    return "\n".join(f"{base}.{k} => {v}" for k, v in entries.items())


def test_snmp_parsing_and_lldp():
    out = _walk(lm_snmp.OIDS["lldpRemSysName"], {"0.48.1": "SVG-TUR-SW02", "0.47.3": "SVG-TUR-UTM01"})
    rem = lm_snmp.parse_walk(out, lm_snmp.OIDS["lldpRemSysName"])
    assert rem == {"0.48.1": "SVG-TUR-SW02", "0.47.3": "SVG-TUR-UTM01"}
    walks = {"lldpRemSysName": rem,
             "lldpRemPortId": {"0.48.1": "47", "0.47.3": "aa:bb:cc:dd:ee:ff"},
             "lldpRemPortDesc": {"0.47.3": "internal1"},
             "lldpLocPortId": {"48": "48", "47": "47"},
             "ifName": {"47": "47", "48": "48"}}
    l2 = lm_snmp.build_l2("SW01", walks)
    assert ("48", "SVG-TUR-SW02", "47") in l2.lldp and ("47", "SVG-TUR-UTM01", "internal1") in l2.lldp
    assert lm_snmp.norm_mac("9cdc.7125.8a3c") == "9c:dc:71:25:8a:3c"
    assert lm_snmp.norm_mac("Hex-STRING: 9C DC 71 25 8A 3C".split(": ")[1]) == "9c:dc:71:25:8a:3c"


def _l2(sid, own, fdb):
    d = lm_snmp.DeviceL2(device_id=sid, own_macs=set(own))
    d.fdb = {p: set(m) for p, m in fdb.items()}
    return d


def test_mac_links_chain():
    # FW --(47) SW1 (48)--(47) SW2 (46)--(23) SW8 ; host H on SW8 port 5
    FW, S1, S2, S8, H = "02:00:00:00:00:fe", "02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:08", "aa:00:00:00:00:99"
    l2 = {
        "FW": _l2("FW", [FW], {}),
        "S1": _l2("S1", [S1], {"47": [FW], "48": [S2, S8, H]}),
        "S2": _l2("S2", [S2], {"47": [S1, FW], "46": [S8, H]}),
        "S8": _l2("S8", [S8], {"23": [S2, S1, FW], "5": [H]}),
    }
    links = {frozenset([(a, ap), (b, bp)]) for a, ap, b, bp in lm_snmp.mac_links(l2)}
    assert links == {frozenset([("S1", "47"), ("FW", None)]),
                     frozenset([("S1", "48"), ("S2", "47")]),
                     frozenset([("S2", "46"), ("S8", "23")])}


class FakeDebugLM(FakeLM):
    def __init__(self):
        self.cmds = []

    def collector_debug(self, collector, cmd):
        self.cmds.append(cmd)
        host, oid = cmd.split()[1:]
        if host == "10.0.99.2" and oid == lm_snmp.OIDS["lldpRemSysName"]:
            return _walk(oid, {"0.10148.1": "CX-SW03.corp.local"})
        if host == "10.0.99.2" and oid == lm_snmp.OIDS["lldpRemPortId"]:
            return _walk(oid, {"0.10148.1": "1/1/49"})
        if host == "10.0.99.2" and oid == lm_snmp.OIDS["ifName"]:
            return _walk(oid, {"10148": "Gi1/0/48", "10101": "Gi1/0/1"})
        if host == "10.0.99.2" and oid == lm_snmp.OIDS["qFdbPort"]:
            return _walk(oid, {"10.170.0.0.0.0.153": "1"})           # aa:00:00:00:00:99 on bridge port 1
        if host == "10.0.99.2" and oid == lm_snmp.OIDS["basePortIf"]:
            return _walk(oid, {"1": "10101"})
        return ""

    def devices(self, f=""):
        return [dict(d, currentCollectorId=7) for d in super().devices()]


def test_collector_snmp_end_to_end(tmp_path):
    s = Settings()
    s.config_dir, s.mapping_file, s.data_dir = str(FIX), "/nonexistent", str(tmp_path)
    s.collector_snmp, s.fetch_status = True, False
    lm = FakeDebugLM()
    rep = build_report(s, lm)
    assert all(c.startswith("!snmpwalk ") for c in lm.cmds) and lm.cmds
    row = next(r for r in rep.rows if r["switch"] == "CORE-SW01" and r["port"] == "GigabitEthernet1/0/1")
    assert row["mac_count"] == 1 and row["macs"] == ["aa:00:00:00:00:99"]
    link = next(l for l in rep.topology["sites"]["default"]["links"]
                if {l["a_port"], l["b_port"]} == {"GigabitEthernet1/0/48", "1/1/49"})
    assert "lldp" in link["sources"]
    assert rep.snmp_stats["lldp_neighbours"] == 1
    # cached: no new debug commands within the cache window
    n = len(lm.cmds)
    build_report(s, lm)
    assert len(lm.cmds) == n


def test_lm_config_diag_and_vdom(tmp_path):
    vdom_fgt = ('#config-version=FG100F-7.2.8:opmode=0:vdom=1\nconfig vdom\nedit root\nnext\nend\n'
                'config global\nconfig system global\n    set hostname "EM-BNE-UTM01"\nend\n'
                'config system interface\n    edit "port1"\n        set vdom "root"\n        set type physical\n    next\n'
                '    edit "vl10"\n        set vdom "root"\n        set interface "port1"\n        set vlanid 10\n    next\nend\nend\n'
                'config vdom\nedit root\nconfig firewall policy\nend\nnext\nend\n')

    class LM(FakeConfigLM):
        def devices(self, f=""):
            return [{"id": 3, "displayName": "EM-BNE-UTM01", "name": "10.9.9.1"},
                    {"id": 4, "displayName": "EM-BNE-SW01", "name": "10.9.9.2"}]

        def group_devices(self, gid, include_subgroups=True):
            return self.devices()

        def paged(self, path, params=None):
            if "/devices/4/" in path:
                return iter([])                       # no ConfigSources on the switch
            return super().paged(path, params)

    s = Settings()
    s.config_dir, s.mapping_file, s.data_dir = str(FIX), "/nonexistent", str(tmp_path)
    s.lm_group_ids, s.config_source, s.fetch_status, s.fetch_alerts = [1], "lm", False, False
    rep = build_report(s, LM(vdom_fgt))
    fw = next(x for x in rep.switches if x["hostname"] == "EM-BNE-UTM01")
    assert fw["port_count"] >= 2
    diag = {d["device"]: d for d in rep.lm_config_diag}
    assert diag["EM-BNE-UTM01"]["vendor"] == "fortios" and "parsed" in diag["EM-BNE-UTM01"]["outcome"]
    assert diag["EM-BNE-UTM01"]["configsources"][0]["instances"] == ["startup-config (excluded)", "running-config"]
    assert diag["EM-BNE-SW01"]["outcome"].startswith("no ConfigSources")
