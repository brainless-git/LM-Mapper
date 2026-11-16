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
