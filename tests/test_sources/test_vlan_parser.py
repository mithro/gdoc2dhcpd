"""Tests for the VLAN Allocations CSV parser."""

from gdoc2netcfg.sources.vlan_parser import VLANDefinition, parse_vlan_allocations

# Sample CSV matching the Welland "VLAN Allocations" sheet format
SAMPLE_CSV = """\
VLAN,Name,IP Range,Netmask,CIDR,,Color,For
1,tmp,10.1.1.X,255.255.255.0,/24,,,Untagged / Unknown traffic quarantine
5,net,10.1.5.X,255.255.255.0,/24,,Red,Network infrastructure
6,pwr,10.1.6.X,255.255.255.0,/24,,Orange,Power infrastructure
7,store,10.1.7.X,255.255.255.0,/24,,Yellow,Storage infrastructure
10,int,10.1.10.X,255.255.248.0,/21,10.1.8.1 - 10.1.15.254,Blue,Internal wired hosts
20,roam,10.1.20.X,255.255.255.0,/24,,Purple,WiFi and wired hosts
31,fpgas,10.31.X.X,255.255.0.0,/16,,,fpgas.online
41,sm,10.41.X.X,255.255.0.0,/16,,,supermicro test infrastructure
90,iot,10.1.90.X,255.255.255.0,/24,,Green,
99,guest,10.1.99.X,255.255.255.0,/24,,,guest network
"""


class TestParseVlanAllocations:
    def test_parses_all_vlans(self):
        defs = parse_vlan_allocations(SAMPLE_CSV)
        assert len(defs) == 10

    def test_vlan_ids(self):
        defs = parse_vlan_allocations(SAMPLE_CSV)
        ids = [d.id for d in defs]
        assert ids == [1, 5, 6, 7, 10, 20, 31, 41, 90, 99]

    def test_vlan_names(self):
        defs = parse_vlan_allocations(SAMPLE_CSV)
        names = [d.name for d in defs]
        assert names == ["tmp", "net", "pwr", "store", "int", "roam", "fpgas", "sm", "iot", "guest"]

    def test_ip_range(self):
        defs = parse_vlan_allocations(SAMPLE_CSV)
        by_name = {d.name: d for d in defs}
        assert by_name["net"].ip_range == "10.1.5.X"
        assert by_name["int"].ip_range == "10.1.10.X"
        assert by_name["fpgas"].ip_range == "10.31.X.X"

    def test_netmask(self):
        defs = parse_vlan_allocations(SAMPLE_CSV)
        by_name = {d.name: d for d in defs}
        assert by_name["net"].netmask == "255.255.255.0"
        assert by_name["int"].netmask == "255.255.248.0"
        assert by_name["fpgas"].netmask == "255.255.0.0"

    def test_cidr(self):
        defs = parse_vlan_allocations(SAMPLE_CSV)
        by_name = {d.name: d for d in defs}
        assert by_name["net"].cidr == "/24"
        assert by_name["int"].cidr == "/21"
        assert by_name["fpgas"].cidr == "/16"

    def test_color(self):
        defs = parse_vlan_allocations(SAMPLE_CSV)
        by_name = {d.name: d for d in defs}
        assert by_name["net"].color == "Red"
        assert by_name["int"].color == "Blue"
        assert by_name["fpgas"].color == ""

    def test_description(self):
        defs = parse_vlan_allocations(SAMPLE_CSV)
        by_name = {d.name: d for d in defs}
        assert by_name["net"].description == "Network infrastructure"
        assert by_name["int"].description == "Internal wired hosts"
        assert by_name["fpgas"].description == "fpgas.online"

    def test_empty_csv(self):
        assert parse_vlan_allocations("") == []

    def test_header_only(self):
        csv = "VLAN,Name,IP Range,Netmask,CIDR,,Color,For\n"
        assert parse_vlan_allocations(csv) == []

    def test_skips_rows_without_vlan_id(self):
        csv = "VLAN,Name,IP Range,Netmask,CIDR,,Color,For\n,net,10.1.5.X,,,,,\n"
        assert parse_vlan_allocations(csv) == []

    def test_skips_rows_without_name(self):
        csv = "VLAN,Name,IP Range,Netmask,CIDR,,Color,For\n5,,10.1.5.X,,,,,\n"
        assert parse_vlan_allocations(csv) == []

    def test_skips_non_numeric_vlan_id(self):
        csv = "VLAN,Name,IP Range,Netmask,CIDR,,Color,For\nabc,net,10.1.5.X,,,,,\n"
        assert parse_vlan_allocations(csv) == []

    def test_missing_header_returns_empty(self):
        csv = "Foo,Bar,Baz\n1,net,10.1.5.X\n"
        assert parse_vlan_allocations(csv) == []

    def test_vlan_definition_fields(self):
        defs = parse_vlan_allocations(SAMPLE_CSV)
        v = defs[0]
        assert isinstance(v, VLANDefinition)
        assert v.id == 1
        assert v.name == "tmp"
        assert v.ip_range == "10.1.1.X"
        assert v.netmask == "255.255.255.0"
        assert v.cidr == "/24"
