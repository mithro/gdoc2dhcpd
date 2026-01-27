
all: fetch dnsmasq.static.conf
	true

fetch:
	uv run gdoc2netcfg fetch

dnsmasq.static.conf:
	uv run gdoc2netcfg generate dnsmasq
	dnsmasq --test

sshfp:
	uv run gdoc2netcfg sshfp --force
	uv run gdoc2netcfg generate dnsmasq
	dnsmasq --test

dnsmasq.reload:
	systemctl restart dnsmasq@internal dnsmasq@external
	systemctl status dnsmasq@internal dnsmasq@external

cisco_sg300:
	uv run gdoc2netcfg generate cisco_sg300

tc_mac_vlan:
	uv run gdoc2netcfg generate --stdout tc_mac_vlan

nagios:
	uv run gdoc2netcfg generate nagios

validate:
	uv run gdoc2netcfg validate

info:
	uv run gdoc2netcfg info

test:
	uv run pytest

.PHONY: all fetch dnsmasq.static.conf sshfp dnsmasq.reload cisco_sg300 tc_mac_vlan nagios validate info test
