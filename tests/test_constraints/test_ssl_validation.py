"""Tests for SSL certificate validation constraints."""

from datetime import datetime, timedelta, timezone

from gdoc2netcfg.constraints.errors import Severity
from gdoc2netcfg.constraints.ssl_validation import (
    format_ssl_validation_report,
    validate_ssl_certificates,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import DNSName, Host, NetworkInterface, SSLCertInfo


def _make_host(
    hostname: str,
    fqdns: list[str],
    ssl_cert: SSLCertInfo | None = None,
) -> Host:
    """Create a test host with DNS names and optional SSL cert."""
    host = Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                ipv4=IPv4Address("10.1.10.100"),
                ipv6_addresses=[],
                dhcp_name=hostname,
            ),
        ],
        default_ipv4=IPv4Address("10.1.10.100"),
        ssl_cert_info=ssl_cert,
    )
    # Add DNS names
    for fqdn in fqdns:
        host.dns_names.append(DNSName(name=fqdn, is_fqdn=True))
    return host


def _future_date(days: int) -> str:
    """Return ISO date string for N days from now."""
    dt = datetime.now(timezone.utc) + timedelta(days=days)
    return dt.strftime("%Y-%m-%d")


def _past_date(days: int) -> str:
    """Return ISO date string for N days ago."""
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    return dt.strftime("%Y-%m-%d")


class TestSelfSignedValidation:
    def test_self_signed_cert_warning(self):
        host = _make_host(
            "printer",
            ["printer.example.com"],
            SSLCertInfo(
                issuer="printer.local",
                self_signed=True,
                valid=False,
                expiry=_future_date(365),
                sans=("printer.example.com",),  # Matching SAN to focus on self-signed
            ),
        )
        result = validate_ssl_certificates([host])

        self_signed = [v for v in result.warnings if v.code == "ssl_self_signed"]
        assert len(self_signed) == 1
        assert "printer.local" in self_signed[0].message

    def test_lets_encrypt_no_self_signed_warning(self):
        host = _make_host(
            "server",
            ["server.example.com"],
            SSLCertInfo(
                issuer="Let's Encrypt",
                self_signed=False,
                valid=True,
                expiry=_future_date(60),
                sans=("server.example.com",),
            ),
        )
        result = validate_ssl_certificates([host])

        self_signed = [v for v in result.violations if v.code == "ssl_self_signed"]
        assert len(self_signed) == 0


class TestExpiryValidation:
    def test_expired_cert_error(self):
        host = _make_host(
            "server",
            ["server.example.com"],
            SSLCertInfo(
                issuer="Let's Encrypt",
                self_signed=False,
                valid=False,
                expiry=_past_date(10),  # Expired ~10 days ago
                sans=("server.example.com",),
            ),
        )
        result = validate_ssl_certificates([host])

        expired = [v for v in result.errors if v.code == "ssl_expired"]
        assert len(expired) == 1
        assert "days ago" in expired[0].message
        assert "Let's Encrypt" in expired[0].message

    def test_expiring_soon_warning(self):
        host = _make_host(
            "server",
            ["server.example.com"],
            SSLCertInfo(
                issuer="Let's Encrypt",
                self_signed=False,
                valid=True,
                expiry=_future_date(15),  # Expires in ~15 days
                sans=("server.example.com",),
            ),
        )
        result = validate_ssl_certificates([host])

        expiring = [v for v in result.warnings if v.code == "ssl_expiring_soon"]
        assert len(expiring) == 1
        assert "days" in expiring[0].message
        assert "Let's Encrypt" in expiring[0].message

    def test_valid_expiry_no_warning(self):
        host = _make_host(
            "server",
            ["server.example.com"],
            SSLCertInfo(
                issuer="Let's Encrypt",
                self_signed=False,
                valid=True,
                expiry=_future_date(60),  # Expires in 60 days - OK
                sans=("server.example.com",),
            ),
        )
        result = validate_ssl_certificates([host])

        expiry_issues = [v for v in result.violations
                        if v.code in ("ssl_expired", "ssl_expiring_soon")]
        assert len(expiry_issues) == 0

    def test_custom_expiry_warning_days(self):
        host = _make_host(
            "server",
            ["server.example.com"],
            SSLCertInfo(
                issuer="Let's Encrypt",
                self_signed=False,
                valid=True,
                expiry=_future_date(45),  # Expires in 45 days
                sans=("server.example.com",),
            ),
        )
        # With default 30 days, no warning
        result = validate_ssl_certificates([host], expiry_warning_days=30)
        expiring = [v for v in result.warnings if v.code == "ssl_expiring_soon"]
        assert len(expiring) == 0

        # With 60 days threshold, should warn
        result = validate_ssl_certificates([host], expiry_warning_days=60)
        expiring = [v for v in result.warnings if v.code == "ssl_expiring_soon"]
        assert len(expiring) == 1


class TestSANValidation:
    def test_missing_primary_san(self):
        host = _make_host(
            "server",
            ["server.example.com", "www.example.com"],
            SSLCertInfo(
                issuer="Let's Encrypt",
                self_signed=False,
                valid=True,
                expiry=_future_date(60),
                sans=("www.example.com",),  # Missing primary
            ),
        )
        result = validate_ssl_certificates([host])

        missing = [v for v in result.warnings if v.code == "ssl_missing_primary_san"]
        assert len(missing) == 1
        assert "server.example.com" in missing[0].message

    def test_missing_expected_sans(self):
        host = _make_host(
            "server",
            ["server.example.com", "api.server.example.com", "www.server.example.com"],
            SSLCertInfo(
                issuer="Let's Encrypt",
                self_signed=False,
                valid=True,
                expiry=_future_date(60),
                sans=("server.example.com",),  # Missing api and www
            ),
        )
        result = validate_ssl_certificates([host])

        missing = [v for v in result.warnings if v.code == "ssl_missing_sans"]
        assert len(missing) == 1
        assert "api.server.example.com" in missing[0].message or "www.server.example.com" in missing[0].message

    def test_extra_sans(self):
        host = _make_host(
            "server",
            ["server.example.com"],
            SSLCertInfo(
                issuer="Let's Encrypt",
                self_signed=False,
                valid=True,
                expiry=_future_date(60),
                sans=("server.example.com", "other.domain.com"),  # Extra SAN
            ),
        )
        result = validate_ssl_certificates([host])

        extra = [v for v in result.warnings if v.code == "ssl_extra_sans"]
        assert len(extra) == 1
        assert "other.domain.com" in extra[0].message

    def test_local_sans_ignored(self):
        """SANs ending in .local should not trigger extra SAN warning."""
        host = _make_host(
            "printer",
            ["printer.example.com"],
            SSLCertInfo(
                issuer="printer.local",
                self_signed=True,
                valid=False,
                expiry=_future_date(365),
                sans=("printer.local", "printer.example.com"),  # .local ignored
            ),
        )
        result = validate_ssl_certificates([host])

        extra = [v for v in result.warnings if v.code == "ssl_extra_sans"]
        assert len(extra) == 0

    def test_all_sans_match(self):
        host = _make_host(
            "server",
            ["server.example.com", "www.server.example.com"],
            SSLCertInfo(
                issuer="Let's Encrypt",
                self_signed=False,
                valid=True,
                expiry=_future_date(60),
                sans=("server.example.com", "www.server.example.com"),
            ),
        )
        result = validate_ssl_certificates([host])

        san_issues = [v for v in result.violations if "san" in v.code]
        assert len(san_issues) == 0


class TestNoSSLCert:
    def test_host_without_cert_skipped(self):
        host = _make_host("server", ["server.example.com"], ssl_cert=None)
        result = validate_ssl_certificates([host])

        assert len(result.violations) == 0


class TestRealWorldCertificates:
    """Tests using actual certificate data found on the network."""

    def test_bmc_big_storage_letsencrypt(self):
        """bmc.big-storage: Let's Encrypt cert with proper SANs."""
        host = _make_host(
            "bmc.big-storage",
            [
                "bmc.big-storage.welland.mithis.com",
                "ipv4.bmc.big-storage.welland.mithis.com",
                "ipv6.bmc.big-storage.welland.mithis.com",
            ],
            SSLCertInfo(
                issuer="Let's Encrypt",
                self_signed=False,
                valid=False,  # Chain valid but not verified in test
                expiry="2026-04-20",
                sans=(
                    "bmc.big-storage.welland.mithis.com",
                    "ipv4.bmc.big-storage.welland.mithis.com",
                    "ipv6.bmc.big-storage.welland.mithis.com",
                ),
            ),
        )
        result = validate_ssl_certificates([host])

        # Should have no violations - cert matches expected
        san_issues = [v for v in result.violations if "san" in v.code]
        assert len(san_issues) == 0

    def test_bmc_supermicro_self_signed(self):
        """bmc.sm-pcie-1: Supermicro BMC with self-signed cert."""
        host = _make_host(
            "bmc.sm-pcie-1",
            [
                "bmc.sm-pcie-1.welland.mithis.com",
                "ipv4.bmc.sm-pcie-1.welland.mithis.com",
            ],
            SSLCertInfo(
                issuer="Super Micro Computer",
                self_signed=True,
                valid=False,
                expiry="2025-10-27",
                sans=("IPMI",),  # Doesn't match expected FQDNs
            ),
        )
        result = validate_ssl_certificates([host])

        # Should flag self-signed
        self_signed = [v for v in result.violations if v.code == "ssl_self_signed"]
        assert len(self_signed) == 1
        assert "Super Micro Computer" in self_signed[0].message

        # Should flag missing primary SAN
        missing = [v for v in result.violations if v.code == "ssl_missing_primary_san"]
        assert len(missing) == 1

    def test_fritz_box_self_signed_many_sans(self):
        """fritz-box-7390-1: Self-signed with many local SANs."""
        host = _make_host(
            "fritz-box-7390-1",
            [
                "fritz-box-7390-1.welland.mithis.com",
                "fritz-box-7390-1.roam.welland.mithis.com",
            ],
            SSLCertInfo(
                issuer="vosowxk194qpctju.myfritz.net",
                self_signed=True,
                valid=False,
                expiry="2038-01-15",
                sans=(
                    "vosowxk194qpctju.myfritz.net",
                    "fritz.box",
                    "www.fritz.box",
                    "myfritz.box",
                    "www.myfritz.box",
                    "fritz-box-7390-1",
                    "fritz.nas",
                    "www.fritz.nas",
                ),
            ),
        )
        result = validate_ssl_certificates([host])

        # Should flag self-signed
        self_signed = [v for v in result.violations if v.code == "ssl_self_signed"]
        assert len(self_signed) == 1

        # Should flag missing expected FQDNs
        missing = [v for v in result.violations if v.code == "ssl_missing_primary_san"]
        assert len(missing) == 1

        # Extra SANs should flag myfritz.net but not .box/.nas (no dot or .local-like)
        extra = [v for v in result.violations if v.code == "ssl_extra_sans"]
        assert len(extra) == 1
        assert "myfritz.net" in extra[0].message

    def test_tweed_letsencrypt_wrong_san(self):
        """tweed: Let's Encrypt cert but for wrong domain."""
        host = _make_host(
            "tweed",
            [
                "tweed.welland.mithis.com",
                "ipv4.tweed.welland.mithis.com",
            ],
            SSLCertInfo(
                issuer="Let's Encrypt",
                self_signed=False,
                valid=False,
                expiry="2025-09-27",
                sans=("fpgas.online",),  # Wrong domain entirely
            ),
        )
        result = validate_ssl_certificates([host])

        # Should flag missing primary SAN
        missing = [v for v in result.violations if v.code == "ssl_missing_primary_san"]
        assert len(missing) == 1
        assert "tweed.welland.mithis.com" in missing[0].message

        # Should flag extra SAN
        extra = [v for v in result.violations if v.code == "ssl_extra_sans"]
        assert len(extra) == 1
        assert "fpgas.online" in extra[0].message

    def test_38printer_self_signed_embedded(self):
        """38printer: Embedded device with self-signed cert."""
        host = _make_host(
            "38printer",
            [
                "38printer.welland.mithis.com",
                "wireless.38printer.welland.mithis.com",
            ],
            SSLCertInfo(
                issuer="wireless-38printer.local",
                self_signed=True,
                valid=False,
                expiry="2110-12-31",  # Far future
                sans=("wireless-38printer.local",),
            ),
        )
        result = validate_ssl_certificates([host])

        # Should flag self-signed
        self_signed = [v for v in result.violations if v.code == "ssl_self_signed"]
        assert len(self_signed) == 1

        # Should flag missing expected FQDNs
        missing = [v for v in result.violations if v.code == "ssl_missing_primary_san"]
        assert len(missing) == 1


class TestValidationReport:
    def test_empty_report(self):
        result = validate_ssl_certificates([])
        report = format_ssl_validation_report(result)
        assert "All certificates OK" in report

    def test_self_signed_section(self):
        host = _make_host(
            "printer",
            ["printer.example.com"],
            SSLCertInfo(
                issuer="printer.local",
                self_signed=True,
                valid=False,
                expiry=_future_date(365),
                sans=("printer.example.com",),
            ),
        )
        result = validate_ssl_certificates([host])
        report = format_ssl_validation_report(result)

        assert "Self-signed certificates" in report
        assert "printer" in report

    def test_expired_section(self):
        host = _make_host(
            "server",
            ["server.example.com"],
            SSLCertInfo(
                issuer="Let's Encrypt",
                self_signed=False,
                valid=False,
                expiry=_past_date(5),
                sans=("server.example.com",),
            ),
        )
        result = validate_ssl_certificates([host])
        report = format_ssl_validation_report(result)

        assert "EXPIRED" in report
        assert "server" in report

    def test_combined_report(self):
        hosts = [
            _make_host(
                "printer",
                ["printer.example.com"],
                SSLCertInfo(
                    issuer="printer.local",
                    self_signed=True,
                    valid=False,
                    expiry=_future_date(365),
                    sans=("printer.example.com",),
                ),
            ),
            _make_host(
                "server",
                ["server.example.com"],
                SSLCertInfo(
                    issuer="Let's Encrypt",
                    self_signed=False,
                    valid=True,
                    expiry=_future_date(10),  # Expiring soon
                    sans=("server.example.com",),
                ),
            ),
        ]
        result = validate_ssl_certificates(hosts)
        report = format_ssl_validation_report(result)

        assert "Self-signed" in report
        assert "expiring soon" in report
