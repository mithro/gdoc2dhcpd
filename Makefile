
OUTPUT_DIR ?=

ifdef OUTPUT_DIR
  OUTPUT_DIR_FLAG = --output-dir $(OUTPUT_DIR)
else
  OUTPUT_DIR_FLAG =
endif

all: fetch dnsmasq
	true

fetch:
	uv run gdoc2netcfg fetch

dnsmasq: dnsmasq_internal dnsmasq_external
	true

dnsmasq_internal:
	uv run gdoc2netcfg generate $(OUTPUT_DIR_FLAG) dnsmasq_internal

dnsmasq_external:
	uv run gdoc2netcfg generate $(OUTPUT_DIR_FLAG) dnsmasq_external

sshfp:
	uv run gdoc2netcfg sshfp --force
	uv run gdoc2netcfg generate $(OUTPUT_DIR_FLAG) dnsmasq_internal

dnsmasq.test:
	dnsmasq --test -C /etc/dnsmasq.d/dnsmasq.internal.conf
	dnsmasq --test -C /etc/dnsmasq.d/dnsmasq.external.conf

dnsmasq.reload:
	systemctl restart dnsmasq@internal dnsmasq@external
	systemctl status dnsmasq@internal dnsmasq@external

nginx:
	uv run gdoc2netcfg generate $(OUTPUT_DIR_FLAG) nginx

nagios:
	uv run gdoc2netcfg generate nagios

validate:
	uv run gdoc2netcfg validate

info:
	uv run gdoc2netcfg info

test:
	uv run pytest

.PHONY: all fetch dnsmasq dnsmasq_internal dnsmasq_external sshfp dnsmasq.test dnsmasq.reload nginx nagios validate info test
