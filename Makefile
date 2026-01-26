
all: dnsmasq.static.conf dhcpd.static.conf
	true

dnsmasq.static.conf: dnsmasq.py
	./dnsmasq.py
	dnsmasq --test -C /etc/dnsmasq.d/dnsmasq.internal.conf
	dnsmasq --test -C /etc/dnsmasq.d/dnsmasq.external.conf

sshfp:
	./sshfp.py --force
	./dnsmasq.py
	dnsmasq --test -C /etc/dnsmasq.d/dnsmasq.internal.conf
	dnsmasq --test -C /etc/dnsmasq.d/dnsmasq.external.conf

dnsmasq.reload:
	systemctl restart dnsmasq@internal dnsmasq@external
	systemctl status dnsmasq@internal dnsmasq@external

dhcpd.static.conf: dhcpd.conf.py
	./dhcpd.conf.py

.PHONY: dnsmasq.static.conf dhcpd.static.conf sshfp

