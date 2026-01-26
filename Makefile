
all: dnsmasq.static.conf dhcpd.static.conf
	true

dnsmasq.static.conf: dnsmasq.py
	./dnsmasq.py
	dnsmasq --test

sshfp:
	./sshfp.py --force
	./dnsmasq.py
	dnsmasq --test

dnsmasq.reload:
	systemctl restart dnsmasq
	systemctl status dnsmasq

dhcpd.static.conf: dhcpd.conf.py
	./dhcpd.conf.py

.PHONY: dnsmasq.static.conf dhcpd.static.conf sshfp

