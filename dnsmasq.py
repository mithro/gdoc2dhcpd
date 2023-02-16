#!/usr/bin/env python3

import csv
import json
import pprint
import re
import sys
import urllib.request

GDOC={
    'Network': "https://docs.google.com/spreadsheets/d/e/2PACX-1vR5j6yiZCEv5YNoeVNLM4MMsxzBVjG4OtViBz7tXXF1LydHd8bCOOVWt7MvfVEPZtK0TeWgyxF3i9Tj/pub?gid=1476589425&single=true&output=csv",
    'IoT':     "https://docs.google.com/spreadsheets/d/e/2PACX-1vR5j6yiZCEv5YNoeVNLM4MMsxzBVjG4OtViBz7tXXF1LydHd8bCOOVWt7MvfVEPZtK0TeWgyxF3i9Tj/pub?gid=1695016218&single=true&output=csv",
}
#    "https://docs.google.com/spreadsheets/d/e/2PACX-1vR5j6yiZCEv5YNoeVNLM4MMsxzBVjG4OtViBz7tXXF1LydHd8bCOOVWt7MvfVEPZtK0TeWgyxF3i9Tj/pub?output=csv",
# https://docs.google.com/spreadsheets/d/e/2PACX-1vR5j6yiZCEv5YNoeVNLM4MMsxzBVjG4OtViBz7tXXF1LydHd8bCOOVWt7MvfVEPZtK0TeWgyxF3i9Tj/pub?output=csv
# https://docs.google.com/spreadsheets/d/e/2PACX-1vR5j6yiZCEv5YNoeVNLM4MMsxzBVjG4OtViBz7tXXF1LydHd8bCOOVWt7MvfVEPZtK0TeWgyxF3i9Tj/pub?gid=1476589425&single=true&output=csv
# https://docs.google.com/spreadsheets/d/e/2PACX-1vR5j6yiZCEv5YNoeVNLM4MMsxzBVjG4OtViBz7tXXF1LydHd8bCOOVWt7MvfVEPZtK0TeWgyxF3i9Tj/pub?gid=1695016218&single=true&output=csv

data = []
for name, doc in GDOC.items():
    r = urllib.request.urlopen(doc)
    csv_data = r.read().decode('utf-8').splitlines()

    for i, r in enumerate(csv.DictReader(csv_data)):
        d = {}
        for k, v in list(r.items()):
            if v.strip():
                d[k] = v

        if '' in d:
            del d['']

        if not d:
            continue
        data.append(((name, i), d))


with open('info.json', 'w') as f:
    json.dump(data, f, indent="  ", sort_keys=True)


def is_iot(ip):
    return ip.startswith('10.1.20.')


def is_local(ip):
    """
+--------------------+-------------------------------+-------------+-----------------+-
| Address block      | Address range                 | Addresses   | Scope           | Description
+--------------------+-------------------------------+-------------+-----------------+-
| 0.0.0.0         /8  | 0.0.0.0      0  .255.255.255 |  16,777,216 | Software        | Current network.
| 10.0.0.0        /8  | 10.0.0.0     10 .255.255.255 |  16,777,216 | Private network | Used for local communications within a private network.
| 100.64.0.0      /10 | 100.64.0.0   100.127.255.255 |   4,194,304 | Private network | Shared address space[9] for communications between a service provider and its subscribers when using a carrier-grade NAT.
| 127.0.0.0       /8  | 127.0.0.0    127.255.255.255 |  16,777,216 | Host            | Used for loopback addresses to the local host.
| 169.254.0.0     /16 | 169.254.0.0  169.254.255.255 |      65,536 | Subnet          | Used for link-local addresses between two hosts on a single link when no IP address is otherwise specified, such as would have normally been retrieved from a DHCP server.
| 172.16.0.0      /12 | 172.16.0.0   172.31 .255.255 |   1,048,576 | Private network | Used for local communications within a private network.
| 192.0.0.0       /24 | 192.0.0.0    192.0  .0  .255 |         256 | Private network | IETF Protocol Assignments.
| 192.0.2.0       /24 | 192.0.2.0    192.0  .2  .255 |         256 | Documentation   | Assigned as TEST-NET-1, documentation and examples.
| 192.88.99.0     /24 | 192.88.99.0  192.88 .99 .255 |         256 | Internet        | Reserved. (Formerly used for IPv6 to IPv4 relay, included IPv6 address block 2002::/16.)
| 192.168.0.0     /16 | 192.168.0.0  192.168.255.255 |      65,536 | Private network | Used for local communications within a private network.
| 198.18.0.0      /15 | 198.18.0.0   198.19 .255.255 |     131,072 | Private network | Used for benchmark testing of inter-network communications between two separate subnets.
| 198.51.100.0    /24 | 198.51.100.0 198.51 .100.255 |         256 | Documentation   | Assigned as TEST-NET-2, documentation and examples.
| 203.0.113.0     /24 | 203.0.113.0  203.0  .113.255 |         256 | Documentation   | Assigned as TEST-NET-3, documentation and examples.
| 224.0.0.0       /4  | 224.0.0.0    239.255.255.255 | 268,435,456 | Internet        | In use for IP multicast. (Former Class D network.)
| 233.252.0.0     /24 | 233.252.0.0  233.252.0  .255 |         256 | Documentation   | Assigned as MCAST-TEST-NET, documentation and examples.
| 240.0.0.0       /4  | 240.0.0.0    255.255.255.254 | 268,435,455 | Internet        | Reserved for future use. (Former Class E network.)
| 255.255.255.255 /32 |              255.255.255.255 |           1 | Subnet          | Reserved for the "limited broadcast" destination address.
+--------------------+-------------------------------+-------------+-----------------+-
    """
    # https://en.wikipedia.org/wiki/Reserved_IP_addresses
    # 10.0.0.0 to 10.255.255.255, a range that provides up to 16 million unique IP addresses.
    # 172.16.0.0 to 172.31.255.255, providing about 1 million unique IP addresses.
    # 192.168.0.0 to 192.168.255.255, which offers about 65,000 unique IP addresses.
    if ip.startswith('10.'):
        return True
    elif ip.startswith('172.'): # Eh, close enough....
        return True
    elif ip.startswith('192.168.'):
        return True
    # Private...
    elif ip.startswith('192.0.'):
        return True
    # Test NETs
    elif ip.startswith('198.0.'):
        return True
    # Link-local IP address ranges
    elif ip.startswith('169.254.'):
        return True
    #  Carrier-grade NAT - 100.64.0.0/10 (100.64.0.0 to 100.127.255.255, netmask 255.192.0.0)
    return False


good_data = []
for i, ((name, lineno), r) in enumerate(data):
    skip = []
    if not r.get('MAC Address', None):
        skip.append('No MAC address')

    if not r.get('Machine', None):
        skip.append('No machine name')

    if not r.get('IP', None):
        skip.append('No IP address')

    if skip:
        print('Skipping row', name, lineno+1, ':', ', '.join(skip))
        pprint.pprint(r)
        print()
        continue

    r['MAC Address'] = r['MAC Address'].lower()

    host_name = r['Machine'].lower().strip()
    if 'Interface' in r and r['Interface'].strip():
        host_name = r['Interface'].lower().strip()+'.'+host_name
    #if name == 'IoT':
    #    host_name += '.iot'
    r['Host Name'] = host_name

    dhcp_name = r['Machine'].lower().strip()
    if 'Interface' in r and r['Interface'].strip():
        dhcp_name = r['Interface'].lower().strip()+'-'+dhcp_name
    simple_dhcp_name = re.sub('[^a-z0-9.\-_]+','#',dhcp_name)
    assert dhcp_name == simple_dhcp_name, ('Invalid characters in machine name!', dhcp_name, simple_dhcp_name)
    r['DHCP Name'] = dhcp_name

    good_data.append(r)


hostname2ip = {}
ip2hostname = {}
for r in good_data:
    hostname = r['Machine']
    ip = r['IP']

    if ip not in ip2hostname:
        ip2hostname[ip] = []
    ip2hostname[ip].append(hostname)

    hostname.split('.')

    if hostname not in hostname2ip:
        hostname2ip[hostname] = []

    hostname2ip[hostname].append(ip)

pprint.pprint(hostname2ip)
pprint.pprint(ip2hostname)

sys.exit(1)

OUTPUT = 'dnsmasq.static.conf'
output = open(OUTPUT, 'w')
for r in good_data:
    print(file=output)
    for k, v in sorted(r.items()):
        if not v.strip():
            continue
        print('# {}: {}'.format(k, v), file=output)

    print("dhcp-host={MAC Address},{IP},{DHCP Name}".format(**r),file=output)
    # `host-record` should add both address and ptr-record
    print("host-record={Host Name}.k207.mithis.com,{IP}".format(**r),file=output)
    print("address=/{Host Name}/{IP}".format(**r),file=output)
    #print("address=/{DHCP Name}.k207.mithis.com/{IP}".format(**r),file=output)
    print("address=/{DHCP Name}/{IP}".format(**r),file=output)
    #print("ptr-record=/{DHCP Name}.k207.mithis.com/{IP}".format(**r),file=output)

print('-'*75)

output.close()
with open(OUTPUT) as f:
    print(f.read())
