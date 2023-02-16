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
