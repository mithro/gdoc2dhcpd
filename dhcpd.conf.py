#!/usr/bin/env python3

import csv
import pprint
import re
import urllib.request

GDOC="https://docs.google.com/spreadsheets/d/e/2PACX-1vR5j6yiZCEv5YNoeVNLM4MMsxzBVjG4OtViBz7tXXF1LydHd8bCOOVWt7MvfVEPZtK0TeWgyxF3i9Tj/pub?output=csv"
r = urllib.request.urlopen(GDOC)
d = r.read().decode('utf-8').splitlines()

OUTPUT = 'dhcpd.static.conf'
output = open(OUTPUT, 'w')
for i, r in enumerate(csv.DictReader(d)):
    d = {}
    for k, v in list(r.items()):
        if v.strip():
            d[k] = v

    if not d:
        continue

    del r['']

    skip = []
    if not r['MAC Address']:
        skip.append('No MAC address')

    if not r['Machine']:
        skip.append('No machine name')

    if not r['IP']:
        skip.append('No IP address')

    if skip:
        print('Skipping row', i+1, ':', ', '.join(skip))
        pprint.pprint(r)
        print()
        continue

    r['MAC Address'] = r['MAC Address'].lower()

    print(file=output)
    for k, v in sorted(r.items()):
        if not v.strip():
            continue
        print('# {}: {}'.format(k, v), file=output)

    dhcp_name = r['Machine'].lower().strip()
    if r['Interface'].strip():
        dhcp_name = r['Interface'].lower().strip()+'.'+dhcp_name

    simple_dhcp_name = re.sub('[^a-z0-9.\-_]+','#',dhcp_name)
    assert dhcp_name == simple_dhcp_name, ('Invalid characters in machine name!', dhcp_name, simple_dhcp_name)

    r['DHCP Name'] = dhcp_name

    

    print("""\
host {DHCP Name} {{
  hardware ethernet {MAC Address};
  fixed-address {IP};
}}""".format(**r), file=output)

print('-'*75)

output.close()
with open(OUTPUT) as f:
    print(f.read())
