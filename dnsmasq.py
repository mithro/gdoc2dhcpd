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

OUTPUT = 'dnsmasq.static.conf'
output = open(OUTPUT, 'w')
for (name, lineno), r in data:
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

    print(file=output)
    for k, v in sorted(r.items()):
        if not v.strip():
            continue
        print('# {}: {}'.format(k, v), file=output)

    dhcp_name = r['Machine'].lower().strip()
    if 'Interface' in r and r['Interface'].strip():
        dhcp_name = r['Interface'].lower().strip()+'.'+dhcp_name

    simple_dhcp_name = re.sub('[^a-z0-9.\-_]+','#',dhcp_name)
    assert dhcp_name == simple_dhcp_name, ('Invalid characters in machine name!', dhcp_name, simple_dhcp_name)
    r['DHCP Name'] = dhcp_name

    print("dhcp-host={MAC Address},{IP},{DHCP Name}".format(**r),file=output)

print('-'*75)

output.close()
with open(OUTPUT) as f:
    print(f.read())
