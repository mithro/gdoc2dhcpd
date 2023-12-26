#!/usr/bin/env python3


import json
import pprint
import sys

import jinja2


SWITCH_TEMPLATE = jinja2.Template("""\
define host {
    host_name   {{row['Host Name']}}
    address     {{row['IP']}}
{% if row['Parent'] %}
    parents     {{row['Parent']}}
{% endif %}
    hostgroups  allhosts,switches
}
""")


def main(args):
    with open('good.json', 'r') as f:
        data = json.load(f)

    output = []
    for row in data:
        rtype = row.get('Type', None)
        if rtype == 'IoT':
            hardware = row.get('Hardware', None)
            if not hardware:
                continue
            continue
        else:
            hardware = row.get('Driver', None)
            if not hardware:
                continue
            hardware = hardware.split(', ')[0].split(' ')[0]

        if hardware == 'switch':
            print()
            pprint.pprint(row)
            output.append(SWITCH_TEMPLATE.render(row=row))

    print('-'*75)
    print('\n'.join(output))
    print('-'*75)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
