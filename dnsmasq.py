#!/usr/bin/env python3


import csv
import json
import pprint
import re
import subprocess
import sys
import urllib.request


DOMAIN='k207.mithis.com'


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


GDOC={
    'Network': "https://docs.google.com/spreadsheets/d/e/2PACX-1vR5j6yiZCEv5YNoeVNLM4MMsxzBVjG4OtViBz7tXXF1LydHd8bCOOVWt7MvfVEPZtK0TeWgyxF3i9Tj/pub?gid=1476589425&single=true&output=csv",
    'IoT':     "https://docs.google.com/spreadsheets/d/e/2PACX-1vR5j6yiZCEv5YNoeVNLM4MMsxzBVjG4OtViBz7tXXF1LydHd8bCOOVWt7MvfVEPZtK0TeWgyxF3i9Tj/pub?gid=1695016218&single=true&output=csv",
}
#    "https://docs.google.com/spreadsheets/d/e/2PACX-1vR5j6yiZCEv5YNoeVNLM4MMsxzBVjG4OtViBz7tXXF1LydHd8bCOOVWt7MvfVEPZtK0TeWgyxF3i9Tj/pub?output=csv",
# https://docs.google.com/spreadsheets/d/e/2PACX-1vR5j6yiZCEv5YNoeVNLM4MMsxzBVjG4OtViBz7tXXF1LydHd8bCOOVWt7MvfVEPZtK0TeWgyxF3i9Tj/pub?output=csv
# https://docs.google.com/spreadsheets/d/e/2PACX-1vR5j6yiZCEv5YNoeVNLM4MMsxzBVjG4OtViBz7tXXF1LydHd8bCOOVWt7MvfVEPZtK0TeWgyxF3i9Tj/pub?gid=1476589425&single=true&output=csv
# https://docs.google.com/spreadsheets/d/e/2PACX-1vR5j6yiZCEv5YNoeVNLM4MMsxzBVjG4OtViBz7tXXF1LydHd8bCOOVWt7MvfVEPZtK0TeWgyxF3i9Tj/pub?gid=1695016218&single=true&output=csv

def get_data():
    """ Download the data from the Google documents. """
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
        if name != 'Network':
            r['Type'] = name

        if not r.get('MAC Address', None):
            skip.append('No MAC address')

        if not r.get('Machine', None):
            skip.append('No machine name')
        else:
            r['Machine'] = r['Machine'].lower()

        if not r.get('IP', None):
            skip.append('No IP address')

        if skip:
            print('Skipping row', name, lineno+1, ':', ', '.join(skip))
            pprint.pprint(r)
            print()
            continue

        r['MAC Address'] = r['MAC Address'].lower()

        host_name = r['Machine'].lower().strip()
        if name == 'IoT':
            host_name += '.iot'
        elif name == 'Test':
            host_name += '.test'
        r['Host Name'] = host_name.lower()

        dhcp_name = r['Machine'].lower().strip()
        if 'Interface' in r and r['Interface'].strip():
            dhcp_name = r['Interface'].lower().strip()+'-'+dhcp_name
        simple_dhcp_name = re.sub('[^a-z0-9.\-_]+','#',dhcp_name)
        assert dhcp_name == simple_dhcp_name, ('Invalid characters in machine name!', dhcp_name, simple_dhcp_name)
        if name == 'IoT':
            dhcp_name += '.iot'
        #elif name == 'Test':
        #    dhcp_name += '-test'
        r['DHCP Name'] = dhcp_name.lower()

        good_data.append(r)

    with open('good.json', 'w') as f:
        json.dump(good_data, f, indent="  ", sort_keys=True)

    return good_data


def common_suffix(a, *others):
    """
    >>> common_suffix('a', 'a')
    'a'
    >>> common_suffix('a', 'a', 'a')
    'a'
    >>> common_suffix('a', 'a', 'b')
    ''
    >>> common_suffix('aa', 'a')
    'a'
    >>> common_suffix('ab', 'a')
    ''
    >>> common_suffix('aba', 'aa')
    'a'
    >>> common_suffix('abca', 'aca')
    'ca'
    >>> common_suffix('abca', 'aca')
    'ca'
    >>> common_suffix('abca')
    'abca'

    """
    if not others:
        return a

    l = [len(b) for b in others]
    l.append(len(a))
    l = min(*l)

    i = 1
    while i < (l+1):
        if not all(a[-i:] == b[-i:] for b in others):
            break
        i += 1
    i -= 1
    if i == 0:
        return ''
    return a[-i:]



def get_ip_info(data):
    """ Process the raw data into a useful form. """

    hostname2ip = {}
    ip2hostname = {}
    for r in data:
        hostname = r['Host Name']
        ip = r['IP']
        inf = r.get('Interface', None)

        if ip not in ip2hostname:
            ip2hostname[ip] = []
        name = hostname
        if inf:
            name = inf+'.'+hostname
        ip2hostname[ip].append(name)

        if hostname not in hostname2ip:
            hostname2ip[hostname] = {}

        assert inf not in hostname2ip[hostname], (inf, hostname2ip[hostname], r)
        hostname2ip[hostname][inf] = ip

    #for r in data:
    #    name = r['DHCP Name']
    #    if name in hostname2ip:
    #        continue
    #    hostname2ip[name] = {None: r['IP']}

    for ip, hosts in ip2hostname.items():
        assert hosts, (ip, hosts)
        hn = common_suffix(*hosts)
        hn = hn.strip('.')
        ip2hostname[ip] = hn
    return hostname2ip, ip2hostname


def get_mac_info(data):
    ip2mac = {}
    for r in data:
        mac = r['MAC Address']
        ip = r['IP']

        if ip not in ip2mac:
            ip2mac[ip] = []

        ip2mac[ip].append((mac, r['DHCP Name']))
    return ip2mac


def printd(title, *data, ip2mac=None):
    data = list(data)
    print()
    print("="*75)
    print(title)
    print("-"*75)
    if ip2mac:
        assert len(data) == 0, (data, ip2mac)
        for ip, macs in sorted(ip2mac.items(), key=lambda x: ip_sort(x[0])):
            print("%-17s %s   %s" % (
                    ip,
                    " ".join(m[0] for m in macs),
                    " ".join(m[1] for m in macs),
                ))
    else:
        last = data.pop(-1)
        for i in data:
            pprint.pprint(data)
            print("-"*75)
        pprint.pprint(last)
    print("="*75, flush=True)


def ip_sort(x):
    """
    >>> a = ['10.1.10.104', '10.1.2.2']
    >>> print(list(sorted(a, key=ip_sort)))
    ['10.1.2.2', '10.1.10.104']
    """
    return tuple(int(b) for b in x.split('.'))


def dhcp_host_config(ip2mac):
    """Generate the dhcp-host entries for dnsmasq.

    ########################
    # dhcp-host config
    ########################

    # Always allocate the host with Ethernet address 11:22:33:44:55:66
    # The IP address 192.168.0.60
    dhcp-host=11:22:33:44:55:66,192.168.0.60

    # Always set the name of the host with hardware address
    # 11:22:33:44:55:66 to be "fred"
    dhcp-host=11:22:33:44:55:66,fred

    # Always give the host with Ethernet address 11:22:33:44:55:66
    # the name fred and IP address 192.168.0.60 and lease time 45 minutes
    dhcp-host=11:22:33:44:55:66,fred,192.168.0.60,45m

    # Give a host with Ethernet address 11:22:33:44:55:66 or
    # 12:34:56:78:90:12 the IP address 192.168.0.60. Dnsmasq will assume
    # that these two Ethernet interfaces will never be in use at the same
    # time, and give the IP address to the second, even if it is already
    # in use by the first. Useful for laptops with wired and wireless
    # addresses.
    dhcp-host=11:22:33:44:55:66,12:34:56:78:90:12,192.168.0.60

    # Give the machine which says its name is "bert" IP address
    # 192.168.0.70 and an infinite lease
    dhcp-host=bert,192.168.0.70,infinite

    # Always give the host with client identifier 01:02:02:04
    # the IP address 192.168.0.60
    dhcp-host=id:01:02:02:04,192.168.0.60

    """
    output = []
    output.append('')
    output.append('# '+'-'*70)
    output.append('# DHCP Host Configuration')
    output.append('# '+'-'*70)
    for ip, macs in sorted(ip2mac.items(), key=lambda x: ip_sort(x[0])):
        dhcp_names = set(m[1] for m in macs)
        dhcp_name = common_suffix(*dhcp_names).strip('-')

        output.append("dhcp-host=%s,%s,%s" % (",".join(m[0] for m in macs), ip, dhcp_name))
    output.append('# '+'-'*70)
    output.append('')
    return output


def ptr_config(ip2hostname):
    """Generate the ptr-record entries for dnsmasq.

    ########################
    # ptr-records
    ########################

    # The following line shows how to make dnsmasq serve an arbitrary PTR
    # record. This is useful for DNS-SD. (Note that the
    # domain-name expansion done for SRV records _does_not
    # occur for PTR records.)
    ptr-record=_http._tcp.dns-sd-services,"New Employee Page._http._tcp.dns-sd-services"

    """

    output = []
    output.append('')
    output.append('# '+'-'*70)
    output.append('# Reverse names for IP addresses')
    output.append('# '+'-'*70)
    for ip, hostname in sorted(ip2hostname.items(), key=lambda x: ip_sort(x[0])):
        output.append("ptr-record=/%s.%s/%s" % (hostname, DOMAIN, ip))
    output.append('# '+'-'*70)
    output.append('')
    return output


def address_config(hostname2ip):
    """Generate the address entries for dnsmasq.

    ########################
    # address config
    ########################

    # Add domains which you want to force to an IP address here.
    # The example below send any host in double-click.net to a local
    # web-server.
    address=/double-click.net/127.0.0.1

    # --address (and --server) work with IPv6 addresses too.
    address=/www.thekelleys.org.uk/fe80::20d:60ff:fe36:f83
    """


def host_record_config(hostname2ip):
    """Generate the host-record entries for dnsmasq.

    ########################
    # host-record
    ########################

    --host-record=<name>[,<name>....],[<IPv4-address>],[<IPv6-address>][,<TTL>]

    Add A, AAAA and PTR records to the DNS.

    This adds one or more names to the DNS with associated IPv4 (A) and IPv6 (AAAA)
    records.

    A name may appear in more than one --host-record and therefore be assigned more
    than one address.

    Only the first address creates a PTR record linking the address to the name.
    This is the same rule as is used reading hosts-files.

    --host-record options are considered to be read before host-files, so a name
    appearing there inhibits PTR-record creation if it appears in hosts-file also.

    Unlike hosts-files, names are not expanded, even when --expand-hosts is in
    effect.

    Short and long names may appear in the same --host-record, eg.
    --host-record=laptop,laptop.thekelleys.org,192.168.0.1,1234::100

    If the time-to-live is given, it overrides the default, which is zero or the
    value of --local-ttl. The value is a positive integer and gives the
    time-to-live in seconds.

    --dynamic-host=<name>,[IPv4-address],[IPv6-address],<interface>

    Add A, AAAA and PTR records to the DNS in the same subnet as the specified
    interface.

    The address is derived from the network part of each address associated with
    the interface, and the host part from the specified address.

    For example --dynamic-host=example.com,0.0.0.8,eth0 will, when eth0 has the
    address 192.168.78.x and netmask 255.255.255.0 give the name example.com an A
    record for 192.168.78.8.

    The same principle applies to IPv6 addresses.

    Note that if an interface has more than one address, more than one A or AAAA
    record will be created. The TTL of the records is always zero, and any changes
    to interface addresses will be immediately reflected in them.
    """
    output = []
    output.append('')
    output.append('# '+'-'*70)
    output.append('# Forward names')
    output.append('# '+'-'*70)

    for host, ips in sorted(hostname2ip.items(), key=lambda x: x[0].split('.')[::-1]):
        output.append('')
        output.append('# '+host)
        if len(ips) == 1:
            ((inf, ip),) = ips.items()
            if inf:
                output.append('host-record=%s.%s.%s,%s' % (inf, host, DOMAIN, ip))
            output.append('host-record=%s.%s,%s' % (host, DOMAIN, ip))
            output.append('host-record=%s,%s' % (host, ip))
        else:
            for inf, ip in sorted(ips.items()):
                output.append('host-record=%s.%s.%s,%s' % (inf, host, DOMAIN, ip))

            # IP address for bare hostname
            # - Public IPs are first choice
            public_ips = []
            for ip in ips.values():
                if not is_local(ip):
                    public_ips.append(ip)
            if public_ips:
                assert len(public_ips) == 1, (public_ips, host, ips)
                output.append('host-record=%s.%s,%s' % (host, DOMAIN, public_ips[0]))
            else:
                # - Else use the earlist private IP address
                ips = list(sorted(ips.values(), key=ip_sort))
                output.append('host-record=%s.%s,%s' % (host, DOMAIN, ips[0]))
            output.append('host-record=%s,%s' % (host, ip))

    output.append('# '+'-'*70)
    output.append('')
    return output


def sshfp_records(hostname2ips):
    """
    44 is the RR type for SSHFP, according to RFC 4255.
    """

    # Check the sshfp
    subprocess.check_call('./sshfp.py')
    with open('sshfp.json', 'r') as f:
        sshfp = json.load(f)

    output = []
    output.append('')
    output.append('# '+'='*70)
    output.append('# SSHFP Records')
    output.append('# '+'='*70)

    for hostname, ips in hostname2ips.items():
        if hostname not in sshfp:
            continue
        fp = sshfp[hostname]

        def records(dnsname):
            output.append('')
            output.append('# sshfp for %s' % dnsname)
            for l in fp:
                _, a, b, c, d, e = l.split()
                assert a == "IN", (a, l)
                assert b == "SSHFP", (b, l)
                output.append('dns-rr=%s,44,%s:%s:%s' % (dnsname, c, d, e))

        output.append('')
        output.append('# ' + '-'*70)
        output.append('# '+hostname)
        output.append('# ' + '-'*70)
        records('%s.%s' % (hostname, DOMAIN))

        for inf in ips.keys():
            if not inf:
                continue
            records('%s.%s.%s' % (inf, hostname, DOMAIN))

        for ip in ips.values():
            records(".".join(ip.split('.')[::-1]+['in-addr.arpa']))
        output.append('# ' + '-'*70)
    return output


def main(argv):
    data = get_data()
    printd("Good Data", data)

    hostname2ip, ip2hostname = get_ip_info(data)
    with open('hosts.json', 'w') as f:
        json.dump(hostname2ip, f, indent="  ", sort_keys=True)
    printd("IP Configuration", hostname2ip, ip2hostname)

    ip2mac = get_mac_info(data)
    with open('macs.json', 'w') as f:
        json.dump(ip2mac, f, indent="  ", sort_keys=True)
    printd("MAC Info", ip2mac=ip2mac)

    output = []
    # Static DHCP Hosts
    output.extend(dhcp_host_config(ip2mac))
    # Reverse addresses
    output.extend(ptr_config(ip2hostname))
    # Forward addresses
    output.extend(host_record_config(hostname2ip))
    # SSHFP records
    output.extend(sshfp_records(hostname2ip))

    output.append('')

    OUTPUT = 'dnsmasq.static.conf'
    with open(OUTPUT, 'w') as f:
        for l in output:
            f.write(l)
            f.write('\n')

    print("-"*75)
    with open(OUTPUT) as f:
        print(f.read())
    print("-"*75)


# DNSMasq configuration directives
"""

########################
# txt-records
########################

# Change the following lines to enable dnsmasq to serve TXT records.
# These are used for things like SPF and zeroconf. (Note that the
# domain-name expansion done for SRV records _does_not
# occur for TXT records.)

#Example SPF.
#txt-record=example.com,"v=spf1 a -all"

#Example zeroconf
#txt-record=_http._tcp.example.com,name=value,paper=A4


--cname=<cname>,[<cname>,]<target>[,<TTL>]

Return a CNAME record which indicates that <cname> is really <target>.

There is a significant limitation on the target; it must be a DNS record which
is known to dnsmasq and NOT a DNS record which comes from an upstream server.

The cname must be unique, but it is permissible to have more than one cname
pointing to the same target. Indeed it's possible to declare multiple cnames to
a target in a single line, like so: --cname=cname1,cname2,target

If the time-to-live is given, it overrides the default, which is zero or the
value of --local-ttl. The value is a positive integer and gives the
time-to-live in seconds.


--auth-zone=<domain>[,<subnet>[/<prefix length>][,<subnet>[/<prefix length>].....][,exclude:<subnet>[/<prefix length>]].....]

Define a DNS zone for which dnsmasq acts as authoritative server. Locally
defined DNS records which are in the domain will be served. If subnet(s) are
given, A and AAAA records must be in one of the specified subnets.

As alternative to directly specifying the subnets, it's possible to give the
name of an interface, in which case the subnets implied by that interface's
configured addresses and netmask/prefix-length are used; this is useful when
using constructed DHCP ranges as the actual address is dynamic and not known
when configuring dnsmasq. The interface addresses may be confined to only IPv6
addresses using <interface>/6 or to only IPv4 using <interface>/4. This is
useful when an interface has dynamically determined global IPv6 addresses which
should appear in the zone, but RFC1918 IPv4 addresses which should not.
Interface-name and address-literal subnet specifications may be used freely in
the same --auth-zone declaration.

It's possible to exclude certain IP addresses from responses. It can be used,
to make sure that answers contain only global routeable IP addresses (by
excluding loopback, RFC1918 and ULA addresses).

The subnet(s) are also used to define in-addr.arpa and ip6.arpa domains which
are served for reverse-DNS queries. If not specified, the prefix length
defaults to 24 for IPv4 and 64 for IPv6. For IPv4 subnets, the prefix length
should be have the value 8, 16 or 24 unless you are familiar with RFC 2317 and
have arranged the in-addr.arpa delegation accordingly. Note that if no subnets
are specified, then no reverse queries are answered.


"""

if __name__ == "__main__":
    import doctest
    r = doctest.testmod()
    if r.failed > 0:
        sys.exit(127)
    sys.exit(main(sys.argv))
