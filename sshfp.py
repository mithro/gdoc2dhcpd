#!/usr/bin/env python3


import json
import os
import pprint
import socket
import subprocess
import sys
import time


def ping(ip, packets=5):

    p = subprocess.Popen(
            ['ping', '-n', '-A', '-c', str(packets), '-w', '1', ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding='utf-8',
        )
    stdout, stderr = p.communicate()
    alive = ('%s packets transmitted, %s received' % (packets, packets)) in stdout
    return alive, stdout, stderr


def check_socket(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        result = sock.connect_ex((ip,port))
        return result == 0
    finally:
        sock.close()


def main(args):
    with open('hosts.json', 'r') as f:
        hosts = json.load(f)

    sshfp = {}
    if os.path.exists('sshfp.json'):
        age = time.time()-os.path.getmtime('sshfp.json')
        if age < 60*5 and '--force' not in args:
            print('sshfp.json last updated', age, 'seconds ago, exiting.')
            return 0

        with open('sshfp.json', 'r') as f:
            sshfp = json.load(f)

    for host, ips in sorted(hosts.items(), key=lambda x: x[0].split('.')[::-1]):
        print('%20s' % host, flush=True, end=' ')
        ping_out = {}
        active_ips = []
        inactive_ips = []
        for inf, ip in ips.items():
            up, stdout, stderr = ping(ip)
            ping_out[ip] = (up, stdout, stderr)
            if up:
                active_ips.append(ip)
            else:
                inactive_ips.append(ip)
        if not active_ips:
            print('down')
            continue
        print('up('+','.join(active_ips)+')', end=' ', flush=True)
        for ssh_ip in active_ips:
            if check_socket(ssh_ip, 22):
                print('with-ssh', end=' ', flush=True)
                break
        else:
            print('no-ssh')
            continue

        try:
            stdout = subprocess.check_output(
                    ['ssh-keyscan', '-D', ssh_ip],
                    stderr=subprocess.DEVNULL,
                    encoding='utf-8',
                ).replace(ssh_ip, host).splitlines()
        except subprocess.CalledProcessError as e:
            print(e)
            continue

        stdout.sort()

        print()
        print(' '*23, ('\n'+' '*24).join(stdout))

        sshfp[host] = stdout

    with open('sshfp.json', 'w') as f:
        json.dump(sshfp, f)

    print()
    print('='*75)
    for host, fp in sshfp.items():
        print()
        print(host)
        print('-'*75)
        print('\n'.join(fp))
    print('='*75)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
