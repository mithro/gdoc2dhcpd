# TODO

## Derivations

- [x] **ipv4./ipv6. prefix subnames for all DNS names**: The DNS names derivation
  pipeline now computes all DNS names per host including ipv4./ipv6. prefixes
  for all dual-stack FQDNs: hostname, interface, subdomain, and combinations.
  The dnsmasq generator now consumes `host.dns_names` instead of computing names
  inline, ensuring interface variants (`ipv4.eth0.big-storage.welland.mithis.com`)
  and subdomain variants (`ipv4.big-storage.int.welland.mithis.com`) all get
  ipv4/ipv6 prefix records.

## Generators

- [ ] **Multi-file output for all generators**: Currently generators return a
  single string and write a single output file. The nginx and letsencrypt
  generators need to produce multiple files (per-host configs in a directory
  structure). Refactor the generator protocol so all generators can return
  either a single string or a dict of `{relative_path: content}`. Migrate
  existing generators (dnsmasq, cisco_sg300, tc_mac_vlan, nagios) to use the
  multi-file approach where it makes sense (e.g., per-host dnsmasq snippets).

## DNS Verification

- [x] **SSHFP records in both internal and external configs**: SSHFP records are
  now generated in both internal (`dnsmasq.static.conf`) and external
  (`dnsmasq.external.conf`) configurations. The external config includes SSHFP
  for hostname.domain and interface.hostname.domain FQDNs, but NOT for PTR
  records (since internal IPs aren't routable externally).

- [ ] **DNSSEC signing for the domain**: For SSHFP records to be trustworthy,
  the domain must be DNSSEC-signed at the authoritative DNS level. Dnsmasq
  cannot sign records—it only forwards/caches. Options:
  - Use a cloud DNS provider with DNSSEC support (Cloudflare, Route53, etc.)
  - Run BIND or similar authoritative DNS with DNSSEC signing
  - Note: dnsmasq's `dnssec` option validates upstream responses but doesn't
    sign local records served via host-record directives
