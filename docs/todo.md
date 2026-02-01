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

- [x] **Multi-file output for generators**: The generator protocol now supports
  returning a dict of `{relative_path: content}` for multi-file output. The
  dnsmasq (internal and external) and nginx generators use this to produce
  per-host config files. The nginx generator produces four config file variants
  per host under `sites-available/`, with multi-interface hosts getting combined
  files containing upstream failover blocks.

- [ ] **Letsencrypt generator multi-file output**: The letsencrypt generator
  still needs to be migrated to the multi-file output approach.

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

## SSHFP

- [ ] **SSHFP records for all host interfaces**: SSHFP records should be
  generated for all of a host's interfaces, even those which might currently
  be inaccessible. Currently the SSHFP supplement only scans reachable hosts,
  so interfaces that are down or firewalled at scan time get no fingerprint
  records. The scan should attempt all interfaces and cache results
  independently, so that previously-scanned interfaces retain their records
  even if temporarily unreachable.

## DHCP

- [ ] **DHCP records matching on hostname when no MAC address exists**: Allow
  creation of dhcp-host records that match on hostname rather than MAC address
  when no MAC address is available in the spreadsheet. This would use
  dnsmasq's `dhcp-host=<hostname>,<ip>` form (without MAC) for hosts that
  are known by name but don't have a recorded hardware address.
