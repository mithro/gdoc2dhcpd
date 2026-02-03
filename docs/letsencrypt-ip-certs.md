# Let's Encrypt IP Address Certificates

Research notes on acquiring Let's Encrypt certificates for public IP addresses
at the Welland site. Covers both the site-wide public IPv4 and per-host
globally-routable IPv6 addresses.

## Background

Let's Encrypt announced IP address certificate support on
[15 January 2025](https://letsencrypt.org/2025/01/16/6-day-and-ip-certs),
issued its first IP certificate on
[1 July 2025](https://letsencrypt.org/2025/07/01/issuing-our-first-ip-address-certificate),
and made the feature
[generally available on 15 January 2026](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability).

Certbot 5.3.0, released on
[3 February 2026](https://community.letsencrypt.org/t/certbot-5-3-0-release/245097),
adds the `--ip-address` flag for requesting IP address certificates via the
`standalone` and `manual` plugins.

### Key constraints

- IP certs are **mandatory short-lived**: valid for 160 hours (~6 days)
- Requires the `shortlived` ACME profile (`--preferred-profile shortlived`)
- Only **HTTP-01** and **TLS-ALPN-01** challenges work for IPs — **not DNS-01**
- Defined by [RFC 8738](https://datatracker.ietf.org/doc/html/rfc8738) (ACME
  IP Identifier Validation Extension)
- The ACME identifier type is `"ip"` (not `"dns"`)

## Site topology

### Public IPv4 (`87.121.95.37`)

- Shared site-wide address, NATed to ten64
- nginx on ten64 listens on ports 80 and 443
- All external HTTP/HTTPS traffic routes through this IP
- One cert covers this single address

### Per-host IPv6 (`2404:e80:a137:XXYY::ZZZ`)

Each host gets globally-routable IPv6 addresses derived deterministically from
its IPv4 addresses using the mapping `10.AA.BB.CCC` → `{prefix}AABB::CCC`
(see `docs/ipv4-to-ipv6.md`).

**Address count per host:**
- Each interface gets one IPv6 address per active IPv6 prefix
- Currently 1 active prefix (`2404:e80:a137:` — Launtel ISP)
- A disabled prefix (`2001:470:82b3:` — HE.net) exists and would double the
  count if re-enabled
- A single-interface host (e.g. `desktop` at `10.1.10.124`) gets 1 IPv6:
  `2404:e80:a137:110::124`
- A multi-interface host gets one per interface — ten64 has ~14 interfaces
  (eth1–eth9, br-int, br-wlan-fast, br-wlan-iot, ha, wlan1), so ~14 IPv6
  addresses

**Example — ten64's IPv6 addresses (Launtel prefix only):**

| Interface     | IPv4        | IPv6                        |
|---------------|-------------|-----------------------------|
| br-int        | 10.1.10.1   | `2404:e80:a137:110::1`      |
| eth1          | 10.1.10.11  | `2404:e80:a137:110::11`     |
| eth2          | 10.1.10.12  | `2404:e80:a137:110::12`     |
| ...           | ...         | ...                         |
| eth9          | 10.1.10.19  | `2404:e80:a137:110::19`     |
| br-wlan-fast  | 10.1.30.1   | `2404:e80:a137:130::1`      |
| wlan1         | 10.1.30.2   | `2404:e80:a137:130::2`      |
| br-wlan-iot   | 10.1.90.1   | `2404:e80:a137:190::1`      |
| ha            | 10.1.90.2   | `2404:e80:a137:190::2`      |

**Reachability:**
- These IPv6 addresses are globally routable (not behind NAT like IPv4)
- Most hosts are behind the nginx reverse proxy for IPv4, but their IPv6
  addresses are directly reachable if the firewall allows it
- ten64 is both the gateway and the only host currently running nginx, so
  its own IPv6 addresses are the easiest to certify
- Other hosts would need inbound port 80 (or 443) opened on each IPv6 for
  challenge validation

**Which IPv6 addresses are worth certifying?**
- Not every IPv6 address needs a cert — only those used for TLS connections
- ten64's addresses are the highest priority since it terminates TLS for the
  site
- Individual hosts' IPv6 addresses matter if clients connect directly via
  IPv6 (bypassing the reverse proxy)
- Bridge/VLAN management interfaces (br-int, br-wlan-fast, etc.) may not
  need certs if they are only used for internal routing

### What cannot get certs

- RFC 1918 IPv4 addresses (`10.1.X.Y`) — private, not publicly routable
- Link-local IPv6 (`fe80::`) — not routable
- ULA IPv6 (`fd00::`) — not publicly routable

## Challenge types for IP addresses

| Challenge    | Works for IPs? | Mechanism                                                        | Port |
|--------------|----------------|------------------------------------------------------------------|------|
| DNS-01       | **No**         | No DNS mechanism exists for proving IP ownership                 | —    |
| HTTP-01      | **Yes**        | HTTP GET to `http://{IP}/.well-known/acme-challenge/{token}`     | 80   |
| TLS-ALPN-01  | **Yes**        | TLS handshake with ALPN protocol `acme-tls/1` to validate IP    | 443  |

The current domain certificate workflow uses DNS-01 via the
`certbot-hook-dnsmasq` auth hook. This **cannot** be reused for IP certs — a
different challenge mechanism is required.

### HTTP-01 (recommended for this site)

Let's Encrypt connects to port 80 on the IP being validated and requests a
challenge token file. The ACME client must serve this file at
`http://{IP}/.well-known/acme-challenge/{token}`.

**For the public IPv4 (`87.121.95.37`):** nginx already serves
`/.well-known/acme-challenge/` from `/var/www/acme` (via
`snippets/acme-challenge.conf`), so the **webroot** method should work
directly.

**For ten64's IPv6 addresses:** nginx on ten64 already listens on
`listen [::]:80`, which means it accepts connections on all of ten64's IPv6
addresses. Since `snippets/acme-challenge.conf` is included in the server
blocks, the ACME challenge directory is already served on ten64's IPv6
addresses too. The webroot method should work for ten64 without changes.

**For other hosts' IPv6 addresses:** each host would need either:
- certbot in **standalone** mode (binds port 80 temporarily), or
- a local web server serving the challenge directory

Since IPv6 addresses are globally routable (not NATed), Let's Encrypt
validates each IPv6 address individually — it connects directly to
`http://[2404:e80:a137:110::124]/.well-known/acme-challenge/{token}`. The
host at that address must respond. There is no way for ten64 to proxy this
validation on behalf of other hosts (unlike IPv4 where all traffic arrives
via the shared NAT address).

### TLS-ALPN-01 (alternative)

Let's Encrypt connects to port 443 with the `acme-tls/1` ALPN protocol. The
server must respond with a self-signed certificate containing the challenge
token.

Certbot does **not** natively support TLS-ALPN-01. Third-party options:
- [`certbot-ualpn`](https://github.com/ndilieto/certbot-ualpn) plugin
  (uncertain IP support)
- Alternative ACME clients (see below)

## Certbot usage (5.3.0+)

### Public IPv4 — webroot mode

nginx on ten64 already serves the ACME challenge directory on port 80. Use
certbot's webroot mode:

```sh
certbot certonly --webroot \
  -w /var/www/acme \
  --preferred-profile shortlived \
  --cert-name ip-87.121.95.37 \
  --ip-address 87.121.95.37
```

**Note:** The `--ip-address` flag is new in certbot 5.3.0. Whether webroot
mode works with `--ip-address` (as opposed to standalone only) needs
verification — the release notes mention `standalone` and `manual` plugins.
If webroot is not supported, use standalone mode instead:

```sh
# Stop nginx first, then:
certbot certonly --standalone \
  --preferred-profile shortlived \
  --cert-name ip-87.121.95.37 \
  --ip-address 87.121.95.37
```

### Ten64's IPv6 addresses — webroot mode

Since nginx on ten64 already listens on `[::]:80` and serves the ACME
challenge directory, ten64's IPv6 addresses can use webroot mode — the same
approach as the public IPv4:

```sh
certbot certonly --webroot \
  -w /var/www/acme \
  --preferred-profile shortlived \
  --cert-name ip-ten64-ipv6 \
  --ip-address 2404:e80:a137:110::1 \
  --ip-address 2404:e80:a137:110::11 \
  --ip-address 2404:e80:a137:110::12 \
  --ip-address 2404:e80:a137:130::1 \
  --ip-address 2404:e80:a137:190::1
```

**Note:** Whether all ~14 of ten64's IPv6 addresses should go in one cert or
be split across multiple certs is a design decision. A single cert simplifies
management but any validation failure blocks the entire cert. Multiple certs
(e.g. one per VLAN/subnet) provide isolation.

**Note:** As with the IPv4 case, whether `--ip-address` works with `--webroot`
(vs only `--standalone`/`--manual`) needs verification.

### Other hosts' IPv6 — standalone mode

Each host runs certbot standalone on port 80 to validate its IPv6 addresses:

```sh
certbot certonly --standalone \
  --preferred-challenges http-01 \
  --preferred-profile shortlived \
  --cert-name ip-desktop.welland.mithis.com \
  --ip-address 2404:e80:a137:110::124
```

A host with multiple interfaces would include all its IPv6 addresses:

```sh
certbot certonly --standalone \
  --preferred-challenges http-01 \
  --preferred-profile shortlived \
  --cert-name ip-big-storage.welland.mithis.com \
  --ip-address 2404:e80:a137:110::200 \
  --ip-address 2404:e80:a137:105::200
```

**Prerequisites:**
- Firewall allows inbound port 80 on each host's IPv6 from the internet
- No other service is using port 80 on the host during validation
- certbot 5.3.0+ installed on each host (or centrally if using manual mode
  with hooks)
- Each IPv6 address in the cert must be individually reachable — Let's
  Encrypt validates each IP separately

## Alternative ACME clients

If certbot's IP support is insufficient (e.g. webroot not supported, or
TLS-ALPN-01 is needed):

| Client          | IP cert support | TLS-ALPN-01 | HTTP-01 | Language | Notes                                    |
|-----------------|-----------------|-------------|---------|----------|------------------------------------------|
| **lego**        | Yes (RFC 8738)  | Yes         | Yes     | Go       | Single binary, 180+ DNS providers        |
| **Caddy**       | Yes (built-in)  | Yes         | Yes     | Go       | Full web server — overkill for just certs |
| **acme.sh**     | Partial         | Yes         | Yes     | Bash     | Use `--alpn` flag for TLS-ALPN-01        |
| **dehydrated**  | Partial         | No          | Yes     | Bash     | DNS-01 focused, IP support unclear       |

[**lego**](https://go-acme.github.io/lego/) is the strongest alternative — it
explicitly supports RFC 8738, has TLS-ALPN-01 built in, and ships as a single
Go binary.

## Renewal

### Frequency

IP certs are valid for 160 hours (~6 days). Renewal must happen every 3-4 days
at minimum.

Recommended cron schedule — twice daily:

```
0 */12 * * * certbot renew --quiet
```

certbot's built-in "skip if not near expiry" logic prevents unnecessary
renewals. Domain certs (90-day) and IP certs (6-day) coexist in certbot's
renewal configuration.

### Urgency

IP cert renewal failures are much more urgent than domain cert failures:
- IP cert: 6-day window to fix before expiry
- Domain cert: 90-day window (soon 45-day per Let's Encrypt plans)

Monitoring should alert on failed IP cert renewals within hours, not days.

## Recommended approach

### Phase 1: Public IPv4 cert on ten64

1. Upgrade certbot to 5.3.0+ on ten64
2. Test whether `--ip-address` works with `--webroot` mode
3. If webroot works: provision cert using nginx's existing ACME webroot
4. If not: use standalone mode (requires briefly stopping nginx)
5. Configure nginx to use the IP cert for the `87.121.95.37` server block
6. Set up twice-daily cron renewal

### Phase 2: Ten64's IPv6 certs

Ten64's IPv6 addresses are the easiest to certify after the public IPv4 —
nginx already listens on `[::]:80` and serves the ACME challenge directory.

1. Decide which of ten64's ~14 IPv6 addresses need certs (probably not all —
   bridge/management interfaces may not need TLS)
2. Decide grouping: one cert with all addresses, or separate certs per
   VLAN/subnet
3. Provision cert(s) using webroot mode (same as Phase 1)
4. Configure nginx to use the IPv6 IP cert(s) — this may require adding
   `server_name` blocks that match by IPv6 address, or using the IP cert on
   the default server block
5. Set up twice-daily cron renewal

### Phase 3: Other hosts' IPv6 certs (requires network changes)

1. Open firewall for inbound port 80 on each host's globally-routable IPv6
2. Test reachability from outside the network (each IPv6 address must be
   individually reachable)
3. Install certbot 5.3.0+ on each host (or use centralised orchestration
   from ten64 via manual mode with hooks)
4. Provision certs per host with all their IPv6 addresses as SANs
5. Configure services on each host to use the IP cert
6. Set up twice-daily cron renewal on each host

## Generated script format (future gdoc2netcfg generator)

When implementing a `letsencrypt_ip` generator in gdoc2netcfg, the generated
scripts would look like:

**Site IPv4 cert (`ip-certs-available/ip-87-121-95-37`):**

```sh
#!/bin/sh
certbot certonly --webroot \
  -w /var/www/acme \
  --preferred-profile shortlived \
  --cert-name ip-87.121.95.37 \
  --ip-address 87.121.95.37
```

**Ten64 IPv6 cert (`ip-certs-available/ip-ten64.welland.mithis.com`):**

```sh
#!/bin/sh
certbot certonly --webroot \
  -w /var/www/acme \
  --preferred-profile shortlived \
  --cert-name ip-ten64.welland.mithis.com \
  --ip-address 2404:e80:a137:110::1 \
  --ip-address 2404:e80:a137:110::11 \
  --ip-address 2404:e80:a137:110::12 \
  --ip-address 2404:e80:a137:110::13 \
  --ip-address 2404:e80:a137:110::14 \
  --ip-address 2404:e80:a137:110::15 \
  --ip-address 2404:e80:a137:110::16 \
  --ip-address 2404:e80:a137:110::17 \
  --ip-address 2404:e80:a137:110::18 \
  --ip-address 2404:e80:a137:110::19 \
  --ip-address 2404:e80:a137:130::1 \
  --ip-address 2404:e80:a137:130::2 \
  --ip-address 2404:e80:a137:190::1 \
  --ip-address 2404:e80:a137:190::2
```

**Other host IPv6 cert (`ip-certs-available/ip-desktop.welland.mithis.com`):**

```sh
#!/bin/sh
certbot certonly --standalone \
  --preferred-challenges http-01 \
  --preferred-profile shortlived \
  --cert-name ip-desktop.welland.mithis.com \
  --ip-address 2404:e80:a137:110::124
```

**Renewal orchestrator (`ip-renew-enabled.sh`):**

```sh
#!/bin/sh
# Renew all enabled IP address certificates
# Run via cron: 0 */12 * * *
certbot renew --quiet
```

## Open questions

- **Mixed certs:** Can a single certificate contain both `dns` and `ip`
  identifiers as SANs (e.g. `desktop.welland.mithis.com` + its IPv6
  addresses)? Let's Encrypt may not allow mixing identifier types in one
  order.

- **Webroot vs standalone:** Does certbot 5.3.0 support `--ip-address` with
  the webroot plugin, or only standalone/manual? This determines whether
  nginx needs to stop during validation.

- **Centralised vs decentralised IPv6:** Should each host manage its own IPv6
  cert renewal, or should ten64 orchestrate everything via the manual plugin
  with hooks?

- **Nginx integration:** Should the nginx generator produce `server_name`
  blocks for IP addresses that reference IP certs? Currently nginx configs
  only use domain-name certs. The nginx generator also excludes IPv6-only
  DNS names entirely (`_is_nginx_name()` filters out names where
  `ipv4 is None`) and only proxies to IPv4 backend addresses — IPv6 backend
  proxying would be a prerequisite for full IPv6 cert usage.

- **Firewall changes:** What rules are needed on ten64/EdgeRouter to allow
  inbound port 80 on each host's globally-routable IPv6 from Let's Encrypt
  validation servers?

- **Ten64 IPv6 cert grouping:** Should ten64's ~14 IPv6 addresses go in one
  cert or be split (e.g. per VLAN — `110::*` management, `130::*` WLAN,
  `190::*` IoT)? One cert is simpler but a single validation failure blocks
  renewal of all addresses. Which of ten64's interfaces actually need TLS
  certs (probably not bridge/VLAN management interfaces)?

- **Multiple IPv6 prefixes:** If the HE.net prefix (`2001:470:82b3:`) is
  re-enabled, each interface gets a second IPv6 address. Should the
  generator include addresses from all active prefixes in the cert, or only
  the primary prefix?

- **Scale of IPv6 validation:** Each `--ip-address` in a cert is validated
  individually by Let's Encrypt. A cert with 14 IPv6 addresses means 14
  separate HTTP-01 challenge validations. Does Let's Encrypt rate-limit
  per-IP validations differently from per-domain?

- **Monarto site:** Monarto has no public IPv4 or external dnsmasq — IP certs
  are only relevant for Welland. However, Monarto hosts also have
  globally-routable IPv6 addresses (`2404:e80:a137:2XX::*`). If those are
  reachable from the internet, IPv6 IP certs could apply there too.

## References

- [Let's Encrypt: 6-day and IP Address Certificates are Generally Available](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability) (15 January 2026)
- [Let's Encrypt: Announcing Six Day and IP Address Certificate Options in 2025](https://letsencrypt.org/2025/01/16/6-day-and-ip-certs) (15 January 2025)
- [Let's Encrypt: We've Issued Our First IP Address Certificate](https://letsencrypt.org/2025/07/01/issuing-our-first-ip-address-certificate) (1 July 2025)
- [Certbot 5.3.0 Release](https://community.letsencrypt.org/t/certbot-5-3-0-release/245097) (3 February 2026)
- [Certbot issue #10346: IP address subjectAlternativeName certificates](https://github.com/certbot/certbot/issues/10346)
- [RFC 8738: ACME IP Identifier Validation Extension](https://datatracker.ietf.org/doc/html/rfc8738) (February 2020)
- [RFC 8737: ACME TLS-ALPN Challenge Extension](https://datatracker.ietf.org/doc/html/rfc8737) (February 2020)
- [Let's Encrypt: Challenge Types](https://letsencrypt.org/docs/challenge-types/)
