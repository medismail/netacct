# netacct

`netacct` is a lightweight IPv4/IPv6 accounting daemon for a small Linux router. The current MVP is intentionally narrow:

- one monitored LAN interface;
- IPv4 and IPv6 per-IP accounting;
- no VLAN parsing;
- kernel interface counters are the authoritative total, suitable for comparison with `vnstat`;
- libpcap is used to attribute IPv4/IPv6 bytes to local LAN addresses.

The main target for this MVP is a Raspberry Pi 3 B+ or similar small router where CPU and SD-card writes should stay low.

## What the MVP measures

`netacct` stores two kinds of counters:

1. **KERNEL totals**: RX/TX deltas read from `/sys/class/net/<iface>/statistics/{rx_bytes,tx_bytes}`. These are the numbers to compare with `vnstat`. The target is less than 1% difference when tested over a meaningful traffic window.
2. **Per-IP totals**: IPv4 and IPv6 packets captured on the LAN interface and attributed to addresses inside the configured local IPv4 subnet and IPv6 prefix. For better closeness to interface counters, netacct attributes the captured L2 packet length, not only the L3 payload length.

Per-IP totals can still be lower than KERNEL totals because ARP, non-IP traffic, multicast/broadcast control traffic, capture drops, or traffic outside the configured local prefixes are not attributed to a client IP.

## Install dependencies

Debian / Raspberry Pi OS:

```bash
sudo apt update
sudo apt install build-essential pkg-config libpcap-dev libcjson-dev zlib1g-dev
```

Optional for comparison:

```bash
sudo apt install vnstat iperf3
```

## Build

```bash
make
```

The binary is created at:

```bash
./bin/netacct
```

## Run manually

Auto-detect the IPv4 LAN subnet and IPv6 LAN prefix from the interface address/netmask:

```bash
sudo ./bin/netacct daemon --iface eth0 --subnet auto --subnet6 auto --root /var/lib/netacct
```

Force local prefixes:

```bash
sudo ./bin/netacct daemon --iface eth0 --subnet 192.168.1.0/24 --subnet6 fd00:1234:5678::/64 --root /var/lib/netacct
```

Lightweight defaults:

- poll interval: 1 second;
- flush interval: 5 seconds;
- pcap buffer: 4 MB;
- non-promiscuous capture;
- BPF filter: `ip or ip6`.

## Report

Daily report with exact byte values:

```bash
./bin/netacct report --iface eth0 --root /var/lib/netacct --day 2026-06-30
```

Human-readable text report:

```bash
./bin/netacct report --iface eth0 --root /var/lib/netacct --day 2026-06-30 --human
```

Monthly report, by summing daily files:

```bash
./bin/netacct report --iface eth0 --root /var/lib/netacct --month 2026-06
```

JSON output keeps exact byte fields for scripts and includes `ip_version`:

```bash
./bin/netacct report --iface eth0 --root /var/lib/netacct --day 2026-06-30 --format json
```

CSV output keeps exact byte fields for scripts and includes an `ip_version` column:

```bash
./bin/netacct report --iface eth0 --root /var/lib/netacct --day 2026-06-30 --format csv
```

List interfaces with stored data:

```bash
./bin/netacct list-ifaces --root /var/lib/netacct
```

## Config file

Example:

```ini
iface=eth0
root_dir=/var/lib/netacct
subnet=auto
subnet6=auto
poll_interval=1
flush_interval=5
pcap_buffer_mb=4
top=50
```

Run with config:

```bash
sudo ./bin/netacct daemon --config /etc/netacct.conf
```

## Install as systemd service

```bash
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now netacct
```

Edit `/etc/netacct.conf` first if your LAN interface is not `eth0`.

## Validation against sysfs and vnStat

The included validation script starts netacct with a temporary storage root, runs for a chosen duration, then compares netacct KERNEL total with direct sysfs RX/TX deltas.

```bash
make
./scripts/run-local-validation.sh eth0 120 /tmp/netacct-validation
```

Generate traffic during the test window. For example, run `iperf3` from a LAN client, download a large file, or run your normal traffic test.

If `vnstat` is installed, the script also prints the daily vnStat view for the same interface. For strict validation, compare netacct `KERNEL` total to sysfs over the same temporary test window; vnStat daily numbers may include traffic outside the test period.

For IPv6 validation, confirm the daemon log shows a real `subnet6=` value. If it shows `subnet6=disabled`, force the prefix with `--subnet6 PREFIX/LEN` or `subnet6=PREFIX/LEN` in the config file.

## Runtime control socket

The daemon exposes `/run/netacct.sock` for manual IP add/remove commands, although the MVP normally auto-creates per-IP counters for any IPv4 or IPv6 address inside the configured local prefixes.

Examples:

```bash
printf '{"action":"add","ip":"192.168.1.50"}' | sudo socat - UNIX-CONNECT:/run/netacct.sock
printf '{"action":"add","ip":"fd00:1234:5678::50"}' | sudo socat - UNIX-CONNECT:/run/netacct.sock
```

## Storage layout

```text
/var/lib/netacct/
  eth0/
    .meta
    .last_counts
    daily/
      2026-06-30.bin
      2026-06-29.bin.gz
```

Daily files are append-only binary records. Old daily files are gzip-compressed automatically after day rotation. Existing IPv4-only daily records remain readable; new records can contain mixed IPv4 and IPv6 entries.

## MVP limits

This MVP deliberately does not implement:

- VLAN-tag parsing;
- multiple local IPv6 prefixes on the same interface;
- multi-interface collection;
- Prometheus/REST export;
- eBPF/XDP acceleration;
- distributed aggregation.

These are good next steps after the single-interface IPv4/IPv6 baseline is validated on real router traffic.
