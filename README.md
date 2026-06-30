# netacct

`netacct` is a lightweight IPv4 accounting daemon for a small Linux router. The current MVP is intentionally narrow:

- one monitored LAN interface;
- IPv4 only;
- no VLAN parsing;
- kernel interface counters are the authoritative total, suitable for comparison with `vnstat`;
- libpcap is used only to attribute IPv4 bytes to local LAN IP addresses.

The main target for this MVP is a Raspberry Pi 3 B+ or similar small router where CPU and SD-card writes should stay low.

## What the MVP measures

`netacct` stores two kinds of counters:

1. **KERNEL totals**: RX/TX deltas read from `/sys/class/net/<iface>/statistics/{rx_bytes,tx_bytes}`. These are the numbers to compare with `vnstat`. The target is less than 1% difference when tested over a meaningful traffic window.
2. **Per-IP totals**: IPv4 packets captured on the LAN interface and attributed to IPs inside the configured local subnet. For better closeness to interface counters, netacct attributes the captured L2 packet length, not only the IPv4 payload length.

Per-IP totals can still be lower than KERNEL totals because ARP, IPv6, multicast/broadcast control traffic, capture drops, or traffic outside the configured subnet are not attributed to a client IP.

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

Auto-detect the IPv4 LAN subnet from the interface address/netmask:

```bash
sudo ./bin/netacct daemon --iface eth0 --subnet auto --root /var/lib/netacct
```

Force a subnet:

```bash
sudo ./bin/netacct daemon --iface eth0 --subnet 192.168.1.0/24 --root /var/lib/netacct
```

Lightweight defaults:

- poll interval: 1 second;
- flush interval: 5 seconds;
- pcap buffer: 4 MB;
- non-promiscuous capture;
- BPF filter: `ip`.

## Report

Daily report:

```bash
./bin/netacct report --iface eth0 --root /var/lib/netacct --day 2026-06-30
```

Monthly report, by summing daily files:

```bash
./bin/netacct report --iface eth0 --root /var/lib/netacct --month 2026-06
```

JSON output:

```bash
./bin/netacct report --iface eth0 --root /var/lib/netacct --day 2026-06-30 --format json
```

CSV output:

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

## Runtime control socket

The daemon exposes `/run/netacct.sock` for manual IP add/remove commands, although the MVP normally auto-creates per-IP counters for any IPv4 address inside the configured subnet.

Example:

```bash
printf '{"action":"add","ip":"192.168.1.50"}' | sudo socat - UNIX-CONNECT:/run/netacct.sock
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

Daily files are append-only binary records. Old daily files are gzip-compressed automatically after day rotation.

## MVP limits

This MVP deliberately does not implement:

- IPv6 accounting;
- VLAN-tag parsing;
- multi-interface collection;
- Prometheus/REST export;
- eBPF/XDP acceleration;
- distributed aggregation.

These are good next steps after the single-interface IPv4 baseline is validated on real router traffic.
