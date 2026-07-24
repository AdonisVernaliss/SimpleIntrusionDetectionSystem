# Simple Intrusion Detection System

A local command-line network intrusion detection system for live interfaces and
saved PCAP files. It extracts packet metadata, applies signature and rate-based
detection rules, prints alerts, and can write structured JSON Lines output.

## Features

- automatic network-interface selection or explicit selection by name;
- live packet capture with a BPF filter;
- offline analysis of `.pcap` files;
- TCP NULL, XMAS, and SYN+FIN flag detection;
- port-scan and host-scan detection;
- TCP SYN, UDP, and ICMP flood detection;
- configurable watched destination ports and packet-size limit;
- alert cooldowns to prevent repeated messages from overwhelming the output;
- human-readable or JSON Lines alerts;
- packet and protocol summary on shutdown;
- graceful termination with `Ctrl+C`;
- Java 8 compatibility and a self-contained executable JAR.

## Requirements

- Java 8 or newer;
- Maven 3.8 or newer for building;
- libpcap on Linux or macOS, or Npcap on Windows.

Install the native capture library if it is not already present:

```bash
# Debian or Ubuntu
sudo apt install libpcap0.8

# Fedora
sudo dnf install libpcap

# macOS with Homebrew
brew install libpcap
```

On Windows, install Npcap in WinPcap API-compatible mode.

## Build and test

```bash
mvn clean verify
```

The executable JAR is created at:

```text
target/intrusion-detection-system-1.0.0.jar
```

## Quick start

List capture interfaces:

```bash
java -jar target/intrusion-detection-system-1.0.0.jar --list-interfaces
```

Monitor an automatically selected interface:

```bash
sudo java -jar target/intrusion-detection-system-1.0.0.jar
```

Monitor a specific interface for 60 seconds:

```bash
sudo java -jar target/intrusion-detection-system-1.0.0.jar \
  --interface en0 \
  --duration 60
```

Analyze a saved capture and append alerts to a JSON Lines file:

```bash
java -jar target/intrusion-detection-system-1.0.0.jar \
  --read capture.pcap \
  --json \
  --log alerts.jsonl
```

Live capture often requires administrator or packet-capture privileges. Prefer
granting the minimum capture capability supported by the operating system rather
than running unrelated tools with elevated privileges.

## Command-line options

```text
  -h, --help                  Show help
      --list-interfaces       List available capture interfaces
  -i, --interface NAME        Capture from the named interface
  -r, --read FILE             Analyze an offline PCAP file
  -f, --filter EXPRESSION     BPF capture filter or "none" (default: ip or ip6)
  -c, --count NUMBER          Stop after NUMBER packets
  -d, --duration SECONDS      Stop after SECONDS of wall-clock time
      --no-promiscuous        Disable promiscuous mode
      --snaplen BYTES         Capture snapshot length (default: 65536)
      --verbose               Print metadata for every packet
      --json                  Print alerts as JSON Lines
      --log FILE              Append alerts as JSON Lines to FILE
      --window-seconds N      Detection window (default: 10)
      --port-scan-threshold N Unique ports in a window (default: 15)
      --host-scan-threshold N Unique hosts in a window (default: 20)
      --syn-threshold N       TCP SYN packets in a window (default: 100)
      --udp-threshold N       UDP packets in a window (default: 250)
      --icmp-threshold N      ICMP packets in a window (default: 100)
      --max-packet-size N     Oversized-packet threshold (default: 2000)
      --cooldown-seconds N    Repeat-alert cooldown (default: 30)
      --watch-ports LIST      Comma-separated destination ports or "none"
```

Examples of BPF filters:

```bash
--filter "tcp"
--filter "host 192.0.2.10"
--filter "tcp port 443 or udp port 53"
```

## Detection model

The detector is passive: it reports suspicious metadata and never blocks,
modifies, or transmits traffic. Rate rules use source/destination observations
inside a sliding time window. Default watched ports are `23`, `2323`, `4444`,
`5555`, and `31337`.

This is a signature and threshold-based IDS. Encrypted payload inspection,
protocol reassembly, threat-intelligence feeds, and automatic response are out of
scope. Tune thresholds for the monitored network to reduce false positives.

## Output and privacy

Packet payloads are not printed or written to alert logs. Alerts contain the
timestamp, rule, severity, addresses, ports, and a short reason. Captures and
generated logs are ignored by Git because they may contain sensitive network
metadata.

Only capture traffic on systems and networks you are authorized to monitor.
