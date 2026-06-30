# CodeAlpha_BasicNetworkSniffer

**Task 1 — CodeAlpha Cyber Security Internship**

A simple Python network packet sniffer built with `scapy`. It captures live
traffic on a chosen network interface and displays the source/destination
IPs, protocol, ports, and (optionally) a preview of the payload.

## Features
- Captures live packets in real time
- Identifies protocol: TCP, UDP, ICMP, ARP, or Other
- Displays source/destination IP addresses and ports
- Optional payload preview (`-v` flag)
- Optional BPF filter (e.g. only HTTP or only ICMP traffic)
- Limit capture to a specific number of packets

## Requirements
- Python 3.8+
- [Scapy](https://scapy.net/): `pip install -r requirements.txt`
- **Administrator/root privileges** (raw sockets require elevated access)
- **Windows only**: install [Npcap](https://npcap.com/) (check "WinPcap API
  compatible mode" during install)

## Installation
```bash
pip install -r requirements.txt
```

## Usage

List available network interfaces:
```bash
python network_sniffer.py --list-interfaces
```

Run the sniffer (Linux/Mac, needs sudo):
```bash
sudo python3 network_sniffer.py
```

Run on Windows (open terminal "As Administrator"):
```bash
python network_sniffer.py
```

Sniff on a specific interface:
```bash
sudo python3 network_sniffer.py -i eth0
```

Capture only 20 packets:
```bash
sudo python3 network_sniffer.py -c 20
```

Capture only TCP traffic on port 80 (HTTP), with payload preview:
```bash
sudo python3 network_sniffer.py -f "tcp port 80" -v
```

Capture only ICMP (ping) traffic:
```bash
sudo python3 network_sniffer.py -f icmp
```

Stop the sniffer anytime with `Ctrl+C`.

## Sample Output
```
======================================================================
 CodeAlpha Cybersecurity - Basic Network Sniffer
 Press Ctrl+C to stop
======================================================================
[14:32:01] TCP      192.168.1.5     -> 142.250.182.46  51322 -> 443
[14:32:01] UDP      192.168.1.5     -> 192.168.1.1     53201 -> 53
[14:32:02] ICMP     192.168.1.5     -> 8.8.8.8
[14:32:02] ARP      192.168.1.1     -> 192.168.1.5     (op=reply)
```

## How It Works
1. `scapy.sniff()` opens a raw socket on the network interface and captures
   every packet that passes through it.
2. Each packet is passed to a callback function (`process_packet`) which
   inspects its layers (IP, TCP, UDP, ICMP, ARP) to extract useful fields.
3. If the packet contains a `Raw` layer, its payload bytes are decoded (or
   shown as hex if not text) and truncated for safe, readable display.

## Disclaimer
This tool is for **educational purposes only**, intended for use on networks
you own or have explicit permission to monitor. Unauthorized packet
sniffing on networks you don't control may be illegal.

## Submission Checklist (per CodeAlpha instructions)
- [ ] Push this folder to a GitHub repo named `CodeAlpha_BasicNetworkSniffer`
- [ ] Record a short video walkthrough and post it on LinkedIn, tagging @CodeAlpha
- [ ] Share the GitHub repo link in the LinkedIn post
- [ ] Submit the task via the WhatsApp group submission form
