#!/usr/bin/env python3
"""
CodeAlpha Cybersecurity Internship - Task 1
Basic Network Sniffer

Captures live network traffic and displays:
- Source / Destination IP addresses
- Protocol (TCP / UDP / ICMP / ARP / Other)
- Source / Destination ports (for TCP/UDP)
- A preview of the packet payload

Requires: scapy  ->  pip install scapy
Must be run with administrator/root privileges.
On Windows, Npcap (https://npcap.com) must also be installed.
"""

import argparse
import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, get_if_list


def get_protocol_name(packet):
    """Return a human-readable protocol name for the packet."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    elif packet.haslayer(ARP):
        return "ARP"
    else:
        return "OTHER"


def format_payload(packet, max_len=64):
    """Extract and safely format a short preview of the raw payload."""
    if packet.haslayer(Raw):
        raw_bytes = bytes(packet[Raw].load)
        # Try to decode as text, fall back to hex if it's binary garbage
        try:
            text = raw_bytes.decode("utf-8")
            text = "".join(ch if ch.isprintable() else "." for ch in text)
        except UnicodeDecodeError:
            text = raw_bytes.hex()
        return text[:max_len] + ("..." if len(text) > max_len else "")
    return ""


def process_packet(packet, verbose=False):
    """Callback invoked for every captured packet."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    protocol = get_protocol_name(packet)

    # ARP doesn't carry an IP layer the same way, handle separately
    if packet.haslayer(ARP):
        arp = packet[ARP]
        print(f"[{timestamp}] ARP      {arp.psrc:<15} -> {arp.pdst:<15} "
              f"(op={'request' if arp.op == 1 else 'reply'})")
        return

    if not packet.haslayer(IP):
        return  # Skip non-IP, non-ARP packets (e.g. some link-layer frames)

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    src_port = dst_port = None
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    port_info = f"{src_port} -> {dst_port}" if src_port else ""
    line = f"[{timestamp}] {protocol:<8} {src_ip:<15} -> {dst_ip:<15} {port_info}"
    print(line)

    if verbose:
        payload = format_payload(packet)
        if payload:
            print(f"            Payload: {payload}")


def list_interfaces():
    print("Available network interfaces:")
    for iface in get_if_list():
        print(f"  - {iface}")


def main():
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer (CodeAlpha Task 1)"
    )
    parser.add_argument(
        "-i", "--interface", default=None,
        help="Network interface to sniff on (default: scapy auto-selects)"
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        help="Number of packets to capture (default: 0 = infinite, stop with Ctrl+C)"
    )
    parser.add_argument(
        "-f", "--filter", default="",
        help='BPF filter, e.g. "tcp port 80" or "icmp" (default: capture everything)'
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show a preview of each packet's payload"
    )
    parser.add_argument(
        "--list-interfaces", action="store_true",
        help="List available network interfaces and exit"
    )
    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    print("=" * 70)
    print(" CodeAlpha Cybersecurity - Basic Network Sniffer")
    print(" Press Ctrl+C to stop")
    print("=" * 70)

    try:
        sniff(
            iface=args.interface,
            filter=args.filter if args.filter else None,
            prn=lambda pkt: process_packet(pkt, verbose=args.verbose),
            count=args.count if args.count > 0 else 0,
            store=False,
        )
    except PermissionError:
        print("\n[!] Permission denied. Run this script as Administrator/root.")
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped by user.")


if __name__ == "__main__":
    main()
