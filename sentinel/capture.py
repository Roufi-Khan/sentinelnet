"""
Network packet capture functionality for SentinelNet.

This part captures packets from a network interface and passes
them to the packet analyzer.
"""

from scapy.all import Packet, sniff

from sentinel.analyzer import analyze_packet
from sentinel.database import log_network_event


def handle_packet(packet: Packet) -> None:
    """
    Analyze, store, and display metadata for a captured packet.

    Packets that are not currently supported by the analyzer
    are ignored.
    """

    packet_info = analyze_packet(packet)

    if packet_info is None:
        return

    log_network_event(packet_info)

    print(
        f"[PACKET] "
        f"{packet_info['protocol']} | "
        f"{packet_info['source_ip']}:{packet_info['source_port']} -> "
        f"{packet_info['destination_ip']}:{packet_info['destination_port']} | "
        f"Flags: {packet_info['tcp_flags']} | "
        f"Length: {packet_info['length']} bytes"
    )


def capture_packets(interface: str | None = None, count: int = 10) -> None:
    """
    Capture a limited number of packets from a network interface.

    Args:
        interface:
            Name of the network interface to monitor.
            If None, Scapy chooses an appropriate interface.

        count:
            Number of packets to capture before stopping.
    """

    print("[INFO] Starting packet capture...")
    print(f"[INFO] Packet limit: {count}")

    if interface:
        print(f"[INFO] Interface: {interface}")
    else:
        print("[INFO] Interface: Scapy default")

    sniff(
        iface=interface,
        prn=handle_packet,
        count=count,
        store=False,
    )

    print("[INFO] Packet capture complete.")