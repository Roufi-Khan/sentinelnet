"""
Packet analysis functionality for SentinelNet.

This part extracts useful network metadata from packets captured
by Scapy. Payload contents are not inspected by choice.
"""

from typing import Any

from scapy.all import IP, TCP, UDP, Packet


def analyze_packet(packet: Packet) -> dict[str, Any] | None:
    """
    Extract useful metadata from an IPv4 network packet.

    Args:
        packet:
            A Scapy packet captured from a network interface.

    Returns:
        A dictionary containing the packet metadata, or None when the
        packet doesn't contain an IPv4 layer.
    """

    if IP not in packet:
        return None

    ip_layer = packet[IP]

    packet_info: dict[str, Any] = {
        "source_ip": ip_layer.src,
        "destination_ip": ip_layer.dst,
        "protocol": "OTHER",
        "source_port": None,
        "destination_port": None,
        "tcp_flags": None,
        "length": len(packet),
    }

    if TCP in packet:
        tcp_layer = packet[TCP]

        packet_info["protocol"] = "TCP"
        packet_info["source_port"] = tcp_layer.sport
        packet_info["destination_port"] = tcp_layer.dport
        packet_info["tcp_flags"] = str(tcp_layer.flags)

    elif UDP in packet:
        udp_layer = packet[UDP]

        packet_info["protocol"] = "UDP"
        packet_info["source_port"] = udp_layer.sport
        packet_info["destination_port"] = udp_layer.dport

    return packet_info