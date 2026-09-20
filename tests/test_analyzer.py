"""
Tests for SentinelNet's packet analysis.
"""

from scapy.all import IP, TCP, UDP

from sentinel.analyzer import analyze_packet


def test_tcp_packet_analysis() -> None:
    """Verify that the TCP packet metadata is extracted correctly."""

    packet = IP(
        src="192.168.1.10",
        dst="8.8.8.8",
    ) / TCP(
        sport=50000,
        dport=443,
        flags="S",
    )

    result = analyze_packet(packet)

    assert result is not None
    assert result["source_ip"] == "192.168.1.10"
    assert result["destination_ip"] == "8.8.8.8"
    assert result["protocol"] == "TCP"
    assert result["source_port"] == 50000
    assert result["destination_port"] == 443
    assert result["tcp_flags"] == "S"


def test_udp_packet_analysis() -> None:
    """Verify that the UDP packet metadata is extracted correctly."""

    packet = IP(
        src="192.168.1.20",
        dst="8.8.8.8",
    ) / UDP(
        sport=53000,
        dport=53,
    )

    result = analyze_packet(packet)

    assert result is not None
    assert result["source_ip"] == "192.168.1.20"
    assert result["destination_ip"] == "8.8.8.8"
    assert result["protocol"] == "UDP"
    assert result["source_port"] == 53000
    assert result["destination_port"] == 53
    assert result["tcp_flags"] is None