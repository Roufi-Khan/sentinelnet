"""
Tests for SentinelNet database operations.
"""

from pathlib import Path

from sentinel.database import initialize_database, log_network_event


def test_database_initialization(tmp_path: Path) -> None:
    """Checks that database initialization creates the database file."""

    database_path = tmp_path / "test.db"

    initialize_database(database_path)

    assert database_path.exists()


def test_network_event_logging(tmp_path: Path) -> None:
    """Check that analyzed packet metadata can be stored."""

    database_path = tmp_path / "test.db"

    initialize_database(database_path)

    packet_info = {
        "source_ip": "192.168.1.10",
        "destination_ip": "8.8.8.8",
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": 443,
        "tcp_flags": "S",
        "length": 40,
    }

    log_network_event(packet_info, database_path)

    import sqlite3

    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT
                source_ip,
                destination_ip,
                protocol,
                source_port,
                destination_port,
                tcp_flags,
                packet_length
            FROM network_events
            """
        ).fetchone()

    assert row == (
        "192.168.1.10",
        "8.8.8.8",
        "TCP",
        50000,
        443,
        "S",
        40,
    )