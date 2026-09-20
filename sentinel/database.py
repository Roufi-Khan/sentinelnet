"""
Database functionality for SentinelNet.

This part manages the SQLite database used to persist
network event metadata.
"""

import sqlite3
from pathlib import Path
from typing import Any


DEFAULT_DATABASE_PATH = Path("sentinelnet.db")


def create_connection(
    database_path: Path = DEFAULT_DATABASE_PATH,
) -> sqlite3.Connection:
    """
    Create and return a connection to the SentinelNet database.
    """

    return sqlite3.connect(database_path)


def initialize_database(
    database_path: Path = DEFAULT_DATABASE_PATH,
) -> None:
    """
    Create the database tables required by SentinelNet.
    """

    with create_connection(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS network_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                source_port INTEGER,
                destination_port INTEGER,
                tcp_flags TEXT,
                packet_length INTEGER NOT NULL
            )
            """
        )


def log_network_event(
    packet_info: dict[str, Any],
    database_path: Path = DEFAULT_DATABASE_PATH,
) -> None:
    """
    Store the analyzed packet metadata in the database.
    """

    with create_connection(database_path) as connection:
        connection.execute(
            """
            INSERT INTO network_events (
                source_ip,
                destination_ip,
                protocol,
                source_port,
                destination_port,
                tcp_flags,
                packet_length
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                packet_info["source_ip"],
                packet_info["destination_ip"],
                packet_info["protocol"],
                packet_info["source_port"],
                packet_info["destination_port"],
                packet_info["tcp_flags"],
                packet_info["length"],
            ),
        )