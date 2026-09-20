"""
SentinelNet
Network Intrusion Detection System

Main application's entry point.
"""

from sentinel.database import initialize_database


APP_NAME = "SentinelNet"
VERSION = "0.1.0"


def print_banner() -> None:
    """Display SentinelNet startup information."""

    print("=" * 50)
    print(f"{APP_NAME} - Network Intrusion Detection System")
    print(f"Version: {VERSION}")
    print("=" * 50)


def main() -> None:
    """Initialize and start SentinelNet."""

    print_banner()

    print("[INFO] Initializing SentinelNet...")

    initialize_database()

    print("[INFO] Database ready.")
    print("[INFO] System ready.")


if __name__ == "__main__":
    main()