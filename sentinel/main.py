"""
SentinelNet
Network Intrusion Detection System (NIDS)

The main application's entry point.
"""

APP_NAME = "SentinelNet"
VERSION = "0.1.0"


def print_banner() -> None:
    """Display SentinelNet startup information."""

    print("=" * 50)
    print(f"{APP_NAME} - Network Intrusion Detection System")
    print(f"Version: {VERSION}")
    print("=" * 50)


def main() -> None:
    """Start the SentinelNet application."""

    print_banner()

    print("[INFO] Initializing SentinelNet...")
    print("[INFO] System ready.")


if __name__ == "__main__":
    main()