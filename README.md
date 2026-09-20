# SentinelNet

SentinelNet is a network monitoring and intrusion detection project I'm building in Python to get more hands-on experience with networking and cybersecurity.

The project currently captures network traffic using Scapy, extracts basic TCP/UDP packet information, and uses SQLite for storing network event data.

## Current Features

- Live packet capture with Scapy
- IPv4 packet analysis
- TCP and UDP metadata extraction
- TCP flag inspection
- SQLite event storage
- Basic automated tests with pytest

## In Progress

I'm currently working on connecting packet capture more fully with event storage and building the detection side of the project.

Planned additions include:

- Port scan detection
- Suspicious connection-rate detection
- Alert generation
- Traffic statistics
- Simple monitoring dashboard

## Technologies

- Python
- Scapy
- SQLite
- pytest

## Structure

```text
sentinelnet/
├── sentinel/
│   ├── analyzer.py
│   ├── capture.py
│   ├── database.py
│   └── main.py
├── tests/
├── requirements.txt
└── README.md