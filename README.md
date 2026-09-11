# WiFi Security Analyzer

A Python-based network security analysis tool that analyzes captured network traffic and displays security findings through a Flask dashboard.

## Overview

The WiFi Security Analyzer analyzes network packet data to identify traffic patterns and potential security concerns. The project uses Scapy to process packet captures and Flask to display the results in a web-based dashboard.

## Technologies Used

- Python
- Scapy
- Wireshark
- Flask
- TCP/IP
- DNS
- HTTP

## Features

- Analyzes captured network packets
- Counts TCP, DNS, and HTTP traffic
- Identifies unique IP addresses
- Detects insecure HTTP traffic
- Flags unusually high DNS activity
- Identifies high numbers of external connections
- Displays the five most contacted IP addresses
- Presents results through a Flask web dashboard

## How It Works

1. Network traffic is captured and saved as a PCAP file.
2. Scapy reads and analyzes the captured packets.
3. The analyzer identifies TCP, DNS, HTTP, and IP activity.
4. Basic security checks flag potentially concerning traffic patterns.
5. Flask displays the analysis through a web-based dashboard.

## Project Files

- `analyzer.py` — Performs packet analysis and generates security findings.
- `app.py` — Runs the Flask dashboard and displays analysis results.

> The original packet capture is not included because network captures may contain sensitive network information.

## Author

**Anmol Sandhu**  
B.S. Information Technology — Cloud Computing  
George Mason University | May 2027
