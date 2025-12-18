## 🛡️ Sentinel Pro: Phoenix Edition
Sentinel Pro is a modern, high-performance Network Analysis and Penetration Testing Suite designed for security professionals and network administrators. Moving beyond simple packet capturing, the Phoenix Edition introduces a modular "Glassmorphism" interface, real-time analytics, and a hybrid scanning engine built for stability and deep reconnaissance.

## ✨ Key Features
### 🔍 Advanced Packet Inspector (Wireshark-Style)
Three-Pane View: Analyze traffic through a real-time list, a detailed protocol tree (IP, TCP, TLS layers), and a raw Hex Dump.

Website & Domain Detection: Identifies the actual websites being visited (e.g., github.com) by extracting the TLS Server Name Indication (SNI) from encrypted handshakes.

Device Identification: Automatically maps IP addresses to hardware manufacturers using an integrated MAC Vendor database.

## 🌐 Network Mapper & Intelligence
Hybrid Scanning Engine: Uses a reliable TCP-Connect method to bypass modern firewalls and accurately identify open ports on local and remote targets.

Banner Grabbing: Automatically extracts service versions and "Welcome Banners" from open ports for deep reconnaissance.

OS Fingerprinting: Analyzes packet TTL (Time To Live) to intelligently guess the target's Operating System (Windows vs. Linux/Unix).

## 📊 Professional UI & Analytics
Cyberpunk Glassmorphism: A stunning Windows 11/12 inspired "Mica" interface with glowing accents, animated sidebars, and high-contrast dark mode.

Live Throughput Visualization: Real-time throughput graph (Packets/Sec) integrated directly into the dashboard.

Modular Landing Page: Access specialized tools like the Packet Sniffer, Port Scanner, and Security Auditor from a central hub.

## 🛠️ Technology Stack
Backend: Python 3, Scapy (Packet Manipulation).

Frontend: PyQt6 (GUI), Matplotlib (Analytics), Qt-Material (Theming).

System: psutil (Interface detection), Cryptography (TLS/SSL decryption).

## 🚀 Getting Started
### Prerequisites
Ensure you have Python 3.10+ installed. This tool requires administrative privileges to access network hardware.

### Installation
Clone the repository:

### Bash

git clone https://github.com/amrindersingh1820/network-packet-capturing-tool.git
Install dependencies:

### Bash

pip install -r requirements.txt
Run with administrative privileges:

### Bash

sudo python live_packet_analyzer.py
## ⚠️ Disclaimer
This tool is intended for educational and ethical security testing purposes only. Unauthorized use of this tool for network interference or data interception is strictly prohibited.

## 👤 Author
### Developed by Amrinder Singh
