# Network Enumeration Script

## Backstory

This script was fully written by ChatGPT 4. What led me to spend several hours developing this script through ChatGPT? 

- **Curiosity**: To prove it can be done.
- **Situation**: I was down with Covid and had nothing better to do :)
- **Laziness**: I wanted to know if there are simpler ways to perform network enumeration when you have time for HackTheBox once per year.
- **Noob**: I am both penetration testing and coding noob.

## Purpose

This script helps you perform an initial network enumeration using Nmap and gather information about potential vulnerabilities and available exploits. It guides you through each step, making it suitable for beginners in penetration testing.

## Features

- **Nmap Scanning**: Perform various Nmap scans to enumerate network hosts and services.
- **Vulnerability Lookup**: Fetch vulnerability information from NVD, Vulners, and Shodan APIs.
- **Exploit Search**: Search for potential exploits using Exploit-DB.
- **Configuration Handling**: Saves API keys and the last scanned IP address for convenience.

## Prerequisites

- **Python 3.x**: Ensure you have Python 3.x installed.
- **Required Libraries**: The script will check and install the following libraries if not already installed:
  - `nmap`
  - `requests`

## Installation

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/your-username/aEnum.git
    cd aEnum
    ```

2. **Install Dependencies**:
    ```bash
    pip install python-nmap requests
    sudo apt update
    sudo apt install nmap exploitdb
    ```

## Usage

1. **Run the Script**:
    ```bash
    sudo python ./aEnum.py
    ```

2. **Follow the Prompts**:
    - **API Keys**: Enter your API keys for Vulners and Shodan when prompted. These will be saved for future use.
    - **IP Address**: Enter the target IP address or range. The script can reuse the last scanned IP.
    - **Nmap Scan Method**: Choose from the suggested Nmap scan techniques.

## Nmap Scan Techniques

### Single Flags

- **`-sn`**: Ping scan to discover live hosts without scanning ports.
- **`-p-`**: Scan all 65535 ports.
- **`-T4`**: Sets aggressive timing for faster scans.
- **`-A`**: Enables OS detection, version detection, script scanning, and traceroute.
- **`-v`**: Increases verbosity for more detailed output.
- **`-sS`**: Performs a stealth SYN scan without completing TCP handshake.
- **`-Pn`**: Skips host discovery and treats all hosts as online.
- **`-sU`**: Performs a UDP scan.
- **`-sT`**: Performs a full TCP connect scan.
- **`-sV`**: Detects service versions.
- **`-O`**: Enables OS detection.
- **`-sA`**: Performs a TCP ACK scan to determine firewall rules.
- **`-f`**: Enables packet fragmentation to bypass firewalls and IDS.

### Flag Combinations

- **`-p- -T4 -A -v`**: Comprehensive scan: Scans all ports with aggressive timing, enables OS and version detection, and increases verbosity.
- **`-sS -T4 -Pn -p-`**: Stealth SYN scan: Stealthily scans all ports with aggressive timing, skips host discovery.
- **`-sU -T4 -Pn -p-`**: UDP scan: Scans all UDP ports with aggressive timing, skips host discovery.
- **`-sT -T4 -p-`**: TCP connect scan: Full TCP connect scan on all ports with aggressive timing.
- **`-A -T4`**: Aggressive scan: Enables OS and version detection, script scanning, and traceroute with aggressive timing.

## Detailed Steps in the Script

1. **Check and Install Required Libraries**:
    - Uses `subprocess` to install missing libraries if they are not already installed.
    
2. **Configuration Handling**:
    - Saves API keys and the last scanned IP to `~/.network_enum_config.json`.
    
3. **Nmap Scan Execution**:
    - Prompts the user to select an Nmap scan method and validates the input.
    - Performs the scan and identifies open ports.
    
4. **Vulnerability Lookup**:
    - Fetches vulnerabilities from NVD, Vulners, and Shodan APIs.
    
5. **Exploit Search**:
    - Uses `searchsploit` to find potential exploits for the discovered services.

## Additional Resources

- **Nmap Documentation**: https://nmap.org/book/man.html
- **Vulners API**: https://vulners.com/
- **Shodan API**: https://developer.shodan.io/api
- **Exploit-DB**: https://www.exploit-db.com/
- **HTB Academy**: https://academy.hackthebox.com/

---

Happy scanning! 🛡️
