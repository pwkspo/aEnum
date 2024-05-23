
# Network Enumeration Script

Welcome to the Network Enumeration Script! This script is designed to help you perform an initial network enumeration using Nmap and gather vulnerability information. It's especially helpful for beginners learning about network security and penetration testing.

## Features

- Perform Nmap scans with various techniques
- Retrieve and display service descriptions
- Fetch vulnerabilities from NVD, Vulners, and Shodan
- Search for exploits using Exploit-DB
- Save and reuse API keys and the last used target IP

## Requirements

- Python 3.x
- Nmap
- Searchsploit

## Installation

### Python Libraries

Install the required Python libraries using pip:
```bash
pip install python-nmap requests
System Tools
Install Nmap and Searchsploit:

bash
Copy code
sudo apt update
sudo apt install nmap exploitdb
Usage
Run the Script:

bash
Copy code
sudo python ./aEnum.py
Follow the Prompts:

You will be asked if you have private API keys for Vulners or Shodan.
Enter the target IP or range.
Choose an Nmap scan method from the provided suggestions.
Nmap Scan Techniques
The script provides suggestions for various Nmap scan techniques. Below are the explanations:

Single Flags:
-sn: Ping scan to discover live hosts without scanning ports.
-p-: Scan all 65535 ports.
-T4: Sets aggressive timing for faster scans.
-A: Enables OS detection, version detection, script scanning, and traceroute.
-v: Increases verbosity for more detailed output.
-sS: Performs a stealth SYN scan without completing TCP handshake.
-Pn: Skips host discovery and treats all hosts as online.
-sU: Performs a UDP scan.
-sT: Performs a full TCP connect scan.
-sV: Detects service versions.
-O: Enables OS detection.
-sA: Performs a TCP ACK scan to determine firewall rules.
-f: Enables packet fragmentation to bypass firewalls and IDS.
Flag Combinations:
-p- -T4 -A -v: Comprehensive scan: Scans all ports with aggressive timing, enables OS and version detection, and increases verbosity.
-sS -T4 -Pn -p-: Stealth SYN scan: Stealthily scans all ports with aggressive timing, skips host discovery.
-sU -T4 -Pn -p-: UDP scan: Scans all UDP ports with aggressive timing, skips host discovery.
-sT -T4 -p-: TCP connect scan: Full TCP connect scan on all ports with aggressive timing.
-A -T4: Aggressive scan: Enables OS and version detection, script scanning, and traceroute with aggressive timing.
Script Flow
Introduction
The script will print an introduction and provide guidance on what it does.
Configuration File
The script checks for and loads a configuration file (~/.network_enum_config.json) to store API keys and the last used target IP.
API Key Prompts
The script asks if you have private API keys for Vulners or Shodan. If you provide them, they will be saved in the configuration file for future use.
Target IP Prompt
If a target IP was used in a previous scan, the script asks if you want to reuse it. Otherwise, it prompts for a new target IP.
Nmap Scan Method Selection
The script provides suggested Nmap scan methods, with explanations for single flags and useful combinations. You can choose a method or enter a custom one.
Scan Execution and Results
The script executes the chosen Nmap scan method.
Displays open ports and their service descriptions.
Fetches vulnerabilities from NVD, Vulners, and Shodan.
Searches for exploits using Exploit-DB.
Provides suggested next steps for further enumeration and exploitation.
Example Output
vbnet
Copy code
Welcome to the Network Enumeration Script!
This script will help you perform an initial network enumeration using Nmap and gather vulnerability information.
Please follow the prompts and read the comments for guidance on each step.
For more information, please refer to the README.md file.
Let's get started!

Do you have private API keys for Vulners or Shodan? (yes/no): yes
Enter your Vulners API key (leave blank to skip Vulners lookup): YOUR_VULNERS_API_KEY
Enter your Shodan API key (leave blank to skip Shodan lookup): YOUR_SHODAN_API_KEY
Enter the target IP or range (e.g., 192.168.1.1 or 192.168.1.1/24): 192.168.1.1

Suggested Nmap scan techniques for a thorough initial enumeration:
Single Flags:
  -sn: Ping scan to discover live hosts without scanning ports.
  -p-: Scan all 65535 ports.
  -T4: Sets aggressive timing for faster scans.
  -A: Enables OS detection, version detection, script scanning, and traceroute.
  -v: Increases verbosity for more detailed output.
  -sS: Performs a stealth SYN scan without completing TCP handshake.
  -Pn: Skips host discovery and treats all hosts as online.
  -sU: Performs a UDP scan.
  -sT: Performs a full TCP connect scan.
  -sV: Detects service versions.
  -O: Enables OS detection.
  -sA: Performs a TCP ACK scan to determine firewall rules.
  -f: Enables packet fragmentation to bypass firewalls and IDS.

Flag Combinations:
  -p- -T4 -A -v: Comprehensive scan: Scans all ports with aggressive timing, enables OS and version detection, and increases verbosity.
  -sS -T4 -Pn -p-: Stealth SYN scan: Stealthily scans all ports with aggressive timing, skips host discovery.
  -sU -T4 -Pn -p-: UDP scan: Scans all UDP ports with aggressive timing, skips host discovery.
  -sT -T4 -p-: TCP connect scan: Full TCP connect scan on all ports with aggressive timing.
  -A -T4: Aggressive scan: Enables OS and version detection, script scanning, and traceroute with aggressive timing.

Enter the Nmap scan method to use (e.g., '-p- -T4 -A -v'): -p-

Starting scan with method: -p-
Total hosts found: 1
Scanning in progress...

Open ports found: [6379]

I have found 1 open port(s) on 192.168.1.1:

Port 6379 (redis - Redis service) –
  - No common vulnerabilities identified
  - API key not provided, skipping Shodan lookup.
    Suggested next steps:
    - Research more about 'API key not provided, skipping Shodan lookup.'.
    - Use tools like Metasploit or search for specific exploits related to 'API key not provided, skipping Shodan lookup.'.
    - Consider updating or reconfiguring the service to mitigate the vulnerability.
    - Conduct a thorough security audit of the service.
    - Review official documentation and security advisories for remediation guidance.
  - No common vulnerabilities identified
  - API key not provided, skipping NVD lookup.
    Suggested next steps:
    - Research more about 'API key not provided, skipping NVD lookup.'.
    - Use tools like Metasploit or search for specific exploits related to 'API key not provided, skipping NVD lookup.'.
    - Consider updating or reconfiguring the service to mitigate the vulnerability.
    - Conduct a thorough security audit of the service.
    - Review official documentation and security advisories for remediation guidance.

Exploits found:
------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                        |  Path
------------------------------------------------------------------------------------------------------ ---------------------------------
Redis - Replication Code Execution (Metasploit)                                                       | linux/remote/48272.rb
Redis 4.x / 5.x - Unauthenticated Code Execution (Metasploit)                                         | linux/remote/47195.rb
Redis 5.0 - Denial of Service                                                                         | linux/dos/44908.txt
Redis-cli < 5.0 - Buffer Overflow (PoC)                                                               | linux/local/44904.py
------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results

Suggested Next Steps for further enumeration and exploitation:
    - Run more detailed scans on port 6379 using tools like Nessus or OpenVAS.
    - Search for potential exploits using Exploit-DB, Metasploit, or other exploit databases.
    - Investigate and analyze the service configuration for weaknesses and misconfigurations.
Learning Resources
For more information and to further enhance your skills, consider exploring the following resources:

Hack The Box Academy - Network Enumeration with Nmap
Nmap Official Documentation
StationX - Nmap Cheat Sheet
Exploit Database - Searchsploit
Happy scanning! 🌐🔍🛡️