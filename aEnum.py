#!/usr/bin/env python

import os
import json
import subprocess
import sys
import nmap  # Python nmap library to run nmap scans and parse results
import socket  # Standard library for low-level networking interface
import requests  # Library to make HTTP requests to fetch data from APIs
import re  # Regular expressions library to validate IP addresses

# How to install the required libraries:
# For nmap and requests:
# pip install python-nmap requests
# For nmap (the command-line tool) and searchsploit:
# sudo apt update
# sudo apt install nmap exploitdb

# File to store installation and API key information
config_file = os.path.expanduser("~/.network_enum_config.json")

# Function to load config
def load_config():
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            return json.load(f)
    return {"libraries_installed": False, "nvd_api_key": "YOUR_DEFAULT_NVD_API_KEY", "vulners_api_key": "", "shodan_api_key": "", "last_target_ip": ""}

# Function to save config
def save_config(config):
    with open(config_file, 'w') as f:
        json.dump(config, f)

config = load_config()

# Function to check and install required libraries
def check_install(package):
    try:
        __import__(package)
    except ImportError:
        print(f"{package} is not installed. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Check for necessary libraries only if they haven't been checked before
if not config.get("libraries_installed", False):
    required_packages = ["nmap", "requests"]
    for package in required_packages:
        check_install(package)
    config["libraries_installed"] = True
    save_config(config)

# Function to get service description dynamically using DuckDuckGo
def get_service_description(port):
    try:
        service_name = socket.getservbyport(port)
        return f"{service_name} - {service_name.capitalize()} service"
    except OSError:
        return fetch_service_description_from_api(port)

# Function to fetch service description from an API (replace with actual API endpoint)
def fetch_service_description_from_api(port):
    try:
        response = requests.get(f"https://api.shodan.io/shodan/host/{port}")
        if response.status_code == 200:
            return response.json().get('description', 'Description not found')
        else:
            return "Description not found"
    except requests.RequestException:
        return "Description not found"

# Function to get common vulnerabilities using the NVD API
def get_vulnerabilities_from_nvd(port, api_key):
    if not api_key:
        return []
    
    try:
        response = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=port {port}&apiKey={api_key}")
        if response.status_code == 200:
            vulnerabilities = response.json().get('result', {}).get('CVE_Items', [])
            vuln_details = []
            for vuln in vulnerabilities:
                cve_id = vuln.get('cve', {}).get('CVE_data_meta', {}).get('ID', 'Unknown ID')
                description = vuln.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value', 'No description available')
                vuln_details.append(f"{cve_id}: {description}")
            return vuln_details if vuln_details else ["No common vulnerabilities identified"]
        else:
            return ["No common vulnerabilities identified"]
    except requests.RequestException:
        return ["No common vulnerabilities identified"]

# Function to get vulnerabilities using the Vulners API
def get_vulnerabilities_from_vulners(port, api_key):
    if not api_key:
        return []
    
    try:
        response = requests.get(f"https://vulners.com/api/v3/search/lucene/?query=port:{port}&apiKey={api_key}")
        if response.status_code == 200:
            vulnerabilities = response.json().get('data', {}).get('search', [])
            vuln_details = []
            for vuln in vulnerabilities:
                cve_id = vuln.get('cvelist', ['Unknown ID'])[0]
                description = vuln.get('title', 'No description available')
                vuln_details.append(f"{cve_id}: {description}")
            return vuln_details if vuln_details else ["No common vulnerabilities identified"]
        else:
            return ["No common vulnerabilities identified"]
    except requests.RequestException as e:
        print(f"RequestException: {e}")
        return ["No common vulnerabilities identified"]

# Function to get vulnerabilities using the Shodan API
def get_vulnerabilities_from_shodan(ip, api_key):
    if not api_key:
        return []
    
    try:
        response = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}")
        if response.status_code == 200:
            data = response.json()
            vuln_details = data.get('vulns', [])
            if vuln_details:
                return [f"{vuln}: {data['vulns'][vuln]}" for vuln in vuln_details]
            else:
                return ["No common vulnerabilities identified"]
        else:
            return ["No common vulnerabilities identified"]
    except requests.RequestException as e:
        print(f"RequestException: {e}")
        return ["No common vulnerabilities identified"]

# Function to combine vulnerabilities from multiple sources
def get_combined_vulnerabilities(port, nvd_api_key, vulners_api_key, ip, shodan_api_key):
    nvd_vulnerabilities = get_vulnerabilities_from_nvd(port, nvd_api_key)
    vulners_vulnerabilities = get_vulnerabilities_from_vulners(port, vulners_api_key)
    shodan_vulnerabilities = get_vulnerabilities_from_shodan(ip, shodan_api_key)
    combined_vulnerabilities = list(set(nvd_vulnerabilities + vulners_vulnerabilities + shodan_vulnerabilities))
    return combined_vulnerabilities

# Function to search Exploit-DB using searchsploit
def search_exploit_db(service):
    try:
        result = subprocess.run(['searchsploit', service], capture_output=True, text=True)
        exploits = result.stdout
        return exploits if exploits else "No exploits found."
    except Exception as e:
        return f"Error searching Exploit-DB: {e}"

# Function to validate IP or range input
def validate_ip_range(ip_range):
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$')
    return ip_pattern.match(ip_range) is not None

# Function to pretty-print vulnerabilities and next steps
def print_vulnerabilities(port, description, vulnerabilities):
    print(f"\nPort {port} ({description}) –")
    for vulnerability in vulnerabilities:
        print(f"  - {vulnerability}")
        if vulnerability != "No common vulnerabilities identified":
            print("    Suggested next steps:")
            print(f"    - Research more about '{vulnerability.split(':')[0]}'.")
            print(f"    - Use tools like Metasploit or search for specific exploits related to '{vulnerability.split(':')[0]}'.")
            print("    - Consider updating or reconfiguring the service to mitigate the vulnerability.")
            print("    - Conduct a thorough security audit of the service.")
            print("    - Review official documentation and security advisories for remediation guidance.")

# Function to perform the Nmap scan
def scan_target(nvd_api_key, vulners_api_key, shodan_api_key):
    if config.get("last_target_ip"):
        reuse_ip = input(f"Last target IP was {config['last_target_ip']}. Do you want to scan the same IP? (yes/no): ").strip().lower()
        if reuse_ip == 'yes':
            target_ip = config["last_target_ip"]
        else:
            target_ip = input("Enter the target IP or range (e.g., 192.168.1.1 or 192.168.1.1/24): ")
    else:
        target_ip = input("Enter the target IP or range (e.g., 192.168.1.1 or 192.168.1.1/24): ")

    if not validate_ip_range(target_ip):
        print("Invalid IP address or range format. Please try again.")
        return

    # Save the last target IP
    config["last_target_ip"] = target_ip
    save_config(config)

    # Suggested Nmap scan techniques for a thorough initial enumeration
    single_flags = {
        '-sn': "Ping scan to discover live hosts without scanning ports.",
        '-p-': "Scan all 65535 ports.",
        '-T4': "Sets aggressive timing for faster scans.",
        '-A': "Enables OS detection, version detection, script scanning, and traceroute.",
        '-v': "Increases verbosity for more detailed output.",
        '-sS': "Performs a stealth SYN scan without completing TCP handshake.",
        '-Pn': "Skips host discovery and treats all hosts as online.",
        '-sU': "Performs a UDP scan.",
        '-sT': "Performs a full TCP connect scan.",
        '-sV': "Detects service versions.",
        '-O': "Enables OS detection.",
        '-sA': "Performs a TCP ACK scan to determine firewall rules.",
        '-f': "Enables packet fragmentation to bypass firewalls and IDS."
    }

    scan_combinations = {
        '-p- -T4 -A -v': "Comprehensive scan: Scans all ports with aggressive timing, enables OS and version detection, and increases verbosity.",
        '-sS -T4 -Pn -p-': "Stealth SYN scan: Stealthily scans all ports with aggressive timing, skips host discovery.",
        '-sU -T4 -Pn -p-': "UDP scan: Scans all UDP ports with aggressive timing, skips host discovery.",
        '-sT -T4 -p-': "TCP connect scan: Full TCP connect scan on all ports with aggressive timing.",
        '-A -T4': "Aggressive scan: Enables OS and version detection, script scanning, and traceroute with aggressive timing."
    }

    print("\n\033[1m\033[94mSuggested Nmap scan techniques for a thorough initial enumeration:\033[0m")
    print("\033[1mSingle Flags:\033[0m")
    for flag, description in single_flags.items():
        print(f"  {flag}: {description}")
    
    print("\n\033[1mFlag Combinations:\033[0m")
    for method, description in scan_combinations.items():
        print(f"  {method}: {description}")

    selected_method = input("\nEnter the Nmap scan method to use (e.g., '-p- -T4 -A -v'): ")

    nm = nmap.PortScanner()
    open_ports = []
    use_pn = False

    while True:
        try:
            print(f"\nStarting scan with method: {selected_method}{' with -Pn' if use_pn else ''}")
            nm.scan(hosts=target_ip, arguments=f"{selected_method}{' -Pn' if use_pn else ''}")
            total_hosts = len(nm.all_hosts())
            print(f"Total hosts found: {total_hosts}")
            print("Scanning in progress...")

            for host in nm.all_hosts():
                if 'tcp' in nm[host]:
                    for port, info in nm[host]['tcp'].items():
                        if info.get('state') == 'open':
                            open_ports.append(port)
                if 'udp' in nm[host]:
                    for port, info in nm[host]['udp'].items():
                        if info.get('state') == 'open':
                            open_ports.append(port)
            if open_ports:
                break
            if total_hosts == 0:
                raise nmap.PortScannerError("No hosts found. The target might be down or blocking our probes.")
        except nmap.PortScannerError as e:
            print(f"Error during scan: {e}")
            if "No hosts found" in str(e) and not use_pn:
                print("Host seems down. Retrying with -Pn to skip host discovery...")
                use_pn = True
            else:
                retry = input("Scan failed. Would you like to try a different scan method? (yes/no): ")
                if retry.lower() == 'yes':
                    selected_method = input("Enter the Nmap scan method to use (e.g., '-p- -T4 -A -v'): ")
                else:
                    return

    print(f"\nOpen ports found: {open_ports}")

    if open_ports:
        print(f"\nI have found {len(open_ports)} open port(s) on {target_ip}:")
        for port in open_ports:
            description = get_service_description(port)
            vulnerabilities = get_combined_vulnerabilities(port, nvd_api_key, vulners_api_key, target_ip, shodan_api_key)
            print_vulnerabilities(port, description, vulnerabilities)
            exploits = search_exploit_db(description.split('-')[0].strip())  # Searching for the main service name
            print(f"\nExploits found:\n{exploits}")
            print("\nSuggested Next Steps for further enumeration and exploitation:")
            print(f"    - Run more detailed scans on port {port} using tools like Nessus or OpenVAS.")
            print(f"    - Search for potential exploits using Exploit-DB, Metasploit, or other exploit databases.")
            print(f"    - Investigate and analyze the service configuration for weaknesses and misconfigurations.")
    else:
        print(f"\nNo open ports found for {target_ip}.")

if __name__ == "__main__":
    # Introduction for beginners
    print("\033[1m\033[94mWelcome to the Network Enumeration Script!\033[0m")
    print("\033[1mThis script will help you perform an initial network enumeration using Nmap and gather vulnerability information.\033[0m")
    print("Please follow the prompts and read the comments for guidance on each step.")
    print("For more information, please refer to the README.md file.")
    print("\033[1mLet's get started!\033[0m\n")
    
    # Load keys from the configuration file
    config = load_config()
    nvd_api_key = config.get("nvd_api_key", "YOUR_DEFAULT_NVD_API_KEY")
    vulners_api_key = config.get("vulners_api_key", "")
    shodan_api_key = config.get("shodan_api_key", "")

    # Prompt the user if they have private API keys
    while True:
        use_private_keys = input("Do you have private API keys for Vulners or Shodan? (yes/no): ").strip().lower()
        if use_private_keys in ['yes', 'no']:
            break
        else:
            print("Please enter 'yes' or 'no'.")

    if use_private_keys == 'yes':
        vulners_api_key = input("Enter your Vulners API key (leave blank to skip Vulners lookup): ").strip()
        shodan_api_key = input("Enter your Shodan API key (leave blank to skip Shodan lookup): ").strip()

    # Save keys back to the config file
    config["nvd_api_key"] = nvd_api_key
    config["vulners_api_key"] = vulners_api_key
    config["shodan_api_key"] = shodan_api_key
    save_config(config)
    
    scan_target(nvd_api_key, vulners_api_key, shodan_api_key)
