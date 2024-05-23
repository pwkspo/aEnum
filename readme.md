# Network Enumeration Script

## Purpose
This script is designed to help beginners perform an initial network enumeration using Nmap. It scans a target IP or range of IPs, identifies open ports, fetches service descriptions, looks for common vulnerabilities, and searches for potential exploits. The script is educational, providing detailed explanations and guidance throughout the process.

## How It Works
1. **Input**: The user is prompted to enter a target IP address or range (e.g., `192.168.1.1` or `192.168.1.1/24`).
2. **Nmap Scan**: The script uses Nmap to perform various types of scans to identify open ports and gather information about the services running on those ports.
3. **Service Description**: For each open port, the script fetches a description of the service running on that port.
4. **Vulnerability Lookup**: The script looks up common vulnerabilities associated with the identified services using the NVD and Vulners APIs.
5. **Exploit Search**: The script searches Exploit-DB for potential exploits related to the identified services.
6. **Results**: The script prints the open ports, service descriptions, vulnerabilities, and potential exploits, along with suggestions for further enumeration and exploitation.

## How to Use

### Prerequisites
1. **Python**: Make sure you have Python installed on your system. You can download it from [python.org](https://www.python.org/).
2. **Nmap**: Nmap should be installed on your system. You can install it using the following command:
   ```sh
   sudo apt update
   sudo apt install nmap
   ```
3. **Exploit-DB**: The `searchsploit` tool should be installed. You can install it using:
   ```sh
   sudo apt update
   sudo apt install exploitdb
   ```
4. **Python Libraries**: Install the required Python libraries using pip:
   ```sh
   pip install python-nmap requests
   ```

### Running the Script
1. **Download the Script**: Save the script to a file, e.g., `network_enum.py`.
2. **Make the Script Executable**: If necessary, make the script executable:
   ```sh
   chmod +x network_enum.py
   ```
3. **Run the Script**: Execute the script with sudo to ensure it has the necessary permissions to perform network scans:
   ```sh
   sudo python network_enum.py
   ```

### Script Walkthrough
1. **Welcome Message**: The script will display a welcome message and guide you through the process.
2. **Input Target**: Enter the target IP address or range when prompted.
3. **Scanning**: The script will perform multiple Nmap scans, displaying progress and details about each scan.
4. **Results**: After scanning, the script will display the open ports, service descriptions, vulnerabilities, and potential exploits.
5. **Suggestions**: The script will provide suggestions for further enumeration and exploitation based on the results.

## Understanding the Script

### Library Imports
- **nmap**: Used to run Nmap scans and parse the results.
- **socket**: Provides a low-level networking interface.
- **requests**: Makes HTTP requests to fetch data from APIs.
- **re**: Uses regular expressions to validate IP addresses.
- **subprocess**: Runs shell commands from within the script.

### Nmap Scan Techniques
The script uses multiple Nmap scan techniques for thorough initial enumeration:

1. **Comprehensive Scan**
   - **Command**: `-p- -T4 -A -v`
   - **Explanation**:
     - `-p-`: Scans all 65535 ports.
     - `-T4`: Sets the timing template to level 4 (aggressive), making the scan faster by reducing the time between probes.
     - `-A`: Enables OS detection, version detection, script scanning, and traceroute. Provides detailed information about the target.
     - `-v`: Increases verbosity, providing more details during the scan.

2. **SYN Scan**
   - **Command**: `-sS -T4 -Pn -p-`
   - **Explanation**:
     - `-sS`: Performs a SYN scan, which is stealthier and faster than a full TCP connect scan. It does not complete the TCP handshake, making it less likely to be logged. This scan sends a SYN packet and waits for a response:
       - **SYN/ACK**: Indicates the port is open.
       - **RST**: Indicates the port is closed.
       - **No response**: Indicates the port is filtered by a firewall.
     - `-T4`: Sets the timing template to level 4 (aggressive), making the scan faster by reducing the time between probes.
     - `-Pn`: Disables host discovery, treating the targets as online, useful when ICMP pings are blocked.
     - `-p-`: Scans all 65535 ports.

3. **UDP Scan**
   - **Command**: `-sU -T4 -Pn -p-`
   - **Explanation**:
     - `-sU`: Performs a UDP scan, which is necessary to detect services running on UDP ports.
     - `-T4`: Sets the timing template to level 4 (aggressive), making the scan faster by reducing the time between probes.
     - `-Pn`: Disables host discovery, treating the targets as online, useful when ICMP pings are blocked.
     - `-p-`: Scans all 65535 ports.

4. **TCP Connect Scan**
   - **Command**: `-sT -T4 -p-`
   - **Explanation**:
     - `-sT`: Performs a full TCP connect scan, which is less stealthy but more reliable on networks where SYN scan is not allowed. This scan completes the three-way TCP handshake:
       - **SYN**: Client sends a SYN packet to the server.
       - **SYN/ACK**: Server responds with a SYN/ACK packet.
       - **ACK**: Client sends an ACK packet, completing the connection.
     - `-T4`: Sets the timing template to level 4 (aggressive), making the scan faster by reducing the time between probes.
     - `-p-`: Scans all 65535 ports.

### Service Descriptions and Vulnerabilities
- **Service Descriptions**: For each open port, the script fetches a description of the service running on that port using predefined descriptions and dynamic search.
- **Vulnerability Lookup**: The script looks up common vulnerabilities associated with the identified services using the NVD and Vulners APIs.

### Exploit Search
- **Exploit-DB**: The script uses `searchsploit` to find potential exploits on Exploit-DB related to the identified services.

### Suggested Next Steps
After displaying the results, the script provides suggestions for further enumeration and exploitation:
- Run more detailed scans using tools like Nessus or OpenVAS.
- Use search engines like Exploit-DB to find potential exploits for the identified services.
- Investigate and analyze the service configuration for weaknesses and misconfigurations.

## Noob's Introduction to Enumeration Techniques

### Nmap
Nmap (Network Mapper) is a powerful open-source tool used for network discovery and security auditing. It helps in identifying open ports, running services, and the operating systems of the target machines. Some common Nmap scan types include:
- **SYN Scan**: A stealthy scan that sends SYN packets and waits for a response without completing the TCP handshake. It is often used because it is faster and less likely to be detected by firewalls.
- **TCP Connect Scan**: Establishes a full TCP connection, making it more reliable but less stealthy. This scan completes the three-way TCP handshake, which makes it more likely to be logged.
- **UDP Scan**: Scans for services running on UDP ports, which can be slower and less reliable than TCP scans. UDP scanning is essential for discovering services that use the UDP protocol, such as DNS and SNMP.
- **Comprehensive Scan**: Combines multiple options to provide detailed information about the target, including OS and version detection.

### Vulnerability Scanning
Vulnerability scanning involves checking the target for known vulnerabilities using databases like the National Vulnerability Database (NVD) and Vulners. These databases maintain information about security vulnerabilities, including descriptions, severity levels, and mitigation steps.

### Exploit Research
After identifying vulnerabilities, the next step is to find potential exploits that can be used to take advantage of those vulnerabilities. Exploit-DB is a popular database of publicly available exploits. Tools like `searchsploit` allow you to search this database for relevant exploits.

## Resources for Further Learning
- [Nmap Official Website](https://nmap.org/)
- [Nmap Network Scanning Guide](https://nmap.org/book/)
- [Exploit-DB](https://www.exploit-db.com/)
- [NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [Vulners](https://vulners.com/)
- [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/)
- [OWASP (Open Web Application Security Project)](https://owasp.org/)


## Example Output
   ```vbnet

Welcome to the Network Enumeration Script!
This script will help you perform an initial network enumeration using Nmap and gather vulnerability information.
Please follow the prompts and read the comments for guidance on each step.
Let's get started!

Enter the target IP or range (e.g., 192.168.1.1 or 192.168.1.1/24): 10.129.186.109

Starting scan with method: -p- -T4 -A -v
Total hosts found: 1
Scanning in progress...

Open ports found: [6379]

I have found 1 open port(s) on 10.129.186.109:

Port 6379 (Redis - In-memory data structure store) –
  - No common vulnerabilities identified

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
   ```