# TCP Port Scanner with Service Categorization
This is a simple yet efficient Python-based TCP port scanner that allows you to scan one or more IP addresses or domain names for open ports. It categorizes the services running on those ports and retrieves service banners to help identify the service versions. Additionally, it can save the scan results in a JSON file for later use.
# Key Features
1. Scan Multiple Targets: Scan one or more IPs or domain names for open ports.

2. Port Range: Customize the port range to scan (e.g., 1-1000 or all).

3. Service Categorization: Automatically categorizes services (e.g., HTTP, FTP, SSH) based on the open port or service banner.

4. Multithreaded Scanning: Scan faster using multiple threads.

5. Save Results: Save the scan results to a JSON file for easy reference.

6. Verbose Output: Option to show detailed scan results.
# Usage
1. Scan a target (default port range: 1-1000):

     `python port_scanner.py -t 192.168.1.1`

2. Scan a custom port range and save results:

    `python port_scanner.py -t example.com -p 1-65535 -o results.json`

3. Enable verbose mode for detailed output:

    `python port_scanner.py -t 192.168.1.1 -v`
# Purpose
This tool is designed to help network administrators and security professionals quickly identify open ports and determine what services are running on those ports. It’s ideal for security assessments or general network monitoring.
