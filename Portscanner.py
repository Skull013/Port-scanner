import argparse
import socket
import threading
import json
from tqdm import tqdm

# Dictionary for known services based on common port numbers
SERVICE_CATEGORIES = {
    20: 'FTP (File Transfer Protocol)',
    21: 'FTP (File Transfer Protocol)',
    22: 'SSH (Secure Shell)',
    23: 'Telnet',
    25: 'SMTP (Simple Mail Transfer Protocol)',
    53: 'DNS (Domain Name System)',
    80: 'HTTP (HyperText Transfer Protocol)',
    110: 'POP3 (Post Office Protocol)',
    143: 'IMAP (Internet Message Access Protocol)',
    443: 'HTTPS (Secure HTTP)',
    3306: 'MySQL Database',
    5432: 'PostgreSQL Database',
    6379: 'Redis',
    27017: 'MongoDB',
    8080: 'HTTP Proxy',
}

# Function to categorize service based on port number
def categorize_service(port):
    return SERVICE_CATEGORIES.get(port, "Unknown Service")

# Function to retrieve the banner from an open port
def get_banner(ip, port):
    try:
        socket_obj = socket.socket()
        socket_obj.settimeout(1)
        socket_obj.connect((ip, port))
        banner = socket_obj.recv(1024).decode().strip()
        return banner
    except (socket.timeout, socket.error):
        return None
    finally:
        socket_obj.close()

# Function to scan a single port and categorize service
def scan_port(ip, port, output, verbose):
    banner = get_banner(ip, port)
    if banner:
        service = categorize_service(port)
        result = {'ip': ip, 'port': port, 'service': service, 'banner': banner}
        output.append(result)
        
        if verbose:
            print(f"Port {port}: {service} - {banner}")
    else:
        result = {'ip': ip, 'port': port, 'service': 'Closed', 'banner': None}
        output.append(result)

# Function to perform multithreaded port scanning
def scan_ports(ip, ports, num_threads, verbose):
    output = []
    threads = []
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(ip, port, output, verbose))
        threads.append(thread)
        thread.start()

        if len(threads) >= num_threads:
            for t in threads:
                t.join()
            threads = []

    for t in threads:
        t.join()

    return output

# Main function to parse arguments and perform scanning
def main():
    parser = argparse.ArgumentParser(description='Simple TCP Port Scanner with Service Categorization')
    parser.add_argument('-t', '--targets', required=True, help='Target IPs or domains', nargs='+')
    parser.add_argument('-p', '--port-range', default='1-1000', help='Port range to scan (e.g., 1-1000 or all)')
    parser.add_argument('-n', '--num-threads', type=int, default=10, help='Number of threads for scanning')
    parser.add_argument('-o', '--output', default='scan_results.json', help='File to save results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

    args = parser.parse_args()

    # Parse port range
    if args.port_range == 'all':
        ports = range(1, 65536)
    else:
        start_port, end_port = map(int, args.port_range.split('-'))
        ports = range(start_port, end_port + 1)

    # Perform scan for each target
    for target in args.targets:
        print(f"\nScanning {target}...")
        output = scan_ports(target, ports, args.num_threads, args.verbose)
        
        # Save results to a file
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=4)

        print(f"Scan results saved to {args.output}")

if __name__ == '__main__':
    main()
