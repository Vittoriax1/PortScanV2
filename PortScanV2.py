import socket
import concurrent.futures
import ipaddress
import sys

def scan_port(targetIP, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((targetIP, port))
    sock.close()
    if result == 0:
        print(f"Port {port}: Open")

def scan_ports(targetIP, start_port, end_port):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        port_range = range(start_port, end_port + 1)
        future_to_port = {executor.submit(scan_port, targetIP, port): port for port in port_range}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                future.result()
            except Exception as e:
                print(f"Error scanning port {port}: {e}")

if __name__ == "__main__":
    print("Port Scanning Script")
    print()
    print("Disclaimer: Port scanning can be intrusive and may be illegal without proper authorization.")
    print("Ensure you have permission to scan the target system before using this script.")
    print()

    # Get the target IP address or hostname
    target = input("Enter the IP address or hostname to scan: ")
    try:
        targetIP = socket.gethostbyname(target)
    except socket.gaierror as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Get the range of ports to scan
    try:
        start_port = int(input("Enter the start port: "))
        end_port = int(input("Enter the end port: "))
        if start_port <= 0 or end_port <= 0 or start_port > end_port:
            raise ValueError("Invalid port range")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    print(f"Starting scan on {targetIP}")

    # Check if targetIP is a single IP or an IP range
    try:
        ip_range = ipaddress.IPv4Network(target, strict=False)
        print(f"Scanning IP range: {ip_range}")
        for ip in ip_range:
            print(f"Scanning IP: {ip}")
            scan_ports(str(ip), start_port, end_port)
    except ipaddress.AddressValueError:
        print(f"Scanning single IP: {targetIP}")
        scan_ports(targetIP, start_port, end_port)
    except socket.gaierror as e:
        print(f"Error: {e}")
        sys.exit(1)

    print("Scanning completed")
