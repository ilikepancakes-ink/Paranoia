#!/usr/bin/env python3

import os
import sys
import subprocess
import socket
import concurrent.futures
import time
import platform
from ipaddress import ip_network, ip_address
import scapy.all as scapy
import csv
import hashlib
import re

def print_step(step_message):
    """Prints a step message with current timestamp."""
    current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"[{current_time}] {step_message}")

def read_logo():
    """Reads and returns the logo from logo.txt."""
    print_step("Reading logo file...")
    try:
        with open('logo.txt', 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "PARANOIA LAN AUDIT TOOL"

def get_local_ip():
    """Gets the local IP address and subnet."""
    print_step("Detecting local IP address and subnet...")
    try:
        # Find the local IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = ip_address(s.getsockname()[0])
        s.close()

        # Default to /24 subnet (common for home networks)
        subnet = ip_network(f"{local_ip}/24", strict=False)
        print_step(f"Local IP: {local_ip}, Scanning subnet: {subnet}")
        return local_ip, subnet
    except Exception as e:
        print_step(f"Failed to detect local IP: {e}. Using default host-only scanning.")
        return None, None

def ping_sweep(subnet):
    """Performs a ping sweep to discover live hosts."""
    print_step("Starting ping sweep to discover live hosts...")

    live_hosts = []

    if subnet:
        print_step(f"Scanning {len(list(subnet))} potential IPv4 addresses...")

        def ping_host(host):
            """Ping a single host."""
            try:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', str(host)],
                    capture_output=True,
                    timeout=2
                )
                if result.returncode == 0:
                    print_step(f"Host {host} is alive")
                    return str(host)
            except subprocess.TimeoutExpired:
                pass
            return None

        # Use thread pool for concurrent pinging
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(ping_host, ip) for ip in subnet.hosts()]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.append(result)

    else:
        print_step("No subnet detected. Skipping ping sweep.")

    print_step(f"Ping sweep complete. Found {len(live_hosts)} live hosts.")
    return live_hosts

def scan_ports(host, ports=None):
    """Scans common ports on a host."""
    if ports is None:
        # Common vulnerable ports to check
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3389]

    open_ports = []

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
                print_step(f"Port {port} is open on {host}")
            sock.close()
        except socket.error:
            pass

    return open_ports

def port_scan_hosts(hosts):
    """Scans ports on discovered hosts."""
    print_step("Starting port scanning on discovered hosts...")

    host_ports = {}

    def scan_host_ports(host):
        """Scan ports for a single host."""
        print_step(f"Scanning ports on {host}...")
        open_ports = scan_ports(host)
        return host, open_ports

    # Use thread pool for concurrent port scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_host_ports, host) for host in hosts]
        for future in concurrent.futures.as_completed(futures):
            host, ports = future.result()
            host_ports[host] = ports
            if ports:
                print_step(f"Host {host} has {len(ports)} open ports: {ports}")

    print_step("Port scanning complete.")
    return host_ports

def load_vulnerability_db():
    """Loads vulnerability database."""
    print_step("Loading vulnerability database...")
    vulnerabilities = {}

    try:
        with open('windowsscan/known_exploited_vulnerabilities.csv', 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            headers = next(reader)  # Skip header
            for row in reader:
                if len(row) >= 5:
                    cve_id = row[0]
                    product = row[2]
                    vuln_name = row[3]
                    # Store by service/port patterns
                    vulnerabilities[product.lower()] = {
                        'cve': cve_id,
                        'name': vuln_name,
                        'short_desc': row[5] if len(row) > 5 else 'No description'
                    }
    except FileNotFoundError:
        print_step("Warning: Vulnerability database not found.")
    except Exception as e:
        print_step(f"Warning: Could not load vulnerability database: {e}")

    print_step(f"Loaded {len(vulnerabilities)} vulnerability entries.")
    return vulnerabilities

def analyze_security_risks(host_ports, vulnerabilities):
    """Analyzes security risks based on open ports and running services."""
    print_step("Analyzing security risks...")

    risk_assessment = {}

    # Common risk mappings
    port_risks = {
        21: ['FTP', 'Unencrypted file transfer - potential for credential theft'],
        22: ['SSH', 'Ensure strong authentication and keep updated'],
        23: ['Telnet', 'Unencrypted protocol - high security risk'],
        25: ['SMTP', 'Scan for open relays and ensure encryption'],
        53: ['DNS', 'Check for cache poisoning vulnerabilities'],
        80: ['HTTP', 'Use HTTPS instead, check for web vulnerabilities'],
        110: ['POP3', 'Unencrypted email protocol - use POP3S'],
        135: ['RPC', 'Windows RPC - potential for remote code execution'],
        139: ['NetBIOS', 'Legacy protocol - high security risk'],
        143: ['IMAP', 'Ensure encryption (IMAPS)'],
        443: ['HTTPS', 'Ensure proper SSL/TLS configuration'],
        445: ['SMB', 'Potential for remote code execution (EternalBlue, etc.)'],
        993: ['IMAPS', 'Secure IMAP implementation'],
        995: ['POP3S', 'Secure POP3 implementation'],
        3389: ['RDP', 'Use NLA and firewall restrictions']
    }

    for host, ports in host_ports.items():
        risks = []

        for port in ports:
            if port in port_risks:
                service, risk_desc = port_risks[port]
                risks.append(f"Port {port} ({service}): {risk_desc}")

            # Check for known vulnerabilities
            service_name = port_risks.get(port, ['Unknown', ''])[0]
            if service_name.lower() in vulnerabilities:
                vuln_info = vulnerabilities[service_name.lower()]
                risks.append(f"Potential vulnerability: {vuln_info['cve']} ({service_name}) - {vuln_info['short_desc'][:100]}...")

        risk_assessment[host] = risks
        print_step(f"Security analysis for {host}: Found {len(risks)} potential issues")

    print_step("Security risk analysis complete.")
    return risk_assessment

def arp_scan(subnet):
    """Performs ARP scan to discover devices."""
    print_step("Starting ARP scan for device discovery...")

    devices = []

    try:
        # Send ARP request to all hosts in subnet
        arp_request = scapy.ARP(pdst=str(subnet))
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        print_step("Sending ARP requests...")
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]

        for element in answered_list:
            client_dict = {
                'ip': element[1].psrc,
                'mac': element[1].hwsrc
            }
            devices.append(client_dict)
            print_step(f"Found device: IP {client_dict['ip']}, MAC {client_dict['mac']}")

    except ImportError:
        print_step("Scapy not available. ARP scan disabled. Install scapy for better device discovery.")
    except Exception as e:
        print_step(f"ARP scan failed: {e}")

    print_step(f"ARP scan complete. Found {len(devices)} devices.")
    return devices

def get_device_info(host):
    """Gets additional device information."""
    print_step(f"Getting host information for {host}...")

    info = {'hostname': 'Unknown', 'os_hints': []}

    try:
        hostname = socket.gethostbyaddr(host)[0]
        info['hostname'] = hostname
        print_step(f"Hostname for {host}: {hostname}")
    except socket.herror:
        print_step(f"Could not resolve hostname for {host}")

    # Try to guess OS based on TTL and other fingerprinting
    try:
        # TTL-based OS detection (rough estimation)
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '1', host],
            capture_output=True,
            text=True,
            timeout=2
        )

        if 'ttl=' in result.stdout.lower():
            ttl_line = result.stdout.lower()
            ttl_match = re.search(r'ttl=(\d+)', ttl_line)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                if ttl <= 64:
                    info['os_hints'].append('Linux/Unix system')
                elif 128 >= ttl > 64:
                    info['os_hints'].append('Windows system')
                else:
                    info['os_hints'].append('Other/Unknown OS')
                print_step(f"OS hint for {host} (TTL {ttl}): {info['os_hints'][-1]}")
    except:
        pass

    return info

def generate_report(live_hosts, host_ports, risk_assessment, devices_info):
    """Generates a comprehensive security report."""
    print_step("Generating security audit report...")

    report = "LAN SECURITY AUDIT REPORT\n"
    report += "=" * 50 + "\n\n"
    report += f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}\n"
    report += f"Total hosts scanned: {len(live_hosts)}\n\n"

    for host in live_hosts:
        report += f"HOST: {host}\n"
        report += "-" * 20 + "\n"

        if host in devices_info:
            info = devices_info[host]
            report += f"Hostname: {info['hostname']}\n"
            if info['os_hints']:
                report += f"OS Hints: {', '.join(info['os_hints'])}\n"

        if host in host_ports and host_ports[host]:
            report += f"Open Ports: {', '.join(map(str, host_ports[host]))}\n"
            report += "Security Issues:\n"
            if host in risk_assessment and risk_assessment[host]:
                for i, risk in enumerate(risk_assessment[host], 1):
                    report += f"  {i}. {risk}\n"
            else:
                report += "  No obvious security issues detected.\n"
        else:
            report += "No open ports found.\n"

        report += "\n"

    print_step("Report generation complete.")
    return report

def main():
    """Main audit function."""
    print(" " * 10 + read_logo())
    print("\nPARANOIA LAN AUDIT TOOL")
    print("=======================")

    # Step 1: Network Discovery
    local_ip, subnet = get_local_ip()

    # Step 2: ARP Scan
    print_step("Performing network discovery...")
    devices = arp_scan(subnet)

    # Step 3: Ping Sweep
    live_hosts = ping_sweep(subnet)

    # Step 4: Host Information Gathering
    print_step("Gathering additional host information...")
    devices_info = {}
    for host in live_hosts:
        devices_info[host] = get_device_info(host)

    # Step 5: Port Scanning
    host_ports = port_scan_hosts(live_hosts)

    # Step 6: Vulnerability Analysis
    vulnerabilities = load_vulnerability_db()

    # Step 7: Security Risk Analysis
    risk_assessment = analyze_security_risks(host_ports, vulnerabilities)

    # Step 8: Generate Report
    report = generate_report(live_hosts, host_ports, risk_assessment, devices_info)

    # Step 9: Display Results
    print("\n" + report)

    # Save report to file
    report_file = f"lan_audit_report_{time.strftime('%Y%m%d_%H%M%S', time.localtime())}.log"
    try:
        with open(report_file, 'w') as f:
            f.write(report)
        print_step(f"Report saved to: {report_file}")
    except Exception as e:
        print_step(f"Failed to save report: {e}")

    print("\n" + "=" * 50)
    print("LAN AUDIT COMPLETE")
    print("Scan Summary:")
    print(f"- Live hosts found: {len(live_hosts)}")
    total_ports = sum(len(ports) for ports in host_ports.values())
    print(f"- Open ports detected: {total_ports}")
    total_risks = sum(len(risks) for risks in risk_assessment.values())
    print(f"- Security issues identified: {total_risks}")
    print("=" * 50)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_step("Audit interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print_step(f"Error during audit: {e}")
        sys.exit(1)
