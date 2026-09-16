#!/usr/bin/env python3
"""
Network Scanner - Scans the local network for active devices.
Displays IP address, hostname, MAC address, and vendor information.
"""

import subprocess
import re
import sys
import socket
import argparse
from typing import List, Dict, Optional

def get_default_interface() -> Optional[str]:
    """Get the default network interface."""
    try:
        # Use ip route to find the default interface
        result = subprocess.run(['ip', 'route', 'show', 'default'],
                              capture_output=True, text=True, check=True)
        # Example output: "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
        match = re.search(r'dev\s+(\S+)', result.stdout)
        if match:
            return match.group(1)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return None

def get_interface_ip(interface: str) -> Optional[str]:
    """Get the IP address of the specified interface."""
    try:
        result = subprocess.run(['ip', '-4', 'addr', 'show', interface],
                              capture_output=True, text=True, check=True)
        # Example output: "    inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic eth0"
        match = re.search(r'inet\s+(\S+)', result.stdout)
        if match:
            ip_with_mask = match.group(1)
            # Return just the IP (without mask)
            return ip_with_mask.split('/')[0]
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return None

def get_network_range(interface: str) -> Optional[str]:
    """Get the network range (CIDR) for the interface."""
    try:
        result = subprocess.run(['ip', '-4', 'addr', 'show', interface],
                              capture_output=True, text=True, check=True)
        # Example output: "    inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic eth0"
        match = re.search(r'inet\s+(\S+)', result.stdout)
        if match:
            return match.group(1)  # Returns IP/mask like "192.168.1.100/24"
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return None

def scan_network(network: str) -> List[Dict[str, str]]:
    """Scan the network using nmap and return list of active hosts."""
    try:
        # Run nmap ping scan (-sn) to discover live hosts without port scanning
        cmd = ['nmap', '-sn', network]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)

        hosts = []
        current_host = {}

        for line in result.stdout.split('\n'):
            line = line.strip()
            if line.startswith('Nmap scan report for'):
                # New host found
                if current_host:
                    hosts.append(current_host)
                # Extract hostname and IP
                # Example: "Nmap scan report for 192.168.1.1"
                # or: "Nmap scan report for hostname (192.168.1.1)"
                match = re.search(r'Nmap scan report for\s+(?:(.*)\s+)?\(?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)?', line)
                if match:
                    hostname = match.group(1) if match.group(1) else ''
                    ip = match.group(2)
                    current_host = {'ip': ip, 'hostname': hostname if hostname else 'unknown', 'mac': '', 'vendor': ''}
            elif line.startswith('MAC Address:'):
                # Example: "MAC Address: AA:BB:CC:DD:EE:FF (Vendor Name)"
                match = re.search(r'MAC Address:\s+([0-9A-Fa-f:]{17})\s+\((.*)\)', line)
                if match:
                    current_host['mac'] = match.group(1)
                    current_host['vendor'] = match.group(2)
                else:
                    # Sometimes only MAC address without vendor
                    match = re.search(r'MAC Address:\s+([0-9A-Fa-f:]{17})', line)
                    if match:
                        current_host['mac'] = match.group(1)
                        current_host['vendor'] = 'unknown'

        # Don't forget the last host
        if current_host:
            hosts.append(current_host)

        return hosts

    except subprocess.CalledProcessError as e:
        print(f"Error running nmap: {e}")
        print(f"stderr: {e.stderr}")
        return []
    except FileNotFoundError:
        print("Error: nmap not found. Please install nmap.")
        return []

def get_hostname(ip: str) -> str:
    """Try to get hostname via reverse DNS."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return 'unknown'

def main():
    parser = argparse.ArgumentParser(description='Network Scanner - Scan local network for active devices.')
    parser.add_argument('-n', '--network', help='Network range to scan (e.g., 192.168.1.0/24). If not provided, will auto-detect.')
    parser.add_argument('-i', '--interface', help='Network interface to use for auto-detection.')
    args = parser.parse_args()

    # Determine network to scan
    if args.network:
        network = args.network
        print(f"Using provided network: {network}")
    else:
        # Auto-detect
        interface = args.interface if args.interface else get_default_interface()
        if not interface:
            print("Error: Could not determine network interface. Please specify with -i or provide network with -n.")
            sys.exit(1)

        ip = get_interface_ip(interface)
        if not ip:
            print(f"Error: Could not get IP address for interface {interface}")
            sys.exit(1)

        network = get_network_range(interface)
        if not network:
            print(f"Error: Could not get network range for interface {interface}")
            sys.exit(1)

        print(f"Auto-detected interface: {interface} ({ip})")
        print(f"Network range: {network}")

    # Scan the network
    print(f"Scanning network {network} for active devices...")
    hosts = scan_network(network)

    if not hosts:
        print("No hosts found or scan failed.")
        return

    # Display results
    print("\n" + "="*80)
    print(f"{'IP Address':<16} {'Hostname':<25} {'MAC Address':<18} {'Vendor'}")
    print("="*80)

    for host in hosts:
        ip = host['ip']
        hostname = host['hostname']
        mac = host['mac'] if host['mac'] else 'N/A'
        vendor = host['vendor'] if host['vendor'] else 'N/A'
        print(f"{ip:<16} {hostname:<25} {mac:<18} {vendor}")

    print("="*80)
    print(f"Total active devices found: {len(hosts)}")

    # Note about location
    print("\nNote: Geographical location is not available for private IP addresses.")
    print("For public IP addresses, you would need to use an external geolocation service.")

if __name__ == '__main__':
    main()