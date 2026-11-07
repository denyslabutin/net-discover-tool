#!/usr/bin/env python3

import argparse
import socket
import sys
import urllib.request
import scapy.all as scapy

# Function to get MAC manufacturer via an open API (or fallback)
def get_vendor(mac):
    try:
        # Using a public MAC vendor lookup API (rate-limited, but great for scripts)
        url = f"https://api.macvendors.com/{mac}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=1) as response:
            return response.read().decode('utf-8')
    except Exception:
        return "Unknown Vendor"

# Function to resolve IP to Hostname
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "N/A"

# Function to check a few common ports to guess device type/services
def check_common_ports(ip):
    common_ports = {22: "SSH", 80: "HTTP", 443: "HTTPS", 445: "SMB", 631: "Printer"}
    open_services = []
    for port, service in common_ports.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_services.append(service)
            s.close()
        except Exception:
            pass
    return open_services if open_services else ["None detected"]

# Function to scan the network for live hosts and gather extended info
def scan(ip_range, interface=None):
    arp = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp

    try:
        kwargs = {"timeout": 2, "verbose": False}
        if interface:
            kwargs["iface"] = interface

        answered_list = scapy.srp(arp_request_broadcast, **kwargs)[0]

    except PermissionError:
        print("[-] Error: Scapy requires root/administrator privileges to send ARP packets. Run with sudo")        
        sys.exit(1)
    except Exception as e:
        print(f"[-] Network error during transmission: {e}")  
        sys.exit(1)                                                                                                  
    
    clients_list = []                                                                                                                                                                        
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        hostname = get_hostname(ip)
        vendor = get_vendor(mac)
        services = check_common_ports(ip)
        
        clients_list.append({
            "ip": ip, 
            "mac": mac, 
            "hostname": hostname,
            "vendor": vendor,
            "services": ", ".join(services)
        })                                                                                                                                                    
    return clients_list                                                                                                                                                                      

# Function to print the results in an expanded table format
def print_result(results):
    if not results:
        print("\n[-] No active hosts found. Check your subnet range or if AP Isolation is enabled on your router")
        return

    print(f"{'IP Address':<16} | {'MAC Address':<18} | {'Hostname':<20} | {'Vendor':<20} | {'Open Services'}")
    print("-" * 105)
    for client in results:
        print(f"{client['ip']:<16} | {client['mac']:<18} | {client['hostname']:<20} | {client['vendor']:<20} | {client['services']}")
    print(f"\n[+] Total active hosts discovered: {len(results)}\n")

def main():
    parser = argparse.ArgumentParser(description="Advanced ARP Network Discovery Tool & Recon Tool")
    parser.add_argument("range", help="IP range to scan (e.g., 192.168.1.1/24)")
    parser.add_argument("-i", "--interface", help="Network interface to use (e.g., wlan0, eth0)", default=None)
    args = parser.parse_args()

    print(f"[*] Scanning {args.range} for live hosts and gathering details...")
    scan_result = scan(args.range)
    print_result(scan_result)

if __name__ == "__main__":
    main()
