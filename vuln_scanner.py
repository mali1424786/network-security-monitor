#!/usr/bin/env python3
"""
Vulnerability Scanner
Scans targets for open ports and potential security issues
"""

import nmap
import socket
from datetime import datetime

class VulnerabilityScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.results = {}
        
    def scan_target(self, target, port_range='1-1000'):
        """Scan target for open ports and services"""
        print(f"\n{'='*70}")
        print(f"Scanning {target}")
        print(f"Port Range: {port_range}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        
        try:
            # Scan with service detection
            print("Scanning... (this may take 1-2 minutes)")
            self.nm.scan(target, port_range, arguments='-sV -T4')
            
            if target not in self.nm.all_hosts():
                print(f"Error: Host {target} is not up or not responding")
                return
            
            self.results[target] = {
                'hostname': self.nm[target].hostname(),
                'state': self.nm[target].state(),
                'protocols': {},
                'vulnerabilities': []
            }
            
            for proto in self.nm[target].all_protocols():
                self.results[target]['protocols'][proto] = {}
                ports = self.nm[target][proto].keys()
                
                for port in ports:
                    port_info = self.nm[target][proto][port]
                    self.results[target]['protocols'][proto][port] = {
                        'state': port_info['state'],
                        'name': port_info.get('name', 'unknown'),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                    }
                    
                    # Check for known vulnerabilities
                    self._check_vulnerabilities(target, port, port_info)
            
            self._generate_report(target)
            
        except Exception as e:
            print(f"Error during scan: {e}")
    
    def _check_vulnerabilities(self, target, port, port_info):
        """Check for common vulnerabilities"""
        service = port_info.get('name', '')
        version = port_info.get('version', '')
        
        # Check for outdated/vulnerable services
        vulnerable_services = {
            'ssh': {'old_versions': ['OpenSSH 6.', 'OpenSSH 5.'], 
                   'risk': 'HIGH',
                   'issue': 'Outdated SSH version - vulnerable to known exploits'},
            'ftp': {'old_versions': ['vsftpd 2.3.4'], 
                   'risk': 'CRITICAL',
                   'issue': 'Known backdoor vulnerability'},
            'http': {'old_versions': ['Apache/2.2', 'Apache/2.0'], 
                    'risk': 'MEDIUM',
                    'issue': 'Outdated web server - missing security patches'},
            'mysql': {'old_versions': ['MySQL 5.0', 'MySQL 4.'], 
                     'risk': 'HIGH',
                     'issue': 'Outdated database - known security vulnerabilities'}
        }
        
        # Check if service is in our vulnerable list
        if service in vulnerable_services:
            for old_ver in vulnerable_services[service]['old_versions']:
                if old_ver in version:
                    self.results[target]['vulnerabilities'].append({
                        'port': port,
                        'service': service,
                        'version': version,
                        'risk': vulnerable_services[service]['risk'],
                        'issue': vulnerable_services[service]['issue']
                    })
        
        # Flag commonly exploited ports
        risky_ports = {
            21: ('FTP', 'MEDIUM', 'FTP allows unencrypted file transfer'),
            23: ('Telnet', 'CRITICAL', 'Telnet transmits credentials in cleartext'),
            445: ('SMB', 'HIGH', 'SMB is commonly exploited (WannaCry, EternalBlue)'),
            3389: ('RDP', 'HIGH', 'RDP exposed to internet - brute force target'),
            5900: ('VNC', 'MEDIUM', 'VNC may have weak authentication')
        }
        
        if port in risky_ports:
            svc, risk, issue = risky_ports[port]
            self.results[target]['vulnerabilities'].append({
                'port': port,
                'service': svc,
                'version': version,
                'risk': risk,
                'issue': issue
            })
    
    def _generate_report(self, target):
        """Generate vulnerability report"""
        result = self.results[target]
        
        print("\n" + "="*70)
        print("VULNERABILITY SCAN REPORT")
        print("="*70)
        print(f"Target: {target}")
        print(f"Hostname: {result['hostname']}")
        print(f"Status: {result['state']}")
        print(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Open ports summary
        print("-"*70)
        print("OPEN PORTS & SERVICES")
        print("-"*70)
        
        total_open = 0
        for proto in result['protocols']:
            for port, info in result['protocols'][proto].items():
                if info['state'] == 'open':
                    total_open += 1
                    service = info['name']
                    product = info['product']
                    version = info['version']
                    
                    service_info = f"{service}"
                    if product:
                        service_info += f" ({product}"
                        if version:
                            service_info += f" {version}"
                        service_info += ")"
                    
                    print(f"Port {port:5}/{proto:3} - {service_info}")
        
        print(f"\nTotal open ports: {total_open}")
        print()
        
        # Vulnerabilities
        if result['vulnerabilities']:
            print("-"*70)
            print("VULNERABILITIES DETECTED")
            print("-"*70)
            
            critical = [v for v in result['vulnerabilities'] if v['risk'] == 'CRITICAL']
            high = [v for v in result['vulnerabilities'] if v['risk'] == 'HIGH']
            medium = [v for v in result['vulnerabilities'] if v['risk'] == 'MEDIUM']
            
            print(f"CRITICAL: {len(critical)} | HIGH: {len(high)} | MEDIUM: {len(medium)}")
            print()
            
            for vuln in result['vulnerabilities']:
                risk_color = vuln['risk']
                print(f"[{risk_color}] Port {vuln['port']} - {vuln['service']}")
                print(f"    Issue: {vuln['issue']}")
                if vuln['version']:
                    print(f"    Version: {vuln['version']}")
                print()
        else:
            print("-"*70)
            print("No critical vulnerabilities detected")
            print("-"*70)
        
        # Recommendations
        print("-"*70)
        print("SECURITY RECOMMENDATIONS")
        print("-"*70)
        
        if result['vulnerabilities']:
            print("1. Patch or upgrade vulnerable services immediately")
            print("2. Close unnecessary ports")
            print("3. Implement firewall rules to restrict access")
            print("4. Use VPN for remote access instead of direct exposure")
            print("5. Enable intrusion detection/prevention systems")
        else:
            print("1. Continue monitoring for new vulnerabilities")
            print("2. Keep all services updated")
            print("3. Perform regular vulnerability scans")
        
        print("="*70)

def main():
    scanner = VulnerabilityScanner()
    
    print("="*70)
    print("VULNERABILITY SCANNER")
    print("="*70)
    print("\nThis tool scans for open ports and security vulnerabilities.")
    print("NOTE: Only scan systems you own or have permission to scan!")
    print()
    
    target = input("Enter target IP or hostname (or 'localhost' for this machine): ")
    
    if not target:
        print("No target specified")
        return
    
    port_range = input("Enter port range (default 1-1000): ") or "1-1000"
    
    scanner.scan_target(target, port_range)

if __name__ == "__main__":
    main()
