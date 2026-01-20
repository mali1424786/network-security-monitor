#!/usr/bin/env python3
"""
Security Log Analyzer
Analyzes system logs for security events
"""

import re
from collections import Counter, defaultdict
from datetime import datetime

class LogAnalyzer:
    def __init__(self):
        self.failed_logins = []
        self.successful_logins = []
        self.sudo_commands = []
        self.ssh_attempts = []
        self.suspicious_ips = Counter()
        
    def analyze_auth_log(self, log_data):
        """Analyze authentication logs"""
        lines = log_data.strip().split('\n')
        
        for line in lines:
            # Failed password attempts
            if 'Failed password' in line or 'authentication failure' in line:
                self.failed_logins.append(line)
                ip = self._extract_ip(line)
                if ip:
                    self.suspicious_ips[ip] += 1
            
            # Successful logins
            elif 'Accepted password' in line or 'Accepted publickey' in line:
                self.successful_logins.append(line)
            
            # Sudo commands
            elif 'sudo:' in line and 'COMMAND=' in line:
                self.sudo_commands.append(line)
            
            # SSH attempts
            elif 'sshd' in line:
                self.ssh_attempts.append(line)
    
    def _extract_ip(self, line):
        """Extract IP address from log line"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        match = re.search(ip_pattern, line)
        return match.group(0) if match else None
    
    def _extract_user(self, line):
        """Extract username from log line"""
        user_patterns = [
            r'user\s+(\w+)',
            r'for\s+(\w+)\s+from',
            r'USER=(\w+)'
        ]
        for pattern in user_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)
        return 'unknown'
    
    def generate_report(self):
        """Generate security analysis report"""
        print("=" * 80)
        print("SECURITY LOG ANALYSIS REPORT")
        print("=" * 80)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Summary
        print("-" * 80)
        print("SUMMARY")
        print("-" * 80)
        print(f"Total Failed Login Attempts: {len(self.failed_logins)}")
        print(f"Total Successful Logins: {len(self.successful_logins)}")
        print(f"Total Sudo Commands: {len(self.sudo_commands)}")
        print(f"Total SSH Events: {len(self.ssh_attempts)}")
        print()
        
        # Failed login analysis
        if self.failed_logins:
            print("-" * 80)
            print("FAILED LOGIN ATTEMPTS")
            print("-" * 80)
            
            failed_users = Counter()
            for line in self.failed_logins:
                user = self._extract_user(line)
                failed_users[user] += 1
            
            print("Top targeted usernames:")
            for user, count in failed_users.most_common(5):
                print(f"  {user:15} {count:5} attempts")
            print()
        
        # Suspicious IPs
        if self.suspicious_ips:
            print("-" * 80)
            print("SUSPICIOUS IP ADDRESSES")
            print("-" * 80)
            print("IPs with multiple failed attempts:")
            for ip, count in self.suspicious_ips.most_common(10):
                if count > 3:
                    threat_level = 'CRITICAL' if count > 10 else 'HIGH' if count > 5 else 'MEDIUM'
                    print(f"  {ip:15} {count:5} attempts  [{threat_level}]")
            print()
        
        # Sudo usage
        if self.sudo_commands:
            print("-" * 80)
            print("SUDO COMMAND USAGE")
            print("-" * 80)
            
            sudo_users = Counter()
            for line in self.sudo_commands:
                user = self._extract_user(line)
                sudo_users[user] += 1
            
            print("Users executing sudo commands:")
            for user, count in sudo_users.most_common(5):
                print(f"  {user:15} {count:5} commands")
            print()
            
            print("Recent sudo commands:")
            for line in self.sudo_commands[-5:]:
                if 'COMMAND=' in line:
                    cmd = line.split('COMMAND=')[1].strip()[:60]
                    print(f"  {cmd}")
            print()
        
        # Security recommendations
        print("-" * 80)
        print("SECURITY RECOMMENDATIONS")
        print("-" * 80)
        
        if len(self.failed_logins) > 10:
            print("⚠️  HIGH: Numerous failed login attempts detected")
            print("   → Consider implementing fail2ban or similar IDS")
            print("   → Review firewall rules to block suspicious IPs")
        
        if any(count > 10 for count in self.suspicious_ips.values()):
            print("⚠️  CRITICAL: Potential brute force attack detected")
            print("   → Immediately block IPs with >10 failed attempts")
            print("   → Enable two-factor authentication")
        
        if len(self.sudo_commands) > 50:
            print("⚠️  MEDIUM: High sudo usage detected")
            print("   → Review sudo privileges")
            print("   → Ensure principle of least privilege")
        
        print()
        print("=" * 80)

def main():
    print("Security Log Analyzer")
    print("=" * 80)
    print()
    print("This tool analyzes authentication logs for security events.")
    print()
    
    print("Options:")
    print("1. Analyze sample log data")
    print("2. Analyze log file (requires file path)")
    
    choice = input("\nSelect option (1-2): ")
    
    analyzer = LogAnalyzer()
    
    if choice == '1':
        # Sample log data for demonstration
        sample_log = """
Jan 15 10:23:45 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
Jan 15 10:23:50 server sshd[1235]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
Jan 15 10:24:12 server sshd[1236]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:25:33 server sshd[1237]: Accepted password for user1 from 192.168.1.50 port 22 ssh2
Jan 15 10:30:15 server sudo: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/usr/bin/apt update
Jan 15 10:31:22 server sshd[1238]: Failed password for invalid user test from 203.0.113.45 port 22 ssh2
Jan 15 10:31:25 server sshd[1239]: Failed password for invalid user test from 203.0.113.45 port 22 ssh2
Jan 15 10:31:28 server sshd[1240]: Failed password for invalid user test from 203.0.113.45 port 22 ssh2
Jan 15 10:31:31 server sshd[1241]: Failed password for invalid user test from 203.0.113.45 port 22 ssh2
Jan 15 10:31:34 server sshd[1242]: Failed password for invalid user test from 203.0.113.45 port 22 ssh2
Jan 15 10:32:10 server sudo: user2 : TTY=pts/1 ; PWD=/home/user2 ; USER=root ; COMMAND=/bin/cat /etc/shadow
Jan 15 10:35:45 server sshd[1243]: Accepted publickey for admin from 192.168.1.10 port 22 ssh2
"""
        print("\nAnalyzing sample log data...")
        analyzer.analyze_auth_log(sample_log)
        analyzer.generate_report()
    
    elif choice == '2':
        filepath = input("\nEnter log file path: ")
        try:
            with open(filepath, 'r') as f:
                log_data = f.read()
            print(f"\nAnalyzing {filepath}...")
            analyzer.analyze_auth_log(log_data)
            analyzer.generate_report()
        except FileNotFoundError:
            print(f"Error: File '{filepath}' not found")
        except Exception as e:
            print(f"Error reading file: {e}")
    else:
        print("Invalid option")

if __name__ == "__main__":
    main()
