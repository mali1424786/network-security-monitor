#!/usr/bin/env python3
"""
Network Security Monitor - Phase 1: Basic Packet Capture
This script captures network packets and logs them with key information.
Run with: sudo python3 packet_sniffer.py
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import json
import sys

class PacketMonitor:
    def __init__(self, interface=None, log_file="network_log.json"):
        """
        Initialize the packet monitor.
        
        Args:
            interface: Network interface to monitor (None = default interface)
            log_file: File to save captured packet data
        """
        self.interface = interface
        self.log_file = log_file
        self.packet_count = 0
        self.packets_data = []
        
    def parse_packet(self, packet):
        """
        Extract key information from a captured packet.
        
        This is where we turn raw packet data into something readable.
        We're looking for: who sent it, who's receiving it, what type of
        traffic it is, and when it happened.
        """
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'number': self.packet_count
        }
        
        # Check if packet has IP layer (most packets do)
        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            packet_info['protocol'] = packet[IP].proto
            packet_info['length'] = len(packet)
            
            # TCP packets (most web traffic, SSH, etc.)
            if TCP in packet:
                packet_info['protocol_name'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['flags'] = str(packet[TCP].flags)
                
                # Common port identification
                common_ports = {
                    80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 
                    21: 'FTP', 25: 'SMTP', 53: 'DNS'
                }
                if packet[TCP].dport in common_ports:
                    packet_info['service'] = common_ports[packet[TCP].dport]
                elif packet[TCP].sport in common_ports:
                    packet_info['service'] = common_ports[packet[TCP].sport]
            
            # UDP packets (DNS, streaming, games, etc.)
            elif UDP in packet:
                packet_info['protocol_name'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    packet_info['service'] = 'DNS'
            
            # ICMP packets (ping, traceroute, etc.)
            elif ICMP in packet:
                packet_info['protocol_name'] = 'ICMP'
                packet_info['icmp_type'] = packet[ICMP].type
                packet_info['service'] = 'ICMP'
        
        return packet_info
    
    def packet_callback(self, packet):
        """
        Called for every packet captured. This is the main processing function.
        """
        self.packet_count += 1
        
        # Parse the packet into readable data
        packet_info = self.parse_packet(packet)
        
        # Print to console so you can see what's happening in real-time
        if 'src_ip' in packet_info:
            protocol = packet_info.get('protocol_name', 'Unknown')
            src = packet_info.get('src_ip', 'N/A')
            dst = packet_info.get('dst_ip', 'N/A')
            service = packet_info.get('service', '')
            
            print(f"[{self.packet_count}] {protocol:6} {src:15} → {dst:15} {service}")
        
        # Store packet data for later analysis
        self.packets_data.append(packet_info)
        
        # Save to log file every 10 packets
        if self.packet_count % 10 == 0:
            self.save_log()
    
    def save_log(self):
        """
        Save captured packet data to a JSON file.
        This ensures we don't lose data if the program crashes.
        """
        try:
            with open(self.log_file, 'w') as f:
                json.dump({
                    'total_packets': self.packet_count,
                    'last_updated': datetime.now().isoformat(),
                    'packets': self.packets_data[-100:]  # Keep last 100 packets
                }, f, indent=2)
        except Exception as e:
            print(f"Error saving log: {e}")
    
    def start(self, packet_limit=0):
        """
        Start capturing packets.
        
        Args:
            packet_limit: Number of packets to capture (0 = unlimited)
        """
        print("=" * 70)
        print("Network Security Monitor - Packet Capture Started")
        print("=" * 70)
        print(f"Interface: {self.interface or 'default'}")
        print(f"Log file: {self.log_file}")
        print(f"Packet limit: {'unlimited' if packet_limit == 0 else packet_limit}")
        print("\nCapturing packets... (Press Ctrl+C to stop)\n")
        print(f"{'#':6} {'Proto':6} {'Source':15}   {'Destination':15} {'Service'}")
        print("-" * 70)
        
        try:
            # Start sniffing packets
            # prn=callback function, store=0 means don't store in memory (we handle that),
            # count=0 means capture forever until Ctrl+C
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=0,
                count=packet_limit
            )
        except KeyboardInterrupt:
            print("\n\nStopping packet capture...")
            self.save_log()
            print(f"\nCaptured {self.packet_count} packets")
            print(f"Log saved to: {self.log_file}")
        except Exception as e:
            print(f"\nError: {e}")
            print("\nMake sure you're running this script with sudo/admin privileges!")
            sys.exit(1)

def main():
    """
    Main entry point for the packet monitor.
    """
    # Create and start the monitor
    monitor = PacketMonitor(
        interface=None,  # None = use default interface
        log_file="network_log.json"
    )
    
    # Start capturing (0 = unlimited packets, use Ctrl+C to stop)
    monitor.start(packet_limit=0)

if __name__ == "__main__":
    main()