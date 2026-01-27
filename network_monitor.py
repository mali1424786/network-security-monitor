#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime, timedelta
from collections import defaultdict
import json
import sys

class PortScanDetector:
    def __init__(self, time_window=60, port_threshold=20):
        self.time_window = time_window
        self.port_threshold = port_threshold
        self.connection_attempts = defaultdict(dict)
        self.detected_scans = []
    
    def track_connection(self, src_ip, dst_port, timestamp):
        self.connection_attempts[src_ip][dst_port] = timestamp
        self._cleanup_old_attempts(src_ip, timestamp)
        port_count = len(self.connection_attempts[src_ip])
        if port_count >= self.port_threshold:
            return self._record_scan(src_ip, port_count, timestamp)
        return False
    
    def _cleanup_old_attempts(self, src_ip, current_time):
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        ports_to_remove = [port for port, timestamp in self.connection_attempts[src_ip].items() if timestamp < cutoff_time]
        for port in ports_to_remove:
            del self.connection_attempts[src_ip][port]
    
    def _record_scan(self, src_ip, port_count, timestamp):
        recent_cutoff = timestamp - timedelta(seconds=self.time_window)
        for scan in self.detected_scans:
            if scan["source_ip"] == src_ip and scan["timestamp"] > recent_cutoff:
                return False
        scan_info = {"source_ip": src_ip, "timestamp": timestamp, "ports_scanned": port_count, "time_window": self.time_window, "ports": list(self.connection_attempts[src_ip].keys())}
        self.detected_scans.append(scan_info)
        return True

class NetworkMonitor:
    def __init__(self, interface=None):
        self.interface = interface
        self.packet_count = 0
        self.packets_data = []
        self.scan_detector = PortScanDetector(time_window=60, port_threshold=20)
        self.stats = {"tcp_count": 0, "udp_count": 0, "icmp_count": 0, "scans_detected": 0}
    
    def parse_packet(self, packet):
        packet_info = {"timestamp": datetime.now(), "number": self.packet_count}
        if IP in packet:
            packet_info["src_ip"] = packet[IP].src
            packet_info["dst_ip"] = packet[IP].dst
            packet_info["protocol"] = packet[IP].proto
            packet_info["length"] = len(packet)
            if TCP in packet:
                packet_info["protocol_name"] = "TCP"
                packet_info["src_port"] = packet[TCP].sport
                packet_info["dst_port"] = packet[TCP].dport
                packet_info["flags"] = str(packet[TCP].flags)
                self.stats["tcp_count"] += 1
                if "S" in packet_info["flags"] and "A" not in packet_info["flags"]:
                    scan_detected = self.scan_detector.track_connection(packet_info["src_ip"], packet_info["dst_port"], packet_info["timestamp"])
                    if scan_detected:
                        self._alert_scan(packet_info["src_ip"])
                common_ports = {80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 25: "SMTP", 53: "DNS", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL"}
                if packet[TCP].dport in common_ports:
                    packet_info["service"] = common_ports[packet[TCP].dport]
            elif UDP in packet:
                packet_info["protocol_name"] = "UDP"
                packet_info["src_port"] = packet[UDP].sport
                packet_info["dst_port"] = packet[UDP].dport
                self.stats["udp_count"] += 1
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    packet_info["service"] = "DNS"
            elif ICMP in packet:
                packet_info["protocol_name"] = "ICMP"
                packet_info["icmp_type"] = packet[ICMP].type
                packet_info["service"] = "ICMP"
                self.stats["icmp_count"] += 1
        return packet_info
    
    def _alert_scan(self, src_ip):
        self.stats["scans_detected"] += 1
        print("\n" + "=" * 70)
        print("PORT SCAN DETECTED!")
        print("=" * 70)
        print(f"Source IP: {src_ip}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        scan_info = self.scan_detector.detected_scans[-1]
        print(f"Ports attempted: {scan_info['ports_scanned']}")
        print(f"Time window: {scan_info['time_window']} seconds")
        print(f"Port samples: {scan_info['ports'][:10]}...")
        print("=" * 70 + "\n")
        self._save_alert(scan_info)
    
    def _save_alert(self, scan_info):
        try:
            alert = {"source_ip": scan_info["source_ip"], "timestamp": scan_info["timestamp"].isoformat(), "ports_scanned": scan_info["ports_scanned"], "time_window": scan_info["time_window"], "ports": scan_info["ports"]}
            try:
                with open("scan_alerts.json", "r") as f:
                    alerts = json.load(f)
            except FileNotFoundError:
                alerts = []
            alerts.append(alert)
            with open("scan_alerts.json", "w") as f:
                json.dump(alerts, f, indent=2)
        except Exception as e:
            print(f"Error saving alert: {e}")
    
    def packet_callback(self, packet):
        self.packet_count += 1
        packet_info = self.parse_packet(packet)
        if "src_ip" in packet_info:
            protocol = packet_info.get("protocol_name", "Unknown")
            src = packet_info.get("src_ip", "N/A")
            dst = packet_info.get("dst_ip", "N/A")
            service = packet_info.get("service", "")
            print(f"[{self.packet_count:6}] {protocol:6} {src:15} -> {dst:15} {service}")
        self.packets_data.append(packet_info)
        if self.packet_count % 50 == 0:
            self._print_stats()
    
    def _print_stats(self):
        print("\n" + "-" * 70)
        print(f"Packets captured: {self.packet_count}")
        print(f"TCP: {self.stats['tcp_count']} | UDP: {self.stats['udp_count']} | ICMP: {self.stats['icmp_count']}")
        print(f"Port scans detected: {self.stats['scans_detected']}")
        print("-" * 70 + "\n")
    
    def start(self, packet_limit=0):
        print("=" * 70)
        print("Network Security Monitor - Active Monitoring")
        print("=" * 70)
        print(f"Interface: {self.interface or 'default'}")
        print(f"Port scan threshold: {self.scan_detector.port_threshold} ports in {self.scan_detector.time_window} seconds")
        print("\nMonitoring network traffic... (Press Ctrl+C to stop)\n")
        print(f"{'Packet#':8} {'Proto':6} {'Source':15}   {'Destination':15} {'Service'}")
        print("-" * 70)
        try:
            sniff(iface=self.interface, prn=self.packet_callback, store=0, count=packet_limit)
        except KeyboardInterrupt:
            print("\n\nStopping network monitor...")
            self._print_stats()
            print(f"\nTotal packets captured: {self.packet_count}")
            print(f"Total scans detected: {self.stats['scans_detected']}")
            if self.stats["scans_detected"] > 0:
                print(f"Alerts saved to: scan_alerts.json")
        except Exception as e:
            print(f"\nError: {e}")
            print("\nMake sure you're running with sudo/admin privileges!")
            sys.exit(1)

def main():
    monitor = NetworkMonitor(interface=None)
    monitor.start(packet_limit=0)

if __name__ == "__main__":
    main()
