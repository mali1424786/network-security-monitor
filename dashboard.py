#!/usr/bin/env python3
from flask import Flask, render_template, jsonify
from datetime import datetime, timedelta
from collections import Counter
import json
import os

app = Flask(__name__)

def read_alerts(filename):
    try:
        if os.path.exists(filename):
            with open(filename) as f:
                return json.load(f)
        return []
    except:
        return []

def get_timeline_data(anomalies):
    now = datetime.now()
    hourly_counts = {}
    for i in range(24):
        hour = (now - timedelta(hours=23-i)).strftime('%H:00')
        hourly_counts[hour] = 0
    
    for anomaly in anomalies:
        try:
            ts = datetime.fromisoformat(anomaly['timestamp'])
            if (now - ts).total_seconds() < 86400:
                hour = ts.strftime('%H:00')
                if hour in hourly_counts:
                    hourly_counts[hour] += 1
        except:
            pass
    
    return list(hourly_counts.keys()), list(hourly_counts.values())

def get_stats():
    port_scans = read_alerts('port_scan_alerts.json')
    anomalies = read_alerts('anomaly_alerts.json')
    traffic_spikes = sum(1 for a in anomalies if a.get('info', {}).get('type') == 'traffic_spike')
    unusual_ports_count = sum(1 for a in anomalies if a.get('info', {}).get('type') == 'unusual_port')
    unusual_protocols = sum(1 for a in anomalies if a.get('info', {}).get('type') == 'unusual_protocol')
    
    ip_counts = {}
    for scan in port_scans:
        ip = scan.get('info', {}).get('source_ip', 'Unknown')
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    for anomaly in anomalies:
        if anomaly.get('info', {}).get('type') == 'unusual_port':
            ip = anomaly.get('info', {}).get('ip', 'Unknown')
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    
    port_counts = {}
    for anomaly in anomalies:
        if anomaly.get('info', {}).get('type') == 'unusual_port':
            port = anomaly.get('info', {}).get('port')
            if port:
                port_counts[port] = port_counts.get(port, 0) + 1
    top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    
    timeline_labels, timeline_data = get_timeline_data(anomalies)
    
    return {
        'total_port_scans': len(port_scans),
        'total_anomalies': len(anomalies),
        'traffic_spikes': traffic_spikes,
        'unusual_ports': unusual_ports_count,
        'unusual_protocols': unusual_protocols,
        'recent_port_scans': port_scans[-5:] if port_scans else [],
        'recent_anomalies': anomalies[-10:] if anomalies else [],
        'top_ips': top_ips,
        'top_ports': top_ports,
        'timeline_labels': timeline_labels,
        'timeline_data': timeline_data
    }

@app.route('/')
def dashboard():
    return render_template('dashboard.html', stats=get_stats())

@app.route('/api/stats')
def api_stats():
    return jsonify(get_stats())

if __name__ == '__main__':
    print("Dashboard: http://localhost:8080")
    app.run(debug=True, host='0.0.0.0', port=8080)
