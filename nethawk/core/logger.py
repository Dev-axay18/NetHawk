"""
Logging and Reporting Module
"""
import json
import os
from datetime import datetime


class Logger:
    """Session logging and JSON report generation"""
    
    def __init__(self, report_dir="reports"):
        self.report_dir = report_dir
        self.session_data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tool": "NetHawk Security Toolkit",
                "version": "1.0"
            },
            "traceroute": [],
            "flows": {},
            "anomalies": [],
            "threats": []
        }
        
        os.makedirs(report_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y-%m-%d-%H%M")
        self.report_path = os.path.join(report_dir, f"report-{timestamp}.json")
    
    def log_traceroute(self, results):
        """Log traceroute results"""
        self.session_data["traceroute"] = results
    
    def log_flows(self, flow_summary):
        """Log flow analysis results"""
        self.session_data["flows"] = flow_summary
    
    def log_anomaly(self, anomaly):
        """Log detected anomaly"""
        self.session_data["anomalies"].append(anomaly)
    
    def log_threat(self, pkt_data):
        """Log threat detection"""
        threat_entry = {
            "timestamp": pkt_data.get("timestamp"),
            "source": pkt_data.get("src"),
            "destination": pkt_data.get("dst"),
            "type": pkt_data.get("type")
        }
        self.session_data["threats"].append(threat_entry)
    
    def save_report(self):
        """Save session report to JSON file"""
        try:
            with open(self.report_path, 'w') as f:
                json.dump(self.session_data, f, indent=2)
        except Exception as e:
            print(f"Error saving report: {e}")
    
    def get_report_path(self):
        """Return path to current report"""
        return self.report_path
