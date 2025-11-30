"""
Anomaly Detection Module
"""
from collections import defaultdict, Counter
from nethawk.ui.console import warning, error, info
import ipaddress


class AnomalyDetector:
    """Detect security anomalies and suspicious patterns"""
    
    def __init__(self):
        self.syn_tracker = defaultdict(set)  # src -> set of dst ports
        self.protocol_counter = Counter()
        self.route_tracker = {}
        self.anomalies = []
        self.packet_count = 0
    
    def analyze(self, pkt_data):
        """Analyze packet for anomalies"""
        self.packet_count += 1
        detected = []
        
        src = pkt_data.get("src")
        dst = pkt_data.get("dst")
        dport = pkt_data.get("dport")
        proto = pkt_data.get("type")
        flags = pkt_data.get("flags", [])
        details = pkt_data.get("details", {})
        
        # Port scan detection
        if proto == "tcp" and "S" in flags and "A" not in flags:
            if src and dport:
                self.syn_tracker[src].add(dport)
                if len(self.syn_tracker[src]) > 10:
                    anomaly = {
                        "type": "port_scan",
                        "source": src,
                        "details": f"SYN packets to {len(self.syn_tracker[src])} ports",
                        "severity": "high"
                    }
                    detected.append(anomaly)
                    self.anomalies.append(anomaly)
        
        # DNS tunneling detection
        if "suspicious" in details and details["suspicious"] == "possible_dns_tunneling":
            anomaly = {
                "type": "dns_tunneling",
                "source": src,
                "details": f"Suspicious DNS query: {details.get('dns_query', 'N/A')}",
                "severity": "medium"
            }
            detected.append(anomaly)
            self.anomalies.append(anomaly)
        
        # Unusual scan patterns
        if "scan_type" in details:
            scan_type = details["scan_type"]
            if scan_type in ["XMAS", "NULL"]:
                anomaly = {
                    "type": "stealth_scan",
                    "source": src,
                    "details": f"{scan_type} scan detected",
                    "severity": "high"
                }
                detected.append(anomaly)
                self.anomalies.append(anomaly)
        
        # Private to public IP anomaly
        if src and dst:
            try:
                src_ip = ipaddress.ip_address(src)
                dst_ip = ipaddress.ip_address(dst)
                if src_ip.is_private and not dst_ip.is_private:
                    if proto in ["icmp"] and self.packet_count % 50 == 0:
                        anomaly = {
                            "type": "private_to_public",
                            "source": src,
                            "details": f"Private IP {src} communicating with public IP {dst}",
                            "severity": "low"
                        }
                        detected.append(anomaly)
            except:
                pass
        
        # Protocol tracking
        if proto:
            self.protocol_counter[proto] += 1
        
        # Alert on detected anomalies
        for anomaly in detected:
            if anomaly["severity"] == "high":
                error(f"[ANOMALY] {anomaly['type']}: {anomaly['details']}")
            elif anomaly["severity"] == "medium":
                warning(f"[ANOMALY] {anomaly['type']}: {anomaly['details']}")
        
        return detected
    
    def print_summary(self):
        """Print anomaly detection summary"""
        if not self.anomalies:
            info("No anomalies detected")
            return
        
        info(f"Total anomalies detected: {len(self.anomalies)}\n")
        
        anomaly_types = Counter(a["type"] for a in self.anomalies)
        for atype, count in anomaly_types.most_common():
            warning(f"{atype}: {count} occurrences")
    
    def get_anomalies(self):
        """Return list of detected anomalies"""
        return self.anomalies
