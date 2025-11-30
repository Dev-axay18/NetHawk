"""
Flow Analysis Module
"""
from collections import defaultdict, Counter
from nethawk.ui.console import info, print_table


class FlowAnalyzer:
    """Analyze packet flows and traffic patterns"""
    
    def __init__(self):
        self.flows = defaultdict(int)
        self.src_ips = Counter()
        self.dst_ips = Counter()
        self.ports = Counter()
        self.protocols = Counter()
        self.tcp_handshakes = {"success": 0, "failed": 0}
        self.total_packets = 0
    
    def add_packet(self, pkt_data):
        """Add packet to flow analysis"""
        self.total_packets += 1
        
        src = pkt_data.get("src")
        dst = pkt_data.get("dst")
        sport = pkt_data.get("sport")
        dport = pkt_data.get("dport")
        proto = pkt_data.get("type", "unknown")
        
        if src:
            self.src_ips[src] += 1
        if dst:
            self.dst_ips[dst] += 1
        if dport:
            self.ports[dport] += 1
        
        self.protocols[proto] += 1
        
        # Flow tracking
        if src and dst:
            flow_key = f"{src}:{sport} -> {dst}:{dport}"
            self.flows[flow_key] += 1
        
        # TCP handshake tracking
        if proto == "tcp":
            flags = pkt_data.get("flags", [])
            if "S" in flags and "A" in flags:
                self.tcp_handshakes["success"] += 1
            elif "R" in flags:
                self.tcp_handshakes["failed"] += 1
    
    def print_summary(self):
        """Print flow analysis summary"""
        info(f"Total packets analyzed: {self.total_packets}\n")
        
        # Top talkers
        print("Top Source IPs:")
        headers = ["IP", "Packets", "Percentage"]
        rows = []
        for ip, count in self.src_ips.most_common(5):
            pct = (count / self.total_packets) * 100
            rows.append([ip, count, f"{pct:.1f}%"])
        print_table(headers, rows)
        
        print("\nTop Destination IPs:")
        rows = []
        for ip, count in self.dst_ips.most_common(5):
            pct = (count / self.total_packets) * 100
            rows.append([ip, count, f"{pct:.1f}%"])
        print_table(headers, rows)
        
        print("\nTop Ports:")
        headers = ["Port", "Packets", "Percentage"]
        rows = []
        for port, count in self.ports.most_common(10):
            pct = (count / self.total_packets) * 100
            rows.append([port, count, f"{pct:.1f}%"])
        print_table(headers, rows)
        
        print("\nProtocol Distribution:")
        for proto, count in self.protocols.most_common():
            pct = (count / self.total_packets) * 100
            info(f"{proto.upper()}: {count} packets ({pct:.1f}%)")
        
        print(f"\nTCP Handshakes: {self.tcp_handshakes['success']} successful, "
              f"{self.tcp_handshakes['failed']} failed")
    
    def get_summary(self):
        """Return flow summary as dictionary"""
        return {
            "total_packets": self.total_packets,
            "top_sources": dict(self.src_ips.most_common(10)),
            "top_destinations": dict(self.dst_ips.most_common(10)),
            "top_ports": dict(self.ports.most_common(10)),
            "protocols": dict(self.protocols),
            "tcp_handshakes": self.tcp_handshakes
        }
