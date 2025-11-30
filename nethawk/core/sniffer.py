"""
Packet Sniffer Module
"""
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw
from scapy.layers.inet import TCP as TCPLayer
from nethawk.ui.console import info, warning, error
import time


class PacketSniffer:
    """Live packet capture and classification"""
    
    def __init__(self, interface, bpf_filter=None, timeout=30):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.timeout = timeout
        self.packets_data = []
    
    def capture(self):
        """Start packet capture"""
        try:
            info(f"Sniffing on {self.interface}...")
            packets = sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                timeout=self.timeout,
                prn=self._process_packet,
                store=True
            )
            info(f"Captured {len(packets)} packets")
            return self.packets_data
        except PermissionError:
            error("Permission denied. Run with sudo/root privileges.")
            return []
        except Exception as e:
            error(f"Capture error: {e}")
            return []
    
    def _process_packet(self, pkt):
        """Process and classify individual packet"""
        try:
            pkt_data = {
                "timestamp": time.time(),
                "protocol": None,
                "src": None,
                "dst": None,
                "sport": None,
                "dport": None,
                "flags": [],
                "type": "unknown",
                "details": {}
            }
            
            if IP in pkt:
                pkt_data["src"] = pkt[IP].src
                pkt_data["dst"] = pkt[IP].dst
                pkt_data["protocol"] = pkt[IP].proto
            
            # TCP Analysis
            if TCP in pkt:
                pkt_data["type"] = "tcp"
                pkt_data["sport"] = pkt[TCP].sport
                pkt_data["dport"] = pkt[TCP].dport
                pkt_data["flags"] = self._parse_tcp_flags(pkt[TCP].flags)
                
                # Detect scan patterns
                if "S" in pkt_data["flags"] and len(pkt_data["flags"]) == 1:
                    pkt_data["details"]["scan_type"] = "SYN"
                elif "F" in pkt_data["flags"] and "P" in pkt_data["flags"] and "U" in pkt_data["flags"]:
                    pkt_data["details"]["scan_type"] = "XMAS"
                elif not pkt_data["flags"]:
                    pkt_data["details"]["scan_type"] = "NULL"
            
            # UDP Analysis
            elif UDP in pkt:
                pkt_data["type"] = "udp"
                pkt_data["sport"] = pkt[UDP].sport
                pkt_data["dport"] = pkt[UDP].dport
            
            # ICMP Analysis
            elif ICMP in pkt:
                pkt_data["type"] = "icmp"
                pkt_data["details"]["icmp_type"] = pkt[ICMP].type
                pkt_data["details"]["icmp_code"] = pkt[ICMP].code
            
            # DNS Analysis
            if DNS in pkt and pkt.haslayer(DNS):
                pkt_data["type"] = "dns"
                if pkt[DNS].qd:
                    query = pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
                    pkt_data["details"]["dns_query"] = query
                    
                    # DNS Tunneling Detection
                    if len(query) > 50 or query.count('.') > 5:
                        pkt_data["details"]["suspicious"] = "possible_dns_tunneling"
            
            # TLS/SSL SNI Extraction
            if TCP in pkt and pkt[TCP].dport == 443 and Raw in pkt:
                payload = bytes(pkt[Raw].load)
                if b"\x16\x03" in payload[:2]:  # TLS handshake
                    pkt_data["details"]["tls_handshake"] = True
            
            self.packets_data.append(pkt_data)
            
        except Exception as e:
            pass  # Silently skip malformed packets
    
    def _parse_tcp_flags(self, flags):
        """Parse TCP flags to readable format"""
        flag_map = {
            0x01: "F",  # FIN
            0x02: "S",  # SYN
            0x04: "R",  # RST
            0x08: "P",  # PSH
            0x10: "A",  # ACK
            0x20: "U",  # URG
        }
        return [v for k, v in flag_map.items() if flags & k]
