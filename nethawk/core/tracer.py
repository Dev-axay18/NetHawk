"""
Advanced Traceroute Module
"""
import socket
import os
from nethawk.ui.console import info, print_table, warning, error
from nethawk.utils.geoip import get_geoip
import time


class Tracer:
    """Advanced traceroute with latency and geo tracking"""
    
    def __init__(self, max_hops=30, timeout=2):
        self.max_hops = max_hops
        self.timeout = timeout
    
    def trace(self, target):
        """Perform traceroute to target"""
        # Check for root privileges
        if os.geteuid() != 0:
            error("Traceroute requires root privileges. Run with sudo.")
            return []
        
        # Import scapy here to ensure proper initialization with root
        try:
            from scapy.all import IP, ICMP, sr1, conf
            conf.verb = 0  # Disable verbose output
        except ImportError:
            error("Scapy not installed. Install with: pip install scapy")
            return []
        
        try:
            dest_ip = socket.gethostbyname(target)
        except socket.gaierror:
            warning(f"Cannot resolve hostname: {target}")
            return []
        
        info(f"Tracing route to {target} ({dest_ip})")
        info(f"Max hops: {self.max_hops}\n")
        
        results = []
        headers = ["Hop", "IP", "Hostname", "Latency", "Location"]
        rows = []
        consecutive_timeouts = 0
        max_consecutive_timeouts = 5
        
        for ttl in range(1, self.max_hops + 1):
            try:
                pkt = IP(dst=dest_ip, ttl=ttl) / ICMP()
                
                start_time = time.time()
                reply = sr1(pkt, verbose=0, timeout=self.timeout, retry=0)
                latency = (time.time() - start_time) * 1000
            except PermissionError as e:
                error(f"Permission denied: {e}")
                error("Ensure you're running with sudo/root and scapy has proper permissions.")
                return results
            except OSError as e:
                error(f"OS Error: {e}")
                error("Try: sudo setcap cap_net_raw=eip $(which python3)")
                return results
            except Exception as e:
                warning(f"Error at hop {ttl}: {e}")
                continue
            
            if reply is None:
                consecutive_timeouts += 1
                rows.append([ttl, "*", "*", "*", "*"])
                results.append({
                    "hop": ttl,
                    "ip": None,
                    "hostname": None,
                    "latency_ms": None,
                    "location": None
                })
                
                # Stop if too many consecutive timeouts
                if consecutive_timeouts >= max_consecutive_timeouts:
                    info(f"\nStopping after {max_consecutive_timeouts} consecutive timeouts")
                    break
                continue
            
            # Reset timeout counter on successful reply
            consecutive_timeouts = 0
            
            hop_ip = reply.src
            
            # Reverse DNS
            try:
                hostname = socket.gethostbyaddr(hop_ip)[0]
            except:
                hostname = hop_ip
            
            # GeoIP lookup
            geo = get_geoip(hop_ip)
            location = f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}"
            
            rows.append([ttl, hop_ip, hostname, f"{latency:.2f} ms", location])
            
            results.append({
                "hop": ttl,
                "ip": hop_ip,
                "hostname": hostname,
                "latency_ms": round(latency, 2),
                "location": location
            })
            
            if hop_ip == dest_ip:
                break
        
        print_table(headers, rows)
        return results
