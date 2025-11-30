"""
Threat Intelligence Module
"""
import os
from nethawk.ui.console import error, warning


class ThreatIntel:
    """Lightweight offline threat intelligence"""
    
    def __init__(self, blacklist_path="data/threat_blacklist.txt"):
        self.blacklist = set()
        self.blacklist_path = blacklist_path
        self._load_blacklist()
    
    def _load_blacklist(self):
        """Load threat blacklist from file"""
        if not os.path.exists(self.blacklist_path):
            warning(f"Threat blacklist not found: {self.blacklist_path}")
            return
        
        try:
            with open(self.blacklist_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.blacklist.add(line)
        except Exception as e:
            error(f"Error loading blacklist: {e}")
    
    def check_threat(self, pkt_data):
        """Check if packet involves blacklisted IP"""
        src = pkt_data.get("src")
        dst = pkt_data.get("dst")
        
        if src in self.blacklist:
            error(f"[THREAT] Source IP {src} matches blacklist")
            return True
        
        if dst in self.blacklist:
            error(f"[THREAT] Destination IP {dst} matches blacklist")
            return True
        
        return False
    
    def add_to_blacklist(self, ip):
        """Add IP to blacklist"""
        self.blacklist.add(ip)
        try:
            with open(self.blacklist_path, 'a') as f:
                f.write(f"{ip}\n")
        except Exception as e:
            error(f"Error updating blacklist: {e}")
