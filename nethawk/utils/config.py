"""
Configuration Module
"""


class Config:
    """Default configuration settings"""
    
    def __init__(self):
        self.sniff_timeout = 30
        self.default_interface = "eth0"
        self.report_dir = "reports"
        self.colors_enabled = True
        self.max_hops = 30
        self.traceroute_timeout = 2
