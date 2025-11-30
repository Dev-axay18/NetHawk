#!/usr/bin/env python3
"""
NetHawk Security Toolkit - Main Entry Point
"""
import argparse
import sys
from nethawk.ui.banner import show_banner
from nethawk.ui.console import success, error, info, section_header
from nethawk.core.sniffer import PacketSniffer
from nethawk.core.tracer import Tracer
from nethawk.core.flow_analyzer import FlowAnalyzer
from nethawk.core.anomaly_detector import AnomalyDetector
from nethawk.core.threat_intel import ThreatIntel
from nethawk.core.logger import Logger
from nethawk.utils.config import Config


def main():
    parser = argparse.ArgumentParser(
        description="NetHawk Security Toolkit - Next-Gen Packet & Path Intelligence"
    )
    parser.add_argument("--sniff", metavar="IFACE", help="Start packet sniffing on interface")
    parser.add_argument("--filter", metavar="FILTER", help="BPF filter for sniffing")
    parser.add_argument("--trace", metavar="TARGET", help="Perform advanced traceroute")
    parser.add_argument("--flows", action="store_true", help="Analyze packet flows")
    parser.add_argument("--detect", action="store_true", help="Enable anomaly detection")
    parser.add_argument("--fullscan", metavar="TARGET", help="Full security scan (trace + sniff + analyze)")
    parser.add_argument("--timeout", type=int, default=30, help="Sniffing timeout in seconds")
    
    args = parser.parse_args()
    
    show_banner()
    
    config = Config()
    logger = Logger(config.report_dir)
    threat_intel = ThreatIntel()
    
    try:
        if args.fullscan:
            run_fullscan(args.fullscan, logger, threat_intel, config)
        elif args.trace:
            run_trace(args.trace, logger)
        elif args.sniff:
            run_sniff(args.sniff, args.filter, args.timeout, args.detect, 
                     args.flows, logger, threat_intel)
        elif args.flows:
            info("Flow analysis requires --sniff to be active")
        else:
            parser.print_help()
    
    except KeyboardInterrupt:
        info("\n[!] Interrupted by user")
        sys.exit(0)
    except PermissionError as e:
        error(f"Permission error: {e}")
        error("Run with sudo for packet capture and traceroute features")
        sys.exit(1)
    except Exception as e:
        import traceback
        error(f"Fatal error: {e}")
        if "--debug" in sys.argv:
            traceback.print_exc()
        sys.exit(1)


def run_trace(target, logger):
    section_header("TRACEROUTE ANALYSIS")
    tracer = Tracer()
    results = tracer.trace(target)
    if results:
        logger.log_traceroute(results)
        logger.save_report()
        success(f"Traceroute completed. Results logged to {logger.report_path}")
    else:
        info("Traceroute returned no results.")


def run_sniff(interface, bpf_filter, timeout, detect, flows, logger, threat_intel):
    section_header("PACKET CAPTURE")
    
    sniffer = PacketSniffer(interface, bpf_filter, timeout)
    anomaly_detector = AnomalyDetector() if detect else None
    flow_analyzer = FlowAnalyzer() if flows else None
    
    info(f"Starting capture on {interface} for {timeout}s...")
    if bpf_filter:
        info(f"Filter: {bpf_filter}")
    
    packets = sniffer.capture()
    
    for pkt_data in packets:
        if threat_intel.check_threat(pkt_data):
            logger.log_threat(pkt_data)
        
        if anomaly_detector:
            anomalies = anomaly_detector.analyze(pkt_data)
            for anomaly in anomalies:
                logger.log_anomaly(anomaly)
        
        if flow_analyzer:
            flow_analyzer.add_packet(pkt_data)
    
    if flow_analyzer:
        section_header("FLOW ANALYSIS")
        flow_analyzer.print_summary()
        logger.log_flows(flow_analyzer.get_summary())
    
    if anomaly_detector:
        section_header("ANOMALY DETECTION")
        anomaly_detector.print_summary()
    
    logger.save_report()
    success(f"Capture complete. Report saved: {logger.report_path}")


def run_fullscan(target, logger, threat_intel, config):
    section_header("FULL SECURITY SCAN")
    info(f"Target: {target}")
    
    # Step 1: Traceroute
    section_header("STEP 1: TRACEROUTE")
    tracer = Tracer()
    trace_results = tracer.trace(target)
    logger.log_traceroute(trace_results)
    
    # Step 2: Packet capture
    section_header("STEP 2: PACKET CAPTURE")
    interface = config.default_interface
    sniffer = PacketSniffer(interface, timeout=20)
    anomaly_detector = AnomalyDetector()
    flow_analyzer = FlowAnalyzer()
    
    info(f"Capturing packets on {interface}...")
    packets = sniffer.capture()
    
    for pkt_data in packets:
        if threat_intel.check_threat(pkt_data):
            logger.log_threat(pkt_data)
        
        anomalies = anomaly_detector.analyze(pkt_data)
        for anomaly in anomalies:
            logger.log_anomaly(anomaly)
        
        flow_analyzer.add_packet(pkt_data)
    
    # Step 3: Analysis
    section_header("STEP 3: FLOW ANALYSIS")
    flow_analyzer.print_summary()
    logger.log_flows(flow_analyzer.get_summary())
    
    section_header("STEP 4: ANOMALY DETECTION")
    anomaly_detector.print_summary()
    
    logger.save_report()
    success(f"\nFull scan complete! Report: {logger.report_path}")


if __name__ == "__main__":
    main()
