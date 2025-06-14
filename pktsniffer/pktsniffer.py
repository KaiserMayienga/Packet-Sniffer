import argparse
from scapy.all import sniff, wrpcap
from logger import init_log, log_packet, log_error
from collections import defaultdict
from datetime import datetime

# Track packet frequency for threat detection
port_scan_tracker = defaultdict(set)
packet_count_tracker = defaultdict(int)
THREAT_LOGGED = set()
captured_packets = []  # List to store packets for optional export


def packet_callback(packet, filters):
    try:
        if packet.haslayer("IP"):
            ip_layer = packet["IP"]
            proto = packet.payload.name.upper()

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = packet.sport if hasattr(packet, 'sport') else "N/A"
            dst_port = packet.dport if hasattr(packet, 'dport') else "N/A"

            # Apply live filters
            if filters["ip"] and filters["ip"] not in [src_ip, dst_ip]:
                return
            if filters["port"] and str(filters["port"]) not in [str(src_port), str(dst_port)]:
                return

            print(f"[{proto}] {src_ip}:{src_port} → {dst_ip}:{dst_port}")
            log_packet(proto, src_ip, src_port, dst_ip, dst_port)

            # Update counters for threats
            port_scan_tracker[src_ip].add(dst_port)
            packet_count_tracker[src_ip] += 1

            detect_threats(src_ip)

            # Save packet for pcap export
            captured_packets.append(packet)

    except Exception as e:
        log_error(f"Callback error: {str(e)}")


def detect_threats(ip):
    """
    Basic heuristics:
    - Port scan: many ports targeted in short time
    - Packet flood: very high frequency from a single IP
    """
    if len(port_scan_tracker[ip]) > 15 and ip not in THREAT_LOGGED:
        msg = f"⚠️ POSSIBLE PORT SCAN detected from {ip} on ports: {list(port_scan_tracker[ip])[:10]}..."
        print(msg)
        log_error(msg)
        THREAT_LOGGED.add(ip)

    if packet_count_tracker[ip] > 100 and ip not in THREAT_LOGGED:
        msg = f"🚨 POSSIBLE PACKET FLOOD detected from {ip} — over 100 packets!"
        print(msg)
        log_error(msg)
        THREAT_LOGGED.add(ip)


def main():
    parser = argparse.ArgumentParser(description="📡 Advanced Python Packet Sniffer")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("--iface", type=str, default=None, help="Interface to sniff on")
    parser.add_argument("--protocol", type=str, choices=["tcp", "udp", "icmp"], help="Protocol filter")
    parser.add_argument("--ip", type=str, help="Filter by IP address (source or destination)")
    parser.add_argument("--port", type=int, help="Filter by port (source or destination)")
    parser.add_argument("--pcap", type=str, help="Optional: Path to export captured packets as .pcap")

    args = parser.parse_args()

    filters = {
        "ip": args.ip,
        "port": args.port
    }

    print("🔍 Starting sniffer... Press Ctrl+C to stop.")
    init_log()

    try:
        sniff(
            prn=lambda pkt: packet_callback(pkt, filters),
            count=args.count if args.count > 0 else 0,
            iface=args.iface,
            filter=args.protocol,
            store=False
        )
    except Exception as e:
        log_error(f"Sniff error: {str(e)}")
        print(f"❌ Error: {e}")

    # Save captured packets to .pcap if path was provided
    if args.pcap and captured_packets:
        try:
            wrpcap(args.pcap, captured_packets)
            print(f"📁 Exported {len(captured_packets)} packets to '{args.pcap}'")
        except Exception as e:
            log_error(f"Failed to save .pcap: {str(e)}")
            print(f"❌ Could not save .pcap file: {e}")


if __name__ == "__main__":
    main()
