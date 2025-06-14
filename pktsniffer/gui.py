import os
import sys  # ✅ FIX: required for getattr(sys, 'frozen', False)
from collections import Counter
import matplotlib.pyplot as plt

# Handle dynamic paths (works if bundled with PyInstaller)
if getattr(sys, 'frozen', False):
    BASE_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Ensure folders exist
os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "assets"), exist_ok=True)

# Define path to the log file
LOG_FILE = os.path.join(BASE_DIR, "logs", "packet_log.txt")

def parse_log_line(line):
    """
    Parses a single log line to extract protocol, source IP, and destination IP.
    Expected format:
    [YYYY-MM-DD HH:MM:SS] [PROTOCOL] SRC_IP:SRC_PORT → DST_IP:DST_PORT
    Returns a tuple: (protocol, src_ip, dst_ip)
    """
    try:
        if line.startswith("[") and "]" in line and "→" in line:
            parts = line.strip().split()
            protocol = parts[2].strip("[]")
            src_ip = parts[3].split(":")[0]
            dst_ip = parts[5].split(":")[0]
            return protocol, src_ip, dst_ip
    except Exception:
        pass  # Skip malformed lines
    return None, None, None

def analyze_log():
    """
    Analyzes the log file and visualizes statistics on protocol usage and IP frequency.
    """
    if not os.path.isfile(LOG_FILE):
        print(f"❌ Log file not found at: {LOG_FILE}")
        return

    protocol_counter = Counter()
    src_ip_counter = Counter()
    dst_ip_counter = Counter()

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            protocol, src_ip, dst_ip = parse_log_line(line)
            if protocol and src_ip and dst_ip:
                protocol_counter[protocol] += 1
                src_ip_counter[src_ip] += 1
                dst_ip_counter[dst_ip] += 1

    print("\n📊 Packet Log Summary")
    print("=" * 40)

    # Protocol Stats
    if protocol_counter:
        print("✅ Packets by Protocol:")
        for proto, count in protocol_counter.items():
            print(f"  {proto:<6}: {count} packets")

        # Bar chart for protocols
        plt.figure(figsize=(7, 4))
        plt.bar(protocol_counter.keys(), protocol_counter.values(), color='royalblue')
        plt.title("Packet Count by Protocol")
        plt.ylabel("Packet Count")
        plt.xlabel("Protocol")
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.show()
    else:
        print("No valid packets found.")

    # Source IP Stats
    if src_ip_counter:
        print("\n📍 Top 5 Source IPs:")
        for ip, count in src_ip_counter.most_common(5):
            print(f"  {ip:<15} {count} packets")

        # Pie chart for top 5 source IPs
        top_src = src_ip_counter.most_common(5)
        labels, values = zip(*top_src)
        plt.figure(figsize=(6, 6))
        plt.pie(values, labels=labels, autopct='%1.1f%%', startangle=140)
        plt.title("Top 5 Source IPs")
        plt.axis('equal')
        plt.tight_layout()
        plt.show()

    # Destination IP Stats
    if dst_ip_counter:
        print("\n🎯 Top 5 Destination IPs:")
        for ip, count in dst_ip_counter.most_common(5):
            print(f"  {ip:<15} {count} packets")

        # Pie chart for top 5 destination IPs
        top_dst = dst_ip_counter.most_common(5)
        labels, values = zip(*top_dst)
        plt.figure(figsize=(6, 6))
        plt.pie(values, labels=labels, autopct='%1.1f%%', startangle=140)
        plt.title("Top 5 Destination IPs")
        plt.axis('equal')
        plt.tight_layout()
        plt.show()

if __name__ == "__main__":
    analyze_log()
