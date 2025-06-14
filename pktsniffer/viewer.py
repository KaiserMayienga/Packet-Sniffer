import os
from collections import Counter
import matplotlib.pyplot as plt

# Attempt to locate log file
LOG_FILE = os.path.join("logs", "packet_log.txt")
if not os.path.isfile(LOG_FILE):
    LOG_FILE = "packet_log.txt"

def parse_log_line(line):
    """
    Parses a single log line to extract protocol, source IP, and destination IP.
    Returns: (protocol, src_ip, dst_ip) or (None, None, None) if invalid.
    """
    try:
        if "[" in line and "]" in line and "→" in line:
            parts = line.strip().split()
            protocol = parts[2].strip("[]")
            src_ip = parts[3].split(":")[0]
            dst_ip = parts[5].split(":")[0]
            return protocol, src_ip, dst_ip
    except Exception:
        pass
    return None, None, None

def analyze_log():
    """
    Reads the log file, parses data, shows printed stats and graphs.
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
    else:
        print("No valid packets found.")

    # Source IP Stats
    if src_ip_counter:
        print("\n📍 Top 5 Source IPs:")
        for ip, count in src_ip_counter.most_common(5):
            print(f"  {ip:<15} {count} packets")

    # Destination IP Stats
    if dst_ip_counter:
        print("\n🎯 Top 5 Destination IPs:")
        for ip, count in dst_ip_counter.most_common(5):
            print(f"  {ip:<15} {count} packets")

    # ======= Show Graphs =======
    if protocol_counter:
        show_bar_chart(protocol_counter, "Packets by Protocol", "Protocol", "Count")

    if src_ip_counter:
        show_bar_chart(src_ip_counter.most_common(5), "Top 5 Source IPs", "IP", "Packets")

    if dst_ip_counter:
        show_bar_chart(dst_ip_counter.most_common(5), "Top 5 Destination IPs", "IP", "Packets")

def show_bar_chart(data, title, xlabel, ylabel):
    """Displays a simple bar chart from a counter or list of tuples."""
    if isinstance(data, Counter):
        labels, values = zip(*data.items())
    else:
        labels, values = zip(*data)

    plt.figure(figsize=(8, 5))
    plt.bar(labels, values, color="skyblue", edgecolor="black")
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.xticks(rotation=30)
    plt.tight_layout()
    plt.grid(axis="y", linestyle="--", alpha=0.5)
    plt.show()

if __name__ == "__main__":
    analyze_log()
