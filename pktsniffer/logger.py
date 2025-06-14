import os
from datetime import datetime

# === Configuration ===
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "packet_log.txt")

# === Setup ===
def init_log():
    """
    Initializes the log file:
    - Creates 'logs' directory if it doesn't exist
    - Writes a session header with timestamp
    """
    os.makedirs(LOG_DIR, exist_ok=True)
    
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write("\n\n=== Packet Sniffing Session Started ===\n")
        f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 40 + "\n")

# === Log packet entries ===
def log_packet(protocol, src_ip, src_port, dst_ip, dst_port):
    """
    Logs details of a captured packet in a readable format.
    
    Args:
        protocol (str): Protocol name (TCP, UDP, etc.)
        src_ip (str): Source IP address
        src_port (int or str): Source port
        dst_ip (str): Destination IP address
        dst_port (int or str): Destination port
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{protocol}] {src_ip}:{src_port} → {dst_ip}:{dst_port}\n"

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_entry)

# === Log any errors ===
def log_error(message):
    """
    Logs an error message with timestamp for debugging.

    Args:
        message (str): Error message string
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[ERROR] [{timestamp}] {message}\n")
