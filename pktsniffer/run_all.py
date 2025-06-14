import os
import time
import sys

# Define base directory where your project files are located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Define paths to the scripts
sniffer_path = os.path.join(BASE_DIR, "sniffer.py")
gui_path = os.path.join(BASE_DIR, "gui.py")

# Optional: Customize packet count here
PACKET_COUNT = 100

def run_sniffer():
    print("🔍 Starting packet capture...")
    os.system(f'python "{sniffer_path}" --count {PACKET_COUNT}')
    print("✅ Packet capture complete.\n")

def run_gui():
    print("📊 Launching log visualizer...")
    os.system(f'python "{gui_path}"')
    print("✅ Visualization complete.\n")

def main():
    run_sniffer()
    time.sleep(2)  # short pause before visualization
    run_gui()

if __name__ == "__main__":
    main()
