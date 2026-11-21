from pathlib import Path
import sys
import argparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.network.packet_capture import check_capture_capabilities
from src.inference.predictor import get_predictor


def run_capture(interface: str = None, packet_count: int = 20):
    print("=" * 70)
    print("AI-BASED INTRUSION DETECTION SYSTEM - TRAFFIC CAPTURE CHECK")
    print("=" * 70)

    caps = check_capture_capabilities()
    print(f"Scapy Installed          : {caps['scapy_installed']}")
    print(f"Packet Driver Present    : {caps['pcap_driver_present']}")
    print(f"Can Sniff Live Packets   : {caps['can_sniff']}")
    print(f"Status Message           : {caps['message']}")

    if caps["interfaces"]:
        print("\nDetected Network Interfaces:")
        for idx, iface in enumerate(caps["interfaces"], 1):
            print(f"  {idx}. {iface['name']} ({iface['description']})")

    if not caps["can_sniff"]:
        print("\n" + "!" * 70)
        print("NOTICE: Live network packet capture is not available in the current environment.")
        print("Reasons may include:")
        print("  1. Npcap or WinPcap driver is not installed.")
        print("  2. Command prompt is not running with Administrator privileges.")
        print("\nRecommended Alternative: Use the Replay / Demonstration mode:")
        print("  python scripts/replay_pcap.py --count 30")
        print("!" * 70)
        return

    print(f"\nStarting live sniffing for {packet_count} packets...")
    try:
        from scapy.all import sniff, IP, TCP, UDP

        def callback(pkt):
            if IP in pkt:
                proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else str(pkt[IP].proto))
                print(f"[LIVE] {proto:4} {pkt[IP].src} -> {pkt[IP].dst} (Len: {len(pkt)})")

        sniff(count=packet_count, prn=callback, store=False)
        print("\nCapture completed successfully.")
    except Exception as e:
        print(f"\nCapture failed: {e}")
        print("Use 'python scripts/replay_pcap.py' for simulated live analysis.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live traffic capture test.")
    parser.add_argument("--count", type=int, default=10, help="Packets to capture.")
    args = parser.parse_args()
    run_capture(packet_count=args.count)
