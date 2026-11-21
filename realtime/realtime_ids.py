"""
Realtime AI-Based Intrusion Detection Engine (SecureFlow).

Connects Scapy/flow capture with the trained 74-feature Random Forest IDS model.
Supports:
  1. Live hardware packet sniffing via Npcap/Scapy
  2. Verified demonstration stream replay from benchmark datasets
  3. Continuous flow aggregation and expiration
  4. Real-time inference, prediction confidence calculation, and threat alert logging
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd

from config import MODEL_PATH, SAMPLES_DIR, RESULTS_DIR
from src.inference.predictor import get_predictor
from src.network.flow_builder import FlowManager, Flow
from src.network.packet_capture import (
    LiveTrafficManager,
    get_available_interfaces,
    check_capture_capabilities,
)
from src.utils.logger import get_logger

logger = get_logger("RealtimeIDS")

# Detection log file path
ALERTS_DIR = RESULTS_DIR / "alerts"
ALERTS_DIR.mkdir(parents=True, exist_ok=True)
DETECTION_LOG_FILE = ALERTS_DIR / "realtime_detection_log.csv"

LOG_COLUMNS = [
    "Timestamp",
    "Protocol",
    "Source_IP",
    "Source_Port",
    "Destination_IP",
    "Destination_Port",
    "Total_Packets",
    "Forward_Packets",
    "Backward_Packets",
    "Forward_Bytes",
    "Backward_Bytes",
    "Prediction",
    "Attack_Type",
    "Confidence",
]


def init_detection_log() -> None:
    """Ensure the realtime detection log CSV has headers."""
    if not DETECTION_LOG_FILE.exists():
        with open(DETECTION_LOG_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(LOG_COLUMNS)


def log_detection(record: Dict[str, Any]) -> None:
    """Append a classified flow event to the persistent CSV detection log."""
    init_detection_log()
    row = [
        record.get("Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        record.get("Protocol", "TCP"),
        record.get("Source_IP", "-"),
        record.get("Source_Port", 0),
        record.get("Destination_IP", "-"),
        record.get("Destination_Port", 0),
        record.get("Total_Packets", 1),
        record.get("Fwd_Packets", 1),
        record.get("Bwd_Packets", 0),
        record.get("Source_Bytes", 0),
        record.get("Download_Bytes", 0),
        record.get("Prediction", "BENIGN"),
        record.get("Attack_Type", "Normal"),
        f"{record.get('Confidence', 100.0):.1f}%",
    ]
    try:
        with open(DETECTION_LOG_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(row)
    except OSError as err:
        logger.warning(f"Could not append to realtime detection log: {err}")


class RealtimeIDSEngine:
    """
    Main controller for the real-time intrusion detection pipeline.
    Bridges network capture with the trained Random Forest classifier.
    """

    def __init__(self, mode: str = "demo", interface: Optional[str] = None):
        self.mode = mode
        self.interface = interface
        self.predictor = get_predictor()
        self.manager = LiveTrafficManager.get_instance(user_id="standalone")
        self.is_running = False

    def start(self, interval_seconds: float = 1.0) -> None:
        """Start monitoring loop."""
        logger.info(f"Starting Realtime IDS Engine (mode={self.mode}, iface={self.interface})")
        self.manager.start(mode=self.mode, interface=self.interface, interval_seconds=interval_seconds)
        self.is_running = True

    def stop(self) -> None:
        """Stop monitoring loop."""
        self.manager.stop()
        self.is_running = False
        logger.info("Realtime IDS Engine stopped.")

    def run_cli_loop(self) -> None:
        """Run terminal-based monitoring console with live output."""
        self.start()
        print("=" * 70)
        print(" SecureFlow AI-IDS · Realtime Telemetry Console")
        print(f" Mode: {self.mode.upper()} | Interface: {self.interface or 'Default'}")
        print(" Press Ctrl+C to stop monitoring.")
        print("=" * 70)

        seen_count = 0
        try:
            while True:
                time.sleep(1.2)
                data = self.manager.get_latest_records(count=20)
                records = data.get("records", [])
                total = data.get("total_streamed", 0)

                if total > seen_count:
                    new_flows = records[-(total - seen_count):] if (total - seen_count) <= len(records) else records
                    for f in new_flows:
                        pred = f.get("Prediction", "BENIGN")
                        attack = f.get("Attack_Type", "Normal")
                        conf = f.get("Confidence", 100.0)
                        src = f"{f.get('Source_IP')}:{f.get('Source_Port')}"
                        dst = f"{f.get('Destination_IP')}:{f.get('Destination_Port')}"
                        tag = "🚨 ATTACK" if pred == "ATTACK" else "✓ BENIGN"
                        print(f"[{f.get('Timestamp')}] {tag:<10} | {attack:<20} | {conf:>5.1f}% | {src} -> {dst}")
                        log_detection(f)
                    seen_count = total
        except KeyboardInterrupt:
            print("\nStopping Realtime IDS Engine...")
            self.stop()
            print("Monitoring terminated cleanly.")


def main():
    parser = argparse.ArgumentParser(description="SecureFlow Realtime AI Intrusion Detection System")
    parser.add_argument("--mode", choices=["demo", "live"], default="demo", help="Telemetry stream mode")
    parser.add_argument("--interface", default=None, help="Network adapter name/GUID for live sniffing")
    parser.add_argument("--list-interfaces", action="store_true", help="List detected network adapters and exit")
    args = parser.parse_args()

    if args.list_interfaces:
        caps = check_capture_capabilities()
        print(f"Npcap / WinPcap Status: {'Available' if caps['can_sniff'] else 'Unavailable / Limited'}")
        print("Detected Network Interfaces:")
        for idx, iface in enumerate(get_available_interfaces(), 1):
            ip_str = f" ({iface['ip']})" if iface.get("ip") else ""
            print(f"  {idx}. {iface['name']}{ip_str} - {iface['description']}")
        return

    engine = RealtimeIDSEngine(mode=args.mode, interface=args.interface)
    engine.run_cli_loop()


if __name__ == "__main__":
    main()

