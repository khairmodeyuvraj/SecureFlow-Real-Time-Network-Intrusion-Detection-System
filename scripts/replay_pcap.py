from pathlib import Path
import sys
import time
import argparse
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import SAMPLES_DIR, RAW_DATA_DIR, PROCESSED_DATA_DIR
from src.inference.predictor import get_predictor
from src.network.pcap_reader import extract_flows_from_pcap


def replay_traffic(
    file_path: Path,
    delay_seconds: float = 0.2,
    max_records: int = 50,
):
    print("=" * 70)
    print("AI-BASED INTRUSION DETECTION SYSTEM - TRAFFIC REPLAY")
    print("=" * 70)
    print(f"Source file    : {file_path}")
    print(f"Delay interval : {delay_seconds}s")
    print(f"Max records    : {max_records}")
    print("=" * 70)

    predictor = get_predictor()

    if file_path.suffix.lower() in {".pcap", ".pcapng"}:
        print("\nExtracting flows from PCAP file...")
        df = extract_flows_from_pcap(file_path, max_packets=5000)
    else:
        print("\nLoading flows from CSV file...")
        df = pd.read_csv(file_path, nrows=max_records, low_memory=False)

    total = min(len(df), max_records)
    print(f"Streaming and classifying {total} flows in real-time:\n")

    for idx in range(total):
        row_df = df.iloc[[idx]]
        res_df, _ = predictor.predict_dataframe(row_df)
        rec = res_df.iloc[0]

        pred = rec["Prediction"]
        conf = rec["Confidence"]
        src = f"{rec['Source_IP']}:{rec['Source_Port']}"
        dst = f"{rec['Destination_IP']}:{rec['Destination_Port']}"
        proto = rec["Protocol"]

        if pred == "ATTACK":
            print(f"[REPLAY] 🚨 [{proto}] {src} -> {dst} | {pred} ({rec['Attack_Type']}) | Confidence: {conf:.1f}%")
        else:
            print(f"[REPLAY] ✓  [{proto}] {src} -> {dst} | {pred} | Confidence: {conf:.1f}%")

        time.sleep(delay_seconds)

    print("\n" + "=" * 70)
    print("Traffic replay finished.")
    print("=" * 70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Replay network traffic through the IDS model.")
    parser.add_argument(
        "--file",
        type=str,
        default=None,
        help="Path to CSV or PCAP file to replay.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.1,
        help="Delay in seconds between records.",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=30,
        help="Number of records to replay.",
    )

    args = parser.parse_args()

    default_file = (
        SAMPLES_DIR / "sample_mixed_traffic.csv"
        if (SAMPLES_DIR / "sample_mixed_traffic.csv").is_file()
        else (PROCESSED_DATA_DIR / "test.csv")
    )

    target_file = Path(args.file).resolve() if args.file else default_file
    replay_traffic(target_file, delay_seconds=args.delay, max_records=args.count)
