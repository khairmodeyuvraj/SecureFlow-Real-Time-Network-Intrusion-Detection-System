
from pathlib import Path
import pandas as pd

root = Path(__file__).resolve().parent

training_csv = (
    root / "data" / "raw" / "CICIDS2017"
    / "Monday-WorkingHours.pcap_ISCX.csv"
)
flow_csv = root / "results" / "feature_validation" / "test_flows.csv"

train = pd.read_csv(training_csv, nrows=1000, encoding="utf-8-sig", low_memory=False)
flows = pd.read_csv(flow_csv, low_memory=False)

train.columns = train.columns.str.strip()

print("=== TRAINING DATA COLUMNS ===")
print(train.columns.tolist())

print("\n=== PCAP FLOW COLUMNS ===")
print(flows.columns.tolist())


checks = [
    ("Flow Duration", "flow_duration"),
    ("Flow IAT Mean", "flow_iat_mean"),
    ("Flow IAT Std", "flow_iat_std"),
    ("Flow IAT Max", "flow_iat_max"),
    ("Flow IAT Min", "flow_iat_min"),
    ("Fwd IAT Total", "fwd_iat_tot"),
    ("Fwd IAT Mean", "fwd_iat_mean"),
    ("Bwd IAT Total", "bwd_iat_tot"),
    ("Active Mean", "active_mean"),
    ("Idle Mean", "idle_mean"),
    ("Flow Bytes/s", "flow_byts_s"),
    ("Flow Packets/s", "flow_pkts_s"),
    ("Fwd Packets/s", "fwd_pkts_s"),
    ("Bwd Packets/s", "bwd_pkts_s"),
]

for train_col, flow_col in checks:
    print(f"\n=== {train_col} vs {flow_col} ===")

    if train_col in train.columns:
        print("Training sample:")
        print(pd.to_numeric(train[train_col], errors="coerce").describe().to_string())
    else:
        print(f"Training column not found: {train_col}")

    if flow_col in flows.columns:
        print("PCAP flows:")
        print(pd.to_numeric(flows[flow_col], errors="coerce").describe().to_string())
    else:
        print(f"PCAP column not found: {flow_col}")
