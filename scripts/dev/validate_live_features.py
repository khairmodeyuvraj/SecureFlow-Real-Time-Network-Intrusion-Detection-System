
import joblib
import numpy as np
import pandas as pd
from pathlib import Path

# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent
MODEL_PATH = PROJECT_ROOT / "models" / "final_ids_model.pkl"
INPUT_CSV = PROJECT_ROOT / "results" / "feature_validation" / "test_flows.csv"
OUTPUT_CSV = PROJECT_ROOT / "results" / "feature_validation" / "test_predictions.csv"

# ============================================================
# LOAD MODEL AND CICFLOWMETER OUTPUT
# ============================================================

model = joblib.load(MODEL_PATH)
df = pd.read_csv(INPUT_CSV)

if df.empty:
    raise ValueError("Input CSV contains no flow records.")

# ============================================================
# CICFLOWMETER COLUMN -> MODEL FEATURE
# ============================================================

mapping = {
    "Destination_Port": "dst_port",
    "Flow_Duration": "flow_duration",
    "Total_Fwd_Packets": "tot_fwd_pkts",
    "Total_Backward_Packets": "tot_bwd_pkts",
    "Total_Length_of_Fwd_Packets": "totlen_fwd_pkts",
    "Total_Length_of_Bwd_Packets": "totlen_bwd_pkts",
    "Fwd_Packet_Length_Max": "fwd_pkt_len_max",
    "Fwd_Packet_Length_Min": "fwd_pkt_len_min",
    "Fwd_Packet_Length_Mean": "fwd_pkt_len_mean",
    "Fwd_Packet_Length_Std": "fwd_pkt_len_std",
    "Bwd_Packet_Length_Max": "bwd_pkt_len_max",
    "Bwd_Packet_Length_Min": "bwd_pkt_len_min",
    "Bwd_Packet_Length_Mean": "bwd_pkt_len_mean",
    "Bwd_Packet_Length_Std": "bwd_pkt_len_std",
    "Flow_Bytess": "flow_byts_s",
    "Flow_Packetss": "flow_pkts_s",
    "Flow_IAT_Mean": "flow_iat_mean",
    "Flow_IAT_Std": "flow_iat_std",
    "Flow_IAT_Max": "flow_iat_max",
    "Flow_IAT_Min": "flow_iat_min",
    "Fwd_IAT_Total": "fwd_iat_tot",
    "Fwd_IAT_Mean": "fwd_iat_mean",
    "Fwd_IAT_Std": "fwd_iat_std",
    "Fwd_IAT_Max": "fwd_iat_max",
    "Fwd_IAT_Min": "fwd_iat_min",
    "Bwd_IAT_Total": "bwd_iat_tot",
    "Bwd_IAT_Mean": "bwd_iat_mean",
    "Bwd_IAT_Std": "bwd_iat_std",
    "Bwd_IAT_Max": "bwd_iat_max",
    "Bwd_IAT_Min": "bwd_iat_min",
    "Fwd_PSH_Flags": "fwd_psh_flags",
    "Fwd_URG_Flags": "fwd_urg_flags",
    "Fwd_Header_Length": "fwd_header_len",
    "Bwd_Header_Length": "bwd_header_len",
    "Fwd_Packetss": "fwd_pkts_s",
    "Bwd_Packetss": "bwd_pkts_s",
    "Min_Packet_Length": "pkt_len_min",
    "Max_Packet_Length": "pkt_len_max",
    "Packet_Length_Mean": "pkt_len_mean",
    "Packet_Length_Std": "pkt_len_std",
    "Packet_Length_Variance": "pkt_len_var",
    "FIN_Flag_Count": "fin_flag_cnt",
    "SYN_Flag_Count": "syn_flag_cnt",
    "RST_Flag_Count": "rst_flag_cnt",
    "PSH_Flag_Count": "psh_flag_cnt",
    "ACK_Flag_Count": "ack_flag_cnt",
    "URG_Flag_Count": "urg_flag_cnt",
    "CWE_Flag_Count": "cwr_flag_count",
    "ECE_Flag_Count": "ece_flag_cnt",
    "DownUp_Ratio": "down_up_ratio",
    "Average_Packet_Size": "pkt_size_avg",
    "Avg_Fwd_Segment_Size": "fwd_seg_size_avg",
    "Avg_Bwd_Segment_Size": "bwd_seg_size_avg",
    "Fwd_Header_Length1": "fwd_header_len",
    "Subflow_Fwd_Packets": "subflow_fwd_pkts",
    "Subflow_Fwd_Bytes": "subflow_fwd_byts",
    "Subflow_Bwd_Packets": "subflow_bwd_pkts",
    "Subflow_Bwd_Bytes": "subflow_bwd_byts",
    "Init_Win_bytes_forward": "init_fwd_win_byts",
    "Init_Win_bytes_backward": "init_bwd_win_byts",
    "act_data_pkt_fwd": "fwd_act_data_pkts",
    "min_seg_size_forward": "fwd_seg_size_min",
    "Active_Mean": "active_mean",
    "Active_Std": "active_std",
    "Active_Max": "active_max",
    "Active_Min": "active_min",
    "Idle_Mean": "idle_mean",
    "Idle_Std": "idle_std",
    "Idle_Max": "idle_max",
    "Idle_Min": "idle_min",
}

features = pd.DataFrame(index=df.index)

for model_feature, source_column in mapping.items():
    if source_column not in df.columns:
        raise KeyError(
            f"Missing CICFlowMeter column: {source_column}"
        )

    features[model_feature] = pd.to_numeric(
        df[source_column],
        errors="coerce"
    )

# ============================================================
# TIMING UNIT CONVERSION
# CICFlowMeter output is in seconds for these fields.
# CICIDS2017 training CSV uses microseconds for corresponding
# duration and IAT fields.
# ============================================================

timing_features = [
    "Flow_Duration",
    "Flow_IAT_Mean",
    "Flow_IAT_Std",
    "Flow_IAT_Max",
    "Flow_IAT_Min",
    "Fwd_IAT_Total",
    "Fwd_IAT_Mean",
    "Fwd_IAT_Std",
    "Fwd_IAT_Max",
    "Fwd_IAT_Min",
    "Bwd_IAT_Total",
    "Bwd_IAT_Mean",
    "Bwd_IAT_Std",
    "Bwd_IAT_Max",
    "Bwd_IAT_Min",
    "Active_Mean",
    "Active_Std",
    "Active_Max",
    "Active_Min",
    "Idle_Mean",
    "Idle_Std",
    "Idle_Max",
    "Idle_Min",
]

for col in timing_features:
    features[col] = features[col] * 1_000_000

# Do not convert rate features such as Flow_Bytess or Flow_Packetss.

# ============================================================
# ENGINEERED FEATURES
# Match the training notebook's safe_divide behavior.
# ============================================================

def safe_divide(numerator, denominator):
    denominator = denominator.replace(0, np.nan)

    result = numerator / denominator

    return result.replace(
        [np.inf, -np.inf], np.nan
    ).fillna(0)


features["Fwd_Bwd_Packet_Ratio"] = safe_divide(
    features["Total_Fwd_Packets"],
    features["Total_Backward_Packets"]
)

features["Fwd_Bwd_Byte_Ratio"] = safe_divide(
    features["Total_Length_of_Fwd_Packets"],
    features["Total_Length_of_Bwd_Packets"]
)

features["Avg_Fwd_Packet_Size"] = safe_divide(
    features["Total_Length_of_Fwd_Packets"],
    features["Total_Fwd_Packets"]
)

features["Avg_Bwd_Packet_Size"] = safe_divide(
    features["Total_Length_of_Bwd_Packets"],
    features["Total_Backward_Packets"]
)

# ============================================================
# VALIDATE FEATURE NAMES AND ORDER
# ============================================================

if not hasattr(model, "feature_names_in_"):
    raise AttributeError(
        "Model does not expose feature_names_in_. "
        "Load the saved feature_config.json to verify feature order."
    )

expected = list(model.feature_names_in_)

missing = [
    name for name in expected
    if name not in features.columns
]

if missing:
    raise ValueError(f"Missing model features: {missing}")

X = features[expected].copy()

# Convert any unexpected infinite values to NaN.
X = X.replace([np.inf, -np.inf], np.nan)

if X.isna().any().any():
    bad = X.columns[X.isna().any()].tolist()
    raise ValueError(
        f"Missing/non-numeric values in features: {bad}"
    )

# ============================================================
# FEATURE VALIDATION REPORT
# ============================================================

print("=" * 60)
print("AI-BASED INTRUSION DETECTION SYSTEM")
print("FEATURE VALIDATION REPORT")
print("=" * 60)

print("Input rows:", len(X))
print("Model features:", X.shape[1])
print("Expected features:", len(expected))
print("Missing features:", len(missing))
print("NaN values:", int(X.isna().sum().sum()))
print("Infinite values:", int(np.isinf(X.to_numpy()).sum()))

print("\nTiming fields after conversion to microseconds:")
print(X[timing_features].head().to_string())

print("\nFeature ranges:")
print(
    X[
        [
            "Flow_Duration",
            "Flow_IAT_Mean",
            "Fwd_IAT_Total",
            "Flow_Bytess",
            "Flow_Packetss",
        ]
    ].describe().to_string()
)

# ============================================================
# SAFETY GATE
# ============================================================
# Do not enable prediction until all feature definitions,
# units, direction conventions, and derived features have
# been validated against the original training dataset.

print("\nStructural feature validation passed.")
print("Prediction remains disabled pending semantic validation.")
print("No predictions have been generated.")