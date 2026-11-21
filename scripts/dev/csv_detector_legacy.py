import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path


# ============================================================
# PATH CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_PATH = PROJECT_ROOT / "models" / "final_ids_model.pkl"
CONFIG_PATH = PROJECT_ROOT / "data" / "processed" / "feature_config.json"

INPUT_CSV = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "CICIDS2017"
    / "Friday-WorkingHours-Morning.pcap_ISCX.csv"
)

OUTPUT_CSV = (
    PROJECT_ROOT
    / "results"
    / "alerts"
    / "detection_log.csv"
)


# ============================================================
# LOAD FEATURE CONFIGURATION
# ============================================================

with open(CONFIG_PATH, "r") as file:
    feature_config = json.load(file)

FEATURES = feature_config["features"]

print("=" * 70)
print("AI-IDS FLOW DETECTOR")
print("=" * 70)

print(f"Required features : {len(FEATURES)}")
print(f"Input file        : {INPUT_CSV}")
print(f"Model             : {MODEL_PATH}")


# ============================================================
# LOAD MODEL
# ============================================================

print("\nLoading trained model...")

model = joblib.load(MODEL_PATH)

print("Model loaded successfully.")


# ============================================================
# LOAD CICIDS2017 CSV
# ============================================================

print("\nLoading CICIDS2017 flow data...")

df = pd.read_csv(INPUT_CSV)

print(f"Rows    : {len(df):,}")
print(f"Columns : {len(df.columns)}")


# ============================================================
# CLEAN COLUMN NAMES
# ============================================================

# CICIDS2017 CSV contains leading spaces in many column names.
df.columns = df.columns.str.strip()

print("\nColumn names cleaned.")


# ============================================================
# CREATE ENGINEERED FEATURES
# ============================================================

print("\nCreating engineered features...")

EPSILON = 1e-10


# ------------------------------------------------------------
# Forward / Backward packet ratio
# ------------------------------------------------------------

df["Fwd_Bwd_Packet_Ratio"] = (
    df["Total Fwd Packets"]
    / (df["Total Backward Packets"] + EPSILON)
)


# ------------------------------------------------------------
# Forward / Backward byte ratio
# ------------------------------------------------------------

df["Fwd_Bwd_Byte_Ratio"] = (
    df["Total Length of Fwd Packets"]
    / (df["Total Length of Bwd Packets"] + EPSILON)
)


# ------------------------------------------------------------
# Average Forward Packet Size
# ------------------------------------------------------------

df["Avg_Fwd_Packet_Size"] = (
    df["Total Length of Fwd Packets"]
    / (df["Total Fwd Packets"] + EPSILON)
)


# ------------------------------------------------------------
# Average Backward Packet Size
# ------------------------------------------------------------

df["Avg_Bwd_Packet_Size"] = (
    df["Total Length of Bwd Packets"]
    / (df["Total Backward Packets"] + EPSILON)
)


print("Engineered features created.")


# ============================================================
# COLUMN NAME MAPPING
# ============================================================

COLUMN_MAPPING = {

    "Destination_Port":
        "Destination Port",

    "Flow_Duration":
        "Flow Duration",

    "Total_Fwd_Packets":
        "Total Fwd Packets",

    "Total_Backward_Packets":
        "Total Backward Packets",

    "Total_Length_of_Fwd_Packets":
        "Total Length of Fwd Packets",

    "Total_Length_of_Bwd_Packets":
        "Total Length of Bwd Packets",

    "Fwd_Packet_Length_Max":
        "Fwd Packet Length Max",

    "Fwd_Packet_Length_Min":
        "Fwd Packet Length Min",

    "Fwd_Packet_Length_Mean":
        "Fwd Packet Length Mean",

    "Fwd_Packet_Length_Std":
        "Fwd Packet Length Std",

    "Bwd_Packet_Length_Max":
        "Bwd Packet Length Max",

    "Bwd_Packet_Length_Min":
        "Bwd Packet Length Min",

    "Bwd_Packet_Length_Mean":
        "Bwd Packet Length Mean",

    "Bwd_Packet_Length_Std":
        "Bwd Packet Length Std",

    "Flow_Bytess":
        "Flow Bytes/s",

    "Flow_Packetss":
        "Flow Packets/s",

    "Flow_IAT_Mean":
        "Flow IAT Mean",

    "Flow_IAT_Std":
        "Flow IAT Std",

    "Flow_IAT_Max":
        "Flow IAT Max",

    "Flow_IAT_Min":
        "Flow IAT Min",

    "Fwd_IAT_Total":
        "Fwd IAT Total",

    "Fwd_IAT_Mean":
        "Fwd IAT Mean",

    "Fwd_IAT_Std":
        "Fwd IAT Std",

    "Fwd_IAT_Max":
        "Fwd IAT Max",

    "Fwd_IAT_Min":
        "Fwd IAT Min",

    "Bwd_IAT_Total":
        "Bwd IAT Total",

    "Bwd_IAT_Mean":
        "Bwd IAT Mean",

    "Bwd_IAT_Std":
        "Bwd IAT Std",

    "Bwd_IAT_Max":
        "Bwd IAT Max",

    "Bwd_IAT_Min":
        "Bwd IAT Min",

    "Fwd_PSH_Flags":
        "Fwd PSH Flags",

    "Fwd_URG_Flags":
        "Fwd URG Flags",

    "Fwd_Header_Length":
        "Fwd Header Length",

    "Bwd_Header_Length":
        "Bwd Header Length",

    "Fwd_Packetss":
        "Fwd Packets/s",

    "Bwd_Packetss":
        "Bwd Packets/s",

    "Min_Packet_Length":
        "Min Packet Length",

    "Max_Packet_Length":
        "Max Packet Length",

    "Packet_Length_Mean":
        "Packet Length Mean",

    "Packet_Length_Std":
        "Packet Length Std",

    "Packet_Length_Variance":
        "Packet Length Variance",

    "FIN_Flag_Count":
        "FIN Flag Count",

    "SYN_Flag_Count":
        "SYN Flag Count",

    "RST_Flag_Count":
        "RST Flag Count",

    "PSH_Flag_Count":
        "PSH Flag Count",

    "ACK_Flag_Count":
        "ACK Flag Count",

    "URG_Flag_Count":
        "URG Flag Count",

    "CWE_Flag_Count":
        "CWE Flag Count",

    "ECE_Flag_Count":
        "ECE Flag Count",

    "DownUp_Ratio":
        "Down/Up Ratio",

    "Average_Packet_Size":
        "Average Packet Size",

    "Avg_Fwd_Segment_Size":
        "Avg Fwd Segment Size",

    "Avg_Bwd_Segment_Size":
        "Avg Bwd Segment Size",

    "Fwd_Header_Length1":
        "Fwd Header Length.1",

    "Subflow_Fwd_Packets":
        "Subflow Fwd Packets",

    "Subflow_Fwd_Bytes":
        "Subflow Fwd Bytes",

    "Subflow_Bwd_Packets":
        "Subflow Bwd Packets",

    "Subflow_Bwd_Bytes":
        "Subflow Bwd Bytes",

    "Init_Win_bytes_forward":
        "Init_Win_bytes_forward",

    "Init_Win_bytes_backward":
        "Init_Win_bytes_backward",

    "act_data_pkt_fwd":
        "act_data_pkt_fwd",

    "min_seg_size_forward":
        "min_seg_size_forward",

    "Active_Mean":
        "Active Mean",

    "Active_Std":
        "Active Std",

    "Active_Max":
        "Active Max",

    "Active_Min":
        "Active Min",

    "Idle_Mean":
        "Idle Mean",

    "Idle_Std":
        "Idle Std",

    "Idle_Max":
        "Idle Max",

    "Idle_Min":
        "Idle Min",

    # Engineered features
    "Fwd_Bwd_Packet_Ratio":
        "Fwd_Bwd_Packet_Ratio",

    "Fwd_Bwd_Byte_Ratio":
        "Fwd_Bwd_Byte_Ratio",

    "Avg_Fwd_Packet_Size":
        "Avg_Fwd_Packet_Size",

    "Avg_Bwd_Packet_Size":
        "Avg_Bwd_Packet_Size",
}


# ============================================================
# VERIFY REQUIRED COLUMNS
# ============================================================

print("\nChecking required features...")

missing_features = []

for feature in FEATURES:

    if feature not in COLUMN_MAPPING:
        missing_features.append(feature)

    elif COLUMN_MAPPING[feature] not in df.columns:
        missing_features.append(feature)


if missing_features:

    print("\nERROR: Missing required features:")

    for feature in missing_features:
        print(" -", feature)

    raise ValueError(
        "Required features are missing from the input dataset."
    )


print(
    f"All {len(FEATURES)} required features are available."
)


# ============================================================
# BUILD MODEL INPUT
# ============================================================

print("\nPreparing model input...")

X = pd.DataFrame()

for feature in FEATURES:

    source_column = COLUMN_MAPPING[feature]

    X[feature] = df[source_column]


# ============================================================
# CLEAN NUMERIC VALUES
# ============================================================

X = X.replace(
    [np.inf, -np.inf],
    np.nan
)

X = X.fillna(0)


print("Model input shape:", X.shape)


# ============================================================
# VERIFY FEATURE ORDER
# ============================================================

if X.columns.tolist() != FEATURES:

    raise ValueError(
        "Feature order does not match feature_config.json"
    )


print("Feature order verified.")


# ============================================================
# RUN MODEL PREDICTIONS
# ============================================================

print("\nRunning AI-IDS predictions...")

predictions = model.predict(X)


# ============================================================
# PREDICTION LABELS
# ============================================================

prediction_labels = np.where(
    predictions == 0,
    "BENIGN",
    "ATTACK"
)


# ============================================================
# OPTIONAL CONFIDENCE
# ============================================================

if hasattr(model, "predict_proba"):

    probabilities = model.predict_proba(X)

    attack_probability = probabilities[:, 1]

else:

    attack_probability = np.full(
        len(X),
        np.nan
    )


# ============================================================
# CREATE DETECTION RESULTS
# ============================================================

results = pd.DataFrame({

    "Flow_ID":
        np.arange(1, len(X) + 1),

    "Prediction":
        prediction_labels,

    "Attack_Probability":
        attack_probability

})


# ============================================================
# ADD BASIC FLOW INFORMATION
# ============================================================

if "Destination Port" in df.columns:

    results["Destination_Port"] = (
        df["Destination Port"].values
    )


if "Flow Duration" in df.columns:

    results["Flow_Duration"] = (
        df["Flow Duration"].values
    )


# ============================================================
# SAVE DETECTION LOG
# ============================================================

OUTPUT_CSV.parent.mkdir(
    parents=True,
    exist_ok=True
)

results.to_csv(
    OUTPUT_CSV,
    index=False
)


# ============================================================
# DISPLAY SUMMARY
# ============================================================

total_flows = len(results)

benign_count = (
    results["Prediction"] == "BENIGN"
).sum()

attack_count = (
    results["Prediction"] == "ATTACK"
).sum()


print("\n" + "=" * 70)
print("AI-IDS DETECTION SUMMARY")
print("=" * 70)

print(f"Total flows detected : {total_flows:,}")
print(f"BENIGN flows         : {benign_count:,}")
print(f"ATTACK flows         : {attack_count:,}")

print(
    f"Attack percentage    : "
    f"{(attack_count / total_flows) * 100:.2f}%"
)

print("\nDetection log saved to:")

print(OUTPUT_CSV)

print("\nFirst 20 predictions:")

print(
    results.head(20).to_string(index=False)
)

print("\nAI-IDS detection completed successfully.")