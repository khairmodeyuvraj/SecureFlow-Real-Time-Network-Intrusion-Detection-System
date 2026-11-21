import os
import joblib
import pandas as pd

from flow_manager import FlowManager, PacketInfo
from feature_extractor import extract_features, validate_features


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "final_ids_model.pkl")


# ============================================================
# CHECK MODEL
# ============================================================

if not os.path.exists(MODEL_PATH):

    raise FileNotFoundError(
        f"Model not found:\n{MODEL_PATH}"
    )


print("=" * 70)
print("AI-IDS MODEL DETECTION TEST")
print("=" * 70)


# ============================================================
# LOAD MODEL
# ============================================================

print()
print("Loading trained model...")

model = joblib.load(MODEL_PATH)

print("Model loaded successfully.")


# ============================================================
# CREATE TEST FLOW
# ============================================================

manager = FlowManager()

import time

now = time.time()


packets = [

    PacketInfo(
        timestamp=now,
        src_ip="172.20.10.6",
        src_port=50000,
        dst_ip="20.52.64.204",
        dst_port=443,
        protocol="TCP",
        packet_length=1200,
        ip_header_length=20,
        transport_header_length=20,
        payload_length=1160,
        tcp_flags="S",
        tcp_window=65535
    ),

    PacketInfo(
        timestamp=now + 0.01,
        src_ip="20.52.64.204",
        src_port=443,
        dst_ip="172.20.10.6",
        dst_port=50000,
        protocol="TCP",
        packet_length=800,
        ip_header_length=20,
        transport_header_length=20,
        payload_length=760,
        tcp_flags="SA",
        tcp_window=65535
    ),

    PacketInfo(
        timestamp=now + 0.02,
        src_ip="172.20.10.6",
        src_port=50000,
        dst_ip="20.52.64.204",
        dst_port=443,
        protocol="TCP",
        packet_length=1500,
        ip_header_length=20,
        transport_header_length=20,
        payload_length=1460,
        tcp_flags="PA",
        tcp_window=65535
    ),

    PacketInfo(
        timestamp=now + 0.03,
        src_ip="20.52.64.204",
        src_port=443,
        dst_ip="172.20.10.6",
        dst_port=50000,
        protocol="TCP",
        packet_length=1000,
        ip_header_length=20,
        transport_header_length=20,
        payload_length=960,
        tcp_flags="PA",
        tcp_window=65535
    )
]


# ============================================================
# ADD PACKETS TO FLOW
# ============================================================

for packet in packets:
    manager.add_packet(packet)


flow = list(manager.flows.values())[0]


# ============================================================
# EXTRACT FEATURES
# ============================================================

print()
print("Extracting 74 features...")

X = extract_features(flow)

validate_features(X)

print("74 features extracted successfully.")


# ============================================================
# MODEL PREDICTION
# ============================================================

print()
print("Running Random Forest prediction...")

prediction = model.predict(X)


# ============================================================
# PROBABILITY
# ============================================================

if hasattr(model, "predict_proba"):

    probabilities = model.predict_proba(X)

    probability = float(
        probabilities[0][prediction[0]]
    )

else:

    probability = None


# ============================================================
# RESULT
# ============================================================

prediction_value = int(prediction[0])


if prediction_value == 1:

    label = "ATTACK"

else:

    label = "BENIGN"


print()
print("=" * 70)
print("DETECTION RESULT")
print("=" * 70)

print()
print(f"Prediction value : {prediction_value}")
print(f"Classification    : {label}")

if probability is not None:

    print(
        f"Confidence        : "
        f"{probability * 100:.2f}%"
    )

print()
print("Flow:")
print(
    f"{flow.forward_src_ip}:{flow.forward_src_port}"
    f" → "
    f"{flow.forward_dst_ip}:{flow.forward_dst_port}"
)

print()
print("=" * 70)
print("MODEL DETECTION TEST COMPLETED")
print("=" * 70)