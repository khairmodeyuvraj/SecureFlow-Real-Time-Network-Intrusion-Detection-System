import os
import csv
import time
from datetime import datetime

import joblib
from scapy.all import sniff, IP, TCP, UDP

from flow_manager import FlowManager, PacketInfo
from feature_extractor import extract_features, validate_features


# ============================================================
# CONFIGURATION
# ============================================================

INTERFACE = r"\Device\NPF_{695DC79C-2EAC-4C44-978A-8CC2EFD1EC2F}"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "final_ids_model.pkl")
LOG_DIR = os.path.join(BASE_DIR, "results", "alerts")
LOG_FILE = os.path.join(
    LOG_DIR,
    "realtime_detection_log.csv"
)

INACTIVITY_TIMEOUT = 10
ACTIVE_TIMEOUT = 60


# ============================================================
# FLOW MANAGER
# ============================================================

flow_manager = FlowManager(
    inactivity_timeout=INACTIVITY_TIMEOUT,
    active_timeout=ACTIVE_TIMEOUT
)


# ============================================================
# LOAD MODEL
# ============================================================

if not os.path.exists(MODEL_PATH):

    raise FileNotFoundError(
        f"Model not found:\n{MODEL_PATH}"
    )

model = joblib.load(MODEL_PATH)


# ============================================================
# CREATE LOG DIRECTORY
# ============================================================

os.makedirs(LOG_DIR, exist_ok=True)


# ============================================================
# INITIALIZE LOG FILE
# ============================================================

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
    "Prediction_Value",
    "Confidence"
]


if not os.path.exists(LOG_FILE):

    with open(
        LOG_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow(LOG_COLUMNS)


# ============================================================
# LOG DETECTION
# ============================================================

def log_detection(
    flow,
    prediction,
    prediction_value,
    confidence
):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    row = [
        timestamp,
        flow.key[0],

        flow.forward_src_ip,
        flow.forward_src_port,

        flow.forward_dst_ip,
        flow.forward_dst_port,

        len(flow.packets),

        flow.forward_packets,
        flow.backward_packets,

        flow.forward_bytes,
        flow.backward_bytes,

        prediction,
        prediction_value,
        f"{confidence * 100:.2f}%"
    ]

    with open(
        LOG_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow(row)


# ============================================================
# CLASSIFY COMPLETED FLOW
# ============================================================

def classify_flow(flow):

    try:

        # ----------------------------------------------------
        # Extract 74 features
        # ----------------------------------------------------

        X = extract_features(flow)

        validate_features(X)

        # ----------------------------------------------------
        # Prediction
        # ----------------------------------------------------

        prediction_value = int(
            model.predict(X)[0]
        )

        # ----------------------------------------------------
        # Probability
        # ----------------------------------------------------

        if hasattr(model, "predict_proba"):

            probabilities = model.predict_proba(X)

            confidence = float(
                probabilities[
                    0,
                    prediction_value
                ]
            )

        else:

            confidence = 0.0

        # ----------------------------------------------------
        # Convert prediction
        # ----------------------------------------------------

        if prediction_value == 1:

            prediction = "ATTACK"

        else:

            prediction = "BENIGN"

        # ----------------------------------------------------
        # Timestamp
        # ----------------------------------------------------

        timestamp = datetime.now().strftime(
            "%H:%M:%S"
        )

        # ----------------------------------------------------
        # Display
        # ----------------------------------------------------

        print()
        print("=" * 70)

        if prediction == "ATTACK":

            print("🚨 INTRUSION DETECTED 🚨")

        else:

            print("✓ BENIGN FLOW")

        print("=" * 70)

        print(
            f"Time              : {timestamp}"
        )

        print(
            f"Protocol          : {flow.key[0]}"
        )

        print(
            f"Source            : "
            f"{flow.forward_src_ip}:"
            f"{flow.forward_src_port}"
        )

        print(
            f"Destination       : "
            f"{flow.forward_dst_ip}:"
            f"{flow.forward_dst_port}"
        )

        print(
            f"Total packets     : "
            f"{len(flow.packets)}"
        )

        print(
            f"Forward packets   : "
            f"{flow.forward_packets}"
        )

        print(
            f"Backward packets  : "
            f"{flow.backward_packets}"
        )

        print(
            f"Forward bytes     : "
            f"{flow.forward_bytes}"
        )

        print(
            f"Backward bytes    : "
            f"{flow.backward_bytes}"
        )

        print(
            f"Prediction        : "
            f"{prediction}"
        )

        print(
            f"Confidence        : "
            f"{confidence * 100:.2f}%"
        )

        print("=" * 70)

        # ----------------------------------------------------
        # Save result
        # ----------------------------------------------------

        log_detection(
            flow,
            prediction,
            prediction_value,
            confidence
        )

    except Exception as error:

        print()
        print("⚠️ Flow processing error:")
        print(error)


# ============================================================
# CHECK EXPIRED FLOWS
# ============================================================

def process_expired_flows():

    expired_flows = (
        flow_manager.get_expired_flows()
    )

    for flow in expired_flows:

        classify_flow(flow)


# ============================================================
# PACKET CALLBACK
# ============================================================

def packet_callback(packet):

    # --------------------------------------------------------
    # IPv4 only
    # --------------------------------------------------------

    if IP not in packet:

        return

    ip = packet[IP]

    src_ip = ip.src
    dst_ip = ip.dst

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    if TCP in packet:

        tcp = packet[TCP]

        protocol = "TCP"

        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)

        transport_header_length = (
            int(tcp.dataofs) * 4
            if tcp.dataofs is not None
            else 20
        )

        payload_length = len(
            tcp.payload
        )

        tcp_flags = str(tcp.flags)

        tcp_window = int(tcp.window)

    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    elif UDP in packet:

        udp = packet[UDP]

        protocol = "UDP"

        src_port = int(udp.sport)
        dst_port = int(udp.dport)

        transport_header_length = 8

        payload_length = len(
            udp.payload
        )

        tcp_flags = ""

        tcp_window = 0

    else:

        return

    # --------------------------------------------------------
    # IP HEADER
    # --------------------------------------------------------

    ip_header_length = (
        int(ip.ihl) * 4
        if ip.ihl is not None
        else 20
    )

    # --------------------------------------------------------
    # IP PACKET LENGTH
    # --------------------------------------------------------

    packet_length = len(ip)

    # --------------------------------------------------------
    # CREATE PacketInfo
    # --------------------------------------------------------

    packet_info = PacketInfo(

        timestamp=time.time(),

        src_ip=src_ip,
        src_port=src_port,

        dst_ip=dst_ip,
        dst_port=dst_port,

        protocol=protocol,

        packet_length=packet_length,

        ip_header_length=ip_header_length,

        transport_header_length=(
            transport_header_length
        ),

        payload_length=payload_length,

        tcp_flags=tcp_flags,

        tcp_window=tcp_window
    )

    # --------------------------------------------------------
    # Add packet to flow
    # --------------------------------------------------------

    flow_manager.add_packet(
        packet_info
    )

    # --------------------------------------------------------
    # Process expired flows
    # --------------------------------------------------------

    process_expired_flows()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 70)
    print("              AI-IDS REAL-TIME DETECTION")
    print("=" * 70)

    print()
    print(
        "Model             : "
        "final_ids_model.pkl"
    )

    print(
        "Interface         : "
        "Wi-Fi"
    )

    print(
        "Inactivity timeout: "
        f"{INACTIVITY_TIMEOUT} seconds"
    )

    print(
        "Active timeout    : "
        f"{ACTIVE_TIMEOUT} seconds"
    )

    print(
        "Detection log     : "
        f"{LOG_FILE}"
    )

    print()
    print("Status: RUNNING")
    print()
    print("Generate normal network activity.")
    print("Press CTRL+C to stop.")
    print()

    try:

        sniff(
            iface=INTERFACE,
            prn=packet_callback,
            store=False
        )

    except KeyboardInterrupt:

        print()
        print("=" * 70)
        print("Stopping AI-IDS...")
        print("=" * 70)

        # ----------------------------------------------------
        # Process remaining flows
        # ----------------------------------------------------

        remaining_flows = (
            flow_manager.flush_all()
        )

        print(
            f"\nRemaining flows: "
            f"{len(remaining_flows)}"
        )

        for flow in remaining_flows:

            classify_flow(flow)

        print()
        print(
            "Detection log saved to:"
        )

        print(LOG_FILE)

        print()
        print("AI-IDS stopped successfully.")
        