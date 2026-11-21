import math
import numpy as np
import pandas as pd

from flow_manager import Flow


# ============================================================
# EXACT 74 FEATURES EXPECTED BY THE TRAINED MODEL
# ============================================================

FEATURE_NAMES = [
    "Destination_Port",
    "Flow_Duration",
    "Total_Fwd_Packets",
    "Total_Backward_Packets",
    "Total_Length_of_Fwd_Packets",
    "Total_Length_of_Bwd_Packets",
    "Fwd_Packet_Length_Max",
    "Fwd_Packet_Length_Min",
    "Fwd_Packet_Length_Mean",
    "Fwd_Packet_Length_Std",
    "Bwd_Packet_Length_Max",
    "Bwd_Packet_Length_Min",
    "Bwd_Packet_Length_Mean",
    "Bwd_Packet_Length_Std",
    "Flow_Bytess",
    "Flow_Packetss",
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
    "Fwd_PSH_Flags",
    "Fwd_URG_Flags",
    "Fwd_Header_Length",
    "Bwd_Header_Length",
    "Fwd_Packetss",
    "Bwd_Packetss",
    "Min_Packet_Length",
    "Max_Packet_Length",
    "Packet_Length_Mean",
    "Packet_Length_Std",
    "Packet_Length_Variance",
    "FIN_Flag_Count",
    "SYN_Flag_Count",
    "RST_Flag_Count",
    "PSH_Flag_Count",
    "ACK_Flag_Count",
    "URG_Flag_Count",
    "CWE_Flag_Count",
    "ECE_Flag_Count",
    "DownUp_Ratio",
    "Average_Packet_Size",
    "Avg_Fwd_Segment_Size",
    "Avg_Bwd_Segment_Size",
    "Fwd_Header_Length1",
    "Subflow_Fwd_Packets",
    "Subflow_Fwd_Bytes",
    "Subflow_Bwd_Packets",
    "Subflow_Bwd_Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active_Mean",
    "Active_Std",
    "Active_Max",
    "Active_Min",
    "Idle_Mean",
    "Idle_Std",
    "Idle_Max",
    "Idle_Min",
    "Fwd_Bwd_Packet_Ratio",
    "Fwd_Bwd_Byte_Ratio",
    "Avg_Fwd_Packet_Size",
    "Avg_Bwd_Packet_Size",
]


# ============================================================
# SAFE STATISTICAL FUNCTIONS
# ============================================================

def safe_mean(values):
    return float(np.mean(values)) if values else 0.0


def safe_std(values):
    return float(np.std(values)) if values else 0.0


def safe_min(values):
    return float(np.min(values)) if values else 0.0


def safe_max(values):
    return float(np.max(values)) if values else 0.0


def safe_sum(values):
    return float(np.sum(values)) if values else 0.0


def safe_variance(values):
    return float(np.var(values)) if values else 0.0


def safe_ratio(numerator, denominator):
    if denominator == 0:
        return 0.0

    return float(numerator / denominator)


# ============================================================
# IAT CALCULATION
# ============================================================

def calculate_iats(packets):
    """
    Calculate inter-arrival times in microseconds.
    """

    if len(packets) < 2:
        return []

    timestamps = [
        packet.timestamp
        for packet in packets
    ]

    iats = []

    for i in range(1, len(timestamps)):

        difference = (
            timestamps[i] - timestamps[i - 1]
        )

        iats.append(
            max(0.0, difference) * 1_000_000
        )

    return iats


# ============================================================
# ACTIVE / IDLE STATISTICS
# ============================================================

def calculate_active_idle(packets, idle_threshold=1.0):
    """
    Estimate active and idle periods.

    A gap greater than idle_threshold seconds
    is treated as an idle period.
    """

    if len(packets) < 2:
        return [], []

    timestamps = [
        packet.timestamp
        for packet in packets
    ]

    active_periods = []
    idle_periods = []

    active_start = timestamps[0]

    for i in range(1, len(timestamps)):

        gap = timestamps[i] - timestamps[i - 1]

        if gap > idle_threshold:

            # End current active period
            active_duration = (
                timestamps[i - 1] - active_start
            )

            if active_duration > 0:
                active_periods.append(
                    active_duration * 1_000_000
                )

            # Idle period
            idle_periods.append(
                gap * 1_000_000
            )

            active_start = timestamps[i]

    # Final active period
    final_active_duration = (
        timestamps[-1] - active_start
    )

    if final_active_duration > 0:
        active_periods.append(
            final_active_duration * 1_000_000
        )

    return active_periods, idle_periods


# ============================================================
# TCP FLAG HELPERS
# ============================================================

def has_flag(packet, flag):
    return flag in packet.tcp_flags


# ============================================================
# MAIN FEATURE EXTRACTION
# ============================================================

def extract_features(flow: Flow) -> pd.DataFrame:

    packets = flow.packets

    if not packets:
        raise ValueError("Cannot extract features from an empty flow.")

    # --------------------------------------------------------
    # Separate directions
    # --------------------------------------------------------

    forward_packets = []
    backward_packets = []

    for packet in packets:

        is_forward = (
            packet.src_ip == flow.forward_src_ip
            and packet.src_port == flow.forward_src_port
            and packet.dst_ip == flow.forward_dst_ip
            and packet.dst_port == flow.forward_dst_port
        )

        if is_forward:
            forward_packets.append(packet)
        else:
            backward_packets.append(packet)

    # --------------------------------------------------------
    # Basic packet lengths
    # --------------------------------------------------------

    fwd_lengths = [
        packet.packet_length
        for packet in forward_packets
    ]

    bwd_lengths = [
        packet.packet_length
        for packet in backward_packets
    ]

    all_lengths = [
        packet.packet_length
        for packet in packets
    ]

    # --------------------------------------------------------
    # Packet payload lengths
    # --------------------------------------------------------

    fwd_payload_lengths = [
        packet.payload_length
        for packet in forward_packets
    ]

    # --------------------------------------------------------
    # Flow duration
    # CICIDS-style duration is microseconds
    # --------------------------------------------------------

    flow_duration = (
        flow.last_timestamp -
        flow.first_timestamp
    ) * 1_000_000

    flow_duration = max(0.0, flow_duration)

    # --------------------------------------------------------
    # IAT statistics
    # --------------------------------------------------------

    flow_iats = calculate_iats(packets)
    fwd_iats = calculate_iats(forward_packets)
    bwd_iats = calculate_iats(backward_packets)

    # --------------------------------------------------------
    # TCP flags
    # --------------------------------------------------------

    fin_count = sum(
        has_flag(packet, "F")
        for packet in packets
    )

    syn_count = sum(
        has_flag(packet, "S")
        for packet in packets
    )

    rst_count = sum(
        has_flag(packet, "R")
        for packet in packets
    )

    psh_count = sum(
        has_flag(packet, "P")
        for packet in packets
    )

    ack_count = sum(
        has_flag(packet, "A")
        for packet in packets
    )

    urg_count = sum(
        has_flag(packet, "U")
        for packet in packets
    )

    cwe_count = sum(
        has_flag(packet, "C")
        for packet in packets
    )

    ece_count = sum(
        has_flag(packet, "E")
        for packet in packets
    )

    # --------------------------------------------------------
    # Forward PSH / URG
    # --------------------------------------------------------

    fwd_psh_count = sum(
        has_flag(packet, "P")
        for packet in forward_packets
    )

    fwd_urg_count = sum(
        has_flag(packet, "U")
        for packet in forward_packets
    )

    # --------------------------------------------------------
    # Header lengths
    # --------------------------------------------------------

    fwd_header_length = sum(
        packet.ip_header_length +
        packet.transport_header_length
        for packet in forward_packets
    )

    bwd_header_length = sum(
        packet.ip_header_length +
        packet.transport_header_length
        for packet in backward_packets
    )

    # --------------------------------------------------------
    # Initial TCP window sizes
    # --------------------------------------------------------

    init_win_forward = 0
    init_win_backward = 0

    for packet in forward_packets:

        if packet.tcp_window > 0:
            init_win_forward = packet.tcp_window
            break

    for packet in backward_packets:

        if packet.tcp_window > 0:
            init_win_backward = packet.tcp_window
            break

    # --------------------------------------------------------
    # Active / Idle
    # --------------------------------------------------------

    active_periods, idle_periods = calculate_active_idle(
        packets
    )

    # --------------------------------------------------------
    # Active/Idle statistics
    # --------------------------------------------------------

    active_mean = safe_mean(active_periods)
    active_std = safe_std(active_periods)
    active_max = safe_max(active_periods)
    active_min = safe_min(active_periods)

    idle_mean = safe_mean(idle_periods)
    idle_std = safe_std(idle_periods)
    idle_max = safe_max(idle_periods)
    idle_min = safe_min(idle_periods)

    # --------------------------------------------------------
    # Packet counts
    # --------------------------------------------------------

    total_fwd_packets = len(forward_packets)
    total_bwd_packets = len(backward_packets)

    total_packets = len(packets)

    # --------------------------------------------------------
    # Bytes
    # --------------------------------------------------------

    total_fwd_bytes = sum(fwd_lengths)
    total_bwd_bytes = sum(bwd_lengths)

    total_bytes = (
        total_fwd_bytes +
        total_bwd_bytes
    )

    # --------------------------------------------------------
    # Flow rates
    # --------------------------------------------------------

    duration_seconds = flow_duration / 1_000_000

    flow_bytes_per_second = safe_ratio(
        total_bytes,
        duration_seconds
    )

    flow_packets_per_second = safe_ratio(
        total_packets,
        duration_seconds
    )

    fwd_packets_per_second = safe_ratio(
        total_fwd_packets,
        duration_seconds
    )

    bwd_packets_per_second = safe_ratio(
        total_bwd_packets,
        duration_seconds
    )

    # --------------------------------------------------------
    # Engineered features
    # --------------------------------------------------------

    fwd_bwd_packet_ratio = safe_ratio(
        total_fwd_packets,
        total_bwd_packets
    )

    fwd_bwd_byte_ratio = safe_ratio(
        total_fwd_bytes,
        total_bwd_bytes
    )

    avg_fwd_packet_size = safe_ratio(
        total_fwd_bytes,
        total_fwd_packets
    )

    avg_bwd_packet_size = safe_ratio(
        total_bwd_bytes,
        total_bwd_packets
    )

    # --------------------------------------------------------
    # Minimum forward segment size
    # --------------------------------------------------------

    min_seg_size_forward = safe_min(
        fwd_payload_lengths
    )

    # --------------------------------------------------------
    # Active data packets forward
    # --------------------------------------------------------

    act_data_pkt_fwd = sum(
        payload > 0
        for payload in fwd_payload_lengths
    )

    # --------------------------------------------------------
    # Down / Up ratio
    # --------------------------------------------------------

    down_up_ratio = safe_ratio(
        total_bwd_packets,
        total_fwd_packets
    )

    # --------------------------------------------------------
    # Build feature dictionary
    # --------------------------------------------------------

    features = {

        "Destination_Port":
            flow.forward_dst_port,

        "Flow_Duration":
            flow_duration,

        "Total_Fwd_Packets":
            total_fwd_packets,

        "Total_Backward_Packets":
            total_bwd_packets,

        "Total_Length_of_Fwd_Packets":
            total_fwd_bytes,

        "Total_Length_of_Bwd_Packets":
            total_bwd_bytes,

        "Fwd_Packet_Length_Max":
            safe_max(fwd_lengths),

        "Fwd_Packet_Length_Min":
            safe_min(fwd_lengths),

        "Fwd_Packet_Length_Mean":
            safe_mean(fwd_lengths),

        "Fwd_Packet_Length_Std":
            safe_std(fwd_lengths),

        "Bwd_Packet_Length_Max":
            safe_max(bwd_lengths),

        "Bwd_Packet_Length_Min":
            safe_min(bwd_lengths),

        "Bwd_Packet_Length_Mean":
            safe_mean(bwd_lengths),

        "Bwd_Packet_Length_Std":
            safe_std(bwd_lengths),

        "Flow_Bytess":
            flow_bytes_per_second,

        "Flow_Packetss":
            flow_packets_per_second,

        "Flow_IAT_Mean":
            safe_mean(flow_iats),

        "Flow_IAT_Std":
            safe_std(flow_iats),

        "Flow_IAT_Max":
            safe_max(flow_iats),

        "Flow_IAT_Min":
            safe_min(flow_iats),

        "Fwd_IAT_Total":
            safe_sum(fwd_iats),

        "Fwd_IAT_Mean":
            safe_mean(fwd_iats),

        "Fwd_IAT_Std":
            safe_std(fwd_iats),

        "Fwd_IAT_Max":
            safe_max(fwd_iats),

        "Fwd_IAT_Min":
            safe_min(fwd_iats),

        "Bwd_IAT_Total":
            safe_sum(bwd_iats),

        "Bwd_IAT_Mean":
            safe_mean(bwd_iats),

        "Bwd_IAT_Std":
            safe_std(bwd_iats),

        "Bwd_IAT_Max":
            safe_max(bwd_iats),

        "Bwd_IAT_Min":
            safe_min(bwd_iats),

        "Fwd_PSH_Flags":
            fwd_psh_count,

        "Fwd_URG_Flags":
            fwd_urg_count,

        "Fwd_Header_Length":
            fwd_header_length,

        "Bwd_Header_Length":
            bwd_header_length,

        "Fwd_Packetss":
            fwd_packets_per_second,

        "Bwd_Packetss":
            bwd_packets_per_second,

        "Min_Packet_Length":
            safe_min(all_lengths),

        "Max_Packet_Length":
            safe_max(all_lengths),

        "Packet_Length_Mean":
            safe_mean(all_lengths),

        "Packet_Length_Std":
            safe_std(all_lengths),

        "Packet_Length_Variance":
            safe_variance(all_lengths),

        "FIN_Flag_Count":
            fin_count,

        "SYN_Flag_Count":
            syn_count,

        "RST_Flag_Count":
            rst_count,

        "PSH_Flag_Count":
            psh_count,

        "ACK_Flag_Count":
            ack_count,

        "URG_Flag_Count":
            urg_count,

        "CWE_Flag_Count":
            cwe_count,

        "ECE_Flag_Count":
            ece_count,

        "DownUp_Ratio":
            down_up_ratio,

        "Average_Packet_Size":
            safe_ratio(
                total_bytes,
                total_packets
            ),

        "Avg_Fwd_Segment_Size":
            safe_ratio(
                total_fwd_bytes,
                total_fwd_packets
            ),

        "Avg_Bwd_Segment_Size":
            safe_ratio(
                total_bwd_bytes,
                total_bwd_packets
            ),

        "Fwd_Header_Length1":
            fwd_header_length,

        "Subflow_Fwd_Packets":
            total_fwd_packets,

        "Subflow_Fwd_Bytes":
            total_fwd_bytes,

        "Subflow_Bwd_Packets":
            total_bwd_packets,

        "Subflow_Bwd_Bytes":
            total_bwd_bytes,

        "Init_Win_bytes_forward":
            init_win_forward,

        "Init_Win_bytes_backward":
            init_win_backward,

        "act_data_pkt_fwd":
            act_data_pkt_fwd,

        "min_seg_size_forward":
            min_seg_size_forward,

        "Active_Mean":
            active_mean,

        "Active_Std":
            active_std,

        "Active_Max":
            active_max,

        "Active_Min":
            active_min,

        "Idle_Mean":
            idle_mean,

        "Idle_Std":
            idle_std,

        "Idle_Max":
            idle_max,

        "Idle_Min":
            idle_min,

        "Fwd_Bwd_Packet_Ratio":
            fwd_bwd_packet_ratio,

        "Fwd_Bwd_Byte_Ratio":
            fwd_bwd_byte_ratio,

        "Avg_Fwd_Packet_Size":
            avg_fwd_packet_size,

        "Avg_Bwd_Packet_Size":
            avg_bwd_packet_size,
    }

    # --------------------------------------------------------
    # Create DataFrame in EXACT model feature order
    # --------------------------------------------------------

    df = pd.DataFrame(
        [[features[name] for name in FEATURE_NAMES]],
        columns=FEATURE_NAMES
    )

    # --------------------------------------------------------
    # Clean invalid values
    # --------------------------------------------------------

    df = df.replace(
        [np.inf, -np.inf],
        np.nan
    )

    df = df.fillna(0)

    return df


# ============================================================
# VALIDATION
# ============================================================

def validate_features(df):

    if list(df.columns) != FEATURE_NAMES:

        raise ValueError(
            "Feature names/order do not match the trained model."
        )

    if df.shape[1] != 74:

        raise ValueError(
            f"Expected 74 features, got {df.shape[1]}."
        )

    if df.isnull().values.any():

        raise ValueError(
            "Feature vector contains NaN values."
        )

    if np.isinf(df.values).any():

        raise ValueError(
            "Feature vector contains infinite values."
        )

    return True


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    import time
    from flow_manager import PacketInfo

    print("=" * 70)
    print("AI-IDS FEATURE EXTRACTOR TEST")
    print("=" * 70)

    now = time.time()

    # --------------------------------------------------------
    # Create test flow
    # --------------------------------------------------------

    flow_manager_packets = [

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

    # --------------------------------------------------------
    # Import FlowManager
    # --------------------------------------------------------

    from flow_manager import FlowManager

    manager = FlowManager()

    for packet in flow_manager_packets:
        manager.add_packet(packet)

    flow = list(manager.flows.values())[0]

    # --------------------------------------------------------
    # Extract features
    # --------------------------------------------------------

    feature_df = extract_features(flow)

    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------

    validate_features(feature_df)

    print()
    print("Feature extraction successful!")
    print()

    print(
        f"Number of features: "
        f"{feature_df.shape[1]}"
    )

    print(
        f"Number of rows: "
        f"{feature_df.shape[0]}"
    )

    print()
    print("Feature order:")
    print()

    for i, column in enumerate(feature_df.columns, start=1):

        print(
            f"{i:2}. {column:<35} "
            f"{feature_df.iloc[0][column]}"
        )

    print()
    print("=" * 70)
    print("74-FEATURE VALIDATION PASSED")
    print("=" * 70)