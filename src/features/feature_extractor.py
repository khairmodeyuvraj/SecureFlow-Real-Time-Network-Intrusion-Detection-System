import numpy as np
import pandas as pd
from typing import List, Tuple, Dict, Any

from src.network.flow_builder import Flow, PacketInfo

# Exact 74 features expected by the trained model
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


def safe_mean(values: List[float]) -> float:
    return float(np.mean(values)) if values else 0.0


def safe_std(values: List[float]) -> float:
    return float(np.std(values)) if values else 0.0


def safe_min(values: List[float]) -> float:
    return float(np.min(values)) if values else 0.0


def safe_max(values: List[float]) -> float:
    return float(np.max(values)) if values else 0.0


def safe_sum(values: List[float]) -> float:
    return float(np.sum(values)) if values else 0.0


def safe_variance(values: List[float]) -> float:
    return float(np.var(values)) if values else 0.0


def safe_ratio(numerator: float, denominator: float) -> float:
    if denominator == 0 or np.isnan(denominator) or np.isinf(denominator):
        return 0.0
    val = numerator / denominator
    return 0.0 if (np.isnan(val) or np.isinf(val)) else float(val)


def calculate_iats(packets: List[PacketInfo]) -> List[float]:
    """Calculate inter-arrival times in microseconds."""
    if len(packets) < 2:
        return []
    timestamps = [p.timestamp for p in packets]
    iats = []
    for i in range(1, len(timestamps)):
        diff = timestamps[i] - timestamps[i - 1]
        iats.append(max(0.0, diff) * 1_000_000.0)
    return iats


def calculate_active_idle(packets: List[PacketInfo], idle_threshold: float = 1.0) -> Tuple[List[float], List[float]]:
    """Estimate active and idle periods in microseconds."""
    if len(packets) < 2:
        return [], []
    timestamps = [p.timestamp for p in packets]
    active_periods = []
    idle_periods = []
    active_start = timestamps[0]

    for i in range(1, len(timestamps)):
        gap = timestamps[i] - timestamps[i - 1]
        if gap > idle_threshold:
            active_duration = timestamps[i - 1] - active_start
            if active_duration > 0:
                active_periods.append(active_duration * 1_000_000.0)
            idle_periods.append(gap * 1_000_000.0)
            active_start = timestamps[i]

    final_active = timestamps[-1] - active_start
    if final_active > 0:
        active_periods.append(final_active * 1_000_000.0)

    return active_periods, idle_periods


def extract_features_from_flow(flow: Flow) -> pd.DataFrame:
    """Extract exact 74 features from an aggregated network flow."""
    packets = flow.packets
    if not packets:
        raise ValueError("Cannot extract features from an empty flow.")

    forward_packets: List[PacketInfo] = []
    backward_packets: List[PacketInfo] = []

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

    fwd_lengths = [p.packet_length for p in forward_packets]
    bwd_lengths = [p.packet_length for p in backward_packets]
    all_lengths = [p.packet_length for p in packets]
    fwd_payload_lengths = [p.payload_length for p in forward_packets]

    # Flow duration in microseconds
    flow_duration = max(0.0, (flow.last_timestamp - flow.first_timestamp) * 1_000_000.0)
    duration_seconds = flow_duration / 1_000_000.0

    flow_iats = calculate_iats(packets)
    fwd_iats = calculate_iats(forward_packets)
    bwd_iats = calculate_iats(backward_packets)

    def has_flag(pkt: PacketInfo, f: str) -> bool:
        return f in pkt.tcp_flags

    fin_count = sum(has_flag(p, "F") for p in packets)
    syn_count = sum(has_flag(p, "S") for p in packets)
    rst_count = sum(has_flag(p, "R") for p in packets)
    psh_count = sum(has_flag(p, "P") for p in packets)
    ack_count = sum(has_flag(p, "A") for p in packets)
    urg_count = sum(has_flag(p, "U") for p in packets)
    cwe_count = sum(has_flag(p, "C") for p in packets)
    ece_count = sum(has_flag(p, "E") for p in packets)

    fwd_psh_count = sum(has_flag(p, "P") for p in forward_packets)
    fwd_urg_count = sum(has_flag(p, "U") for p in forward_packets)

    fwd_header_len = sum(p.ip_header_length + p.transport_header_length for p in forward_packets)
    bwd_header_len = sum(p.ip_header_length + p.transport_header_length for p in backward_packets)

    init_win_fwd = next((p.tcp_window for p in forward_packets if p.tcp_window > 0), 0)
    init_win_bwd = next((p.tcp_window for p in backward_packets if p.tcp_window > 0), 0)

    active_periods, idle_periods = calculate_active_idle(packets)

    total_fwd_pkts = len(forward_packets)
    total_bwd_pkts = len(backward_packets)
    total_pkts = len(packets)

    total_fwd_bytes = sum(fwd_lengths)
    total_bwd_bytes = sum(bwd_lengths)
    total_bytes = total_fwd_bytes + total_bwd_bytes

    features: Dict[str, Any] = {
        "Destination_Port": flow.forward_dst_port,
        "Flow_Duration": flow_duration,
        "Total_Fwd_Packets": total_fwd_pkts,
        "Total_Backward_Packets": total_bwd_pkts,
        "Total_Length_of_Fwd_Packets": total_fwd_bytes,
        "Total_Length_of_Bwd_Packets": total_bwd_bytes,
        "Fwd_Packet_Length_Max": safe_max(fwd_lengths),
        "Fwd_Packet_Length_Min": safe_min(fwd_lengths),
        "Fwd_Packet_Length_Mean": safe_mean(fwd_lengths),
        "Fwd_Packet_Length_Std": safe_std(fwd_lengths),
        "Bwd_Packet_Length_Max": safe_max(bwd_lengths),
        "Bwd_Packet_Length_Min": safe_min(bwd_lengths),
        "Bwd_Packet_Length_Mean": safe_mean(bwd_lengths),
        "Bwd_Packet_Length_Std": safe_std(bwd_lengths),
        "Flow_Bytess": safe_ratio(total_bytes, duration_seconds),
        "Flow_Packetss": safe_ratio(total_pkts, duration_seconds),
        "Flow_IAT_Mean": safe_mean(flow_iats),
        "Flow_IAT_Std": safe_std(flow_iats),
        "Flow_IAT_Max": safe_max(flow_iats),
        "Flow_IAT_Min": safe_min(flow_iats),
        "Fwd_IAT_Total": safe_sum(fwd_iats),
        "Fwd_IAT_Mean": safe_mean(fwd_iats),
        "Fwd_IAT_Std": safe_std(fwd_iats),
        "Fwd_IAT_Max": safe_max(fwd_iats),
        "Fwd_IAT_Min": safe_min(fwd_iats),
        "Bwd_IAT_Total": safe_sum(bwd_iats),
        "Bwd_IAT_Mean": safe_mean(bwd_iats),
        "Bwd_IAT_Std": safe_std(bwd_iats),
        "Bwd_IAT_Max": safe_max(bwd_iats),
        "Bwd_IAT_Min": safe_min(bwd_iats),
        "Fwd_PSH_Flags": fwd_psh_count,
        "Fwd_URG_Flags": fwd_urg_count,
        "Fwd_Header_Length": fwd_header_len,
        "Bwd_Header_Length": bwd_header_len,
        "Fwd_Packetss": safe_ratio(total_fwd_pkts, duration_seconds),
        "Bwd_Packetss": safe_ratio(total_bwd_pkts, duration_seconds),
        "Min_Packet_Length": safe_min(all_lengths),
        "Max_Packet_Length": safe_max(all_lengths),
        "Packet_Length_Mean": safe_mean(all_lengths),
        "Packet_Length_Std": safe_std(all_lengths),
        "Packet_Length_Variance": safe_variance(all_lengths),
        "FIN_Flag_Count": fin_count,
        "SYN_Flag_Count": syn_count,
        "RST_Flag_Count": rst_count,
        "PSH_Flag_Count": psh_count,
        "ACK_Flag_Count": ack_count,
        "URG_Flag_Count": urg_count,
        "CWE_Flag_Count": cwe_count,
        "ECE_Flag_Count": ece_count,
        "DownUp_Ratio": safe_ratio(total_bwd_pkts, total_fwd_pkts),
        "Average_Packet_Size": safe_ratio(total_bytes, total_pkts),
        "Avg_Fwd_Segment_Size": safe_mean(fwd_lengths),
        "Avg_Bwd_Segment_Size": safe_mean(bwd_lengths),
        "Fwd_Header_Length1": fwd_header_len,
        "Subflow_Fwd_Packets": total_fwd_pkts,
        "Subflow_Fwd_Bytes": total_fwd_bytes,
        "Subflow_Bwd_Packets": total_bwd_pkts,
        "Subflow_Bwd_Bytes": total_bwd_bytes,
        "Init_Win_bytes_forward": init_win_fwd,
        "Init_Win_bytes_backward": init_win_bwd,
        "act_data_pkt_fwd": sum(p > 0 for p in fwd_payload_lengths),
        "min_seg_size_forward": safe_min(fwd_payload_lengths),
        "Active_Mean": safe_mean(active_periods),
        "Active_Std": safe_std(active_periods),
        "Active_Max": safe_max(active_periods),
        "Active_Min": safe_min(active_periods),
        "Idle_Mean": safe_mean(idle_periods),
        "Idle_Std": safe_std(idle_periods),
        "Idle_Max": safe_max(idle_periods),
        "Idle_Min": safe_min(idle_periods),
        "Fwd_Bwd_Packet_Ratio": safe_ratio(total_fwd_pkts, total_bwd_pkts),
        "Fwd_Bwd_Byte_Ratio": safe_ratio(total_fwd_bytes, total_bwd_bytes),
        "Avg_Fwd_Packet_Size": safe_ratio(total_fwd_bytes, total_fwd_pkts),
        "Avg_Bwd_Packet_Size": safe_ratio(total_bwd_bytes, total_bwd_pkts),
    }

    df = pd.DataFrame([features])[FEATURE_NAMES]
    return df
