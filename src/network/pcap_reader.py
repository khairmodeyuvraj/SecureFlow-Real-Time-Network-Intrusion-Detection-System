from pathlib import Path
from typing import Optional, List
import pandas as pd
import numpy as np

from src.network.flow_builder import FlowManager, PacketInfo, Flow
from src.features.feature_extractor import extract_features_from_flow
from src.utils.logger import get_logger

logger = get_logger("PCAPReader")


def extract_flows_from_pcap(
    pcap_path: Path | str,
    output_csv: Optional[Path | str] = None,
    max_packets: Optional[int] = 10000,
) -> pd.DataFrame:
    """
    Extract network flows and compute the 74 IDS features directly from a PCAP file.
    Uses Scapy streaming PcapReader to avoid excessive memory usage.
    """
    path = Path(pcap_path).resolve()

    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    suffix = path.suffix.lower()
    if suffix not in {".pcap", ".pcapng"}:
        raise ValueError(f"Unsupported packet capture format '{suffix}'. Expected .pcap or .pcapng")

    try:
        from scapy.all import PcapReader, IP, TCP, UDP
    except ImportError as e:
        raise ImportError(f"Scapy is required for PCAP extraction: {e}")

    logger.info(f"Opening packet capture: {path} (max packets limit: {max_packets})")

    manager = FlowManager(inactivity_timeout=15.0, active_timeout=120.0)
    completed_flows: List[Flow] = []
    packet_count = 0

    try:
        with PcapReader(str(path)) as pcap_reader:
            for packet in pcap_reader:
                packet_count += 1
                if max_packets and packet_count > max_packets:
                    logger.info(f"Reached max packet limit ({max_packets}). Finalizing active flows.")
                    break

                if IP not in packet:
                    continue

                ip = packet[IP]
                timestamp = float(packet.time)

                if TCP in packet:
                    tcp = packet[TCP]
                    proto = "TCP"
                    sport = int(tcp.sport)
                    dport = int(tcp.dport)
                    trans_hdr_len = int(tcp.dataofs * 4) if tcp.dataofs is not None else 20
                    payload_len = len(tcp.payload)
                    tcp_flags = str(tcp.flags)
                    tcp_window = int(tcp.window)
                elif UDP in packet:
                    udp = packet[UDP]
                    proto = "UDP"
                    sport = int(udp.sport)
                    dport = int(udp.dport)
                    trans_hdr_len = 8
                    payload_len = len(udp.payload)
                    tcp_flags = ""
                    tcp_window = 0
                else:
                    continue

                ip_hdr_len = int(ip.ihl * 4) if ip.ihl is not None else 20

                pkt_info = PacketInfo(
                    timestamp=timestamp,
                    src_ip=str(ip.src),
                    src_port=sport,
                    dst_ip=str(ip.dst),
                    dst_port=dport,
                    protocol=proto,
                    packet_length=len(packet),
                    ip_header_length=ip_hdr_len,
                    transport_header_length=trans_hdr_len,
                    payload_length=payload_len,
                    tcp_flags=tcp_flags,
                    tcp_window=tcp_window,
                )

                completed = manager.add_packet(pkt_info)
                if completed:
                    completed_flows.append(completed)

    except Exception as error:
        logger.error(f"Error reading PCAP file {path}: {error}")
        raise RuntimeError(f"Failed to parse PCAP file: {error}")

    # Flush remaining active flows
    remaining = manager.flush_all()
    completed_flows.extend(remaining)

    if not completed_flows:
        raise ValueError(
            f"No valid IP/TCP/UDP network flows could be reconstructed from '{path.name}'. "
            "Ensure the capture contains valid IP traffic."
        )

    logger.info(f"Reconstructed {len(completed_flows)} network flows from {packet_count} packets.")

    # Extract 74 features for each flow
    flow_dfs = []
    for flow in completed_flows:
        flow_df = extract_features_from_flow(flow)
        # Attach basic presentation metadata
        flow_df["Source_IP"] = flow.forward_src_ip
        flow_df["Source_Port"] = flow.forward_src_port
        flow_df["Destination_IP"] = flow.forward_dst_ip
        flow_df["Destination_Port"] = flow.forward_dst_port
        flow_df["Protocol"] = flow.key[0]
        flow_dfs.append(flow_df)

    flows_table = pd.concat(flow_dfs, ignore_index=True)

    if output_csv:
        out_path = Path(output_csv).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        flows_table.to_csv(out_path, index=False)
        logger.info(f"Saved extracted flows to {out_path}")

    return flows_table


# Backward compatibility alias
extract_flows = extract_flows_from_pcap
