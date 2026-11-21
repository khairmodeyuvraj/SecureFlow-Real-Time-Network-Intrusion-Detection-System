import pytest
import numpy as np
import pandas as pd

from src.features.feature_engineering import safe_divide, add_engineered_features
from src.data.cleaner import clean_numeric_features, clean_column_name
from src.network.flow_builder import Flow, PacketInfo
from src.features.feature_extractor import extract_features_from_flow, FEATURE_NAMES


def test_safe_divide():
    num = pd.Series([10.0, 0.0, 5.0, np.nan, 8.0])
    den = pd.Series([2.0, 5.0, 0.0, 2.0, np.nan])
    res = safe_divide(num, den)

    assert res.iloc[0] == 5.0
    assert res.iloc[1] == 0.0
    assert res.iloc[2] == 0.0  # Zero denominator handled safely
    assert res.iloc[3] == 0.0  # NaN numerator handled safely
    assert res.iloc[4] == 0.0  # NaN denominator handled safely
    assert not np.isinf(res).any()


def test_add_engineered_features():
    df = pd.DataFrame({
        "Total_Fwd_Packets": [10, 5],
        "Total_Backward_Packets": [2, 0],
        "Total_Length_of_Fwd_Packets": [1000, 500],
        "Total_Length_of_Bwd_Packets": [200, 0],
    })

    enriched = add_engineered_features(df)
    assert "Fwd_Bwd_Packet_Ratio" in enriched.columns
    assert "Fwd_Bwd_Byte_Ratio" in enriched.columns
    assert "Avg_Fwd_Packet_Size" in enriched.columns
    assert "Avg_Bwd_Packet_Size" in enriched.columns

    assert enriched.loc[0, "Fwd_Bwd_Packet_Ratio"] == 5.0
    assert enriched.loc[1, "Fwd_Bwd_Packet_Ratio"] == 0.0  # 0 denominator
    assert enriched.loc[0, "Avg_Fwd_Packet_Size"] == 100.0


def test_clean_numeric_features():
    df = pd.DataFrame({
        "a": [1.0, np.nan, np.inf],
        "b": [-np.inf, 2.5, 3.0],
    })
    cleaned = clean_numeric_features(df)
    assert not cleaned.isna().any().any()
    assert not np.isinf(cleaned.to_numpy()).any()
    assert cleaned.loc[1, "a"] == 0.0
    assert cleaned.loc[2, "a"] == 0.0
    assert cleaned.loc[0, "b"] == 0.0


def test_clean_column_name():
    assert clean_column_name(" Destination Port") == "Destination_Port"
    assert clean_column_name("Flow Bytes/s") == "Flow_Bytess"
    assert clean_column_name("Flow Packets/s") == "Flow_Packetss"
    assert clean_column_name("Down/Up Ratio") == "DownUp_Ratio"
    assert clean_column_name("Fwd Header Length.1") == "Fwd_Header_Length1"


def test_extract_features_from_flow():
    now = 1700000000.0
    packets = [
        PacketInfo(
            timestamp=now,
            src_ip="192.168.1.5",
            src_port=50000,
            dst_ip="8.8.8.8",
            dst_port=53,
            protocol="UDP",
            packet_length=64,
            payload_length=44,
        ),
        PacketInfo(
            timestamp=now + 0.02,
            src_ip="8.8.8.8",
            src_port=53,
            dst_ip="192.168.1.5",
            dst_port=50000,
            protocol="UDP",
            packet_length=128,
            payload_length=108,
        ),
    ]

    flow = Flow(
        key=("UDP", "192.168.1.5", 50000, "8.8.8.8", 53),
        first_timestamp=now,
        last_timestamp=now + 0.02,
        forward_src_ip="192.168.1.5",
        forward_src_port=50000,
        forward_dst_ip="8.8.8.8",
        forward_dst_port=53,
        packets=packets,
        forward_packets=1,
        backward_packets=1,
        forward_bytes=64,
        backward_bytes=128,
    )

    features_df = extract_features_from_flow(flow)
    assert len(features_df) == 1
    assert list(features_df.columns) == FEATURE_NAMES
    assert np.isfinite(features_df.to_numpy()).all()
    assert features_df.loc[0, "Destination_Port"] == 53
    assert features_df.loc[0, "Total_Fwd_Packets"] == 1
    assert features_df.loc[0, "Total_Backward_Packets"] == 1
