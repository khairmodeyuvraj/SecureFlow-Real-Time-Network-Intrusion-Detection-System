import numpy as np
import pandas as pd


def safe_divide(numerator: pd.Series, denominator: pd.Series) -> pd.Series:
    """
    Safely divide two pandas Series.
    Zero denominators return 0 instead of infinity.
    Missing values and infs are converted to 0.
    """
    numerator = pd.to_numeric(numerator, errors="coerce")
    denominator = pd.to_numeric(denominator, errors="coerce").replace(0, np.nan)

    result = numerator / denominator
    return result.replace([np.inf, -np.inf], np.nan).fillna(0.0)


def add_engineered_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate the 4 engineered ratio features used during model training:
    1. Fwd_Bwd_Packet_Ratio = Total_Fwd_Packets / Total_Backward_Packets
    2. Fwd_Bwd_Byte_Ratio = Total_Length_of_Fwd_Packets / Total_Length_of_Bwd_Packets
    3. Avg_Fwd_Packet_Size = Total_Length_of_Fwd_Packets / Total_Fwd_Packets
    4. Avg_Bwd_Packet_Size = Total_Length_of_Bwd_Packets / Total_Backward_Packets
    """
    result = df.copy()

    # 1. Forward / Backward Packet Ratio
    if "Total_Fwd_Packets" in result.columns and "Total_Backward_Packets" in result.columns:
        result["Fwd_Bwd_Packet_Ratio"] = safe_divide(
            result["Total_Fwd_Packets"], result["Total_Backward_Packets"]
        )
    elif "Fwd_Bwd_Packet_Ratio" not in result.columns:
        result["Fwd_Bwd_Packet_Ratio"] = 0.0

    # 2. Forward / Backward Byte Ratio
    if "Total_Length_of_Fwd_Packets" in result.columns and "Total_Length_of_Bwd_Packets" in result.columns:
        result["Fwd_Bwd_Byte_Ratio"] = safe_divide(
            result["Total_Length_of_Fwd_Packets"], result["Total_Length_of_Bwd_Packets"]
        )
    elif "Fwd_Bwd_Byte_Ratio" not in result.columns:
        result["Fwd_Bwd_Byte_Ratio"] = 0.0

    # 3. Average Forward Packet Size
    if "Total_Length_of_Fwd_Packets" in result.columns and "Total_Fwd_Packets" in result.columns:
        result["Avg_Fwd_Packet_Size"] = safe_divide(
            result["Total_Length_of_Fwd_Packets"], result["Total_Fwd_Packets"]
        )
    elif "Avg_Fwd_Packet_Size" not in result.columns:
        result["Avg_Fwd_Packet_Size"] = 0.0

    # 4. Average Backward Packet Size
    if "Total_Length_of_Bwd_Packets" in result.columns and "Total_Backward_Packets" in result.columns:
        result["Avg_Bwd_Packet_Size"] = safe_divide(
            result["Total_Length_of_Bwd_Packets"], result["Total_Backward_Packets"]
        )
    elif "Avg_Bwd_Packet_Size" not in result.columns:
        result["Avg_Bwd_Packet_Size"] = 0.0

    return result
