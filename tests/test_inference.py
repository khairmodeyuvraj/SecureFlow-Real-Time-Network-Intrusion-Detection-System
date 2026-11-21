import pytest
import numpy as np
import pandas as pd

from src.inference.preprocessor import IDSPreprocessor
from src.inference.predictor import get_predictor
from config import SAMPLES_DIR, PROCESSED_DATA_DIR, RAW_DATA_DIR


def test_preprocessor_with_processed_format():
    preprocessor = IDSPreprocessor()
    sample_file = SAMPLES_DIR / "sample_mixed_traffic.csv"
    if not sample_file.is_file():
        sample_file = PROCESSED_DATA_DIR / "test.csv"

    df = pd.read_csv(sample_file, nrows=10)
    X, meta = preprocessor.transform(df)

    assert X.shape[1] == 74
    assert len(X) == 10
    assert np.isfinite(X.to_numpy()).all()
    assert "Source_IP" in meta.columns
    assert "Destination_IP" in meta.columns


def test_preprocessor_with_raw_cicids_format():
    preprocessor = IDSPreprocessor()
    raw_file = RAW_DATA_DIR / "Friday-WorkingHours-Morning.pcap_ISCX.csv"

    if raw_file.is_file():
        df = pd.read_csv(raw_file, nrows=15)
        X, meta = preprocessor.transform(df)
        assert X.shape[1] == 74
        assert len(X) == 15
        assert np.isfinite(X.to_numpy()).all()


def test_preprocessor_incompatible_format_raises_value_error():
    preprocessor = IDSPreprocessor()
    bad_df = pd.DataFrame({
        "username": ["admin", "guest"],
        "email": ["admin@example.com", "guest@example.com"],
        "login_count": [12, 1],
    })

    with pytest.raises(ValueError) as excinfo:
        preprocessor.transform(bad_df)

    assert "Incompatible dataset format" in str(excinfo.value)
    assert "Missing features include" in str(excinfo.value)


def test_preprocessor_empty_dataframe_raises_value_error():
    preprocessor = IDSPreprocessor()
    with pytest.raises(ValueError, match="empty"):
        preprocessor.transform(pd.DataFrame())


def test_predictor_predict_dataframe_end_to_end():
    predictor = get_predictor()
    sample_file = SAMPLES_DIR / "sample_mixed_traffic.csv"
    if not sample_file.is_file():
        sample_file = PROCESSED_DATA_DIR / "test.csv"

    df = pd.read_csv(sample_file, nrows=25)
    results_df, summary = predictor.predict_dataframe(df)

    assert len(results_df) == 25
    assert "Prediction" in results_df.columns
    assert "Prediction_Value" in results_df.columns
    assert "Confidence" in results_df.columns
    assert "Attack_Probability" in results_df.columns
    assert "Attack_Type" in results_df.columns

    assert set(results_df["Prediction"].unique()).issubset({"BENIGN", "ATTACK"})
    assert set(results_df["Prediction_Value"].unique()).issubset({0, 1})

    assert summary["total"] == 25
    assert summary["attacks"] + summary["benign"] == 25
    assert 0.0 <= summary["threat_percentage"] <= 100.0
    assert summary["predictions_available"] is True
