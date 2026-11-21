import pytest
import pandas as pd
from pathlib import Path

from src.data.loader import load_csv, inspect_csv_file
from src.data.cleaner import standardize_label
from src.data.splitter import split_dataset
from config import SAMPLES_DIR, PROCESSED_DATA_DIR


def test_standardize_label():
    assert standardize_label("BENIGN") == 0
    assert standardize_label("benign") == 0
    assert standardize_label("NORMAL") == 0
    assert standardize_label("0") == 0
    assert standardize_label(0) == 0
    assert standardize_label("ATTACK") == 1
    assert standardize_label("DDoS") == 1
    assert standardize_label("PortScan") == 1
    assert standardize_label("1") == 1
    assert standardize_label(1) == 1


def test_load_csv_and_inspect():
    sample_file = SAMPLES_DIR / "sample_benign_traffic.csv"
    if not sample_file.is_file():
        sample_file = PROCESSED_DATA_DIR / "test.csv"

    df = load_csv(sample_file, nrows=20)
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 20
    # Column names must be stripped
    assert all(c == c.strip() for c in df.columns)

    rows, cols = inspect_csv_file(sample_file)
    assert rows > 0
    assert len(cols) > 0


def test_split_dataset():
    df = pd.DataFrame({
        "feat1": list(range(100)),
        "feat2": list(range(100, 200)),
        "Attack": [0] * 80 + [1] * 20,
    })

    X_train, X_val, X_test, y_train, y_val, y_test = split_dataset(
        df, target_column="Attack", train_ratio=0.7, val_ratio=0.15, test_ratio=0.15
    )

    assert len(X_train) == 70
    assert len(X_val) == 15
    assert len(X_test) == 15
    assert (y_train == 1).sum() == 14  # Stratified 20%
    assert (y_val == 1).sum() == 3
    assert (y_test == 1).sum() == 3
