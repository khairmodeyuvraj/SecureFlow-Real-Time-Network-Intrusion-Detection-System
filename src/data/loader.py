from pathlib import Path
from typing import Optional, Tuple, List
import pandas as pd


ENCODINGS_TO_TRY = ["utf-8-sig", "utf-8", "latin-1", "cp1252"]


def load_csv(
    file_path: Path | str,
    nrows: Optional[int] = None,
    low_memory: bool = False,
) -> pd.DataFrame:
    """
    Load a CSV file with automatic encoding detection and stripped column names.
    """
    path = Path(file_path).resolve()

    if not path.is_file():
        raise FileNotFoundError(f"CSV file not found: {path}")

    last_error = None
    for encoding in ENCODINGS_TO_TRY:
        try:
            df = pd.read_csv(
                path,
                nrows=nrows,
                encoding=encoding,
                low_memory=low_memory,
            )
            # Strip whitespace from column headers
            df.columns = df.columns.astype(str).str.strip()
            return df
        except (UnicodeDecodeError, pd.errors.ParserError) as error:
            last_error = error
            continue

    raise ValueError(f"Could not parse CSV file {path}: {last_error}")


def inspect_csv_file(file_path: Path | str) -> Tuple[int, List[str]]:
    """
    Quickly inspect CSV header and row count without loading the entire file.
    """
    path = Path(file_path).resolve()
    df_sample = load_csv(path, nrows=5)
    columns = list(df_sample.columns)

    # Estimate or count lines safely
    line_count = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            line_count += chunk.count(b"\n")

    # Subtract header line if at least 1 line
    data_rows = max(0, line_count - 1)
    return data_rows, columns
