from pathlib import Path
import sys

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.evaluate_model import evaluate_dataset, main

if __name__ == "__main__":
    from config import PROCESSED_DATA_DIR, RAW_DATA_DIR
    test_csv = PROCESSED_DATA_DIR / "test.csv"
    raw_csv = RAW_DATA_DIR / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    eval_path = test_csv if test_csv.is_file() else raw_csv
    evaluate_dataset(eval_path, nrows=10000)
