
from pathlib import Path
import pandas as pd
import joblib

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data" / "raw" / "CICIDS2017"
MODEL_PATH = ROOT / "models" / "final_ids_model.pkl"

print("=== MODEL DETAILS ===")
model = joblib.load(MODEL_PATH)
print("Model type:", type(model).__name__)
print("Classes:", model.classes_)
print("Number of features:", len(model.feature_names_in_))
print("Feature names:")
for name in model.feature_names_in_:
    print(" -", name)

print("\n=== TRAINING CSV LABEL DISTRIBUTION ===")
csv_files = sorted(DATA_DIR.glob("*.csv"))

if not csv_files:
    raise FileNotFoundError(f"No CSV files found in {DATA_DIR}")

for csv_file in csv_files:
    print(f"\nFile: {csv_file.name}")
    counts = {}

    # Read in chunks to avoid loading large files into memory.
    for chunk in pd.read_csv(
        csv_file,
        encoding="utf-8-sig",
        low_memory=False,
        chunksize=100_000,
    ):
        chunk.columns = chunk.columns.str.strip()

        if "Label" not in chunk.columns:
            print("Label column not found.")
            break

        labels = chunk["Label"].astype("string").str.strip()
        chunk_counts = labels.value_counts(dropna=False)

        for label, count in chunk_counts.items():
            counts[str(label)] = counts.get(str(label), 0) + int(count)

    for label, count in sorted(counts.items()):
        print(f"  {label}: {count:,}")
