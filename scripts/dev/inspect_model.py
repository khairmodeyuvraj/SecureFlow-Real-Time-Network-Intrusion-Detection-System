
from pathlib import Path
import joblib
import pandas as pd

root = Path(__file__).resolve().parent
model_path = root / "models" / "final_ids_model.pkl"
csv_path = root / "data" / "raw" / "CICIDS2017" / "Monday-WorkingHours.pcap_ISCX.csv"

model = joblib.load(model_path)

print("\n=== MODEL DETAILS ===")
print("Model type:", type(model).__name__)
print("Classes:", getattr(model, "classes_", "Not available"))
print("Feature count:", getattr(model, "n_features_in_", "Not available"))

if hasattr(model, "feature_names_in_"):
    print("\n=== MODEL FEATURES ===")
    for i, name in enumerate(model.feature_names_in_, start=1):
        print(f"{i:02}. {name}")

print("\n=== PIPELINE DETAILS ===")
if hasattr(model, "named_steps"):
    for name, step in model.named_steps.items():
        print(name, "->", type(step).__name__)

print("\n=== TRAINING CSV SAMPLE ===")
df = pd.read_csv(csv_path, nrows=1000, encoding="utf-8-sig", low_memory=False)
df.columns = df.columns.str.strip()

print("Rows loaded:", len(df))
print("Columns:", len(df.columns))
print("Label distribution in sample:")
print(df["Label"].value_counts(dropna=False).to_string())

for col in ["Flow Duration", "Flow Byts/s", "Flow Pkts/s",
            "Flow IAT Mean", "Fwd IAT Total"]:
    if col in df.columns:
        values = pd.to_numeric(df[col], errors="coerce")
        print(f"\n{col}:")
        print(values.describe().to_string())
