
import json
from pathlib import Path

keywords = [
    "Flow Duration",
    "Flow_Duration",
    "Flow Bytes/s",
    "Flow_Bytess",
    "Fwd_Bwd_Packet_Ratio",
    "Fwd_Bwd_Byte_Ratio",
    "RandomForestClassifier",
    "joblib.dump",
    "final_ids_model",
    "fit(",
]

for path in Path("notebooks").rglob("*.ipynb"):
    try:
        notebook = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        continue

    for i, cell in enumerate(notebook.get("cells", [])):
        source = "".join(cell.get("source", []))

        matches = [
            keyword for keyword in keywords
            if keyword.lower() in source.lower()
        ]

        if matches:
            print(f"\n--- {path} | Cell {i} ---")
            print("Matched:", ", ".join(matches))
            print(source[:1800])
