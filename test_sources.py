import json

with open("reports/unified_report_20260606_204146.json", "r") as f:
    data = json.load(f)

sources = set(item.get("source") for item in data)
print(f"Unique sources: {sources}")
