"""Export detection/analysis results to JSON and CSV."""
# ======================================================================
# GIẢI THÍCH CHO GIẢNG VIÊN - report_export.py
# Vai trò: xuất kết quả phân tích detection ra file JSON (đầy đủ) và CSV (gọn, mở bằng Excel) để đưa vào báo cáo.
# ======================================================================
from __future__ import annotations

import csv
import json
import os
from datetime import datetime
from typing import Dict, List


def export_analysis_json(alerts: List[Dict], events_count: int, sample: bool, path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    # Kèm nhãn nguồn dữ liệu ("SAMPLE DATA" hay dữ liệu người dùng nhập) để không bao giờ nhầm dữ liệu mẫu với quan sát thật.
    payload = {"generated": datetime.now().isoformat(timespec="seconds"),
               "data_label": "SAMPLE DATA (synthetic)" if sample else "User-imported data",
               "events_analyzed": events_count, "alerts": alerts}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return path


# Bản CSV chỉ giữ các cột chính; bản JSON ở trên còn có bằng chứng, độ tin cậy, báo động giả và MITRE.
def export_analysis_csv(alerts: List[Dict], path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    cols = ["alert_id", "process", "severity", "score", "rules", "explanation", "response"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for a in alerts:
            w.writerow([a["alert_id"], a["process"], a["severity"], a["score"],
                        ",".join(a["rules"]), a["explanation"], a["response"]])
    return path
