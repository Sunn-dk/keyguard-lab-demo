"""Sysmon XML / JSON importer and parser.

Accepts: a single <Event>, a wrapper <Events>, or concatenated <Event>
elements (as produced by `wevtutil qe ... /f:xml`). Also accepts a JSON list
of already-normalised event dicts.
"""
# ======================================================================
# GIẢI THÍCH CHO GIẢNG VIÊN - sysmon_analyzer.py
# Vai trò: nhập (import) và phân tích cú pháp log Sysmon thật (XML xuất bằng wevtutil, hoặc JSON) thành
# danh sách dict thống nhất để detection_engine xử lý.
# Sysmon là công cụ Microsoft Sysinternals ghi sự kiện hệ thống (tạo tiến trình, nạp driver/module,
# truy cập tiến trình, thay đổi registry) vào Windows Event Log.
# Có kiểm tra định dạng: file rỗng, JSON sai, XML hỏng hoặc không phải Sysmon đều ném SysmonFormatError
# để giao diện báo lỗi thay vì bị treo.
# ======================================================================
from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from typing import Dict, List

# Namespace XML của Windows Event Log; các thẻ trong file xuất ra mang tiền tố này.
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
# Các Event ID được hỗ trợ theo đề: 1, 6, 7, 10, 12-14 (thêm 11 cho luật KG-007).
SUPPORTED_IDS = {1, 6, 7, 10, 11, 12, 13, 14}
# Tên dễ đọc của từng Event ID để hiển thị trong bảng.
EVENT_NAMES = {1: "Process Create", 6: "Driver Loaded", 7: "Image Loaded", 11: "File Created",
               10: "Process Access", 12: "Registry Object Create/Delete",
               13: "Registry Value Set", 14: "Registry Rename"}


# Lỗi định dạng file đầu vào; giao diện bắt lỗi này và hiện hộp thoại báo lỗi.
class SysmonFormatError(ValueError):
    pass


def _strip_ns(tag: str) -> str:
    return tag.replace(NS, "")


# Tìm thẻ con, chấp nhận cả khi có namespace lẫn khi không có.
def _find(el, name):
    r = el.find(f"{NS}{name}")
    return r if r is not None else el.find(name)


# Chuyển MỘT thẻ <Event> thành dict gồm: event_id, tên sự kiện, thời gian, tên tiến trình, đường dẫn image
# và toàn bộ các trường <Data>.
def _parse_event(el: ET.Element) -> Dict:
    sysel = _find(el, "System")
    if sysel is None:
        raise SysmonFormatError("Event has no <System> element")

    def sys_text(name):
        n = sysel.find(f"{NS}{name}")
        if n is None:
            n = sysel.find(name)
        return n.text if n is not None else None

    # EventID phải là số, nếu không thì coi file không phải Sysmon.
    eid = sys_text("EventID")
    if eid is None or not str(eid).strip().isdigit():
        raise SysmonFormatError("Event has no numeric EventID")
    tc = _find(sysel, "TimeCreated")
    data: Dict[str, str] = {}
    ed = _find(el, "EventData")
    if ed is not None:
        for d in ed:
            data[d.get("Name") or _strip_ns(d.tag)] = (d.text or "")
    # Image (tiến trình) có ở hầu hết sự kiện; sự kiện Process Access (ID 10) dùng SourceImage.
    image = data.get("Image") or data.get("SourceImage") or ""
    return {
        "event_id": int(eid),
        "event_name": EVENT_NAMES.get(int(eid), "Other"),
        "timestamp": (tc.get("SystemTime") if tc is not None else "") or data.get("UtcTime", ""),
        "process": os.path.basename(image.replace("\\", "/")) if image else "",
        "image": image,
        "data": data,
    }


# Nhận chuỗi văn bản và tự nhận biết JSON hay XML.
def parse_text(text: str) -> List[Dict]:
    text = text.strip()
    if not text:
        raise SysmonFormatError("File is empty")
    # Nhánh JSON: danh sách sự kiện đã chuẩn hóa (hoặc {"events": [...]}).
    if text[0] in "[{":
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as e:
            raise SysmonFormatError(f"Invalid JSON: {e}") from e
        items = obj if isinstance(obj, list) else obj.get("events", [])
        if not isinstance(items, list):
            raise SysmonFormatError("JSON must be a list of events")
        out = []
        for it in items:
            if not isinstance(it, dict) or "event_id" not in it:
                raise SysmonFormatError("JSON event missing 'event_id'")
            it.setdefault("event_name", EVENT_NAMES.get(it["event_id"], "Other"))
            it.setdefault("data", {})
            it.setdefault("image", it["data"].get("Image", ""))
            it.setdefault("process", os.path.basename(str(it["image"]).replace("\\", "/")))
            it.setdefault("timestamp", "")
            out.append(it)
        return out
    # XML: drop declarations/comments-safe wrapper for concatenated events
    # Nhánh XML: wevtutil xuất các thẻ <Event> nối liền nhau, không có thẻ gốc.
    body = re.sub(r"<\?xml[^>]*\?>", "", text)
    if not re.search(r"<(\w+:)?Events?\b", body):
        raise SysmonFormatError("Not Sysmon XML: no <Event> element found")
    try:
        # Bọc trong <Events> nếu thiếu thẻ gốc để ElementTree phân tích được; XML hỏng sẽ báo lỗi rõ ràng.
        root = ET.fromstring(body if body.lstrip().startswith("<Events") else f"<Events>{body}</Events>")
    except ET.ParseError as e:
        raise SysmonFormatError(f"Malformed XML: {e}") from e
    events = []
    for el in root.iter():
        if _strip_ns(el.tag) == "Event":
            events.append(_parse_event(el))
    if not events:
        raise SysmonFormatError("No <Event> elements found")
    return events


# Đọc file từ đĩa; file không tồn tại thì báo FileNotFoundError.
def load_file(path: str) -> List[Dict]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File not found: {path}")
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return parse_text(f.read())


# Nhận biết dữ liệu mẫu qua nhãn "SAMPLE DATA" trong từng sự kiện, để giao diện luôn ghi rõ đây KHÔNG phải quan sát từ máy thật.
def is_sample(events: List[Dict]) -> bool:
    return any(str(e.get("data", {}).get("DataLabel", "")).startswith("SAMPLE DATA") for e in events)


# Lọc theo tên tiến trình và/hoặc Event ID (chức năng tìm kiếm trong tab Detection).
def filter_events(events: List[Dict], process: str = "", event_id: int | None = None) -> List[Dict]:
    p = process.strip().lower()
    return [e for e in events
            if (not p or p in e.get("process", "").lower() or p in str(e.get("image", "")).lower())
            and (event_id is None or e["event_id"] == event_id)]
