import json
import os
from pathlib import Path
import tempfile
import unittest

from app import sysmon_analyzer as S

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "data", "sample_sysmon.xml")


# Kiểm thử đọc log Sysmon: dữ liệu mẫu, nhiều sự kiện nối liền không có thẻ gốc, lọc, và file thiếu/rỗng/sai định dạng/JSON.
class TestSysmon(unittest.TestCase):
    def test_parse_sample(self):
        ev = S.load_file(SAMPLE)
        self.assertEqual(len(ev), 6)
        self.assertTrue(S.is_sample(ev))
        self.assertEqual({e["event_id"] for e in ev}, {1, 6, 7, 10, 13})
        self.assertEqual(ev[0]["process"], "updater_svc.exe")
        self.assertTrue(ev[0]["timestamp"].startswith("2026-11-15"))

    def test_concatenated_events_without_root(self):
        xml = ('<Event><System><EventID>1</EventID><TimeCreated SystemTime="t"/></System>'
               '<EventData><Data Name="Image">C:\\a\\b.exe</Data></EventData></Event>'
               '<Event><System><EventID>13</EventID></System><EventData/></Event>')
        ev = S.parse_text(xml)
        self.assertEqual(len(ev), 2)
        self.assertEqual(ev[0]["process"], "b.exe")

    def test_filter_by_process_and_id(self):
        ev = S.load_file(SAMPLE)
        self.assertEqual(len(S.filter_events(ev, process="updater")), 4)
        self.assertEqual(len(S.filter_events(ev, event_id=1)), 2)
        self.assertEqual(S.filter_events(ev, process="nothing"), [])

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            S.load_file("does_not_exist.xml")

    def test_invalid_and_empty(self):
        for bad in ("", "   ", "not xml at all", "<Events><Event></Events>", "<root><a/></root>"):
            with self.assertRaises(S.SysmonFormatError, msg=repr(bad)):
                S.parse_text(bad)

    def test_json_import(self):
        j = json.dumps([{"event_id": 1, "image": "C:\\x\\y.exe", "data": {"Image": "C:\\x\\y.exe"}}])
        ev = S.parse_text(j)
        self.assertEqual(ev[0]["process"], "y.exe")
        with self.assertRaises(S.SysmonFormatError):
            S.parse_text('[{"nope": 1}]')

    def test_file_from_disk_invalid(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.xml")
            Path(p).write_text("garbage", encoding="utf-8")
            with self.assertRaises(S.SysmonFormatError):
                S.load_file(p)


if __name__ == "__main__":
    unittest.main()
