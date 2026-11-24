import os
from pathlib import Path
import tempfile
import unittest

from app import detection_engine as D
from app import report_export, sysmon_analyzer as S

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "data", "sample_sysmon.xml")


def ev(eid, image="C:\\Users\\u\\AppData\\Local\\Temp\\x.exe", **data):
    d = {"Image": image}
    d.update(data)
    return {"event_id": eid, "event_name": "", "timestamp": "t", "image": image,
            "process": image.split("\\")[-1], "data": d}


# Kiểm thử detection: một chỉ báo chưa đủ kết luận, tương quan nâng mức, trường giải thích và MITRE,
# hồi quy báo động giả (driver đã ký bình thường, ứng dụng chat chạy từ AppData), và xuất file.
class TestDetection(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(D.analyze([]), [])
        self.assertEqual(D.risk_level([]), "LOW")

    def test_single_indicator_is_not_malicious(self):
        alerts = D.analyze([ev(1)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "LOW")
        self.assertIn("Single indicator", alerts[0].explanation)

    def test_correlation_raises_severity(self):
        events = [ev(1), ev(13, TargetObject="HKU\\x\\CurrentVersion\\Run\\Up", Details="x"),
                  ev(7, ImageLoaded="C:\\Windows\\System32\\hid.dll")]
        a = D.analyze(events)[0]
        self.assertIn(a.severity, ("HIGH", "CRITICAL"))
        self.assertEqual(set(a.rules), {"KG-001", "KG-002", "KG-003"})
        self.assertTrue(a.evidence)

    def test_alert_has_required_fields_and_mitre(self):
        a = D.analyze(S.load_file(SAMPLE))[0].to_dict()
        for k in ("alert_id", "severity", "explanation", "evidence", "response", "mitre", "rules"):
            self.assertIn(k, a)
        self.assertEqual(a["mitre"]["technique"], "T1056")
        self.assertEqual(a["mitre"]["subtechnique"], "T1056.001")
        self.assertEqual(a["mitre"]["detection"], "DET0089")

    def test_sample_results(self):
        alerts = D.analyze(S.load_file(SAMPLE))
        by = {a.process: a for a in alerts}
        self.assertEqual(by["updater_svc.exe"].severity, "HIGH")
        self.assertEqual(by["code.exe"].severity, "LOW")  # false-positive example
        self.assertEqual(D.risk_level(alerts), "HIGH")

    def test_benign_system_event_no_alert(self):
        self.assertEqual(D.analyze([ev(1, "C:\\Windows\\System32\\svchost.exe")]), [])

    def test_unsigned_driver_alone_is_medium_not_critical(self):
        e = {"event_id": 6, "timestamp": "t", "image": "", "process": "",
             "data": {"ImageLoaded": "C:\\d.sys", "Signed": "false"}}
        self.assertEqual(D.analyze([e])[0].severity, "MEDIUM")

    def test_explainability_fields(self):
        a = D.analyze(S.load_file(SAMPLE))[0]
        self.assertEqual(a.confidence, "HIGH")
        self.assertEqual(len(a.false_positives), len(a.rules))
        self.assertTrue(all(len(x) > 10 for x in a.false_positives))
        self.assertIn("not a real antivirus", a.detection_basis)
        self.assertIn("detection_basis", a.to_dict())
        for r in D.RULES.values():
            self.assertTrue(r.false_positives)

    def test_ordinary_signed_drivers_are_not_indicators(self):
        """Regression: a real boot loads hundreds of signed drivers; they must not produce an alert."""
        evs = [{"event_id": 6, "timestamp": "t", "image": "", "process": "",
                "data": {"ImageLoaded": f"C:\\Windows\\System32\\drivers\\drv{i}.sys", "Signed": "true"}}
               for i in range(300)]
        self.assertEqual(D.analyze(evs), [])

    def test_signed_keyboard_driver_is_low(self):
        e = {"event_id": 6, "timestamp": "t", "image": "", "process": "",
             "data": {"ImageLoaded": "C:\\Windows\\System32\\drivers\\kbdhid.sys", "Signed": "true"}}
        a = D.analyze([e])
        self.assertEqual((a[0].rules, a[0].severity), (["KG-004"], "LOW"))

    def test_benign_per_user_app_is_not_high(self):
        """Regression: user32.dll + AppData + Run key (a normal chat client) must not reach HIGH."""
        img = "C:\\Users\\u\\AppData\\Local\\Chat\\chat.exe"
        mk = lambda eid, **d: {"event_id": eid, "timestamp": "t", "image": img, "process": "chat.exe",
                               "data": {"Image": img, **d}}
        a = D.analyze([mk(1), mk(7, ImageLoaded="C:\\Windows\\System32\\user32.dll"),
                       mk(13, TargetObject="HKU\\x\\CurrentVersion\\Run\\Chat", Details=img)])[0]
        self.assertEqual(a.rules, ["KG-001", "KG-003"])
        self.assertEqual(a.severity, "MEDIUM")

    def test_file_create_rule_and_name(self):
        self.assertEqual(S.EVENT_NAMES[11], "File Created")
        a = D.analyze([ev(11, TargetFilename="C:\\Users\\u\\AppData\\Local\\Temp\\k.log")])
        self.assertEqual(a[0].rules, ["KG-007"])

    def test_export(self):
        alerts = [a.to_dict() for a in D.analyze(S.load_file(SAMPLE))]
        with tempfile.TemporaryDirectory() as d:
            j = report_export.export_analysis_json(alerts, 6, True, os.path.join(d, "a.json"))
            c = report_export.export_analysis_csv(alerts, os.path.join(d, "a.csv"))
            self.assertIn("SAMPLE DATA", Path(j).read_text(encoding="utf-8"))
            self.assertGreater(len(Path(c).read_text(encoding="utf-8").splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
