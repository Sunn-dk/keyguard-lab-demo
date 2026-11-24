"""Rule-based, correlation-driven educational detection engine.

Sysmon does NOT record API calls such as SetWindowsHookEx, so the rules look
at observable *context* (where a process runs from, what it loads, what it
persists, what drivers load). A process is only reported as HIGH/CRITICAL when
several independent indicator types correlate; a single indicator is at most
LOW ("informational"), which limits false positives.
"""
# ======================================================================
# GIẢI THÍCH CHO GIẢNG VIÊN - detection_engine.py
# Vai trò: engine phát hiện keylogger dựa trên luật (rule-based) và GIẢI THÍCH ĐƯỢC - phần Detection của đề.
# Các ý chính cần nói:
#  1. Sysmon KHÔNG ghi lại lời gọi API như SetWindowsHookEx, nên engine không "thấy hook" trực tiếp.
#     Nó suy luận từ NGỮ CẢNH quan sát được: tiến trình chạy từ đâu, nạp module nào, ghi khóa Run nào,
#     nạp driver nào, truy cập tiến trình nào.
#  2. Chống báo động giả: KHÔNG kết luận độc hại từ một chỉ báo đơn lẻ. Một chỉ báo -> tối đa LOW
#     (driver chưa ký đơn lẻ: MEDIUM). Nhiều loại chỉ báo độc lập cùng một tiến trình (tương quan) mới lên HIGH/CRITICAL.
#  3. Mỗi cảnh báo có: ID, mức độ, điểm, độ tin cậy, giải thích, bằng chứng, khả năng báo động giả,
#     hành động đề xuất và ánh xạ MITRE ATT&CK.
#  4. Đây là mô phỏng giáo dục, KHÔNG phải antivirus/EDR thật (xem DETECTION_BASIS).
# ======================================================================
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, List

# Ánh xạ MITRE ATT&CK: T1056 (Input Capture), T1056.001 (Keylogging) và DET0089 (chiến lược phát hiện hành vi keylogging theo đề bài).
MITRE = {"technique": "T1056", "subtechnique": "T1056.001",
         "name": "Input Capture: Keylogging", "detection": "DET0089"}

# Thư mục người dùng thường ghi được: AppData, Downloads, Desktop, Temp, ProgramData.
# Phần mềm cài hợp pháp thường nằm ở Program Files, còn mã độc hay chạy từ những nơi này.
USER_WRITABLE = re.compile(r"\\(users\\[^\\]+\\(appdata|downloads|desktop)|temp|programdata)\\", re.I)
# Khóa registry tự khởi động cùng Windows (Run/RunOnce): dấu hiệu duy trì (persistence).
RUN_KEYS = re.compile(r"\\(currentversion\\run(once)?|policies\\explorer\\run)\\", re.I)
# user32.dll / win32u.dll are loaded by virtually every GUI program, so they say nothing about input capture
# and are NOT used. Only HID/keyboard-stack modules count as an "input-related" module indicator.
# Chỉ module thuộc stack HID/bàn phím mới được tính. user32.dll bị loại vì mọi chương trình giao diện đều nạp (không phân biệt được).
INPUT_DLLS = ("hid.dll", "kbdhid.sys", "kbdclass.sys")
# Tên driver liên quan bàn phím.
KEYBOARD_DRIVER = re.compile(r"(kbd|keyboard|i8042|hidclass|hidusb)", re.I)
# Khóa registry liên quan cấu hình driver bàn phím.
KEYBOARD_REG = re.compile(r"(keyboard layout|kbdclass|kbdhid|i8042prt)", re.I)
# Tiến trình hệ thống nhạy cảm (lsass giữ thông tin đăng nhập). Tiến trình lạ mở handle tới chúng là dấu hiệu đáng ngờ.
SYSTEM_PROCS = ("lsass.exe", "winlogon.exe", "csrss.exe")


@dataclass
# Một luật phát hiện: mã, chỉ báo, mức cơ sở, giải thích, hành động đề xuất và báo động giả có thể gặp.
class Rule:
    rule_id: str
    indicator: str
    base_severity: str
    explanation: str
    response: str
    false_positives: str = ""


# Câu nói rõ cơ sở và giới hạn của engine; đi kèm mọi cảnh báo để không bị hiểu nhầm là antivirus thật.
DETECTION_BASIS = ("Behavioural / telemetry-correlation based. Sysmon does not log API calls such as "
                   "SetWindowsHookEx or GetAsyncKeyState, so this engine infers suspicious input-capture "
                   "activity from process, module, registry, driver and access context. It is not a real "
                   "antivirus/EDR and cannot detect every API hook.")

# Bảy luật KG-001..KG-007. "Mức cơ sở" chỉ là trọng số điểm; mức cuối của cảnh báo do TƯƠNG QUAN quyết định
# (hàm analyze bên dưới).
RULES = {
    "KG-001": Rule("KG-001", "Process started from a user-writable path", "LOW",
                   "Executables in Temp/AppData/Downloads are common for malware but also for legitimate per-user installs.",
                   "Verify publisher, signature and hash; check how it was delivered.",
                   false_positives="Per-user installers/updaters (VS Code, Teams, Discord), portable apps, developer builds in Downloads/Temp."),
    "KG-002": Rule("KG-002", "Input-related module loaded by an unusual process", "LOW",
                   "Loading HID/keyboard-stack modules is normal for peripheral/game/accessibility software; it matters only with other indicators.",
                   "Review process purpose and parent process.",
                   false_positives="Peripheral, game-controller and accessibility software legitimately loads HID modules; meaningful only when combined with other indicators."),
    "KG-003": Rule("KG-003", "Persistence via Run/RunOnce registry key", "MEDIUM",
                   "Auto-start entries let a program survive reboot; legitimate software does this too.",
                   "Compare against known software inventory; check the target binary.",
                   false_positives="Most desktop software (chat, cloud sync, VPN, launchers) registers a Run key legitimately."),
    "KG-004": Rule("KG-004", "Keyboard-related driver or driver-config change", "MEDIUM",
                   "Unexpected keyboard filter drivers/registry changes can intercept input below user mode.",
                   "Check driver signature and vendor; review change history.",
                   false_positives="Keyboard utilities, remapping tools, vendor gaming-keyboard drivers, accessibility software."),
    "KG-005": Rule("KG-005", "Unsigned or untrusted driver loaded", "HIGH",
                   "Unsigned drivers run in kernel mode and can read raw input.",
                   "Isolate host; verify driver origin; enforce driver block rules.",
                   false_positives="Old or niche hardware drivers, internal/test drivers on development machines."),
    "KG-006": Rule("KG-006", "Process access to a sensitive/other process", "MEDIUM",
                   "Opening handles with broad access to other processes may indicate injection or credential access.",
                   "Review GrantedAccess and caller; compare with security-tool behaviour.",
                   false_positives="Security products, debuggers and remote-support tools open handles to other processes."),
    "KG-007": Rule("KG-007", "Process writes/opens logs from a user-writable path", "LOW",
                   "Frequent small file writes can indicate local key logging, but many apps log files.",
                   "Inspect file contents/location only with authorization.",
                   false_positives="Many applications write log files into AppData/Temp."),
}
# Thứ tự mức độ, dùng để sắp xếp cảnh báo và tính rủi ro tổng.
SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
# Một cảnh báo cho MỘT tiến trình, gom mọi luật đã khớp (tương quan theo tiến trình).
class Alert:
    alert_id: str
    process: str
    severity: str
    score: int
    rules: List[str]
    explanation: str
    evidence: List[str]
    response: str
    mitre: Dict = field(default_factory=lambda: dict(MITRE))
    confidence: str = "LOW"
    false_positives: List[str] = field(default_factory=list)
    detection_basis: str = DETECTION_BASIS

    # Chuyển cảnh báo thành dict để xuất JSON/CSV.
    def to_dict(self):
        return asdict(self)


# Bước 1: duyệt từng sự kiện Sysmon, kiểm tra điều kiện của từng luật và gom bằng chứng theo tiến trình rồi theo mã luật.
def _hits(events: List[Dict]) -> Dict[str, Dict[str, List[str]]]:
    """process -> rule_id -> evidence strings"""
    out: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
    for e in events:
        d, eid = e.get("data", {}), e.get("event_id")
        proc = (e.get("process") or "").lower()
        ts = e.get("timestamp", "")
        # Event ID 1 (Process Create) -> KG-001: tiến trình khởi chạy từ thư mục người dùng ghi được.
        if eid == 1:
            img = d.get("Image", "")
            if USER_WRITABLE.search(img):
                out[proc]["KG-001"].append(f"[{ts}] EID1 {img} (parent: {d.get('ParentImage','?')})")
        # Event ID 7 (Image Loaded) -> KG-002: tiến trình ở thư mục người dùng nạp module HID/bàn phím.
        elif eid == 7:
            loaded = d.get("ImageLoaded", "").lower()
            if any(loaded.endswith(x) for x in INPUT_DLLS) and USER_WRITABLE.search(e.get("image", "")):
                out[proc]["KG-002"].append(f"[{ts}] EID7 {e.get('image')} loaded {d.get('ImageLoaded')}")
        # Event ID 12-14 (Registry) -> KG-003 nếu ghi khóa Run (duy trì), KG-004 nếu đụng cấu hình bàn phím.
        elif eid in (12, 13, 14):
            tgt = d.get("TargetObject", "")
            if RUN_KEYS.search(tgt):
                out[proc]["KG-003"].append(f"[{ts}] EID{eid} {tgt} = {d.get('Details','')}")
            elif KEYBOARD_REG.search(tgt):
                out[proc]["KG-004"].append(f"[{ts}] EID{eid} {tgt}")
        # Event ID 6 (Driver Loaded) -> KG-005 nếu driver CHƯA ký; KG-004 nếu đã ký nhưng tên liên quan bàn phím.
        elif eid == 6:
            signed = d.get("Signed", "").lower() == "true"
            drv = d.get("ImageLoaded", "")
            note = f"[{ts}] EID6 driver {drv} Signed={d.get('Signed')} Status={d.get('SignatureStatus')}"
            if not signed:
                out[proc or "(kernel)"]["KG-005"].append(note)
            elif KEYBOARD_DRIVER.search(drv.replace("\\", "/").rsplit("/", 1)[-1]):
                out[proc or "(kernel)"]["KG-004"].append(note)
            # an ordinary signed non-keyboard driver is NOT an indicator (a real boot loads hundreds)
        # Event ID 10 (Process Access) -> KG-006: tiến trình ở thư mục người dùng mở handle tới lsass/winlogon/csrss.
        elif eid == 10:
            tgt = d.get("TargetImage", "").lower()
            src = d.get("SourceImage", "")
            if any(tgt.endswith(s) for s in SYSTEM_PROCS) and USER_WRITABLE.search(src):
                out[proc]["KG-006"].append(f"[{ts}] EID10 {src} -> {d.get('TargetImage')} access={d.get('GrantedAccess')}")
        # Event ID 11 (File Created) -> KG-007: tiến trình tạo file trong thư mục người dùng ghi được.
        if eid in (11,) and USER_WRITABLE.search(d.get("TargetFilename", "")):
            out[proc]["KG-007"].append(f"[{ts}] EID11 {d.get('TargetFilename')}")
    return out


# Bước 2: TƯƠNG QUAN. Với mỗi tiến trình, tính điểm và đếm số loại chỉ báo KHÁC NHAU rồi quyết định mức độ.
def analyze(events: List[Dict]) -> List[Alert]:
    alerts: List[Alert] = []
    n = 0
    for proc, rules in _hits(events).items():
        ids = sorted(rules)
        ev = [x for r in ids for x in rules[r]]
        # Điểm = tổng trọng số các luật đã khớp (LOW=1, MEDIUM=2, HIGH=3). Mỗi luật chỉ tính một lần dù khớp nhiều sự kiện.
        score = sum({"LOW": 1, "MEDIUM": 2, "HIGH": 3}[RULES[r].base_severity] for r in ids)
        distinct = len(ids)
        # Từ 3 loại chỉ báo khác nhau (hoặc 2 loại đủ điểm) mới là HIGH; điểm từ 7 trở lên là CRITICAL.
        if distinct >= 3 or (distinct >= 2 and score >= 5):
            sev = "CRITICAL" if score >= 7 else "HIGH"
        # Chỉ 2 loại chỉ báo yếu: MEDIUM.
        elif distinct >= 2:
            sev = "MEDIUM"
        # Một driver chưa ký đứng riêng thì đáng chú ý nhưng chưa phải bằng chứng.
        elif "KG-005" in ids:
            sev = "MEDIUM"  # one unsigned driver alone is suspicious, not proof
        else:
            sev = "LOW"
        n += 1
        # Độ tin cậy tăng theo số loại chỉ báo độc lập.
        confidence = "LOW" if distinct == 1 else ("MEDIUM" if distinct == 2 else "HIGH")
        expl = "; ".join(f"{r}: {RULES[r].indicator}" for r in ids)
        # Với một chỉ báo, lời giải thích nói rõ "không đủ để kết luận độc hại" (chống báo động giả).
        if distinct == 1:
            expl += ". Single indicator only - not enough to call this malicious (possible false positive)."
        else:
            expl += f". {distinct} independent indicator types correlate for this process."
        # Tạo cảnh báo gồm giải thích, bằng chứng, hành động đề xuất và báo động giả có thể có của từng luật.
        alerts.append(Alert(f"ALERT-{n:03d}", proc or "(unknown)", sev, score, ids, expl, ev,
                            " | ".join(sorted({RULES[r].response for r in ids})),
                            confidence=confidence,
                            false_positives=[f"{r}: {RULES[r].false_positives}" for r in ids]))
    # Sắp xếp: nghiêm trọng nhất lên đầu.
    alerts.sort(key=lambda a: (-SEV_ORDER[a.severity], -a.score))
    return alerts


# Mức rủi ro tổng (hiện trên Dashboard) = mức của cảnh báo cao nhất; không có cảnh báo thì là LOW.
def risk_level(alerts: List[Alert]) -> str:
    if not alerts:
        return "LOW"
    top = max(SEV_ORDER[a.severity] for a in alerts)
    return {0: "LOW", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}[top]
