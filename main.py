"""Run the KeyGuard Lab demo with bundled synthetic data."""
from pathlib import Path
import tkinter as tk
from tkinter import ttk

from app.detection_engine import analyze
from app.sysmon_analyzer import is_sample, load_file

SAMPLE = Path(__file__).resolve().parent / "data" / "sample_sysmon.xml"


def run_detection():
    events = load_file(SAMPLE)
    if not is_sample(events):
        raise ValueError("Tệp đi kèm phải có nhãn SAMPLE DATA.")
    return len(events), analyze(events)


def main():
    root = tk.Tk()
    root.title("KeyGuard Lab – Demo Nhóm 08")
    root.minsize(760, 465)
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)

    tabs = ttk.Notebook(root)
    tabs.grid(sticky="nsew", padx=16, pady=16)
    input_tab = ttk.Frame(tabs, padding=18)
    detection_tab = ttk.Frame(tabs, padding=18)
    tabs.add(input_tab, text="Mô phỏng nhập liệu")
    tabs.add(detection_tab, text="Phát hiện hành vi")

    ttk.Label(
        input_tab,
        text="Cùng chuỗi mẫu abc123, hệ thống có thể nhận số sự kiện khác nhau.",
    ).pack(anchor="w")
    summary = tk.StringVar(value="Chọn một kịch bản để xem kết quả mô phỏng.")
    ttk.Label(input_tab, textvariable=summary, wraplength=650).pack(anchor="w", pady=16)
    ttk.Button(
        input_tab,
        text="Sự kiện phím mô phỏng",
        command=lambda: summary.set(
            "Ô nhập: abc123    ·    6 lần nhấn, 6 lần nhả    ·    Chuỗi dựng lại: abc123"
        ),
    ).pack(anchor="w", pady=4)
    ttk.Button(
        input_tab,
        text="Bàn phím ảo chèn chữ trực tiếp",
        command=lambda: summary.set(
            "Ô nhập: abc123    ·    0 sự kiện phím    ·    Chuỗi dựng lại: rỗng"
        ),
    ).pack(anchor="w", pady=4)
    ttk.Button(
        input_tab,
        text="Bàn phím ảo Windows mô phỏng",
        command=lambda: summary.set(
            "Ô nhập: abc123    ·    6 lần nhấn, 6 lần nhả    ·    Chuỗi dựng lại: abc123"
        ),
    ).pack(anchor="w", pady=4)

    status = tk.StringVar(value="SAMPLE DATA – nhật ký Sysmon giả lập")
    ttk.Label(detection_tab, textvariable=status).pack(anchor="w")
    table = ttk.Treeview(detection_tab, columns=("process", "severity", "score", "rules"),
                         show="headings", height=4, selectmode="browse")
    for key, title, width in (
        ("process", "Đối tượng", 180),
        ("severity", "Mức cảnh báo", 105),
        ("score", "Điểm", 65),
        ("rules", "Luật đã khớp", 255),
    ):
        table.heading(key, text=title)
        table.column(key, width=width)
    details = tk.StringVar(value="Chọn một hàng để xem lý do và hướng xác minh.")
    alerts_by_row = {}

    def analyze_sample():
        for row_id in table.get_children():
            table.delete(row_id)
        alerts_by_row.clear()
        details.set("Chọn một hàng để xem lý do và hướng xác minh.")
        try:
            count, alerts = run_detection()
        except (OSError, ValueError):
            status.set("Không đọc được dữ liệu mẫu. Kiểm tra thư mục data trong repo.")
            return
        status.set(f"SAMPLE DATA – {count} sự kiện, {len(alerts)} cảnh báo")
        for alert in alerts:
            row_id = table.insert("", "end", values=(
                alert.process, alert.severity, alert.score, ", ".join(alert.rules)
            ))
            alerts_by_row[row_id] = alert

    def show_details(event):
        selection = event.widget.selection()
        if selection:
            alert = alerts_by_row[selection[0]]
            details.set(f"{alert.explanation}\n\n{alert.response}")

    table.bind("<<TreeviewSelect>>", show_details)
    ttk.Button(detection_tab, text="Phân tích dữ liệu mẫu", command=analyze_sample).pack(
        anchor="w", pady=8
    )
    table.pack(fill="x")
    ttk.Label(detection_tab, textvariable=details, wraplength=650).pack(anchor="w", pady=12)
    root.mainloop()


if __name__ == "__main__":
    main()
