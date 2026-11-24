# KeyGuard Lab Demo

Bản trình diễn học phần Nhập môn Bảo mật thông tin của Nhóm 08, lớp N05.

## Chạy trên Windows

Cài Python 3.10 trở lên với Tcl/Tk, mở PowerShell trong thư mục repo rồi chạy:

```powershell
py main.py
```

Ứng dụng dùng thư viện chuẩn Python và dữ liệu đi kèm. Có thể kiểm tra Tkinter bằng `py -m tkinter`.

## Trình diễn

- Mở **Mô phỏng nhập liệu** rồi chọn từng kịch bản với chuỗi cố định `abc123`. So sánh số sự kiện và chuỗi dựng lại. Các con số trên màn hình là giá trị minh họa.
- Mở **Phát hiện hành vi**, chọn **Phân tích dữ liệu mẫu**. Bảy luật chạy trên sáu sự kiện Sysmon giả lập. Kết quả mẫu gồm ba cảnh báo ở mức HIGH, MEDIUM và LOW. Chọn một hàng để đọc lý do và hướng xác minh.

Bản demo chỉ dùng chuỗi và nhật ký mẫu đi kèm. Giao diện không thu phím thật, giám sát tiến trình, đọc nhật ký máy hoặc gửi dữ liệu qua mạng.

## Chạy kiểm thử

```powershell
py -m unittest discover -s tests
```
