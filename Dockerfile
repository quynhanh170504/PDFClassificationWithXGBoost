# Sử dụng image Kali Linux làm base
FROM kalilinux/kali-rolling

# Cập nhật hệ thống và cài đặt python3, pip3, python3-venv và các công cụ cần thiết
RUN apt-get update && apt-get install -y python3 python3-pip python3-venv

# Tạo một virtual environment
RUN python3 -m venv /opt/venv

# Kích hoạt virtual environment và cài đặt pdfid
RUN /opt/venv/bin/pip install pdfid

# Thêm virtual environment vào PATH
ENV PATH="/opt/venv/bin:$PATH"

# Thiết lập thư mục làm việc
WORKDIR /pdf-analysis

# Lệnh mặc định để vào shell (có thể thay đổi nếu cần chạy lệnh cụ thể)
CMD ["bash"]
