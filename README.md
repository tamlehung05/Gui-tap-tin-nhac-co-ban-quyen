🎵 Ứng Dụng Gửi Tập Tin Nhạc Có Bản Quyền Qua Mạng

✨ Giới thiệu

Hệ thống mô phỏng việc gửi tập tin nhạc có bản quyền giữa hai máy tính thật. File nhạc được mã hóa an toàn, metadata được đảm bảo riêng biệt, và toàn vẹn dữ liệu được kiểm tra nghiêm ngặt.

🏠 Tính năng chính

✉️ Gửi file nhạc đã mã hóa qua socket TCP.

🔐 Bảo mật file nhạc bằng Triple DES (CBC).

✨ Metadata (tên bài hát, nghệ sĩ, ID) được mã hóa bằng DES.

🌐 Trao đổi khóa đảm bảo qua RSA 1024-bit (OAEP).

🔎 Kiểm tra toàn vẹn bằng SHA-512 (iv + ciphertext).

🔧 Công nghệ sử dụng

Python 3.x

PyCryptodome

Socket TCP/IP

Thuật toán: RSA (1024-bit), Triple DES, DES, SHA-512

📊 Cấu trúc thư mục

SecureMusicSender/
├── nguoi_gui.py               # Máy người gửi (Client)
├── nguoi_nhan.py              # Máy người nhận (Server)
├── receiver_public_key.pem   # Khóa RSA công khai của người nhận
├── receiver_private_key.pem  # Khóa RSA riêng của người nhận
├── song.mp3                  # File nhạc cần gửi

🤓 Quy trình hoạt động

Handshake: Client gửi "Hello!" → Server phản hồi "Ready!".

Trao khóa:

Client tạo session_key (24 byte cho Triple DES).

Mã hóa session_key bằng RSA (PKCS1_OAEP).

Mã hóa:

Mã hóa song.mp3 bằng Triple DES.

Mã hóa metadata bằng DES.

Tính SHA-512(iv + ciphertext).

Gửi: Gửi session key + gói JSON chứa iv, cipher, meta, hash.

Nhận: Server giải mã, kiểm hash, ghi file, gửi ACK.

⚖️ Gói JSON gửi đi

{
  "iv": "Base64",
  "cipher": "Base64",
  "meta": "Base64",
  "hash": "SHA-512 hex"
}

✨ Cách chạy

Bời người nhận (Server)

python nguoi_nhan.py

Tự động tạo receiver_private_key.pem nếu chưa có.

Bời người gửi (Client)

Copy receiver_public_key.pem từ server sang.

Chạy:

python nguoi_gui.py

Nhập đường dẫn tới file song.mp3

📄 Kết quả mô phỏng

✅ File nhạc được mã hóa gửi sang, lưu lại với tên song.mp3

📝 Metadata in ra:

Metadata: TênBàiHát: Xa Em | Nghệ Sĩ: Thanh Hưng | ID Bản Quyền: ABCXYZ123

📅 Nhóm thực hiện

Họ và tên

Vai trò

Lê Hưng Tâm

Viết mã client + server, logic trao đổi khóa

Nguyễn Hữu Bảo

Mã hóa/giải mã file, DES & Triple DES

Trịnh Kiều Trinh

Viết README, mô phỏng test socket LAN

🔐 Ghi chú

Không gửi file private key.

Hệ thống có thể mở rộng tích hợp giao diện GUI.

File nhạc có thể là .mp3, .wav, .aac vần vạn.

© 2025 - Nhóm 7 - ứng dụng gửi file nhạc bản quyền với bảo mật TripleDES + RSA - Môn Nhập môn An toàn Thông tin
