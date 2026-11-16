# LinuxSign

Ký số bằng USB Token (Viettel-CA, VNPT-CA, BKAV-CA, FPT-CA, Nacencomm, MISA, SafeNet,
Feitian, Longmai, ...) trên **Linux, Windows, macOS**, viết bằng Rust. Gồm ứng dụng
desktop quản lý token và hạn chứng thư, CLI, và agent HTTP cho ứng dụng web.

## Nguyên lý

Mọi USB Token chữ ký số đều có driver theo chuẩn **PKCS#11** (`.so` trên Linux,
`.dll` trên Windows). LinuxSign không gắn với hãng nào, mà tự tìm và dùng mọi driver
PKCS#11 có trên máy:

```
App desktop (Tauri) · CLI · Agent HTTP localhost
                 │
           crates/core
  discovery → probe (tiến trình con) → manager → signer → cms / pdf / xml / tsa
                 │
     Driver PKCS#11 của hãng  /  OpenSC
                 │
          pcscd → USB Token
```

| Thành phần | Vai trò |
|---|---|
| `discovery` | Tìm driver từ p11-kit, tên driver đã biết, và quét `/opt`, `Program Files` tìm thư viện có `C_GetFunctionList`. Nhờ vậy nhận được cả hãng chưa có trong danh sách. |
| `probe` | Nạp từng driver trong **tiến trình con riêng**, có timeout. Driver crash hay treo không làm sập ứng dụng. |
| `manager` | Gộp token được nhiều driver cùng thấy; driver chính hãng làm chính, OpenSC làm dự phòng. |
| `signer` | Thử cơ chế ký từ phổ biến nhất (`CKM_RSA_PKCS` + DigestInfo) rồi lần lượt các cơ chế khác. Luôn **xác minh lại** chữ ký bằng chứng thư. Sai PIN thì dừng ngay để tránh khóa token. |
| `cms` / `pdf` / `tsa` | CMS CAdES-BES (`.p7s`), PDF **PAdES** (incremental update, ký nhiều lần được), dấu thời gian RFC 3161. |
| `font` | Nhúng font Noto Sans (subset, Type0/Identity-H, có ToUnicode) để khung chữ ký PDF hiển thị đủ dấu tiếng Việt. |
| `xml` | XMLDSig/XAdES-BES với Canonical XML 1.0 tự hiện thực (khớp từng byte với libxml2). Hồ sơ hóa đơn điện tử VN (`DLHDon` → `DSCKS/NBan`), tờ khai (enveloped), XAdES-BES. |
| `agent` | HTTP `127.0.0.1` cho web, chỉ chấp nhận các website trong danh sách cho phép. |

## Cài đặt môi trường

```bash
# Linux (Ubuntu/Debian)
sudo apt install pcscd libccid opensc
sudo systemctl enable --now pcscd.socket
# + driver Linux của nhà cung cấp chữ ký số (nếu có)
```

Windows/macOS: cài driver token của nhà cung cấp như bình thường.

## Build

```bash
cargo build --release -p linuxsign-cli          # CLI → target/release/linuxsign
cargo build --release -p linuxsign-app          # App desktop → target/release/linuxsign-app
cd app && npx @tauri-apps/cli@2 build           # Bộ cài: .deb/.rpm/.AppImage, .msi, .dmg
```

Build ứng dụng desktop trên Linux cần `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`,
`libsoup-3.0-dev` (xem tài liệu cài đặt của Tauri 2).

## Ứng dụng desktop

- **Tổng quan**: token đang cắm, chứng thư (tên, MST/CCCD, nhà cung cấp), số ngày còn
hạn kèm thanh tiến độ, cảnh báo PIN sắp khóa. Tự nhận khi cắm hoặc rút token.
- **Theo dõi hạn**: gửi thông báo hệ thống khi sắp hết hạn, xuất nhắc lịch `.ics` để
thêm vào Google Calendar/Outlook, xuất chứng thư `.cer`.
- **Ký số**: ký PDF (chọn trang, vị trí khung chữ ký, xem trước, lý do, nơi ký, TSA),
ký XML hóa đơn điện tử / tờ khai / XAdES, và ký file bất kỳ (`.p7s`).
- **Khay hệ thống**: đóng cửa sổ thì chạy nền ở khay; menu khay hiện token đang cắm và
tình trạng hạn, bật/tắt agent, khởi động cùng hệ thống (chạy ẩn), quét lại, thoát.
Khi chạy nền: báo cắm/rút token, nhắc hằng ngày chứng thư sắp hết hạn.
- **Chẩn đoán**: kiểm tra pcscd, USB, từng driver, kèm khuyến nghị khắc phục.
- **Hướng dẫn**: cài đặt, ký, kiểm tra chữ ký, gia hạn, PIN, tích hợp web, xử lý sự cố.
- **Cài đặt**: số ngày cảnh báo, TSA, giá trị mặc định, font khung chữ ký, chạy nền,
khởi động cùng hệ thống, agent, driver bổ sung.

## CLI

```bash
linuxsign doctor                      # chẩn đoán
linuxsign list                        # token + chứng thư + hạn
linuxsign expiry --days 30            # mã thoát 1 nếu có chứng thư sắp/đã hết hạn (dùng cho cron)
linuxsign sign hopdong.docx           # → hopdong.docx.p7s
linuxsign sign-pdf in.pdf out.pdf --reason "Phê duyệt" --rect 350,40,560,110 --page 1
linuxsign sign-pdf in.pdf out.pdf --tsa http://timestamp.digicert.com
linuxsign sign-xml hoadon.xml hoadon_signed.xml --profile einvoice
linuxsign sign-xml tokhai.xml tokhai_signed.xml --profile enveloped --ref-id _NODE_TO_SIGN --parent CKyDTu
linuxsign sign-xml vanban.xml vanban_signed.xml --profile xades
linuxsign serve --allow-origin https://app.congty.vn
```

Ký XML:
- `--profile einvoice`: ký `<DLHDon Id="…">` (tự dò), đặt chữ ký trong `DSCKS/NBan` (tạo
nếu thiếu), kèm `SignatureProperty/SigningTime`.
- `--profile enveloped`: cả văn bản (hoặc `--ref-id`), chữ ký ở cuối phần tử gốc hoặc tại `--parent`.
- `--profile xades`: XAdES-BES (SigningTime, SigningCertificate).

Tất cả dùng RSA-SHA256 và C14N 1.0. Tên phần tử và vị trí chữ ký do hệ thống tiếp nhận
quy định, nên trước khi dùng chính thức hãy nộp thử một file lên môi trường thử nghiệm
của nhà cung cấp hóa đơn hoặc cơ quan thuế.

Chọn chứng thư bằng `--cert <thumbprint | serial | MST | một phần tên>`. PIN được hỏi
khi chạy, hoặc truyền qua biến `LINUXSIGN_PIN`.

## Agent cho web

| Endpoint | Body |
|---|---|
| `GET /health` | |
| `GET /certificates` | |
| `POST /sign` | `{cert_id, pin, data_b64 \| digest_b64, hash?, pss?, format?: "raw"\|"cms", attached?, tsa_url?}` |
| `POST /sign/pdf` | `{cert_id, pin, pdf_b64, reason?, location?, page?, rect?, tsa_url?}` |
| `POST /sign/xml` | `{cert_id, pin, xml_b64, profile?: "einvoice"\|"enveloped"\|"xades", reference_id?, parent_path?, signature_id?}` |

Mã lỗi: `401` PIN, `403` website chưa được phép, `404` không thấy chứng thư, `500` ký thất bại.

## Cấu hình

`~/.config/linuxsign/config.json` (Windows: `%APPDATA%\linuxsign\config.json`), xem
[config.example.json](config.example.json). Biến `LINUXSIGN_MODULES=/a.so:/b.so` dùng
để chỉ định driver tạm thời.

## Kiểm thử

```bash
cargo test -p linuxsign-core                   # không cần token
cargo test -p linuxsign-core -- --ignored tsa  # cần mạng: thử dấu thời gian thật
```

Kiểm thử dùng một "token" phần mềm và chỉ thay lớp gọi driver. Kết quả được kiểm tra
chéo bằng công cụ độc lập nếu máy có:
- CMS: `openssl cms -verify`
- PDF: `pdfsig` (poppler)
- C14N: `xmllint --c14n`
- Chữ ký XML: `xmlsec1 --verify`. Biến `XMLSEC1` trỏ tới file chạy nếu không nằm trong `PATH`.
Có cả bài kiểm thử sửa dữ liệu đã ký để đảm bảo xmlsec1 phát hiện được.

Với token thật: `linuxsign doctor` → `linuxsign list` → `linuxsign sign-pdf`, rồi mở
file bằng Adobe Reader hoặc Okular. Không có token thì dùng SoftHSM
(`sudo apt install softhsm2`).

## Giới hạn hiện tại

- Chưa được kiểm thử trên token vật lý của từng nhà cung cấp.
- Ký XML mới hỗ trợ file mã hóa UTF-8 và C14N 1.0 inclusive. Chưa có Exclusive C14N,
chưa ký nhiều tham chiếu tùy ý, chưa có XAdES-T (dấu thời gian trong XML).
- Trên GNOME, biểu tượng khay cần tiện ích AppIndicator (Ubuntu có sẵn).

## Giấy phép font

Font Noto Sans đi kèm (`crates/core/assets/NotoSans-Regular.ttf`) theo SIL Open Font
License 1.1, xem [OFL.txt](crates/core/assets/OFL.txt).
