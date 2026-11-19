# ITShield Antivirus

## معرفی

 یک پلتفرم حفاظت نقطه پایانی (Endpoint Protection) با قابلیت‌های آنتی‌ویروس و EDR است که برای Linux و Windows توسعه یافته. این نرم‌افزار با Python، Rust و C++ نوشته شده و شامل موتور تشخیص چندلایه، حفاظت بلادرنگ، تحلیل رفتاری، قرنطینه امن، و رابط گرافیکی کامل است.

## قابلیت‌ها

### موتور تشخیص
- **تشخیص با هش**: محاسبه SHA-256 فایل و مقایسه با بانک امضا
- **تشخیص با YARA**: استفاده از YARA 4.x با پشتیبانی از بارگذاری چندین فایل قاعده به‌صورت همزمان
- **تحلیل PE**: parse کامل ساختار فایل‌های اجرایی ویندوز (DOS/COFF/Optional headers، section table با entropy، import/export directories، شناسایی ۴۰+ تابع خطرناک)
- **موتور ریسک**: ترکیب چندین سیگنال (امضا، YARA، entropy، packing، imports) در یک امتیاز ۰-۱۰۰

### دانلود هوشمندانه تهدیدات

- **۱۲ منبع قواعد YARA** از GitHub (Florian Roth، Elastic، ReversingLabs، InQuest، bartblaze، Didier Stevens، ESET، McAfee و...)
- **۳ فید IOC** از abuse.ch (ThreatFox، URLHaus، FeodoTracker) — شامل IP، دامنه، URL و هش مخرب
- ذخیره در بانک SQLite با تاریخچه کامل و امکان rollback
### حفاظت بلادرنگ
- پایش فایل‌ها با inotify (Linux) — اسکن خودکار فایل‌های جدید یا تغییر یافته
- قرنطینه خودکار فایل‌های مخرب با دسترسی محدود (0400)
- اعلان دسکتاپ هنگام شناسایی تهدید
### تحلیل رفتاری
- پایش پردازه‌ها (/proc روی Linux، Toolhelp32 روی Windows)
- پایش شبکه (/proc/net روی Linux، GetExtendedTcpTable روی Windows)
- پایش Registry ویندوز برای شناسایی persistence
- تشخیص الگوهای مشکوک: ransomware (ایجاد/تغییر دسته‌جمعی فایل)، C2 beaconing (اتصال منظم به یک IP)، living-off-the-land (اجرای interpreter ها)
### موتور همبستگی رویدادها
- زنجیره‌سازی رویدادها برای تشکیل رخداد امنیتی (Incident)
- ۵ قانون همبستگی: پردازه→شبکه، تغییر دسته‌جمعی فایل، اجرایی drop+run، تهدید متعدد، C2 beaconing
- مدیریت چرخه حادثه: OPEN → INVESTIGATING → RESOLVED/DISMISSED
### قرنطینه

- انتقال امن فایل با `O_NOFOLLOW` (جلوگیری از symlink attack)
- اعتبارسنجی SHA-256 قبل از بازیابی (tamper detection)
- محافظت در برابر path traversal (رد کردن restore به مسیرهای سیستمی)
- حذف امن (overwrite با random bytes)

### Sandbox

- اجرای فایل مشکوک در دایرکتوری ایزوله با timeout
- محیط کاهش‌یافته (بدون HOME/PATH)
- پایش رفتار (inotify + /proc/net delta)
- خروجی: BENIGN / SUSPICIOUS / MALICIOUS / TIMEOUT / ERROR

### گزارش‌گیری

- گزارش HTML (RTL، color-coded، self-contained)
- گزارش JSON (برای SIEM)
- گزارش متنی (terminal)

### شتاب‌دهنده Rust
- تابع `sha256_file` با Rust (استریم ۱MiB، آزادسازی GIL)
- تابع `parse_pe` با Rust
- در صورت نبود، به‌صورت خودکار به Python fallback می‌کند

## رابط گرافیکی
- کاملاً راست‌چین (RTL)
- System tray با اعلان تهدیدات
- منوی فایل/نمایش/راهنما با shortcut

**صفحات GUI**:
1. **داشبورد** — وضعیت Core، آمار، فعالیت اخیر
2. **اسکن** — انتخاب مسیر، progress bar زنده، جدول نتایج
3. **حفاظت زنده** — فعال/غیرفعال inotify + auto-quarantine
4. **قرنطینه** — لیست، بازیابی، حذف دائمی
5. **رویدادها** — جریان زنده EventBus با فیلتر
6. **سیستم** — پردازه‌ها + اتصال‌های شبکه
7. **رخدادها** — رخدادهای امنیتی با resolve/dismiss
8. **به‌روزرسانی** — دانلود قواعد YARA از ۱۲ منبع
9. **آمار و روند** — نمودار روند تهدیدات + تاریخچه اسکن
10. **تنظیمات** — مسیرها، max size، تم

## نحوه اجرا در لینوکس


pip install protobuf yara-python PySide6 grpcio-tools inotify_simple cryptography pytest

cd ITShield-Antivirus

python -m grpc_tools.protoc --proto_path=itshield/ipc --python_out=itshield/ipc itshield/ipc/protocol.proto

### GUI
python -m itshield.gui.main

### CLI
python -m itshield.cli scan /home/user/Downloads
python -m itshield.cli update yara --all
python -m itshield.cli update ioc
python -m itshield.cli sandbox /tmp/suspicious_file
python -m itshield.cli report <job-id> --format html

### اجرای سرویس پس‌زمینه
python -m itshield.cli serve
python -m itshield.cli status

## نحوه اجرا در ویندوز

pip install pywin32

python -m grpc_tools.protoc --proto_path=itshield\ipc --python_out=itshield\ipc itshield\ipc\protocol.proto
### GUI
python -m itshield.gui.main
###  CLI (همان دستورات Linux)
python -m itshield.cli scan C:\Users\YourName\Downloads
## داکر
docker build -t itshield-antivirus .
docker run --rm -it -v $(pwd)/data:/opt/itshield/data itshield-antivirus scan /tmp
### شتاب‌دهنده Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

source ~/.cargo/env

pip install maturin

cd native/rust && maturin develop --release && cd ../..
