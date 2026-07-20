# مشاركة التطبيق بأمان / Sharing this app safely

## الخلاصة (بالعربية)

أفضل طريقة تشارك فيها التطبيق مع الآخرين **بدون ما يشكّون فيه** هي إرساله
كـ **كود مصدري (source code)** مثل ما هو — مو كملف `.exe` جاهز.

**ليش الكود المصدري أأمن للمشاركة؟**
- أي شخص يقدر يفتح الملفات ويقرأ بالضبط وش يسوي التطبيق — ما فيه شيء مخفي.
- ملفات `.py` نصية عادية، ما تنفّذ نفسها، ومحرّكات مكافحة الفيروسات نادراً ما
  تعلّم عليها.
- بالعكس: لو حوّلناه لملف `.exe` عن طريق أدوات مثل PyInstaller، **كثير من برامج
  الحماية (ومنها Windows SmartScreen) ترفعه كإنذار كاذب (false positive)**، لأن
  هذي الأدوات تحزم مفسّر بايثون كامل بطريقة تشبه سلوك بعض البرمجيات الخبيثة.
  فالـ .exe يخوّف الناس أكثر، مو أقل.

**كيف يتأكد الشخص اللي يستلمه إنه سليم؟**
1. **بصمة SHA-256**: أرفقت لك ملف بصمة مع النسخة المضغوطة. المستلم يقارن البصمة
   (بأمر `Get-FileHash`) للتأكد إن الملف ما تغيّر أثناء الإرسال.
2. **VirusTotal**: يقدر يرفع الملف المضغوط على [virustotal.com](https://www.virustotal.com)
   ويشوف نتيجة أكثر من 70 محرّك فحص قبل ما يشغّله.
3. **يقرأ الكود**: خصوصاً `app/server.py` (الحماية) و `app/agents/` (وش يسوي كل وكيل).

**وش الصلاحيات اللي يحتاجها التطبيق (كن صريح مع المستلم):**
- يقرأ ملف `inventory.txt` فقط من مجلده.
- يتصل بالإنترنت فقط بموقع `services.nvd.nist.gov` الرسمي.
- زر "تحديث" ينفّذ `winget upgrade` — أي يثبّت تحديثات من مصادر winget الرسمية،
  وبس لمّا المستخدم يضغط ويأكّد بنفسه.
- ما يرسل أي بيانات لأي جهة، ولا فيه تتبّع (telemetry).

> ملاحظة: لا ترسل ملف `inventory.txt` أو `threat_intel_report.md` الخاص فيك مع
> النسخة — فيها قائمة برامجك الحقيقية (خصوصية). النسخة المضغوطة تستبعدها تلقائياً
> وتضم `inventory.example.txt` بدلاً عنها.

---

## Summary (English)

Share this app as **source code**, not as a prebuilt `.exe`.

- Source `.py` files are plain text and fully inspectable — nothing is hidden.
- A PyInstaller `.exe`, by contrast, frequently trips **antivirus / SmartScreen
  false positives** because bundling a whole Python interpreter resembles some
  malware packers. The `.exe` makes people *more* suspicious, not less.

**How a recipient verifies it's safe:**
1. **SHA-256 checksum** — ship the `.sha256` file next to the zip; they run
   `Get-FileHash` and compare to confirm the file wasn't altered in transit.
2. **VirusTotal** — upload the zip to <https://www.virustotal.com> for a 70+
   engine scan before running.
3. **Read the code** — especially `app/server.py` (security) and `app/agents/`.

**What the app is allowed to do (state this plainly to recipients):**
- Reads only `inventory.txt` in its folder.
- Network access only to `services.nvd.nist.gov`.
- The "Update" button runs `winget upgrade` (installs from official winget
  sources) — only when the user clicks and confirms.
- No data is sent anywhere; no telemetry.

> Do not include your own `inventory.txt` or `threat_intel_report.md` in the
> package — they list your real installed software. The build script excludes
> them and ships `inventory.example.txt` instead.

## Security posture (OWASP-aligned)

- **A01 / CSRF & DNS-rebinding**: the local API validates the `Host` header
  (rejects rebinding) and requires a per-process CSRF token that a cross-site
  page cannot read. Verified: a token-less POST returns `403`, a forged `Host`
  returns `421`.
- **A03 Injection**: winget and the agents run fixed `argv` lists — never
  `shell=True`, never a command built from input.
- **A05 Misconfiguration**: strict CSP, `X-Frame-Options: DENY`, nosniff,
  no-referrer, no-store on every response; request bodies size-capped.
- **Filesystem**: reads are sandboxed to the app folder; the report writer can
  only ever write one fixed path (atomic write).
- **Package updates** only apply IDs that a prior read-only scan returned.
