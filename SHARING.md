# مشاركة التطبيق بأمان / Sharing this app safely

## الخلاصة (بالعربية)

كل [إصدار](https://github.com/N1W1F/securo/releases) يحتوي على **صيغتين**، وكلٌّ
لها مقابل:

| الصيغة | لمن | المقابل |
|---|---|---|
| **الكود المصدري** (`.zip`) | من يريد قراءة ما يشغّله قبل تشغيله | يتطلب Python 3.10+ |
| **`Securo.exe`** | من يريد التشغيل مباشرة | **غير موقّع بعد** — سيظهر تحذير SmartScreen |

**عن تحذير SmartScreen:** الملف التنفيذي مبني بـPyInstaller، وهذي الأداة تحزم
مفسّر بايثون كامل بطريقة تشبه شكلياً بعض حزم البرمجيات الخبيثة، فيرفعها ويندوز
وبعض محرّكات الحماية كـ**إنذار كاذب**. التوقيع الرقمي عبر
[SignPath Foundation](https://signpath.org/) قيد الإجراء ولم يكتمل بعد. حتى
ذلك الحين، سترى: «Windows protected your PC» ← *More info* ← *Run anyway*.

**إذا كان هذا التحذير يزعجك — استخدم الكود المصدري.** يؤدي نفس الوظيفة تماماً،
وملفات `.py` نصية عادية يمكن قراءتها قبل تشغيلها. هذا هو الخيار الذي نرشّحه لمن
يشارك التطبيق مع شخص لا يعرفه: أن يقدر المستلم على مراجعة الكود أفضل من أن
يُطلب منه تجاوز تحذير أمني.

**كيف يتأكد المستلم أن الملف سليم؟**
1. **بصمة SHA-256**: كل إصدار يرفق ملف بصمة. يقارنها المستلم بأمر
   `Get-FileHash` للتأكد أن الملف لم يتغيّر أثناء النقل.
2. **VirusTotal**: يرفع الملف على [virustotal.com](https://www.virustotal.com)
   ويرى نتيجة أكثر من 70 محرّك فحص قبل التشغيل.
3. **يقرأ الكود**: خصوصاً `app/server.py` (الحماية) و`app/agents/` (وظيفة كل
   وكيل) و[`ARCHITECTURE.md`](ARCHITECTURE.md) (التصميم وحدود الثقة).

**ما الذي يفعله التطبيق فعلياً (كن صريحاً مع المستلم):**
- **يقرأ** قائمة البرامج المثبّتة عبر `winget list` (وملف `inventory.txt`
  كبديل احتياطي على الأجهزة التي لا يتوفر فيها winget).
- **يتصل بالإنترنت** بثلاث جهات فقط، وكلها قراءة فقط:
  `services.nvd.nist.gov` (قاعدة الثغرات) · `www.cisa.gov` (قائمة الثغرات
  المستغَلة فعلياً) · وطلب `HEAD` لرابط المثبِّت الذي يعلنه winget نفسه لمعرفة
  حجم التحميل (https حصراً، بلا تنزيل محتوى).
- **المحلّل الذكي اختياري** ويعمل على `localhost` عبر Ollama — لا يغادر الجهاز.
- **زر التحديث** ينفّذ `winget upgrade` — أي يثبّت من مصادر winget الرسمية،
  وفقط بعد ضغط المستخدم وتأكيده.
- **لا يرسل أي بيانات لأي جهة، ولا يوجد تتبّع (telemetry).**

> ملاحظة: لا ترسل ملفات `inventory.txt` أو `threat_intel_report.md` أو
> `threat_intel_findings.json` الخاصة بك مع النسخة — فيها قائمة برامجك الحقيقية
> (خصوصية). سكربت البناء يستبعدها تلقائياً ويضم `inventory.example.txt` بدلاً
> عنها.

---

## Summary (English)

Every [release](https://github.com/N1W1F/securo/releases) ships **two forms**,
each with a real trade-off:

| Form | For | Trade-off |
|---|---|---|
| **Source** (`.zip`) | People who want to read what they run | Needs Python 3.10+ |
| **`Securo.exe`** | People who want to just run it | **Not code-signed yet** — SmartScreen will warn |

**About the SmartScreen warning:** the executable is built with PyInstaller,
which bundles a whole Python interpreter in a way that superficially resembles
some malware packers — so Windows and some AV engines raise a **false
positive**. Code signing via [SignPath Foundation](https://signpath.org/) is
pending. Until then you will see "Windows protected your PC" → *More info* →
*Run anyway*.

**If that warning bothers you, use the source archive.** It does exactly the
same thing, and `.py` files are plain text you can read before running. This is
the form we recommend when sharing with someone who does not know you: letting
them inspect the code beats asking them to click past a security warning.

**How a recipient verifies it's safe:**
1. **SHA-256 checksum** — every release ships a `.sha256`; run `Get-FileHash`
   and compare to confirm the file wasn't altered in transit.
2. **VirusTotal** — upload to <https://www.virustotal.com> for a 70+ engine
   scan before running.
3. **Read the code** — especially `app/server.py` (security), `app/agents/`,
   and [`ARCHITECTURE.md`](ARCHITECTURE.md) (design and trust boundaries).

**What the app actually does (state this plainly to recipients):**
- **Reads** the installed-software list via `winget list` (falling back to
  `inventory.txt` on machines without winget).
- **Network access** to exactly three destinations, all read-only:
  `services.nvd.nist.gov` (CVE data) · `www.cisa.gov` (known-exploited list) ·
  and a `HEAD` request to the installer URL winget itself reports, to show
  download size (https only, no body downloaded).
- **The AI analyst is optional** and runs against `localhost` via Ollama —
  nothing leaves the machine.
- **The Update button** runs `winget upgrade` (installs from official winget
  sources) — only when the user clicks and confirms.
- **No data is sent anywhere; no telemetry.**

> Do not include your own `inventory.txt`, `threat_intel_report.md`, or
> `threat_intel_findings.json` in the package — they list your real installed
> software. The build script excludes them and ships `inventory.example.txt`
> instead.

## Security posture (OWASP-aligned)

- **A01 / CSRF & DNS-rebinding**: the local API validates the `Host` header
  (rejects rebinding) and requires a per-process CSRF token that a cross-site
  page cannot read. Verified: a token-less POST returns `403`, a forged `Host`
  returns `421`.
- **A03 Injection**: winget and the agents run fixed `argv` lists — never
  `shell=True`, never a command built from input.
- **A05 Misconfiguration**: strict CSP, `X-Frame-Options: DENY`, nosniff,
  no-referrer, no-store on every response; oversized request bodies are
  rejected with `413` rather than silently treated as empty.
- **Filesystem**: reads are sandboxed to the app folder; the report writer can
  only ever write one fixed path (atomic write).
- **Package updates** only apply IDs that a prior read-only scan returned.
- **Fail-safe by default**: when a check cannot complete — the KEV feed is
  unreachable, the update scan hasn't run, winget output is unparseable — the
  result is an explicit *unknown*, never a clean bill of health.

A 142-test security suite covering 35 attack categories runs in CI on every
change and can also be run from inside the app.
