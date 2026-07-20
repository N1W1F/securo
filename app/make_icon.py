"""Generate the app icon (original artwork, drawn from primitives).

A rounded-square badge with a live "pulse" (ECG heartbeat) line — the app's
core idea is continuous monitoring, not a static badge. Violet line, one
blood-red beat marking the alert/finding — matches the app's dark purple +
blood-red theme (style.css :root). Rendered at 1024px for crisp
downsampling, then saved as a multi-resolution .ico (16..256) so Windows
picks the right size everywhere (window icon, taskbar, Start menu, Alt-Tab).
"""
from pathlib import Path

from PIL import Image, ImageDraw

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"

S = 1024
BG = (10, 6, 18, 255)            # --bg #0a0612
BORDER = (61, 36, 86, 255)       # --border-strong #3d2456
VIOLET = (168, 85, 247, 255)     # --violet #a855f7
BLOOD_BRIGHT = (255, 77, 94, 255)  # --blood-bright #ff4d5e


def build() -> Image.Image:
    """Kept deliberately bold and low-detail — this has to stay legible at
    16-32px in the Windows taskbar, where fine linework turns to mush."""
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    margin = S * 0.08
    d.rounded_rectangle([margin, margin, S - margin, S - margin], radius=S * 0.19,
                         fill=BG, outline=BORDER, width=int(S * 0.03))

    # ECG pulse line — flat, spike down, spike up (the "finding"), flat,
    # small blip, flat. A single bold polyline reads clearly at any size.
    mid = S * 0.52
    pts = [
        (S * 0.14, mid),
        (S * 0.28, mid),
        (S * 0.35, mid + S * 0.10),
        (S * 0.42, mid - S * 0.28),
        (S * 0.49, mid + S * 0.20),
        (S * 0.56, mid - S * 0.06),
        (S * 0.64, mid),
        (S * 0.72, mid),
        (S * 0.78, mid - S * 0.07),
        (S * 0.84, mid),
        (S * 0.90, mid),
    ]
    d.line(pts, fill=VIOLET, width=int(S * 0.052), joint="curve")
    for p in (pts[0], pts[-1]):
        d.ellipse([p[0] - S * 0.026, p[1] - S * 0.026, p[0] + S * 0.026, p[1] + S * 0.026], fill=VIOLET)

    # blood-red dot on the peak = the alert this whole app exists to catch
    peak = pts[3]
    r = S * 0.052
    d.ellipse([peak[0] - r, peak[1] - r, peak[0] + r, peak[1] + r], fill=BLOOD_BRIGHT)

    return img


def main():
    STATIC_DIR.mkdir(exist_ok=True)
    icon = build()
    icon.save(STATIC_DIR / "icon.png")
    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    icon.save(STATIC_DIR / "favicon.ico", sizes=sizes)
    icon.save(APP_DIR / "app.ico", sizes=sizes)
    print("icon written:", STATIC_DIR / "favicon.ico")


if __name__ == "__main__":
    main()
