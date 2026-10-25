"""Render demo.html into docs/demo.gif.  Needs: pip install playwright pillow (uses Edge if `playwright install chromium` wasn't run)"""
import io
import pathlib
from PIL import Image
from playwright.sync_api import sync_playwright

HERE = pathlib.Path(__file__).resolve().parent
FPS, SECONDS, WIDTH = 20, 10, 800

frames = []
with sync_playwright() as pw:
    try:
        browser = pw.chromium.launch()
    except Exception:  # no bundled chromium: fall back to the system Edge
        browser = pw.chromium.launch(channel="msedge")
    page = browser.new_page(viewport={"width": 960, "height": 540})
    page.goto((HERE / "demo.html").as_uri() + "?render")
    page.evaluate("document.fonts.ready")
    for i in range(FPS * SECONDS):
        page.evaluate(f"seek({i / FPS})")
        img = Image.open(io.BytesIO(page.screenshot())).convert("RGB")
        frames.append(img.resize((WIDTH, WIDTH * 540 // 960), Image.LANCZOS))

# one shared palette keeps the gif small and stops colours flickering between frames
sample = frames[::FPS // 2]
sheet = Image.new("RGB", (WIDTH, sample[0].height * len(sample)))
for n, f in enumerate(sample):
    sheet.paste(f, (0, n * f.height))
pal = sheet.quantize(255, method=Image.MEDIANCUT)
gif = [f.quantize(palette=pal, dither=Image.Dither.NONE) for f in frames]
out = HERE.parent / "demo.gif"
gif[0].save(out, save_all=True, append_images=gif[1:], duration=1000 // FPS, loop=0, optimize=True)
print(out, round(out.stat().st_size / 1e6, 2), "MB")
