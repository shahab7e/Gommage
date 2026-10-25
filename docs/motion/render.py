"""Render demo.html into docs/demo.gif, or with `mp4` into a 1080p60 docs/demo.mp4.
Needs: pip install playwright pillow (uses Edge if `playwright install chromium` wasn't run); mp4 also needs imageio-ffmpeg."""
import io
import pathlib
import subprocess
import sys
from PIL import Image
from playwright.sync_api import sync_playwright

HERE = pathlib.Path(__file__).resolve().parent
MP4 = "mp4" in sys.argv[1:]
FPS, SECONDS, WIDTH = (60, 10, 1920) if MP4 else (20, 10, 800)


def frames():
    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch()
        except Exception:  # no bundled chromium: fall back to the system Edge
            browser = pw.chromium.launch(channel="msedge")
        page = browser.new_page(viewport={"width": 960, "height": 540}, device_scale_factor=2 if MP4 else 1)
        page.goto((HERE / "demo.html").as_uri() + "?render")
        page.evaluate("document.fonts.ready")
        for i in range(FPS * SECONDS):
            page.evaluate(f"seek({i / FPS})")
            yield page.screenshot()


if MP4:
    import imageio_ffmpeg
    out = HERE.parent / "demo.mp4"
    enc = subprocess.Popen([imageio_ffmpeg.get_ffmpeg_exe(), "-y", "-loglevel", "error", "-f", "image2pipe", "-framerate", str(FPS),
                            "-i", "-", "-c:v", "libx264", "-preset", "slow", "-crf", "16", "-pix_fmt", "yuv420p",
                            "-movflags", "+faststart", str(out)], stdin=subprocess.PIPE)
    for png in frames():
        enc.stdin.write(png)
    enc.stdin.close()
    enc.wait()
else:
    imgs = [Image.open(io.BytesIO(png)).convert("RGB").resize((WIDTH, WIDTH * 540 // 960), Image.LANCZOS) for png in frames()]
    # one shared palette, sampled across the whole clip, keeps the gif small and stops colours flickering between frames
    sample = imgs[::FPS // 2]
    sheet = Image.new("RGB", (WIDTH, sample[0].height * len(sample)))
    for n, f in enumerate(sample):
        sheet.paste(f, (0, n * f.height))
    pal = sheet.quantize(255, method=Image.MEDIANCUT)
    gif = [f.quantize(palette=pal, dither=Image.Dither.NONE) for f in imgs]
    out = HERE.parent / "demo.gif"
    gif[0].save(out, save_all=True, append_images=gif[1:], duration=1000 // FPS, loop=0, optimize=True)
print(out, round(out.stat().st_size / 1e6, 2), "MB")
