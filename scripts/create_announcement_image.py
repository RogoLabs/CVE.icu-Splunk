#!/usr/bin/env python3
"""Create a social media announcement image for the cve.icu v2.0 launch.

Composites four dashboard screenshots into a polished 1200x1200 image
with dark infosec aesthetic, branding, and feature highlights.

Usage:
    python3 scripts/create_announcement_image.py
    python3 scripts/create_announcement_image.py --output /tmp/announcement.png
"""

import argparse
import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont, ImageFilter
except ImportError:
    import subprocess

    subprocess.check_call([sys.executable, "-m", "pip", "install", "Pillow"])
    from PIL import Image, ImageDraw, ImageFont, ImageFilter

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_DIR = SCRIPT_DIR.parent
SCREENSHOTS_DIR = REPO_DIR / "docs" / "screenshots"
ICON_PATH = REPO_DIR / "TA-cveicu" / "static" / "appIcon_2x.png"

BG_COLOR = (13, 17, 23)
ACCENT_GREEN = (101, 166, 55)
ACCENT_PURPLE = (123, 86, 219)
TEXT_WHITE = (255, 255, 255)
TEXT_MUTED = (139, 148, 158)
TEXT_DIM = (72, 79, 88)
BORDER_COLOR = (48, 54, 61)
PILL_BG = (28, 33, 40)

CANVAS_SIZE = 1200
PADDING = 44
GRID_GAP = 14
CORNER_RADIUS = 10

SCREENSHOTS = [
    "vulnerability-landscape.png",
    "risk-priority.png",
    "cve-explorer.png",
    "operational-health.png",
]


def find_font(bold=False, size=48):
    paths_bold = [
        "/System/Library/Fonts/SFNS.ttf",
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
    ]
    paths_regular = [
        "/System/Library/Fonts/SFNS.ttf",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
    ]
    for p in paths_bold if bold else paths_regular:
        if Path(p).exists():
            try:
                return ImageFont.truetype(p, size)
            except Exception:
                continue
    return ImageFont.load_default(size=size)


def round_corners(img, radius):
    mask = Image.new("L", img.size, 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle([(0, 0), img.size], radius=radius, fill=255)
    result = img.copy()
    result.putalpha(mask)
    return result


def add_border(img, color, width=1):
    bordered = img.copy()
    draw = ImageDraw.Draw(bordered)
    w, h = bordered.size
    draw.rounded_rectangle(
        [(0, 0), (w - 1, h - 1)],
        radius=CORNER_RADIUS,
        outline=color,
        width=width,
    )
    return bordered


def add_shadow(img, offset=4, blur_radius=12, opacity=100):
    shadow_size = (img.width + blur_radius * 2, img.height + blur_radius * 2)
    shadow = Image.new("RGBA", shadow_size, (0, 0, 0, 0))
    shadow_inner = Image.new("RGBA", img.size, (0, 0, 0, opacity))
    if img.mode == "RGBA":
        shadow_inner.putalpha(img.split()[3])
    shadow.paste(shadow_inner, (blur_radius + offset, blur_radius + offset))
    shadow = shadow.filter(ImageFilter.GaussianBlur(blur_radius))
    result = Image.new("RGBA", shadow_size, (0, 0, 0, 0))
    result = Image.alpha_composite(result, shadow)
    result.paste(img, (blur_radius, blur_radius), img if img.mode == "RGBA" else None)
    return result, blur_radius


def draw_gradient_line(draw, x, y, width, height):
    for i in range(width):
        t = i / width
        if t < 0.5:
            t2 = t * 2
            r = int(ACCENT_GREEN[0] + (ACCENT_PURPLE[0] - ACCENT_GREEN[0]) * t2)
            g = int(ACCENT_GREEN[1] + (ACCENT_PURPLE[1] - ACCENT_GREEN[1]) * t2)
            b = int(ACCENT_GREEN[2] + (ACCENT_PURPLE[2] - ACCENT_GREEN[2]) * t2)
        else:
            t2 = (t - 0.5) * 2
            r = int(ACCENT_PURPLE[0] + (ACCENT_GREEN[0] - ACCENT_PURPLE[0]) * t2)
            g = int(ACCENT_PURPLE[1] + (ACCENT_GREEN[1] - ACCENT_PURPLE[1]) * t2)
            b = int(ACCENT_PURPLE[2] + (ACCENT_GREEN[2] - ACCENT_PURPLE[2]) * t2)
        draw.line([(x + i, y), (x + i, y + height - 1)], fill=(r, g, b))


def create_pill(text, font):
    bbox = font.getbbox(text)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]
    pill_w = text_w + 32
    pill_h = text_h + 18
    pill = Image.new("RGBA", (pill_w, pill_h), (0, 0, 0, 0))
    d = ImageDraw.Draw(pill)
    d.rounded_rectangle(
        [(0, 0), (pill_w - 1, pill_h - 1)],
        radius=pill_h // 2,
        fill=PILL_BG + (255,),
        outline=BORDER_COLOR + (255,),
        width=1,
    )
    d.text(
        (16, (pill_h - text_h) // 2 - bbox[1]),
        text,
        fill=(201, 209, 217, 255),
        font=font,
    )
    return pill


def main():
    parser = argparse.ArgumentParser(
        description="Create cve.icu v2.0 announcement image"
    )
    parser.add_argument("--output", type=str, default=None)
    parser.add_argument("--screenshots-dir", type=str, default=None)
    args = parser.parse_args()

    screenshots_dir = (
        Path(args.screenshots_dir) if args.screenshots_dir else SCREENSHOTS_DIR
    )
    output_path = (
        Path(args.output) if args.output else screenshots_dir / "announcement.png"
    )

    for name in SCREENSHOTS:
        if not (screenshots_dir / name).exists():
            print(f"ERROR: Missing screenshot: {screenshots_dir / name}")
            sys.exit(1)

    canvas = Image.new("RGBA", (CANVAS_SIZE, CANVAS_SIZE), BG_COLOR + (255,))
    draw = ImageDraw.Draw(canvas)

    # -- Header --
    brand_font = find_font(bold=True, size=52)
    tagline_font = find_font(bold=False, size=26)
    version_font = find_font(bold=True, size=26)

    y_cursor = 36

    icon = Image.open(ICON_PATH).convert("RGBA")
    icon = icon.resize((64, 64), Image.LANCZOS)
    icon = round_corners(icon, 14)

    brand_text = "cve.icu"
    brand_bbox = brand_font.getbbox(brand_text)
    brand_w = brand_bbox[2] - brand_bbox[0]
    brand_h = brand_bbox[3] - brand_bbox[1]

    total_header_w = 64 + 16 + brand_w
    header_x = (CANVAS_SIZE - total_header_w) // 2

    canvas.paste(icon, (header_x, y_cursor), icon)
    draw.text(
        (header_x + 64 + 16, y_cursor + (64 - brand_h) // 2 - brand_bbox[1]),
        brand_text,
        fill=TEXT_WHITE,
        font=brand_font,
    )

    y_cursor += 64 + 14

    tagline = "CVE Intelligence for Splunk"
    tag_bbox = tagline_font.getbbox(tagline)
    tag_w = tag_bbox[2] - tag_bbox[0]

    version = "  v2.0"
    ver_bbox = version_font.getbbox(version)
    ver_w = ver_bbox[2] - ver_bbox[0]

    combined_w = tag_w + ver_w
    tag_x = (CANVAS_SIZE - combined_w) // 2

    draw.text(
        (tag_x, y_cursor - tag_bbox[1]),
        tagline,
        fill=TEXT_MUTED,
        font=tagline_font,
    )
    draw.text(
        (tag_x + tag_w, y_cursor - ver_bbox[1]),
        version,
        fill=ACCENT_GREEN,
        font=version_font,
    )

    y_cursor += 36 + 12

    # -- Gradient accent line --
    line_x = PADDING
    line_w = CANVAS_SIZE - 2 * PADDING
    draw_gradient_line(draw, line_x, y_cursor, line_w, 3)
    y_cursor += 3 + 20

    # -- Screenshot grid --
    grid_w = CANVAS_SIZE - 2 * PADDING
    cell_w = (grid_w - GRID_GAP) // 2
    cell_h = int(cell_w * 900 / 1440)

    screenshots = []
    for name in SCREENSHOTS:
        img = Image.open(screenshots_dir / name).convert("RGBA")
        img = img.resize((cell_w, cell_h), Image.LANCZOS)
        img = round_corners(img, CORNER_RADIUS)
        img = add_border(img, BORDER_COLOR + (255,))
        img_with_shadow, shadow_pad = add_shadow(
            img, offset=3, blur_radius=10, opacity=80
        )
        screenshots.append((img_with_shadow, shadow_pad))

    positions = [
        (PADDING, y_cursor),
        (PADDING + cell_w + GRID_GAP, y_cursor),
        (PADDING, y_cursor + cell_h + GRID_GAP),
        (PADDING + cell_w + GRID_GAP, y_cursor + cell_h + GRID_GAP),
    ]

    for (img, pad), (px, py) in zip(screenshots, positions):
        canvas.paste(img, (px - pad, py - pad), img)

    y_cursor += 2 * cell_h + GRID_GAP + 28

    # -- Feature pills --
    pill_font = find_font(bold=False, size=18)
    pills_text = ["327K+ CVEs", "EPSS + KEV + SSVC", "Free & Open Source"]
    pills = [create_pill(t, pill_font) for t in pills_text]

    total_pills_w = sum(p.width for p in pills) + 16 * (len(pills) - 1)
    pill_x = (CANVAS_SIZE - total_pills_w) // 2

    for pill in pills:
        canvas.paste(pill, (pill_x, y_cursor), pill)
        pill_x += pill.width + 16

    y_cursor += pills[0].height + 18

    # -- Splunkbase URL --
    url_font = find_font(bold=False, size=17)
    url_text = "Available on Splunkbase  |  cve.icu"
    url_bbox = url_font.getbbox(url_text)
    url_w = url_bbox[2] - url_bbox[0]
    draw.text(
        ((CANVAS_SIZE - url_w) // 2, y_cursor - url_bbox[1]),
        url_text,
        fill=TEXT_DIM,
        font=url_font,
    )

    # -- Crop to content height --
    url_h = url_bbox[3] - url_bbox[1]
    y_cursor += url_h + 30
    canvas = canvas.crop((0, 0, CANVAS_SIZE, y_cursor))

    # -- Save --
    final = canvas.convert("RGB")
    final.save(output_path, "PNG", optimize=True)
    size_kb = output_path.stat().st_size / 1024
    print(f"Saved: {output_path} ({size_kb:.0f} KB)")


if __name__ == "__main__":
    main()
