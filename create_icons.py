#!/usr/bin/env python3
from PIL import Image, ImageDraw, ImageFont
import os

def create_cve_icon(size, filename):
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    red_dark = (192, 57, 43)
    red_light = (231, 76, 60)
    white = (255, 255, 255)
    
    padding = size * 0.1
    shield_points = [
        (size/2, padding),
        (size - padding, size * 0.25),
        (size - padding, size * 0.5),
        (size/2, size - padding),
        (padding, size * 0.5),
        (padding, size * 0.25),
    ]
    draw.polygon(shield_points, fill=red_light, outline=red_dark)
    
    try:
        font_size = int(size * 0.25)
        font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", font_size)
    except:
        font = ImageFont.load_default()
    
    text = "CVE"
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_x = (size - text_width) / 2
    text_y = size * 0.25
    draw.text((text_x, text_y), text, fill=white, font=font)
    
    circle_y = size * 0.6
    circle_r = size * 0.12
    left = size/2 - circle_r
    top = circle_y - circle_r
    right = size/2 + circle_r
    bottom = circle_y + circle_r
    draw.ellipse([left, top, right, bottom], fill=white)
    
    inner_r = circle_r * 0.5
    draw.ellipse([size/2 - inner_r, circle_y - inner_r, size/2 + inner_r, circle_y + inner_r], fill=red_dark)
    
    img.save(filename, 'PNG')
    print(f"Created {filename}")

os.chdir('/Users/gamblin/Documents/Github/SplunkCVEList/TA-cvelist-v5/static')
create_cve_icon(36, 'appIcon.png')
create_cve_icon(72, 'appIcon_2x.png')
create_cve_icon(48, 'appIconAlt.png')
create_cve_icon(96, 'appIconAlt_2x.png')
print("All icons created!")
