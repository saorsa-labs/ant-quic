#!/usr/bin/env python3
"""
Background Example - DO NOT COPY, create your own design.

Learn: HTML/CSS techniques (radial-gradient, positioning, transparency), Playwright workflow.
Do NOT copy: colors, layout, this specific aesthetic.

Design Directions (pick one, then create original):

  Universal:
    Swiss Grid / Minimalist / Double Border / Clean Whitespace
    Soft Blocks / Gradient Ribbons / Frosted Glass / Subtle Grid
    Watercolor Wash / Ink Wash / Line Art / Grain Texture

  Expressive (match scenario well = stunning; mismatch = distracting):
    Bauhaus Geometric / Memphis / Art Deco / Monochrome Bold

Technical: 794x1123px, device_scale_factor=2, center clear for text, low saturation.

Color Schemes: Import from color_schemes.py (synced with ColorSchemes.cs)
"""
from playwright.sync_api import sync_playwright
import os
import sys

from color_schemes import SCHEMES, hex_to_css

# Default scheme, can be overridden via command line
SCHEME_NAME = sys.argv[2] if len(sys.argv) > 2 else 'Morandi'
OUTPUT_DIR = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))

PAGE_W = 794
PAGE_H = 1123

# Get color scheme
scheme = SCHEMES.get(SCHEME_NAME, SCHEMES['Morandi'])

# Map scheme colors to CSS variables (new nested structure)
C = {
    'primary': hex_to_css(scheme['Decorative']['Muted']['Primary']),
    'secondary': hex_to_css(scheme['Decorative']['Muted']['Secondary']),
    'accent': hex_to_css(scheme['Decorative']['Muted']['Accent']),
    'dark': hex_to_css(scheme['Text']['Primary']),
    'mid': hex_to_css(scheme['Text']['Body']),
    'light': hex_to_css(scheme['Text']['Muted']),
    'border': hex_to_css(scheme['UI']['Border']),
    'bg': hex_to_css(scheme['UI']['TableHeader']),
}

# ============================================================================
# Cover - Color block gradient, no frames
# ============================================================================
COVER_BG_HTML = f'''
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}

body {{
    width: {PAGE_W}px;
    height: {PAGE_H}px;
    background: linear-gradient(160deg, {C['bg']} 0%, {C['border']} 100%);
    position: relative;
    overflow: hidden;
}}

/* Top-right large blob */
.blob-1 {{
    position: absolute;
    top: -120px;
    right: -150px;
    width: 550px;
    height: 550px;
    background: radial-gradient(ellipse at center,
        {C['primary']}50 0%,
        {C['primary']}25 40%,
        transparent 70%
    );
    border-radius: 50%;
}}

/* Bottom-left blob */
.blob-2 {{
    position: absolute;
    bottom: -150px;
    left: -120px;
    width: 600px;
    height: 600px;
    background: radial-gradient(ellipse at center,
        {C['secondary']}40 0%,
        {C['secondary']}18 45%,
        transparent 70%
    );
    border-radius: 50%;
}}

/* Center-right blob */
.blob-3 {{
    position: absolute;
    top: 35%;
    right: 5%;
    width: 350px;
    height: 350px;
    background: radial-gradient(ellipse at center,
        {C['accent']}35 0%,
        transparent 60%
    );
    border-radius: 50%;
}}

/* Top accent bar */
.accent-bar {{
    position: absolute;
    top: 60px;
    left: 60px;
    width: 140px;
    height: 6px;
    background: linear-gradient(90deg, {C['primary']}, {C['accent']});
    border-radius: 3px;
}}

/* Bottom-right corner accent */
.corner-accent {{
    position: absolute;
    bottom: 50px;
    right: 50px;
    width: 90px;
    height: 90px;
    border: 2.5px solid {C['primary']}40;
    border-radius: 50%;
}}

.corner-accent::after {{
    content: '';
    position: absolute;
    top: 18px;
    left: 18px;
    width: 54px;
    height: 54px;
    background: {C['primary']}20;
    border-radius: 50%;
}}
</style>
</head>
<body>
    <div class="blob-1"></div>
    <div class="blob-2"></div>
    <div class="blob-3"></div>
    <div class="accent-bar"></div>
    <div class="corner-accent"></div>
</body>
</html>
'''

# ============================================================================
# Back Cover - Echo cover, mirrored positioning
# ============================================================================
BACKCOVER_BG_HTML = f'''
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}

body {{
    width: {PAGE_W}px;
    height: {PAGE_H}px;
    background: linear-gradient(200deg, {C['bg']} 0%, {C['border']} 100%);
    position: relative;
    overflow: hidden;
}}

/* Bottom-left blob - echo cover top-right */
.blob-1 {{
    position: absolute;
    bottom: -120px;
    left: -150px;
    width: 500px;
    height: 500px;
    background: radial-gradient(ellipse at center,
        {C['primary']}45 0%,
        {C['primary']}20 40%,
        transparent 70%
    );
    border-radius: 50%;
}}

/* Top-right blob - echo cover bottom-left */
.blob-2 {{
    position: absolute;
    top: -100px;
    right: -80px;
    width: 400px;
    height: 400px;
    background: radial-gradient(ellipse at center,
        {C['secondary']}35 0%,
        transparent 65%
    );
    border-radius: 50%;
}}

/* Top accent */
.top-accent {{
    position: absolute;
    top: 60px;
    right: 60px;
    width: 120px;
    height: 5px;
    background: linear-gradient(90deg, {C['accent']}, {C['primary']});
    border-radius: 2px;
}}

/* Bottom-left corner accent */
.corner-accent {{
    position: absolute;
    bottom: 50px;
    left: 50px;
    width: 70px;
    height: 70px;
    border: 2px solid {C['primary']}35;
    border-radius: 50%;
}}
</style>
</head>
<body>
    <div class="blob-1"></div>
    <div class="blob-2"></div>
    <div class="top-accent"></div>
    <div class="corner-accent"></div>
</body>
</html>
'''

# ============================================================================
# Body - More noticeable decoration, but doesn't interfere with reading
# ============================================================================
BODY_BG_HTML = f'''
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}

body {{
    width: {PAGE_W}px;
    height: {PAGE_H}px;
    background: #FDFEFE;
    position: relative;
    overflow: hidden;
}}

/* Top gradient band - more noticeable */
.top-gradient {{
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 120px;
    background: linear-gradient(180deg,
        {C['primary']}12 0%,
        {C['primary']}04 60%,
        transparent 100%
    );
}}

/* Left side bar - thicker and longer */
.side-bar {{
    position: absolute;
    top: 0;
    left: 0;
    width: 5px;
    height: 100%;
    background: linear-gradient(180deg,
        {C['primary']}30 0%,
        {C['primary']}15 30%,
        {C['primary']}08 60%,
        transparent 100%
    );
}}

/* Bottom-right subtle decoration */
.corner-blob {{
    position: absolute;
    bottom: -80px;
    right: -80px;
    width: 200px;
    height: 200px;
    background: radial-gradient(ellipse at center,
        {C['secondary']}08 0%,
        transparent 70%
    );
    border-radius: 50%;
}}
</style>
</head>
<body>
    <div class="top-gradient"></div>
    <div class="side-bar"></div>
    <div class="corner-blob"></div>
</body>
</html>
'''


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"Using color scheme: {SCHEME_NAME}")

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(
            viewport={'width': PAGE_W, 'height': PAGE_H},
            device_scale_factor=2
        )

        page.set_content(COVER_BG_HTML)
        page.screenshot(path=os.path.join(OUTPUT_DIR, 'cover_bg.png'), type='png')
        print("cover_bg.png")

        page.set_content(BACKCOVER_BG_HTML)
        page.screenshot(path=os.path.join(OUTPUT_DIR, 'backcover_bg.png'), type='png')
        print("backcover_bg.png")

        page.set_content(BODY_BG_HTML)
        page.screenshot(path=os.path.join(OUTPUT_DIR, 'body_bg.png'), type='png')
        print("body_bg.png")

        browser.close()
    print(f"Done - {SCHEME_NAME}")


if __name__ == '__main__':
    main()
