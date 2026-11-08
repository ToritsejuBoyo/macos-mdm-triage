#!/usr/bin/env python3
"""
generate-demo-media.py - Generates terminal demo GIF and HD MP4 for macos-mdm-triage.
Uses PIL to render high-contrast terminal playback frames and ffmpeg to compile MP4.
Zero third-party runtime dependencies for skill execution.
Complies with Rule 7, Rule 10, and Rule 12.
"""

import os
import subprocess
import sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT_DIR = Path(__file__).resolve().parent.parent
ASSETS_DIR = ROOT_DIR / "assets"
ASSETS_DIR.mkdir(parents=True, exist_ok=True)

WIDTH, HEIGHT = 1100, 680
BG_COLOR = (15, 23, 42)        # Slate 900
PANEL_COLOR = (30, 41, 59)     # Slate 800
BORDER_COLOR = (51, 65, 85)    # Slate 700
TEXT_MAIN = (241, 245, 249)    # Slate 100
TEXT_MUTED = (148, 163, 184)   # Slate 400
ACCENT_CYAN = (6, 182, 212)    # Cyan 500
ACCENT_GREEN = (34, 197, 94)   # Green 500
ACCENT_RED = (239, 68, 68)     # Red 500
ACCENT_YELLOW = (234, 179, 8)  # Yellow 500


def get_font(size=14, bold=False):
    font_names = [
        "consola.ttf" if not bold else "consolab.ttf",
        "arial.ttf" if not bold else "arialbd.ttf",
        "DejaVuSansMono.ttf"
    ]
    for fn in font_names:
        try:
            return ImageFont.truetype(fn, size)
        except Exception:
            continue
    return ImageFont.load_default()


def render_terminal_frame(lines, title="macOS MDM & Jamf Diagnostic Console - zsh"):
    im = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
    draw = ImageDraw.Draw(im)

    # Outer border
    draw.rectangle([(10, 10), (WIDTH - 10, HEIGHT - 10)], outline=BORDER_COLOR, width=1)

    # Titlebar
    draw.rectangle([(10, 10), (WIDTH - 10, 45)], fill=PANEL_COLOR)
    draw.line([(10, 45), (WIDTH - 10, 45)], fill=BORDER_COLOR, width=1)

    # Traffic light window buttons
    draw.ellipse([(25, 22), (37, 34)], fill=(239, 68, 68))
    draw.ellipse([(45, 22), (57, 34)], fill=(234, 179, 8))
    draw.ellipse([(65, 22), (77, 34)], fill=(34, 197, 94))

    # Title text
    font_title = get_font(13, bold=True)
    draw.text((WIDTH // 2 - 140, 20), title, font=font_title, fill=TEXT_MUTED)

    # Terminal body
    y = 65
    font_code = get_font(14, bold=False)
    font_bold = get_font(14, bold=True)

    for line, color, is_bold in lines:
        f = font_bold if is_bold else font_code
        draw.text((30, y), line, font=f, fill=color)
        y += 22

    return im


def generate_demo():
    print("Generating demo frames for macos-mdm-triage...")

    script_lines = [
        ("% python3 scripts/triage_macos_mdm.py -i tests/fixtures/fixture-pkg-postinstall-script-error.json --sanitize", ACCENT_CYAN, True),
        ("================================================================================", TEXT_MUTED, False),
        ("macOS MDM & JAMF PROFILE DIAGNOSTIC REPORT", ACCENT_CYAN, True),
        ("================================================================================", TEXT_MUTED, False),
        ("Target Mac Hostname : mac-a1b2c3d4.corp.example.com", TEXT_MAIN, False),
        ("Hardware Serial     : C02G9988XXXX", TEXT_MAIN, False),
        ("Operating System    : macOS Sequoia 15.0.1 (arm64)", TEXT_MAIN, False),
        ("--------------------------------------------------------------------------------", TEXT_MUTED, False),
        ("TRIAGE RESULT   : [FAIL] DOMAIN 3 - APPLE PACKAGEKIT (.PKG) & INSTALLER ENGINE", ACCENT_RED, True),
        ("PRIORITY        : P2 - High", ACCENT_YELLOW, True),
        ("ROOT CAUSE      : Apple PackageKit installation failed: postinstall script exited with status 1.", TEXT_MAIN, False),
        ("--------------------------------------------------------------------------------", TEXT_MUTED, False),
        ("TECHNICAL TELEMETRY EVIDENCE:", ACCENT_CYAN, True),
        ("  * PackageKit: Executing script './postinstall' in /private/tmp/PKInstallSandbox.001", TEXT_MUTED, False),
        ("  * ./postinstall: line 42: /usr/local/bin/custom_agent: No such file or directory", ACCENT_RED, False),
        ("  * PackageKit: postinstall exited with status 1", ACCENT_RED, False),
        ("  * PackageKit: Install Failed: Error Domain=PKInstallErrorDomain Code=112", ACCENT_RED, True),
        ("--------------------------------------------------------------------------------", TEXT_MUTED, False),
        ("USER SELF-SERVICE RESOLUTION STEPS:", ACCENT_CYAN, True),
        ("  1. Restart the Mac and re-attempt installation from Jamf Self Service.", TEXT_MAIN, False),
        ("--------------------------------------------------------------------------------", TEXT_MUTED, False),
        ("TIER 2 / MAC ADMIN REMEDIATION PLAYBOOK:", ACCENT_CYAN, True),
        ("  * Extract .pkg payload with 'pkgutil --expand' and inspect Scripts/postinstall.", ACCENT_GREEN, False),
        ("  * Verify postinstall script does not require interactive GUI prompts.", ACCENT_GREEN, False),
        ("  * Ensure interpreter path (#!/bin/zsh) exists on modern macOS versions.", ACCENT_GREEN, False),
        ("================================================================================", TEXT_MUTED, False),
        ("% echo 'ITSM ticket and Markdown report generated in 0.04s' [Exit 0]", ACCENT_GREEN, True),
    ]

    frames = []

    # Progressive typing / command execution
    for i in range(1, len(script_lines) + 1):
        visible = script_lines[:i]
        im = render_terminal_frame(visible)
        # Duplicate last frame for reading pause
        repeat = 20 if i == len(script_lines) else (4 if i in (1, 8, 12, 17) else 2)
        for _ in range(repeat):
            frames.append(im)

    gif_path = ASSETS_DIR / "demo.gif"
    frames[0].save(
        gif_path,
        save_all=True,
        append_images=frames[1:],
        duration=120,
        loop=0,
        optimize=True
    )
    print(f"Generated demo GIF: {gif_path} ({os.path.getsize(gif_path):,} bytes)")

    # Render MP4 via ffmpeg
    mp4_path = ASSETS_DIR / "demo.mp4"
    temp_dir = ASSETS_DIR / "temp_frames"
    temp_dir.mkdir(exist_ok=True)

    try:
        for idx, frame in enumerate(frames):
            frame.save(temp_dir / f"frame_{idx:04d}.png")

        cmd = [
            "ffmpeg", "-y",
            "-framerate", "10",
            "-i", str(temp_dir / "frame_%04d.png"),
            "-c:v", "libx264",
            "-pix_fmt", "yuv420p",
            "-crf", "22",
            str(mp4_path)
        ]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        print(f"Generated demo MP4: {mp4_path} ({os.path.getsize(mp4_path):,} bytes)")
    except Exception as exc:
        print(f"Notice: ffmpeg generation note: {exc}")
    finally:
        for p in temp_dir.glob("*.png"):
            p.unlink()
        temp_dir.rmdir()


if __name__ == "__main__":
    generate_demo()
