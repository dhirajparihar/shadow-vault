"""
Script to generate an ultra-realistic, high-fidelity Terminal GIF
recording of `python examples/demo_agent_roundtrip.py`.
Output: assets/demo.gif
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from typing import List, Tuple
from PIL import Image, ImageDraw, ImageFont

# Canvas and layout configuration
FONT_PATH = r"C:\Windows\Fonts\CascadiaCode.ttf"
if not os.path.exists(FONT_PATH):
    FONT_PATH = r"C:\Windows\Fonts\consola.ttf"

FONT_SIZE = 15
FONT_TITLE_SIZE = 12

IMG_WIDTH = 900
IMG_HEIGHT = 690

MARGIN_X = 20
MARGIN_Y = 18

WIN_X0 = MARGIN_X
WIN_Y0 = MARGIN_Y
WIN_X1 = IMG_WIDTH - MARGIN_X
WIN_Y1 = IMG_HEIGHT - MARGIN_Y
WIN_RADIUS = 12

HEADER_HEIGHT = 38
PADDING_X = 24
PADDING_Y = 16

CONTENT_X = WIN_X0 + PADDING_X
CONTENT_Y = WIN_Y0 + HEADER_HEIGHT + PADDING_Y
LINE_HEIGHT = 21

MAX_VISIBLE_LINES = 26

# Colors
C_BG = (13, 17, 23)           # #0d1117 (Terminal background)
C_HEADER = (22, 27, 34)       # #161b22 (Title bar)
C_BORDER = (48, 54, 61)       # #30363d (Window border)
C_TITLE = (139, 148, 158)     # #8b949e (Title text)
C_OUTER_BG = (245, 247, 243)  # Match project paper background or neutral dark (0,0,0,0)

# Monokai / Catppuccin ANSI palette
ANSI_COLORS = {
    "0": (201, 209, 217),      # Default text
    "1": (240, 246, 252),      # Bold
    "2": (110, 118, 129),      # Dim
    "1;31": (255, 123, 114),   # Bright Red
    "1;32": (126, 231, 135),   # Bright Green
    "1;33": (242, 204, 96),    # Bright Yellow
    "1;34": (121, 192, 255),   # Bright Blue
    "1;35": (210, 168, 255),   # Bright Magenta
    "1;36": (86, 212, 221),    # Bright Cyan
    "1;37": (255, 255, 255),   # Bright White
}

def parse_ansi_line(raw: str) -> List[Tuple[str, Tuple[int, int, int]]]:
    """Parse a single line containing ANSI escape codes into colored segments."""
    tokens = re.split(r"(\x1b\[[0-9;]*m)", raw)
    current_color = ANSI_COLORS["0"]
    segments: List[Tuple[str, Tuple[int, int, int]]] = []

    for t in tokens:
        if not t:
            continue
        if t.startswith("\x1b[") and t.endswith("m"):
            code = t[2:-1]
            if code in ANSI_COLORS:
                current_color = ANSI_COLORS[code]
            elif code == "" or code == "0":
                current_color = ANSI_COLORS["0"]
        else:
            segments.append((t, current_color))
    return segments

def draw_window_frame(draw: ImageDraw.ImageDraw, title_font: ImageFont.FreeTypeFont) -> None:
    # Outer terminal window background
    draw.rounded_rectangle(
        [WIN_X0, WIN_Y0, WIN_X1, WIN_Y1],
        radius=WIN_RADIUS,
        fill=C_BG,
        outline=C_BORDER,
        width=1,
    )
    # Header bar
    draw.rounded_rectangle(
        [WIN_X0, WIN_Y0, WIN_X1, WIN_Y0 + HEADER_HEIGHT],
        radius=WIN_RADIUS,
        fill=C_HEADER,
        outline=C_BORDER,
        width=1,
    )
    # Fix bottom corners of header
    draw.rectangle(
        [WIN_X0, WIN_Y0 + HEADER_HEIGHT - 6, WIN_X1, WIN_Y0 + HEADER_HEIGHT],
        fill=C_HEADER,
    )
    draw.line(
        [(WIN_X0, WIN_Y0 + HEADER_HEIGHT), (WIN_X1, WIN_Y0 + HEADER_HEIGHT)],
        fill=C_BORDER,
        width=1,
    )

    # Window traffic light buttons
    btn_y = WIN_Y0 + HEADER_HEIGHT // 2
    # Red (Close)
    draw.ellipse([WIN_X0 + 16, btn_y - 6, WIN_X0 + 28, btn_y + 6], fill=(255, 95, 86))
    # Yellow (Minimize)
    draw.ellipse([WIN_X0 + 34, btn_y - 6, WIN_X0 + 46, btn_y + 6], fill=(255, 189, 46))
    # Green (Maximize)
    draw.ellipse([WIN_X0 + 52, btn_y - 6, WIN_X0 + 64, btn_y + 6], fill=(39, 201, 63))

    # Title text
    title_text = "shadow-vault — demo_agent_roundtrip.py"
    t_bbox = draw.textbbox((0, 0), title_text, font=title_font)
    t_w = t_bbox[2] - t_bbox[0]
    title_x = (WIN_X0 + WIN_X1 - t_w) // 2
    title_y = WIN_Y0 + (HEADER_HEIGHT - (t_bbox[3] - t_bbox[1])) // 2 - 1
    draw.text((title_x, title_y), title_text, fill=C_TITLE, font=title_font)

def render_terminal_frame(
    lines: List[List[Tuple[str, Tuple[int, int, int]]]],
    font: ImageFont.FreeTypeFont,
    title_font: ImageFont.FreeTypeFont,
    cursor: bool = False,
) -> Image.Image:
    """Render a single frame of terminal output."""
    # Create canvas with alpha
    img = Image.new("RGBA", (IMG_WIDTH, IMG_HEIGHT), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Soft drop shadow
    for offset, opacity in [(4, 25), (8, 20), (12, 15)]:
        draw.rounded_rectangle(
            [WIN_X0 - 2, WIN_Y0 + offset, WIN_X1 + 2, WIN_Y1 + offset],
            radius=WIN_RADIUS + 2,
            fill=(0, 0, 0, opacity),
        )

    # Window
    draw_window_frame(draw, title_font)

    # Calculate viewport lines (scroll buffer)
    visible_lines = lines[-MAX_VISIBLE_LINES:] if len(lines) > MAX_VISIBLE_LINES else lines

    # Draw lines
    y = CONTENT_Y
    for row_idx, row in enumerate(visible_lines):
        x = CONTENT_X
        for text, color in row:
            draw.text((x, y), text, fill=color, font=font)
            bbox = draw.textbbox((x, y), text, font=font)
            x = bbox[2]
        
        # If this is the last line and cursor is enabled
        if cursor and row_idx == len(visible_lines) - 1:
            draw.text((x, y), "█", fill=(86, 212, 221), font=font)
            
        y += LINE_HEIGHT

    return img

def main():
    print("[*] Generating frames for terminal demo...")
    font = ImageFont.truetype(FONT_PATH, FONT_SIZE)
    title_font = ImageFont.truetype(FONT_PATH, FONT_TITLE_SIZE)

    # Run script and get raw stdout
    proc = subprocess.run(
        [sys.executable, "examples/demo_agent_roundtrip.py"],
        capture_output=True,
        text=True,
    )
    raw_output = proc.stdout
    raw_lines = raw_output.split("\n")

    # Clean empty tail
    while raw_lines and not raw_lines[-1].strip():
        raw_lines.pop()

    parsed_lines = [parse_ansi_line(l) for l in raw_lines]

    frames: List[Image.Image] = []
    durations: List[int] = []

    prompt_prefix = [
        ("user@vault-node", (88, 166, 255)),
        (":", (139, 148, 158)),
        ("~/shadow-vault", (126, 231, 135)),
        ("$ ", (201, 209, 217)),
    ]

    # Frame 0: Initial prompt with blinking cursor
    frames.append(render_terminal_frame([[*prompt_prefix]], font, title_font, cursor=True))
    durations.append(450)
    frames.append(render_terminal_frame([[*prompt_prefix]], font, title_font, cursor=False))
    durations.append(300)

    # Typing the command
    command = "python examples/demo_agent_roundtrip.py"
    type_steps = [
        "py",
        "python ",
        "python examples/",
        "python examples/demo_agent_roundtrip.py",
    ]
    for step in type_steps:
        line = [*prompt_prefix, (step, (240, 246, 252))]
        frames.append(render_terminal_frame([line], font, title_font, cursor=True))
        durations.append(180)

    # Keystroke pause before Enter
    cmd_line = [*prompt_prefix, (command, (240, 246, 252))]
    frames.append(render_terminal_frame([cmd_line], font, title_font, cursor=False))
    durations.append(400)

    # Progressive reveal of output
    current_buffer: List[List[Tuple[str, Tuple[int, int, int]]]] = [cmd_line]

    # Group output by logical milestones
    # Stage indices from stdout:
    # 0..5: Banner
    # 6..20: Stage 1
    # 21..35: Stage 2
    # 36..55: Stage 3
    # 56..62: Stage 4
    # 63: Completion

    milestone_delays = {
        5: 500,   # Banner
        11: 300,  # Stage 1 prompt
        20: 750,  # Stage 1 detected
        26: 300,  # Stage 2 prompt
        35: 800,  # Stage 2 mappings
        41: 300,  # Stage 3 tool call
        50: 300,  # Stage 3 tool return
        55: 800,  # Stage 3 sanitized
        59: 400,  # Stage 4 incoming
        62: 1000, # Stage 4 streamed output
        len(parsed_lines) - 1: 4500, # Final complete hold
    }

    # Simulate line-by-line output
    for i, line in enumerate(parsed_lines):
        current_buffer.append(line)
        
        # Check if this line is a key milestone or batch lines for smoothness
        if i in milestone_delays:
            f = render_terminal_frame(current_buffer, font, title_font, cursor=False)
            frames.append(f)
            durations.append(milestone_delays[i])
        elif i % 3 == 0 or "STAGE" in raw_lines[i] or "[OK]" in raw_lines[i]:
            f = render_terminal_frame(current_buffer, font, title_font, cursor=False)
            frames.append(f)
            durations.append(140)

    # Final prompt line after completion
    final_buffer = list(current_buffer)
    final_buffer.append([*prompt_prefix])
    frames.append(render_terminal_frame(final_buffer, font, title_font, cursor=True))
    durations.append(4500)

    print(f"[*] Total frames: {len(frames)}")
    print("[*] Encoding animated GIF...")

    # Quantize and save GIF
    out_path = "assets/demo.gif"
    
    # Convert frames to RGB with background compositing for clean GIF edges
    bg_comp = Image.new("RGB", (IMG_WIDTH, IMG_HEIGHT), (245, 247, 243))
    rgb_frames = []
    for f in frames:
        c = bg_comp.copy()
        c.paste(f, (0, 0), f)
        # Quantize to adaptive 128 colors palette
        p_frame = c.quantize(colors=128, method=Image.Quantize.MEDIANCUT)
        rgb_frames.append(p_frame)

    rgb_frames[0].save(
        out_path,
        save_all=True,
        append_images=rgb_frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )

    size_kb = os.path.getsize(out_path) / 1024
    print(f"[OK] Generated {out_path} ({size_kb:.1f} KB)")

if __name__ == "__main__":
    main()
