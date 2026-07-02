#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
render_report.py - 把带 ANSI 颜色的纯文本终端报告渲染成 PNG 截图

用法:
  python3 tools/render_report.py docs/sample-report.ans docs/sample-report.png

依赖:
  Pillow
"""
import sys
import re
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

# 8 色调色板(亮色版,贴近大多数 Linux 终端)
COLORS = {
    "30": (60, 60, 60),       # black
    "31": (220, 50, 47),      # red
    "32": (133, 153, 0),      # green
    "33": (181, 137, 0),      # yellow
    "34": (38, 139, 210),     # blue
    "35": (211, 54, 130),     # magenta
    "36": (42, 161, 152),     # cyan
    "37": (200, 200, 200),    # white
    "90": (128, 128, 128),    # bright black (gray)
    "91": (255, 85, 85),      # bright red
    "92": (185, 207, 80),     # bright green
    "93": (255, 199, 95),     # bright yellow
    "94": (115, 175, 230),    # bright blue
    "95": (255, 130, 195),    # bright magenta
    "96": (120, 215, 200),    # bright cyan
    "97": (255, 255, 255),    # bright white
}

# 背景色映射(40-47, 100-107)
BG_COLORS = {
    "40": (0, 0, 0), "41": (220, 50, 47), "42": (30, 80, 30), "43": (180, 130, 0),
    "44": (30, 60, 110), "45": (130, 40, 90), "46": (30, 90, 90), "47": (200, 200, 200),
    "100": (60, 60, 60), "101": (180, 50, 50), "102": (50, 110, 50), "103": (180, 130, 0),
    "104": (50, 100, 160), "105": (180, 50, 130), "106": (50, 130, 130), "107": (230, 230, 230),
}

BG_DEFAULT = (24, 24, 28)
FG_DEFAULT = (220, 220, 220)

# ANSI 转义正则
ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m")


class AnsiParser:
    """把带 ANSI 转义的字符串切成 (text, fg, bg, bold) 段"""

    def __init__(self):
        self.fg = FG_DEFAULT
        self.bg = None
        self.bold = False

    def parse(self, text):
        segments = []
        pos = 0
        for m in ANSI_RE.finditer(text):
            start = m.start()
            if start > pos:
                segments.append((text[pos:start], self.fg, self.bg, self.bold))
            pos = m.end()
            params = m.group(1).split(";") if m.group(1) else ["0"]
            self._apply(params)
        if pos < len(text):
            segments.append((text[pos:], self.fg, self.bg, self.bold))
        return segments

    def _apply(self, params):
        for p in params:
            if p in ("0", ""):
                self.fg = FG_DEFAULT
                self.bg = None
                self.bold = False
            elif p in COLORS:
                self.fg = COLORS[p]
            elif p in BG_COLORS:
                self.bg = BG_COLORS[p]
            elif p == "1":
                self.bold = True
            elif p == "22":
                self.bold = False
            elif p == "39":
                self.fg = FG_DEFAULT
            elif p == "49":
                self.bg = None


def measure_line(draw, segments, font):
    """计算一行最大像素宽度"""
    max_w = 0
    cur_w = 0
    for text, _fg, _bg, _bold in segments:
        for ch in text:
            if ch == "\t":
                cur_w += font.getbbox(" ")[2] * 4
            else:
                bbox = font.getbbox(ch)
                cur_w += bbox[2] - bbox[0]
        max_w = max(max_w, cur_w)
    return max_w


def render_text(input_path: str, output_path: str,
                font_path: str = r"C:\Windows\Fonts\simsun.ttc",
                font_size: int = 14, padding: int = 20):
    raw = Path(input_path).read_text(encoding="utf-8")
    raw = raw.replace("\r\n", "\n").rstrip("\n") + "\n"
    lines = raw.split("\n")

    # 加载字体
    try:
        font = ImageFont.truetype(font_path, font_size)
    except OSError:
        # Linux fallback
        for cand in ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
                     "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf"):
            try:
                font = ImageFont.truetype(cand, font_size)
                break
            except OSError:
                continue
        else:
            font = ImageFont.load_default()

    # 预解析每行
    parser = AnsiParser()
    parsed_lines = [parser.parse(line) for line in lines]

    # 计算行高
    line_height = int(font_size * 1.45)
    char_w = font.getbbox("M")[2] - font.getbbox("M")[0]

    # 计算尺寸
    tmp_img = Image.new("RGB", (1, 1))
    tmp_draw = ImageDraw.Draw(tmp_img)
    max_line_w = 0
    for segs in parsed_lines:
        w = measure_line(tmp_draw, segs, font)
        max_line_w = max(max_line_w, w)
    img_w = int(max_line_w + padding * 2)
    img_h = line_height * len(parsed_lines) + padding * 2

    # 绘制
    img = Image.new("RGB", (img_w, img_h), BG_DEFAULT)
    draw = ImageDraw.Draw(img)
    y = padding
    for segs in parsed_lines:
        x = padding
        for text, fg, bg, bold in segs:
            # 处理背景填充(简化:只为非空段填充)
            if bg is not None:
                text_w = sum(font.getbbox(ch)[2] - font.getbbox(ch)[0] if ch != "\t" else font.getbbox(" ")[2] * 4 for ch in text)
                draw.rectangle([x, y, x + text_w, y + line_height], fill=bg)
            for ch in text:
                if ch == "\t":
                    x += char_w * 4
                    continue
                color = fg if not bold else tuple(min(255, c + 40) for c in fg)
                draw.text((x, y), ch, font=font, fill=color)
                bbox = font.getbbox(ch)
                x += bbox[2] - bbox[0]
        y += line_height

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    img.save(output_path, "PNG", optimize=True)
    print(f"✓ 生成: {output_path} ({img_w}x{img_h}, {len(lines)} 行)")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python3 tools/render_report.py <input.ans> <output.png>")
        sys.exit(1)
    render_text(sys.argv[1], sys.argv[2])
