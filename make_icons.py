"""Generate three solid-color PNG icons for the Chrome extension.

Uses only stdlib (struct + zlib + binascii). No Pillow.
Renders a rounded shield shape with a '!' on a dark background.
"""
import os
import struct
import zlib


def png(width: int, height: int, pixels: list) -> bytes:
    """Build a minimal PNG from a list of (R,G,B) tuples row-major."""
    def chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return (struct.pack(">I", len(data)) + tag + data +
                struct.pack(">I", crc))

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)  # 8-bit RGB
    # raw scanlines
    raw = b""
    for y in range(height):
        raw += b"\x00"
        for x in range(width):
            r, g, b = pixels[y * width + x]
            raw += bytes((r, g, b))
    idat = zlib.compress(raw, 9)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def render_shield(size: int) -> list:
    """Make a pixel list: dark blue shield with a white '!' in the center."""
    bg       = (15, 23, 42)       # dark navy
    fg       = (220, 38, 38)      # red accent ring
    txt      = (255, 255, 255)    # white
    shield   = (248, 250, 252)    # very light blue/white
    pixels = [bg] * (size * size)

    cx, cy = size / 2, size / 2
    r_outer = size * 0.46
    r_inner = size * 0.40
    # shield path: rounded top, pointed bottom
    for y in range(size):
        for x in range(size):
            dx = x + 0.5 - cx
            dy = y + 0.5 - cy
            d  = (dx*dx + dy*dy) ** 0.5
            # bottom narrowing
            half_w_at_y = r_outer * (1 if y < cy else max(0.15, 1 - (y - cy) / r_outer * 1.1))
            in_shield = (abs(dx) <= half_w_at_y) and (y <= cy + r_outer * 0.85)
            if in_shield:
                # border
                edge_dist = min(half_w_at_y - abs(dx), (cy + r_outer * 0.85) - y) if y <= cy else min(half_w_at_y - abs(dx), (cy + r_outer * 0.85) - y)
                if edge_dist < max(1, size * 0.04):
                    pixels[y * size + x] = fg
                else:
                    pixels[y * size + x] = shield

    # exclamation mark
    bar_w = max(2, size // 8)
    bar_h = int(size * 0.36)
    bar_x0 = int(cx - bar_w / 2)
    bar_y0 = int(cy - bar_h * 0.6)
    for yy in range(bar_y0, bar_y0 + bar_h):
        for xx in range(bar_x0, bar_x0 + bar_w):
            if 0 <= xx < size and 0 <= yy < size:
                pixels[yy * size + xx] = txt
    # dot
    dot_r = bar_w
    dot_cy = int(cy + size * 0.22)
    for yy in range(dot_cy - dot_r, dot_cy + dot_r):
        for xx in range(bar_x0, bar_x0 + bar_w):
            if 0 <= xx < size and 0 <= yy < size:
                pixels[yy * size + xx] = txt

    return pixels


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(here, "chrome-extension", "icons")
    os.makedirs(out_dir, exist_ok=True)
    for sz in (16, 48, 128):
        pixels = render_shield(sz)
        data = png(sz, sz, pixels)
        path = os.path.join(out_dir, f"icon-{sz}.png")
        with open(path, "wb") as f:
            f.write(data)
        print(f"  wrote {path}  ({len(data)} bytes)")


if __name__ == "__main__":
    main()
