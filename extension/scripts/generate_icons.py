"""
Generates the Phishing Guard extension icon set as real RGBA PNGs with
proper transparency (the previous icons were JPEGs mislabeled .png, with
a baked-in dark background scene and fine glass-effect linework that
turned to mush at 16px - the size it's actually seen at 95% of the time).

Design: a solid-filled shield silhouette with a bold checkmark, on a
transparent background, using the existing brand gradient (purple -> blue
-> cyan) already established in popup.html/content.js. Bold enough to
read clearly at 16px, not just at 128px.

Run: python3 scripts_gen_icons.py
"""

from PIL import Image, ImageDraw


BRAND_STOPS = [
    (0.0, (139, 92, 246)),   # #8b5cf6 violet
    (0.5, (59, 130, 246)),   # #3b82f6 blue
    (1.0, (6, 182, 212)),    # #06b6d4 cyan
]


def lerp(a, b, t):
    return a + (b - a) * t


def gradient_color(t, stops=BRAND_STOPS):
    t = max(0.0, min(1.0, t))
    for (t0, c0), (t1, c1) in zip(stops, stops[1:]):
        if t0 <= t <= t1:
            local_t = (t - t0) / (t1 - t0) if t1 != t0 else 0
            return tuple(int(lerp(c0[i], c1[i], local_t)) for i in range(3))
    return stops[-1][1]


def shield_path(size, margin_ratio=0.06):
    """Shield outline points, scaled to a size x size canvas."""
    m = size * margin_ratio
    w = size - 2 * m
    top = m
    bottom = size - m
    left = m
    right = size - m
    mid_x = size / 2
    # Flat-topped shield with two shoulders tapering to a bottom point.
    return [
        (left, top + w * 0.12),
        (mid_x, top),
        (right, top + w * 0.12),
        (right, top + w * 0.52),
        (mid_x, bottom),
        (left, top + w * 0.52),
    ]


def draw_gradient_shield(size):
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))

    # Build the gradient on a full-size layer (diagonal, top-left to
    # bottom-right), then mask it to the shield silhouette.
    gradient = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    gpix = gradient.load()
    for y in range(size):
        for x in range(size):
            t = (x + y) / (2 * size)
            r, g, b = gradient_color(t)
            gpix[x, y] = (r, g, b, 255)

    mask = Image.new('L', (size, size), 0)
    mdraw = ImageDraw.Draw(mask)
    mdraw.polygon(shield_path(size), fill=255)

    img.paste(gradient, (0, 0), mask)

    # Bold checkmark, solid white, thick enough to survive downscaling.
    draw = ImageDraw.Draw(img)
    stroke = max(2, round(size * 0.11))
    cx, cy = size * 0.5, size * 0.54
    p1 = (cx - size * 0.20, cy)
    p2 = (cx - size * 0.04, cy + size * 0.16)
    p3 = (cx + size * 0.24, cy - size * 0.18)
    draw.line([p1, p2], fill=(255, 255, 255, 255), width=stroke, joint='curve')
    draw.line([p2, p3], fill=(255, 255, 255, 255), width=stroke, joint='curve')
    # Round the joints/caps so the checkmark doesn't look chopped off.
    for pt in (p1, p2, p3):
        r = stroke / 2
        draw.ellipse([pt[0] - r, pt[1] - r, pt[0] + r, pt[1] + r], fill=(255, 255, 255, 255))

    return img


def main():
    sizes = [16, 32, 48, 128]
    for size in sizes:
        # Render at 4x and downsample for clean anti-aliased edges.
        big = draw_gradient_shield(size * 4)
        icon = big.resize((size, size), Image.LANCZOS)
        icon.save(f'icons/icon-{size}.png')
        print(f'Wrote icons/icon-{size}.png ({size}x{size}, RGBA)')


if __name__ == '__main__':
    main()
