#!/usr/bin/env python3
"""Rebuilds the Gujarati and Devanagari font files from the text on the pages.

Run it after changing any Gujarati or Hindi text, or a new letter combination
may draw in the wrong shape:

    python3 -m venv /tmp/fontenv && /tmp/fontenv/bin/pip install fonttools brotli uharfbuzz
    /tmp/fontenv/bin/python scripts/subset-fonts.py

Each file keeps only the glyphs HarfBuzz uses, at any step, to draw the pages'
words, so it is a few KB instead of hundreds. The script then checks that every
word shapes the same with the subset as with the full font, and fails if not.

  baloo-bhai-2-gujarati.woff2       Gujarati on the English and Hindi pages
  baloo-bhai-2-gujarati-text.woff2  the Gujarati pages
  baloo-2-devanagari-mini.woff2     Devanagari on the English and Gujarati pages
  baloo-2-devanagari-text.woff2     the Hindi pages

join.html uses system fonts and is skipped. Sources are the variable fonts from
github.com/google/fonts (SIL Open Font License), downloaded on first run.
"""
import glob
import html
import io
import os
import re
import subprocess
import sys
import urllib.request

import uharfbuzz as hb
from fontTools.ttLib import TTFont

SITE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(os.path.expanduser('~'), '.cache', 'kodi-site-fonts')
SOURCES = {
    'BalooBhai2.ttf': 'https://github.com/google/fonts/raw/main/ofl/baloobhai2/BalooBhai2%5Bwght%5D.ttf',
    'Baloo2.ttf': 'https://github.com/google/fonts/raw/main/ofl/baloo2/Baloo2%5Bwght%5D.ttf',
}
GUJARATI = (0x0A80, 0x0AFF)
DEVANAGARI = (0x0900, 0x097F)
WEIGHTS = (500, 600, 700, 800)


def source(name):
    os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, name)
    if not os.path.exists(path):
        urllib.request.urlretrieve(SOURCES[name], path)
    return path


def words(files, script):
    """Each run of the script's letters (with dandas and joiners) in the files."""
    lo, hi = script
    pattern = re.compile(f'[\\u{lo:04x}-\\u{hi:04x}\\u0964\\u0965\\u200c\\u200d]+')
    found = set()
    for f in files:
        found.update(pattern.findall(html.unescape(open(f, encoding='utf-8').read())))
    return {w for w in found if w.strip('‌‍')}


def shaping_font(data, weight):
    font = hb.Font(hb.Face(hb.Blob(data)))
    font.set_variations({'wght': weight})
    return font


def shape(font, word, on_step=None):
    buf = hb.Buffer()
    buf.add_str(word)
    buf.guess_segment_properties()
    if on_step:
        buf.set_message_func(lambda message: on_step(message, buf) or True)
    hb.shape(font, buf, {})
    return buf


def glyphs_used(data, word_list):
    """Glyph ids seen at any lookup step: conjuncts form through half forms."""
    used = {0}
    def record(message, buf):
        if message.startswith(('start lookup', 'end lookup')):
            used.update(info.codepoint for info in buf.glyph_infos)
    for weight in WEIGHTS:
        font = shaping_font(data, weight)
        for w in word_list:
            buf = shape(font, w, record)
            used.update(info.codepoint for info in buf.glyph_infos)
    return used


def as_ttf(path):
    font = TTFont(path)
    font.flavor = None
    out = io.BytesIO()
    font.save(out)
    return out.getvalue()


def layout(font, word):
    buf = shape(font, word)
    return [(p.x_advance, p.x_offset, p.y_offset) for p in buf.glyph_positions]


def main():
    pages = [p for p in glob.glob(f'{SITE}/**/*.html', recursive=True)
             if not p.endswith('/join.html')]
    gu_pages = [p for p in pages if '/gu/' in p]
    hi_pages = [p for p in pages if '/hi/' in p]
    jobs = [
        ('baloo-bhai-2-gujarati.woff2', 'BalooBhai2.ttf',
         words([p for p in pages if p not in gu_pages], GUJARATI)),
        ('baloo-bhai-2-gujarati-text.woff2', 'BalooBhai2.ttf', words(gu_pages, GUJARATI)),
        ('baloo-2-devanagari-mini.woff2', 'Baloo2.ttf',
         words([p for p in pages if p not in hi_pages], DEVANAGARI)),
        ('baloo-2-devanagari-text.woff2', 'Baloo2.ttf', words(hi_pages, DEVANAGARI)),
    ]
    failed = False
    for name, src, word_list in jobs:
        full_path = source(src)
        full = open(full_path, 'rb').read()
        gids = glyphs_used(full, word_list)
        text = ''.join(sorted(set(''.join(word_list)))) + '◌'
        out = os.path.join(SITE, 'assets', 'fonts', name)
        subprocess.run([sys.executable, '-m', 'fontTools.subset', full_path,
                        f'--text={text}', '--gids=' + ','.join(map(str, sorted(gids))),
                        '--no-layout-closure', '--flavor=woff2', '--no-hinting',
                        '--desubroutinize', f'--output-file={out}'], check=True)
        sub = as_ttf(out)
        wrong = []
        for weight in (500, 700, 800):
            a, b = shaping_font(full, weight), shaping_font(sub, weight)
            wrong += [w for w in word_list if layout(a, w) != layout(b, w)]
        status = 'ok' if not wrong else f'{len(wrong)} words differ, e.g. {sorted(set(wrong))[:5]}'
        failed |= bool(wrong)
        print(f'{name:34s} {len(word_list):4d} words  {len(gids):4d} glyphs  '
              f'{os.path.getsize(out) / 1024:5.1f} KB  {status}')
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
