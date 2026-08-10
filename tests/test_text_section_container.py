"""A text section's container obeys the toolbar, and can hug its own text.

    venv/bin/python tests/test_text_section_container.py

Setting a max width used to add `margin-left:auto; margin-right:auto`, which
centred the whole container regardless of what the text toolbar said — so
narrowing a left-aligned block silently moved it to the middle of the page.
The auto margins are gone; where a narrowed box sits now follows the text's own
alignment. Measured in a browser, 400px box inside a 900px section:

    left-aligned text    gap 0 / 500
    centred text         gap 250 / 250
    right-aligned text   gap 500 / 0

There is also a "fit the text" width, for a background that hugs its contents
with the padding still applied.

The layout half needs a real browser; those checks skip when Chrome isn't on
PATH. The rest reads the shipped template and CSS so it cannot drift.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-text-container')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-textbox-test-')
shutil.copy2(os.path.join(_REPO, 'main.py'), os.path.join(_SCRATCH, 'main.py'))
for _linked in ('Templates', 'icons', 'static'):
    _src = os.path.join(_REPO, _linked)
    if os.path.exists(_src):
        os.symlink(_src, os.path.join(_SCRATCH, _linked))

sys.path.insert(0, _SCRATCH)
import main  # noqa: E402

assert os.path.dirname(os.path.abspath(main.__file__)) == _SCRATCH, \
    'refusing to run against the real checkout'

app, db = main.app, main.db
FAILURES = []
SKIPPED = []


def check(label, cond):
    print(('  PASS  ' if cond else '  FAIL  ') + label)
    if not cond:
        FAILURES.append(label)


def skip(label, why):
    print(f'  SKIP  {label} — {why}')
    SKIPPED.append(label)


def _tpl(name):
    return open(os.path.join(_REPO, 'Templates', name)).read()


def test_saved():
    print('\n[1] the width choice is stored with the section')
    with app.app_context():
        sec = main.PageSection(section_type='text', content={})
        main.update_text_section(sec, {
            'text': '<p>Hi</p>', 'container_width': 'fit', 'text_max_width': '400'})
        check(f"'fit' round-trips ({sec.content.get('container_width')})",
              sec.content.get('container_width') == 'fit')
        sec2 = main.PageSection(section_type='text', content={})
        main.update_text_section(sec2, {'text': '<p>Hi</p>'})
        check(f"the default is the full-width box ({sec2.content.get('container_width')})",
              sec2.content.get('container_width') == 'block')


def test_markup():
    print('\n[2] a max width no longer forces the box to the middle')
    pub = _tpl('public.html')
    block = pub[pub.index('{% elif section.section_type == \'text\' %}'):]
    block = block[:block.index('{% elif section.section_type == \'markdown\' %}')]
    check('the text container no longer sets auto margins',
          'margin-left: auto' not in block and 'margin-right: auto' not in block)
    check('but the max width itself is still applied',
          'max-width: {{ text_max_width }}px' in block)
    check('and "fit the text" tags the container',
          "container_width == 'fit'" in block and 'is-fit-content' in block)

    print('\n[3] placement follows the alignment set in the toolbar')
    check('centred text centres the box',
          '.text-area:has(.ql-align-center)' in pub)
    check('right-aligned text pushes it right',
          '.text-area:has(.ql-align-right)' in pub)
    check('left is the default, so it needs no rule of its own',
          '.text-area:has(.ql-align-left)' not in pub)
    check('and "fit" shrinks the box to its text',
          re.search(r'\.text-area\.is-fit-content\s*\{[^}]*width:\s*fit-content', pub))
    check('capped so a long line cannot push it past the section',
          re.search(r'\.text-area\.is-fit-content\s*\{[^}]*max-width:\s*100%', pub))

    print('\n[4] the editor preview agrees with the published page')
    ed = _tpl('page_editor.html')
    check('the editor offers the width choice',
          'name="container_width"' in ed)
    check('it previews "fit" as fit-content',
          "fitWidth ? 'fit-content'" in ed)
    check('and no longer centres on max width alone',
          "style.marginLeft = (maxWidth && maxWidth !== '0') ? 'auto'" not in ed)
    check('deciding from the text alignment instead',
          "querySelector('.ql-align-center')" in ed)


def test_toolbar():
    print('\n[5] the text toolbar offers what the other editors offer')
    ed = _tpl('page_editor.html')
    tb = ed[ed.index('const _textToolbarOptions'):]
    tb = tb[:tb.index('];') + 2]
    for name, token in (('colour', "'color': []"),
                        ('background colour', "'background': []"),
                        ('headings', "'header':"),
                        ('indent', "'indent':"),
                        ('blockquote', "'blockquote'"),
                        ('code block', "'code-block'"),
                        ('sub/superscript', "'script':")):
        check(f'{name} is on the toolbar', token in tb)

    # Whatever the post editor offers, a text section should too — that is the
    # editor people compare it against.
    post = _tpl('post_editor.html')
    ptb = post[post.index('const toolbarOptions'):]
    ptb = ptb[:ptb.index('];') + 2]
    missing = [t for t in ("'header':", "'color': []", "'background': []", "'align': []",
                           "'indent':", "'blockquote'", "'code-block'", "'script':",
                           "'list': 'ordered'", "'list': 'bullet'")
               if t in ptb and t not in tb]
    check(f'nothing the post editor has is missing here ({missing or "none missing"})',
          not missing)


def _chrome():
    for exe in ('google-chrome', 'chromium', 'chromium-browser'):
        p = shutil.which(exe)
        if p:
            return p
    return None


def _css():
    pub = _tpl('public.html')
    start = pub.index('/* ── Text section container placement')
    end = pub.index('/* ── Quill nested unordered lists ── */')
    return pub[start:end]


def test_layout():
    print('\n[6] and it lays out that way in a browser')
    chrome = _chrome()
    if not chrome:
        skip('container layout', 'no Chrome/Chromium on PATH')
        return
    css = _css()

    def measure(cls, style, inner):
        page = f"""<!doctype html><html><head><meta charset=utf-8>
<style>body{{margin:0;font-family:sans-serif}} .wrap{{width:900px}}
{css}</style></head><body>
<div class="wrap"><div class="text-area{cls}" style="{style}">{inner}</div></div>
<div id=o></div><script>window.addEventListener('load',function(){{
var w=document.querySelector('.wrap').getBoundingClientRect();
var t=document.querySelector('.text-area').getBoundingClientRect();
document.getElementById('o').textContent='RESULT '+JSON.stringify({{
 boxW:Math.round(t.width), leftGap:Math.round(t.left-w.left),
 rightGap:Math.round(w.right-t.right)}});}});</script></body></html>"""
        d = tempfile.mkdtemp(prefix='uwebia-textbox-render-')
        f = os.path.join(d, 'p.html')
        with open(f, 'w') as fh:
            fh.write(page)
        out = subprocess.run(
            [chrome, '--headless=new', '--disable-gpu', '--no-sandbox',
             f'--user-data-dir={os.path.join(d, "profile")}',
             '--virtual-time-budget=4000', '--window-size=1000,400',
             '--hide-scrollbars', '--dump-dom', f'file://{f}'],
            capture_output=True, text=True, timeout=90).stdout
        m = re.search(r'RESULT (\{[^<]*\})', out)
        return json.loads(m.group(1)) if m else None

    CAP = 'max-width:400px;background:#3af'
    r = measure('', CAP, '<p>Left aligned</p>')
    if r is None:
        skip('container layout', 'browser produced no measurement')
        return
    check(f'left-aligned text keeps the box on the left (gaps {r["leftGap"]}/{r["rightGap"]})',
          r['leftGap'] == 0 and r['rightGap'] > 0)
    check(f'and the max width is respected ({r["boxW"]}px)', r['boxW'] == 400)

    r = measure('', CAP, '<p class="ql-align-center">Centred</p>')
    check(f'centred text centres the box (gaps {r["leftGap"]}/{r["rightGap"]})',
          abs(r['leftGap'] - r['rightGap']) <= 1 and r['leftGap'] > 0)

    r = measure('', CAP, '<p class="ql-align-right">Right</p>')
    check(f'right-aligned text pushes it right (gaps {r["leftGap"]}/{r["rightGap"]})',
          r['rightGap'] == 0 and r['leftGap'] > 0)

    print('\n[7] "fit the text" hugs the text, padding and all')
    full = measure('', 'background:#3af;padding:20px', '<p>Short</p>')
    fit = measure(' is-fit-content', 'background:#3af;padding:20px', '<p>Short</p>')
    check(f'the default box fills the section ({full["boxW"]}px of 900)',
          full['boxW'] == 900)
    check(f'"fit" shrinks it to the text ({fit["boxW"]}px)',
          0 < fit['boxW'] < 300)
    check('the padding is still there — the box is wider than the words alone',
          fit['boxW'] > 40)
    check(f'and it sits left with left-aligned text (gap {fit["leftGap"]})',
          fit['leftGap'] == 0)

    fit_c = measure(' is-fit-content', 'background:#3af;padding:20px',
                    '<p class="ql-align-center">Short</p>')
    check(f'centring the text centres the hugged box too '
          f'(gaps {fit_c["leftGap"]}/{fit_c["rightGap"]})',
          abs(fit_c['leftGap'] - fit_c['rightGap']) <= 1 and fit_c['leftGap'] > 0)


if __name__ == '__main__':
    test_saved()
    test_markup()
    test_toolbar()
    test_layout()
    tail = f' ({len(SKIPPED)} skipped)' if SKIPPED else ''
    print('\n' + (f'ALL PASSED{tail}' if not FAILURES
                  else f'{len(FAILURES)} FAILED{tail}: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
