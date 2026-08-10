"""Wide tables scroll inside themselves instead of dragging the page sideways.

    venv/bin/python tests/test_markdown_table_scroll.py

A five-column table is reasonable to write in a markdown section and impossible
to fit on a phone. With nothing holding it, the table pushed the whole page
wider than the screen, so the reader had to scroll the entire site left and
right to read one row:

    BEFORE @500px: page scrolls sideways: true,  no scroll container
    AFTER  @500px: page scrolls sideways: false, table scrolls: true

Markdown tables are wrapped server-side; rich-text and code sections hold
admin-authored HTML that isn't rewritten, so on narrow screens those tables
become their own scroll container.

The layout half of this needs a real browser. Those checks run when Chrome is
on PATH and are skipped (loudly) when it isn't, so the suite still runs
anywhere.

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

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-table-scroll')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-table-test-')
shutil.copy2(os.path.join(_REPO, 'main.py'), os.path.join(_SCRATCH, 'main.py'))
for _linked in ('Templates', 'icons', 'static'):
    _src = os.path.join(_REPO, _linked)
    if os.path.exists(_src):
        os.symlink(_src, os.path.join(_SCRATCH, _linked))

sys.path.insert(0, _SCRATCH)
import main  # noqa: E402

assert os.path.dirname(os.path.abspath(main.__file__)) == _SCRATCH, \
    'refusing to run against the real checkout'

app = main.app
FAILURES = []
SKIPPED = []


def check(label, cond):
    print(('  PASS  ' if cond else '  FAIL  ') + label)
    if not cond:
        FAILURES.append(label)


def skip(label, why):
    print(f'  SKIP  {label} — {why}')
    SKIPPED.append(label)


WIDE_TABLE = (
    '<table><thead><tr><th>Team number</th><th>Match</th><th>Alliance</th>'
    '<th>Auto points</th><th>Teleop points</th><th>Endgame</th><th>Result</th>'
    '</tr></thead><tbody><tr><td>1234567</td><td>Qual 12</td><td>Red 2</td>'
    '<td>18</td><td>44</td><td>Climbed high</td><td>Win</td></tr></tbody></table>')
NARROW_TABLE = ('<table><thead><tr><th>A</th><th>B</th></tr></thead>'
                '<tbody><tr><td>1</td><td>2</td></tr></tbody></table>')
PROSE_TABLE = (
    '<table><thead><tr><th>Step</th><th>What to do</th></tr></thead><tbody><tr>'
    '<td>1</td><td>A fairly long sentence of guidance that should wrap rather '
    'than forcing the table to become enormously wide on a phone, because that '
    'is worse than the problem it solves.</td></tr></tbody></table>')


def test_wrapping():
    print('\n[1] the wrapper goes around every top-level table')
    w = main._wrap_tables_for_scrolling
    check('content with no table is returned untouched',
          w('<p>hi</p>') == '<p>hi</p>')
    check('a plain table is wrapped',
          w('<table><tr><td>a</td></tr></table>')
          == '<div class="uw-table-scroll"><table><tr><td>a</td></tr></table></div>')
    check('attributes on the tag do not defeat it',
          w('<table class="x"><tr><td>a</td></tr></table>').startswith(
              '<div class="uw-table-scroll"><table class="x">'))
    check('uppercase markup is matched too',
          w('<TABLE><TR><TD>a</TD></TR></TABLE>').startswith('<div class="uw-table-scroll">'))

    two = w('<table><tr><td>a</td></tr></table><p>x</p><table><tr><td>b</td></tr></table>')
    check('two tables get one wrapper each',
          two.count('<div class="uw-table-scroll">') == 2 and two.count('</div>') == 2)

    nested = w('<table><tr><td><table><tr><td>n</td></tr></table></td></tr></table>')
    check('a nested table gets ONE wrapper, around the outer one',
          nested.count('<div class="uw-table-scroll">') == 1
          and nested.count('</div>') == 1
          and nested.startswith('<div class="uw-table-scroll"><table>'))

    # An unclosed div would swallow the rest of the page, so malformed input
    # has to come back untouched rather than half-wrapped.
    broken = '<table><tr><td>a</td></tr>'
    check('unbalanced markup is left alone', w(broken) == broken)

    print('\n[2] and markdown tables come out wrapped')
    with app.app_context():
        html = str(main.render_markdown_filter('| A | B |\n|---|---|\n| 1 | 2 |\n'))
    check('the filter wraps its table', html.startswith('<div class="uw-table-scroll">'))
    check('the table itself survives intact', '<th>A</th>' in html and '</table></div>' in html)
    with app.app_context():
        plain = str(main.render_markdown_filter('Just a paragraph.'))
    check('markdown with no table gains no wrapper', 'uw-table-scroll' not in plain)


def _css():
    """The shipped rules, read from the template so the test can't drift."""
    src = open(os.path.join(_REPO, 'Templates', 'public.html')).read()
    return src[src.index('.markdown-area {'):src.index('/* Normalize paragraph spacing')]


def test_css_present():
    print('\n[3] the stylesheet carries the rules that make it work')
    css = _css()
    check('the scroll container is defined', '.uw-table-scroll' in css)
    check('it scrolls horizontally', re.search(r'\.uw-table-scroll\s*{[^}]*overflow-x:\s*auto', css))
    check('and is capped at the width available',
          re.search(r'\.uw-table-scroll\s*{[^}]*max-width:\s*100%', css))
    check('rich-text and code tables are handled on narrow screens',
          '.text-area table' in css and '.code-section-output table' in css)
    check('with the nowrap headers that make them actually scroll',
          re.search(r'\.text-area table th[^{]*{[^}]*nowrap', css))


def _chrome():
    for exe in ('google-chrome', 'chromium', 'chromium-browser'):
        path = shutil.which(exe)
        if path:
            return path
    return None


def _measure(chrome, body, width):
    """Lay the markup out for real and report what scrolls."""
    page = f"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><style>
html,body{{margin:0;font-family:sans-serif;font-size:16px}}
{_css()}
</style></head><body>{body}<div id=out></div>
<script>window.addEventListener('load',function(){{
var s=document.querySelector('.uw-table-scroll')||document.querySelector('table');
document.getElementById('out').textContent='RESULT '+JSON.stringify({{
 sideways:document.documentElement.scrollWidth>window.innerWidth+1,
 scrolls:s?(s.scrollWidth>s.clientWidth+1):null}});}});
</script></body></html>"""
    d = tempfile.mkdtemp(prefix='uwebia-table-render-')
    f = os.path.join(d, 'p.html')
    with open(f, 'w') as fh:
        fh.write(page)
    out = subprocess.run(
        [chrome, '--headless=new', '--disable-gpu', '--no-sandbox',
         f'--user-data-dir={os.path.join(d, "profile")}',
         '--virtual-time-budget=2500', f'--window-size={width},800',
         '--dump-dom', f'file://{f}'],
        capture_output=True, text=True, timeout=90).stdout
    m = re.search(r'RESULT (\{[^<]*\})', out)
    return json.loads(m.group(1)) if m else None


def test_layout():
    print('\n[4] and the page really stops scrolling sideways')
    chrome = _chrome()
    if not chrome:
        skip('browser layout checks', 'no Chrome/Chromium on PATH')
        return
    # Chrome floors the window at 500px wide; that is still well under the
    # 700px breakpoint, so the narrow-screen rules are the ones in play.
    NARROW, WIDE = 500, 1200

    areas = {
        'markdown': lambda t: f'<div class="markdown-area">{main._wrap_tables_for_scrolling(t)}</div>',
        'rich text': lambda t: f'<div class="text-area">{t}</div>',
        'code': lambda t: f'<div class="code-section-output">{t}</div>',
    }
    for area, wrap in areas.items():
        r = _measure(chrome, wrap(WIDE_TABLE), NARROW)
        if r is None:
            skip(f'{area}: wide table on a phone', 'browser produced no measurement')
            continue
        check(f'{area}: a wide table does not drag the page sideways', r['sideways'] is False)
        check(f'{area}: it scrolls inside itself instead', r['scrolls'] is True)

        r = _measure(chrome, wrap(PROSE_TABLE), NARROW)
        if r:
            check(f'{area}: a prose table still wraps rather than scrolling',
                  r['sideways'] is False and r['scrolls'] is False)

        r = _measure(chrome, wrap(NARROW_TABLE), NARROW)
        if r:
            check(f'{area}: a narrow table needs no scrolling',
                  r['sideways'] is False and r['scrolls'] is False)

        r = _measure(chrome, wrap(WIDE_TABLE), WIDE)
        if r:
            check(f'{area}: and on a desktop it is left alone',
                  r['sideways'] is False and r['scrolls'] is False)


if __name__ == '__main__':
    test_wrapping()
    test_css_present()
    test_layout()
    tail = f' ({len(SKIPPED)} skipped)' if SKIPPED else ''
    print('\n' + (f'ALL PASSED{tail}' if not FAILURES
                  else f'{len(FAILURES)} FAILED{tail}: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
