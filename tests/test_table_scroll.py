"""Wide tables scroll inside themselves instead of dragging the page sideways.

    venv/bin/python tests/test_table_scroll.py

A five-column table is reasonable to write and impossible to fit on a phone.
With nothing holding it, the table pushed the whole page wider than the screen,
so the reader had to scroll the entire site left and right to read one row:

    BEFORE @500px: page scrolls sideways: true,  no scroll container
    AFTER  @500px: page scrolls sideways: false, table scrolls: true

Covers every public surface that renders admin- or member-authored content:

    page builder  markdown / rich text / code sections
    guides        lesson HTML
    quizzes       prompts and text blocks
    newsletters   the web view of a campaign
    forum         posts (plain text — see below)

Where the HTML is rendered server-side it is wrapped there, so the fix holds at
every width. Where it is inserted at runtime (quiz prompts) or authored as raw
HTML (rich-text and code sections), the table becomes its own scroll container
on narrow screens instead.

Forum posts are the odd one out: they are plain text and cannot contain a real
table at all. They hit the same symptom anyway, because pre-wrap keeps a pasted
ASCII table's rows on one line, and one long URL does it too.

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


def _slice(path, start, end):
    """A block of the shipped CSS, read from source so the test can't drift."""
    src = open(os.path.join(_REPO, path)).read()
    return src[src.index(start):src.index(end)]


def _css():
    return _slice('Templates/public.html',
                  '.markdown-area {', '/* Normalize paragraph spacing')


# Each public surface: the CSS that governs it, and how its content is placed
# into the page. `wrap` mirrors what the server does before it reaches the DOM.
SURFACES = {
    'page builder (markdown)': dict(
        css=_css, container='markdown-area', wraps=True),
    'page builder (rich text)': dict(
        css=_css, container='text-area', wraps=False),
    'page builder (code)': dict(
        css=_css, container='code-section-output', wraps=False),
    'guides': dict(
        css=lambda: _slice('Templates/guide_view.html',
                           '.gv-content {', '.gv-content a:hover'),
        container='gv-content', wraps=True),
    'newsletters': dict(
        css=lambda: _slice('Templates/newsletter_public.html',
                           '.nlp-body .uw-table-scroll', '</style>'),
        container='nlp-body', wraps=True),
    'quizzes': dict(
        css=lambda: _slice('static/js/guide_quiz.js',
                           '.uwq-rich table,', '.uwq-rich ul,'),
        container='uwq-rich', wraps=False),
}


def test_css_present():
    print('\n[3] the page-builder stylesheet carries the rules that make it work')
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


def _measure(chrome, body, width, css=None):
    """Lay the markup out for real and report what scrolls."""
    css = _css() if css is None else css
    page = f"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><style>
html,body{{margin:0;font-family:sans-serif;font-size:16px}}
{css}
</style></head><body>{body}<div id=out></div>
<script>window.addEventListener('load',function(){{
var s=document.querySelector('.uw-table-scroll')||document.querySelector('table')||document.querySelector('.forum-body');
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
    print('\n[4] and on every surface the page really stops scrolling sideways')
    chrome = _chrome()
    if not chrome:
        skip('browser layout checks', 'no Chrome/Chromium on PATH')
        return
    # Chrome floors its window at 500px wide; still well under the 700px
    # breakpoint, so the narrow-screen rules are the ones in play.
    NARROW, WIDE = 500, 1200

    for name, spec in SURFACES.items():
        css = spec['css']()
        wrap = main._wrap_tables_for_scrolling if spec['wraps'] else (lambda h: h)

        def body(table):
            return f'<div class="{spec["container"]}">{wrap(table)}</div>'

        r = _measure(chrome, body(WIDE_TABLE), NARROW, css)
        if r is None:
            skip(f'{name}: wide table on a phone', 'browser produced no measurement')
            continue
        check(f'{name}: a wide table does not drag the page sideways',
              r['sideways'] is False)
        check(f'{name}: it scrolls inside itself instead', r['scrolls'] is True)

        r = _measure(chrome, body(PROSE_TABLE), NARROW, css)
        if r:
            check(f'{name}: a prose table still wraps rather than scrolling',
                  r['sideways'] is False and r['scrolls'] is False)

        r = _measure(chrome, body(NARROW_TABLE), NARROW, css)
        if r:
            check(f'{name}: a narrow table needs no scrolling',
                  r['sideways'] is False and r['scrolls'] is False)

        r = _measure(chrome, body(WIDE_TABLE), WIDE, css)
        if r:
            check(f'{name}: and on a desktop it is left alone',
                  r['sideways'] is False and r['scrolls'] is False)

    print('\n[5] forum posts are plain text, and scroll for a different reason')
    # No real table can reach a forum post — the body is escaped and displayed
    # with pre-wrap. But a pasted ASCII table keeps its rows on one line, and a
    # long URL never breaks, so the page went sideways just the same.
    forum_css = _slice('Templates/public_forum_thread.html',
                       '.forum-body {', '    textarea {')
    # Comfortably wider than any phone, so the check measures the mechanism
    # rather than whether a borderline sample happens to fit.
    pasted = ('Scouting results:\n\n'
              '| Team number | Match    | Alliance | Auto points | Teleop points '
              '| Endgame     | Result |\n'
              '|-------------|----------|----------|-------------|---------------'
              '|-------------|--------|\n'
              '| 1234567     | Qual 12  | Red 2    | 18          | 44            '
              '| Climbed high| Win    |\n\n'
              'See https://example.com/a/very/long/link/that/never/breaks/anywhere/'
              'at/all/and/keeps/going/well/past/the/edge/of/a/phone/screen\n')
    r = _measure(chrome, f'<div class="forum-body">{pasted}</div>', NARROW, forum_css)
    if r is None:
        skip('forum post on a phone', 'browser produced no measurement')
    else:
        check('a pasted table does not drag the page sideways', r['sideways'] is False)
        check('the post scrolls instead', r['scrolls'] is True)
    r = _measure(chrome, f'<div class="forum-body">{pasted}</div>', WIDE, forum_css)
    if r:
        check('and on a desktop it needs no scrolling', r['scrolls'] is False)
    check('the alignment of a pasted table is preserved, not re-wrapped',
          'pre-wrap' in forum_css and 'overflow-x: auto' in forum_css)


def test_email_untouched():
    print('\n[6] the newsletter EMAIL body is not rewritten')
    # The wrapper is applied by a Jinja filter in the web view only. Mail
    # clients handle overflow containers poorly, and the stored body is what
    # gets sent, so it has to come through unchanged.
    tpl = open(os.path.join(_REPO, 'Templates', 'newsletter_public.html')).read()
    check('the web view wraps its tables', 'campaign.html_body | scroll_tables' in tpl)
    stored = '<table><tr><td>rows</td></tr></table>'
    with app.app_context():
        rendered = str(main.scroll_tables_filter(stored))
    check('rendering wraps a copy', rendered.startswith('<div class="uw-table-scroll">'))
    check('and leaves the stored body alone', stored == '<table><tr><td>rows</td></tr></table>')

    src = open(os.path.join(_REPO, 'main.py')).read()
    sends = [ln for ln in src.splitlines()
             if 'scroll_tables' in ln and 'send' in ln.lower()]
    check(f'no send path applies it ({len(sends)} found)', not sends)


if __name__ == '__main__':
    test_wrapping()
    test_css_present()
    test_layout()
    test_email_untouched()
    tail = f' ({len(SKIPPED)} skipped)' if SKIPPED else ''
    print('\n' + (f'ALL PASSED{tail}' if not FAILURES
                  else f'{len(FAILURES)} FAILED{tail}: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
