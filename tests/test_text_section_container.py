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
import atexit
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
# Each of these holds a ~2.5 MB copy of main.py and a SQLite database; nothing
# removed them, so repeated suite runs left GBs behind in /tmp.
atexit.register(shutil.rmtree, _SCRATCH, ignore_errors=True)
shutil.copy2(os.path.join(_REPO, 'main.py'), os.path.join(_SCRATCH, 'main.py'))
for _linked in ('Templates', 'icons'):
    _src = os.path.join(_REPO, _linked)
    if os.path.exists(_src):
        os.symlink(_src, os.path.join(_SCRATCH, _linked))
# static is rebuilt child by child rather than symlinked whole: uploads_folder
# lives inside it, and a symlink points main.py's file writes AND DELETES at the
# real project's static/uploads. A backup import run that way once destroyed 18
# of the live instance's images permanently.
os.mkdir(os.path.join(_SCRATCH, 'static'))
for _child in os.listdir(os.path.join(_REPO, 'static')):
    if _child != 'uploads':
        os.symlink(os.path.join(_REPO, 'static', _child),
                   os.path.join(_SCRATCH, 'static', _child))
os.makedirs(os.path.join(_SCRATCH, 'static', 'uploads'), exist_ok=True)

sys.path.insert(0, _SCRATCH)
import main  # noqa: E402

assert os.path.dirname(os.path.abspath(main.__file__)) == _SCRATCH, \
    'refusing to run against the real checkout'
# The uploads folder must resolve inside the scratch dir. This is the guard that
# would have caught the symlink above: without it, any delete path a test reaches
# operates on the real instance's files.
assert os.path.realpath(main.uploads_folder).startswith(os.path.realpath(_SCRATCH)), \
    'uploads folder escapes the scratch directory'

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


# Every combination that matters, seeded as real sections on a real page.
# An earlier version of this test built a page from the .text-area rules alone
# and passed while the feature was broken: the cell those sections actually sit
# in carries `width:100%` and `margin:0` overrides that only appear once the
# whole stylesheet is in play. Measure the page the visitor gets.
CASES = [
    ('full width, left',      'block', '0',   '<p>Hello world</p>'),
    ('capped, left',          'block', '300', '<p>Hello world</p>'),
    ('capped, centred',       'block', '300', '<p class="ql-align-center">Hello world</p>'),
    ('fit, left',             'fit',   '0',   '<p>Hello world</p>'),
    ('fit, centred',          'fit',   '0',   '<p class="ql-align-center">Hello world</p>'),
    ('fit, right',            'fit',   '0',   '<p class="ql-align-right">Hello world</p>'),
]

PROBE = """
<script>
window.addEventListener('load', function () {
  setTimeout(function () {
    var out = [].slice.call(document.querySelectorAll('.text-area')).map(function (t) {
      var r = t.getBoundingClientRect(), cell = t.parentElement.getBoundingClientRect();
      return { boxW: Math.round(r.width), cellW: Math.round(cell.width),
               leftGap: Math.round(r.left - cell.left),
               rightGap: Math.round(cell.right - r.right) };
    });
    var d = document.createElement('div'); d.id = 'probeout';
    d.textContent = 'RESULT ' + JSON.stringify(out);
    document.body.appendChild(d);
  }, 700);
});
</script>
"""


def _seed_and_serve():
    """A live page holding one text section per case. Returns the port."""
    import socket
    import threading
    import time
    import urllib.request
    from flask import request

    @app.after_request
    def _inject(resp):                       # noqa: ANN001
        try:
            if request.args.get('probe') and (resp.content_type or '').startswith('text/html'):
                body = resp.get_data(as_text=True)
                resp.set_data(body.replace('</body>', PROBE + '</body>'))
        except Exception:
            pass
        return resp

    with app.app_context():
        db.create_all()
        db.session.remove()
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        db.session.commit()
        owner = main.User(username='owner', parent_user_id=None)
        owner.set_password('x')
        db.session.add(owner)
        db.session.commit()
        site = main.Website(user_id=owner.id, name='Site', is_draft=False, is_live=True)
        db.session.add(site)
        db.session.commit()
        page = main.PublicPageContent(website_id=site.id, name='Home', slug='home',
                                      site_active_status=True)
        db.session.add(page)
        db.session.commit()
        group = main.SectionGroup(page_content_id=page.id, name='G', group_order=0)
        db.session.add(group)
        db.session.commit()
        for i, (_label, cw, cap, html) in enumerate(CASES):
            sec = main.PageSection(
                page_content_id=page.id, section_type='text', order=i,
                content={'html': html, 'text_max_width': cap,
                         'background_color': '#112233', 'background_opacity': '0.8',
                         'padding': '20', 'border_radius': '10',
                         'box_shadow': 'medium', 'container_width': cw})
            db.session.add(sec)
            db.session.commit()
            row = main.Row(page_content_id=page.id, row_number=i,
                           section_group_id=group.id)
            db.session.add(row)
            db.session.commit()
            db.session.add(main.Column(row_id=row.id, column_number=0,
                                       section_id=sec.id, width=100))
            db.session.commit()

    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    threading.Thread(
        target=lambda: app.run(port=port, debug=False, use_reloader=False,
                               threaded=True),
        daemon=True).start()
    for _ in range(60):
        try:
            urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=1).read()
            return port
        except Exception:
            time.sleep(0.5)
    return None



def _render_dir(prefix):
    """A temp dir for one headless-Chrome render, removed when the run ends.

    Every render gets its own --user-data-dir, and nothing ever deleted them:
    1679 abandoned Chrome profiles totalling ~5 GB had built up in /tmp. atexit
    rather than a try/finally because the helper has several return points, and
    the directory has to outlive the subprocess call either way.
    """
    d = tempfile.mkdtemp(prefix=prefix)
    atexit.register(shutil.rmtree, d, ignore_errors=True)
    return d

def test_layout():
    print('\n[6] and the published page lays out that way')
    chrome = _chrome()
    if not chrome:
        skip('container layout', 'no Chrome/Chromium on PATH')
        return
    port = _seed_and_serve()
    if not port:
        skip('container layout', 'test server did not start')
        return

    d = _render_dir('uwebia-textbox-render-')
    out = subprocess.run(
        [chrome, '--headless=new', '--disable-gpu', '--no-sandbox',
         f'--user-data-dir={os.path.join(d, "profile")}',
         '--virtual-time-budget=9000', '--window-size=1300,900',
         '--hide-scrollbars', '--dump-dom',
         f'http://127.0.0.1:{port}/?probe=1'],
        capture_output=True, text=True, timeout=120).stdout
    m = re.search(r'RESULT (\[[^<]*\])', out)
    if not m:
        skip('container layout', 'browser produced no measurement')
        return
    rows = json.loads(m.group(1))
    if len(rows) != len(CASES):
        skip('container layout', f'expected {len(CASES)} sections, saw {len(rows)}')
        return

    by = dict(zip([c[0] for c in CASES], rows))

    r = by['full width, left']
    check(f'with no cap the box fills its cell ({r["boxW"]} of {r["cellW"]})',
          r['cellW'] - r['boxW'] <= 14)

    r = by['capped, left']
    check(f'a max width caps it ({r["boxW"]}px, asked for 300)', r['boxW'] == 300)
    check(f'and left-aligned text keeps it left (gaps {r["leftGap"]}/{r["rightGap"]})',
          r['leftGap'] < 10 and r['rightGap'] > 100)

    r = by['capped, centred']
    check(f'centred text centres the capped box (gaps {r["leftGap"]}/{r["rightGap"]})',
          abs(r['leftGap'] - r['rightGap']) <= 2 and r['leftGap'] > 100)

    print('\n[7] "fit the text" hugs the text, padding and all')
    full = by['full width, left']
    r = by['fit, left']
    check(f'fit shrinks the box to its text ({r["boxW"]}px vs {full["boxW"]}px full)',
          r['boxW'] < full['boxW'] / 3)
    check('the padding is still there — wider than the words alone',
          r['boxW'] > 40)
    check(f'and it sits left with left-aligned text (gap {r["leftGap"]})',
          r['leftGap'] < 10)

    r = by['fit, centred']
    check(f'centring the text centres the hugged box (gaps {r["leftGap"]}/{r["rightGap"]})',
          abs(r['leftGap'] - r['rightGap']) <= 2 and r['leftGap'] > 100)

    r = by['fit, right']
    check(f'right-aligned text pushes it right (gaps {r["leftGap"]}/{r["rightGap"]})',
          r['rightGap'] < 10 and r['leftGap'] > 100)


if __name__ == '__main__':
    test_saved()
    test_markup()
    test_toolbar()
    test_layout()
    tail = f' ({len(SKIPPED)} skipped)' if SKIPPED else ''
    print('\n' + (f'ALL PASSED{tail}' if not FAILURES
                  else f'{len(FAILURES)} FAILED{tail}: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
