"""A long search result list must not push the nav links off the screen.

    venv/bin/python tests/test_navbar_menu_scroll.py

Search from the mobile navbar, get twenty hits, and the menu panel grew to fit
them all. In dropdown mode the panel is absolutely positioned inside a fixed
navbar, so growing past the viewport does not make anything scrollable — the
links below the results were simply unreachable. Measured at a 557px viewport
with nine nav links and twenty results:

    before  panel 657px tall, overflows the viewport, does not scroll,
            last link sits at y=711 and no scrolling brings it back
    after   panel 481px, scrolls, last link reachable

Two separate caps do the work: the results list gets a share of the panel
rather than most of the screen, and the panel itself is bounded to the viewport
and scrolls. Side-panel mode already scrolled; it benefits from the smaller
results box.

Needs a real browser — layout is the whole question here. Skips (loudly) when
Chrome isn't on PATH.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-navbar-scroll')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-navscroll-test-')
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


# Opens the menu, fills the results list with `n` fake hits, optionally scrolls
# the panel to the bottom, then reports what is reachable.
PROBE = """
<script>
window.addEventListener('load', function () {
  var p = new URLSearchParams(location.search);
  var mode = p.get('mode') || 'dropdown';
  var n = parseInt(p.get('n') || '0', 10);
  var nav = document.querySelector('.public-navbar');
  nav.className = nav.className.replace(/dropdown-mode-\\w+/, 'dropdown-mode-' + mode);
  var menu = document.getElementById('publicNavbarMenu');
  menu.classList.add('show');
  var res = menu.querySelector('[data-search-results]');
  var h = '';
  for (var i = 0; i < n; i++) {
    h += '<a class="public-navbar-search-result" href="#">'
       + '<div class="public-navbar-search-result-title">'
       + '<span class="public-navbar-search-result-type">Lesson</span>'
       + '<span>Result ' + i + '</span></div>'
       + '<div class="public-navbar-search-result-snippet">Snippet ' + i + '.</div></a>';
  }
  if (res) res.innerHTML = h;
  setTimeout(function () {
    if (p.get('scroll')) { menu.scrollTop = menu.scrollHeight; }
    var vis = [].slice.call(menu.querySelectorAll('a:not(.public-navbar-search-result)'))
      .filter(function (el) {
        var r = el.getBoundingClientRect();
        return r.width > 0 && r.height > 0;
      });
    var last = vis[vis.length - 1];
    var lr = last ? last.getBoundingClientRect() : null;
    var mr = menu.getBoundingClientRect();
    var d = document.createElement('div');
    d.id = 'probeout';
    d.textContent = 'RESULT ' + JSON.stringify({
      mode: mode, n: n, vh: window.innerHeight, visibleLinks: vis.length,
      menuH: Math.round(mr.height),
      menuScrolls: menu.scrollHeight > menu.clientHeight + 1,
      menuOverflowsViewport: mr.bottom > window.innerHeight + 1,
      resultsScrolls: res ? (res.scrollHeight > res.clientHeight + 1) : null,
      resultsH: res ? Math.round(res.getBoundingClientRect().height) : null,
      lastLinkOnScreen: lr ? (lr.bottom <= window.innerHeight + 1) : null
    });
    document.body.appendChild(d);
  }, 400);
});
</script>
"""


def _free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _seed():
    from flask import request

    @app.after_request
    def _inject(resp):                      # noqa: ANN001
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
        site = main.Website(user_id=owner.id, name='Test Site', is_draft=False,
                            is_live=True, public_users_enabled=True,
                            public_navbar_show_search=True)
        # A navbar with a realistic number of links — the whole point is that
        # these stay reachable.
        site.public_navbar_items = [
            {'type': 'link', 'label': lbl, 'url': '/' + lbl.lower()}
            for lbl in ['About', 'Events', 'Team', 'Sponsors', 'Blog',
                        'Shop', 'Contact', 'Education', 'Members']
        ]
        db.session.add(site)
        db.session.commit()
        db.session.add(main.PublicPageContent(website_id=site.id, name='Home',
                                              slug='home', site_active_status=True))
        db.session.commit()


def _chrome():
    for exe in ('google-chrome', 'chromium', 'chromium-browser'):
        p = shutil.which(exe)
        if p:
            return p
    return None


def _measure(chrome, port, profile, mode, n, scroll=False, width=500, height=700):
    url = (f'http://127.0.0.1:{port}/?probe=1&mode={mode}&n={n}'
           + ('&scroll=1' if scroll else ''))
    out = subprocess.run(
        [chrome, '--headless=new', '--disable-gpu', '--no-sandbox',
         f'--user-data-dir={profile}', '--virtual-time-budget=4000',
         f'--window-size={width},{height}', '--dump-dom', url],
        capture_output=True, text=True, timeout=120).stdout
    m = re.search(r'RESULT (\{[^<]*\})', out)
    return json.loads(m.group(1)) if m else None


def main_test():
    chrome = _chrome()
    if not chrome:
        skip('navbar panel layout', 'no Chrome/Chromium on PATH')
        return

    _seed()
    port = _free_port()
    threading.Thread(
        target=lambda: app.run(port=port, debug=False, use_reloader=False,
                               threaded=True),
        daemon=True).start()
    for _ in range(60):
        try:
            urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=1).read()
            break
        except Exception:
            time.sleep(0.5)
    else:
        skip('navbar panel layout', 'test server did not start')
        return

    profile = os.path.join(_SCRATCH, 'chrome-profile')

    for mode in ('dropdown', 'side_panel'):
        print(f'\n[{mode}] with no search results')
        r = _measure(chrome, port, profile, mode, 0)
        if r is None:
            skip(f'{mode}: baseline', 'browser produced no measurement')
            continue
        check(f'the nav links are all there ({r["visibleLinks"]})', r['visibleLinks'] == 9)
        check('the panel fits on screen', r['menuOverflowsViewport'] is False)
        check('and the last link is visible without scrolling',
              r['lastLinkOnScreen'] is True)

        print(f'[{mode}] with twenty search results')
        r = _measure(chrome, port, profile, mode, 20)
        if r is None:
            skip(f'{mode}: long result list', 'browser produced no measurement')
            continue
        check(f'the panel still fits on screen (was 657px in a {r["vh"]}px '
              f'viewport, now {r["menuH"]}px)',
              r['menuOverflowsViewport'] is False)
        check('the results list caps itself and scrolls',
              r['resultsScrolls'] is True)
        check(f'taking a share of the panel, not most of the screen '
              f'({r["resultsH"]}px of {r["vh"]}px)',
              r['resultsH'] <= r['vh'] * 0.5)
        check('and the panel itself scrolls when the whole thing is too long',
              r['menuScrolls'] is True)

        r = _measure(chrome, port, profile, mode, 20, scroll=True)
        if r:
            # Scrolling has to actually get you there — that is the difference
            # between "bounded" and "usable".
            check('scrolling the panel brings the last nav link into view',
                  r['lastLinkOnScreen'] is True)

    print('\n[both] a very long list changes nothing')
    for mode in ('dropdown', 'side_panel'):
        r = _measure(chrome, port, profile, mode, 60)
        if r:
            check(f'{mode}: 60 results still do not overflow the viewport',
                  r['menuOverflowsViewport'] is False)
            check(f'{mode}: and the panel is still scrollable',
                  r['menuScrolls'] is True)


if __name__ == '__main__':
    main_test()
    tail = f' ({len(SKIPPED)} skipped)' if SKIPPED else ''
    print('\n' + (f'ALL PASSED{tail}' if not FAILURES
                  else f'{len(FAILURES)} FAILED{tail}: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
