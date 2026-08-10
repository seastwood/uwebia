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

Two follow-ons, both measured from screenshots rather than asserted about CSS:

  backdrop  the panel's background and blur are painted by an absolutely
            positioned ::before, and an abspos child of a scroll container
            scrolls with the content — so scrolling slid the backdrop up and
            the bottom of the menu showed the bare page through it. The
            scrolling moved to the inner wrapper to pin it.

  blur      `transform` and `opacity < 1` each make an element a backdrop root,
            which has nothing behind it to sample, so the menu opened clear and
            only turned frosted once the animation stopped. Against a striped
            backdrop 15% into the open, pixel variance under the panel was 107
            (sharp stripes) before and 35 (smeared) after.

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
  // Sharp stripes behind everything — blur is only detectable against detail,
  // a solid colour blurs to the same solid colour and proves nothing.
  if (p.get('stripes')) {
    var bg = document.createElement('div');
    bg.style.cssText = 'position:fixed;inset:0;z-index:9000;pointer-events:none;' +
      'background:repeating-linear-gradient(0deg,#fff 0 6px,#000 6px 12px);';
    document.body.insertBefore(bg, document.body.firstChild);
  }
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
  // Freeze the open animation at a fraction so a screenshot catches the
  // mid-animation state deterministically instead of racing it.
  var freeze = p.get('freeze');
  if (freeze) {
    menu.style.animationDelay = '-' + (0.2 * parseFloat(freeze)) + 's';
    menu.style.animationPlayState = 'paused';
  }
  setTimeout(function () {
    // Whichever element actually scrolls: the panel, or its inner wrapper.
    var glass = menu.querySelector('.public-navbar-menu-glass');
    var scroller = (menu.scrollHeight > menu.clientHeight + 1) ? menu
                 : ((glass && glass.scrollHeight > glass.clientHeight + 1) ? glass : menu);
    if (p.get('scroll')) { scroller.scrollTop = scroller.scrollHeight; }
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
      anythingScrolls: scroller.scrollHeight > scroller.clientHeight + 1,
      menuLeft: Math.round(mr.left), menuTop: Math.round(mr.top),
      menuRight: Math.round(mr.right), menuBottom: Math.round(mr.bottom),
      menuW: Math.round(mr.width),
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
                            public_navbar_show_search=True,
                            # A loud page colour so "the page is showing through
                            # where the panel should be" is unmistakable in a
                            # screenshot. Against the default dark background it
                            # looks the same as the panel and proves nothing.
                            background_color='#ff0000')
        # A navbar with a realistic number of links — the whole point is that
        # these stay reachable.
        site.public_navbar_items = [
            {'type': 'link', 'label': lbl, 'url': '/' + lbl.lower()}
            for lbl in ['About', 'Events', 'Team', 'Sponsors', 'Blog', 'Shop',
                        'Contact', 'Education', 'Members', 'Calendar', 'Gallery',
                        'History', 'Awards', 'Outreach', 'Mentors', 'Donate',
                        'Volunteer', 'Safety', 'Rules', 'Archive']
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


def _url(port, mode, n, scroll=False, stripes=False, freeze=None):
    u = f'http://127.0.0.1:{port}/?probe=1&mode={mode}&n={n}'
    if scroll:
        u += '&scroll=1'
    if stripes:
        u += '&stripes=1'
    if freeze is not None:
        u += f'&freeze={freeze}'
    return u


def _chrome_args(chrome, profile, width, height):
    return [chrome, '--headless=new', '--disable-gpu', '--no-sandbox',
            f'--user-data-dir={profile}', '--virtual-time-budget=4000',
            f'--window-size={width},{height}', '--hide-scrollbars']


def _measure(chrome, port, profile, mode, n, scroll=False, stripes=False,
             freeze=None, width=500, height=700):
    out = subprocess.run(
        _chrome_args(chrome, profile, width, height)
        + ['--dump-dom', _url(port, mode, n, scroll, stripes, freeze)],
        capture_output=True, text=True, timeout=120).stdout
    m = re.search(r'RESULT (\{[^<]*\})', out)
    return json.loads(m.group(1)) if m else None


def _shoot(chrome, port, profile, mode, n, path, **kw):
    """Screenshot the same state _measure reports on."""
    subprocess.run(
        _chrome_args(chrome, profile, kw.pop('width', 500), kw.pop('height', 700))
        + [f'--screenshot={path}', _url(port, mode, n, **kw)],
        capture_output=True, timeout=120)
    return path


def _column(img, x, y0, y1):
    return [img.getpixel((int(x), int(y)))[0] for y in range(int(y0), int(y1))]


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
        check(f'the nav links are all there ({r["visibleLinks"]})', r['visibleLinks'] == 20)
        check('the panel fits on screen', r['menuOverflowsViewport'] is False)
        # Twenty links do not fit a phone even with no search results, so what
        # matters is that they are reachable, not that they are all on screen.
        r2 = _measure(chrome, port, profile, mode, 0, scroll=True)
        check('and scrolling reaches the last one',
              r2 is not None and r2['lastLinkOnScreen'] is True)

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
        # The panel is bounded and something inside it scrolls. WHICH element
        # scrolls differs by mode: dropdown mode scrolls its inner wrapper so
        # that the panel's ::before backdrop stays pinned (see below), side
        # panel scrolls itself.
        check('and it scrolls when the whole thing is too long',
              r['anythingScrolls'] is True)

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
                  r['anythingScrolls'] is True)

    test_backdrop(chrome, port, profile)
    test_blur_during_open(chrome, port, profile)


def test_backdrop(chrome, port, profile):
    """The panel's background and blur must cover it all the way down.

    The backdrop is painted by an absolutely positioned ::before, and an
    absolutely positioned child of a scroll container scrolls with the content
    — so when the panel itself was the scroller, scrolling slid the backdrop up
    and the bottom of the menu showed the bare page through it.
    """
    try:
        from PIL import Image
    except ImportError:
        skip('backdrop checks', 'Pillow not installed')
        return

    print('\n[backdrop] the panel stays opaque all the way down')
    for mode in ('dropdown', 'side_panel'):
        geo = _measure(chrome, port, profile, mode, 20, scroll=True)
        path = os.path.join(_SCRATCH, f'bg_{mode}.png')
        _shoot(chrome, port, profile, mode, 20, path, scroll=True)
        if geo is None or not os.path.exists(path):
            skip(f'{mode}: backdrop', 'no screenshot')
            continue
        img = Image.open(path).convert('RGB')
        cx = geo['menuLeft'] + geo['menuW'] // 2
        top = img.getpixel((cx, geo['menuTop'] + 12))
        bottom = img.getpixel((cx, geo['menuBottom'] - 8))
        # The scratch site's page is pure red; anything close to it means the
        # page is showing through where the panel should be.
        page_ish = bottom[0] > 200 and bottom[1] < 60 and bottom[2] < 60
        check(f'{mode}: scrolled to the bottom, the panel is still painted '
              f'(bottom pixel {bottom}, top {top})', not page_ish)


def test_blur_during_open(chrome, port, profile):
    """The blur has to be live while the menu opens, not only once it lands.

    `transform` and `opacity < 1` both make an element a backdrop root, and a
    backdrop root has nothing behind it to sample — so a menu animated with
    those opens clear and turns frosted only at the end.
    """
    try:
        from PIL import Image
        import statistics
    except ImportError:
        skip('blur checks', 'Pillow not installed')
        return

    print('\n[blur] frosted from the first frame, not just at the end')
    geo = _measure(chrome, port, profile, 'dropdown', 3, stripes=True)
    if geo is None:
        skip('blur during open', 'no measurement')
        return
    # Near the top-right: the first corner revealed, so it is covered at every
    # point in the animation.
    x = geo['menuRight'] - 25
    y0, y1 = geo['menuTop'] + 8, geo['menuTop'] + 34
    outside_x = min(499 - 4, geo['menuRight'] + 25)

    for label, freeze in (('fully open', None), ('15% in', 0.15),
                          ('40% in', 0.4), ('80% in', 0.8)):
        path = os.path.join(_SCRATCH, f'blur_{label.replace(" ", "_").replace("%","")}.png')
        _shoot(chrome, port, profile, 'dropdown', 3, path,
               stripes=True, freeze=freeze)
        if not os.path.exists(path):
            skip(f'blur {label}', 'no screenshot')
            continue
        img = Image.open(path).convert('RGB')
        inside = statistics.pstdev(_column(img, x, y0, y1))
        backdrop = statistics.pstdev(_column(img, outside_x, y0, y1))
        # Sharp stripes behind => high variance. Blurred => it collapses.
        check(f'{label}: the stripes behind are smeared, not sharp '
              f'(panel {inside:.0f} vs backdrop {backdrop:.0f})',
              backdrop > 40 and inside < backdrop * 0.5)


if __name__ == '__main__':
    main_test()
    tail = f' ({len(SKIPPED)} skipped)' if SKIPPED else ''
    print('\n' + (f'ALL PASSED{tail}' if not FAILURES
                  else f'{len(FAILURES)} FAILED{tail}: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
