"""Per-picture zoom and reposition for guides, quizzes and resources.

    venv/bin/python tests/test_image_framing.py

A generated illustration is rarely framed the way a 58px icon or a 16:9 cover
needs it — the subject sits too small, or the crop cuts the wrong edge. Each
picture now carries its own zoom (100–300%) and focal point.

The framing has to survive two different kinds of overflow, and one stored
focus steers both:

  • Aspect mismatch — a square picture in a 16:9 cover slot. object-fit crops
    it and object-position picks which part survives. This is the ONLY overflow
    at 100%, and it is what a guide cover needs.

  • Zoom — past 100% the picture is bigger than the frame in both directions,
    which object-position cannot pan at all (a square picture in a square frame
    has no aspect overflow). A translate after the scale moves it instead, and
    is scaled by (z-1)/z so focus 0–100 always maps to the full pannable range
    and never exposes an empty edge.

The editor draws its own live preview, so the browser's maths and the server's
have to agree exactly — that is checked here by running both.

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

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-framing')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-fit-test-')
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
URL = '/static/uploads/1/assets/pic.webp'


def check(label, cond):
    print(('  PASS  ' if cond else '  FAIL  ') + label)
    if not cond:
        FAILURES.append(label)


def setup():
    with app.app_context():
        db.create_all()
        db.session.remove()
        db.session.execute(main.User.__table__.update().values(permission_group_id=None))
        db.session.execute(main.PermissionGroup.__table__.delete())
        db.session.commit()
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        db.session.commit()

        owner = main.User(username='owner', parent_user_id=None)
        owner.set_password('ownerpassword')
        db.session.add(owner)
        db.session.commit()
        site = main.Website(user_id=owner.id, name='Site', is_draft=False, is_live=True)
        db.session.add(site)
        db.session.commit()
        db.session.add(main.PublicPageContent(website_id=site.id, name='Home',
                                              slug='home', site_active_status=True))
        guide = main.Guide(website_id=site.id, title='Soldering', slug='sold',
                           status='published', description='d', cover_image_url=URL)
        quiz = main.Quiz(website_id=site.id, title='Safety', is_public=True,
                         image_url=URL)
        res = main.Resource(website_id=site.id, title='Checklist', resource_type='page',
                            content='<p>x</p>', is_public=True, image_url=URL)
        db.session.add_all([guide, quiz, res])
        db.session.commit()
        return dict(owner=owner.id, site=site.id, guide=guide.id,
                    quiz=quiz.id, resource=res.id)


def as_owner(ids):
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(ids['owner'])
        s['_fresh'] = True
        s['editing_website_id'] = ids['site']
    return c


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    ids = setup()
    c = as_owner(ids)
    fit = main.image_fit_style

    print('\n[1] an unframed picture gets no transform at all')
    # Every picture that has never been touched renders exactly as before.
    check(f'default is object-position only ({fit()})',
          fit() == 'object-position:50% 50%;')
    check('so nothing already published moves', 'transform' not in fit(100, 50, 50))

    print('\n[2] zoom scales, and focus stays inside the frame')
    css = fit(200, 50, 50)
    check(f'centred zoom does not need to translate ({css})',
          'scale(2)' in css and 'translate(0%,0%)' in css)
    # At the extreme the picture edge must land exactly on the frame edge:
    # shift = (50-fx)*(z-1)/100 frames = 0.5, and the element spans ±z/2 about
    # the centre, so its left edge sits at 0.5 - 1 + 0.5 = 0.
    css = fit(200, 0, 50)
    check(f'focus at the left edge shifts by exactly half a frame ({css})',
          'translate(25%,0%)' in css)
    check('and object-position agrees on the direction',
          css.startswith('object-position:0% 50%;'))
    check('vertical works the same way',
          'translate(0%,25%)' in fit(200, 50, 0))

    print('\n[3] the numbers are clamped, never trusted')
    for label, args, want in (
            ('below 100% is not allowed (it would show gaps)', (10, 50, 50), 100),
            ('above the maximum is capped', (9999, 50, 50), main.IMAGE_ZOOM_MAX),
            ('nonsense falls back to unzoomed', ('abc', 50, 50), 100)):
        got = main.clamp_image_fit(*args)[0]
        check(f'{label} — {args[0]} → {got}', got == want)
    check('focus is held to 0–100',
          main.clamp_image_fit(150, -40, 900)[1:] == (0, 100))
    check('and nonsense focus centres it',
          main.clamp_image_fit(150, None, 'x')[1:] == (50, 50))

    print('\n[4] the editor preview and the server agree exactly')
    # The slider draws its own preview. If the two implementations drift, what
    # you framed is not what readers see — and nothing else would catch it.
    src = open(os.path.join(_REPO, 'Templates', 'components', 'image_spot.html')).read()
    body = src[src.index('function fitCss('):src.index('function paintFit(')]
    clamp = src[src.index('function clampFit('):src.index('/* Must match')]
    harness = (f'const ZOOM_MIN={main.IMAGE_ZOOM_MIN},ZOOM_MAX={main.IMAGE_ZOOM_MAX};'
               + clamp + body + '''
const cases = JSON.parse(process.argv[2]);
console.log(JSON.stringify(cases.map(a => fitCss({zoom: a[0], focus_x: a[1], focus_y: a[2]}))));
''')
    path = os.path.join(_SCRATCH, 'fit.js')
    with open(path, 'w') as f:
        f.write(harness)
    cases = [[100, 50, 50], [200, 50, 50], [200, 0, 50], [150, 25, 75],
             [300, 100, 0], [135, 60, 40], [9999, -5, 250], [105, 50, 50],
             # Reset and "new picture" pass nothing at all. Number(null) is 0
             # in JavaScript, so this is where the two drift if anywhere does.
             [None, None, None], ['', '', ''], ['abc', None, 50]]
    py = [fit(*a) for a in cases]
    r = subprocess.run(['node', path, json.dumps(cases)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        check(f'the browser maths runs — {r.stderr[:120]}', False)
    else:
        js = json.loads(r.stdout)
        for a, j, p in zip(cases, js, py):
            check(f'zoom {a[0]}% focus {a[1]}/{a[2]} → {p}', j == p)

    # The guide cover preview is a second implementation of the same maths
    # (it lives in the guide modal, not the shared component), so it gets held
    # to the same standard rather than assumed to match.
    gsrc = open(os.path.join(_REPO, 'Templates', 'guides_admin.html')).read()
    gclamp = gsrc[gsrc.index('function gpClampFit('):gsrc.index('function gpPaintCoverFit(')]
    gpaint = gsrc[gsrc.index('function gpPaintCoverFit('):gsrc.index('function gpResetCoverFit(')]
    gharness = (f'const GP_ZOOM_MIN={main.IMAGE_ZOOM_MIN},'
                f'GP_ZOOM_MAX={main.IMAGE_ZOOM_MAX};let gpCoverFit;'
                + gclamp
                # Only the css string is under test, so stub out the DOM the
                # painter writes into.
                + gpaint.replace(
                    "const img = document.getElementById('guideModalCoverImg');",
                    'const img = {setAttribute: (k, v) => { OUT = v; }};')
                  .replace("document.getElementById('guideModalCoverZoom').value"
                           " = gpCoverFit.zoom;", '')
                  .replace("document.getElementById('guideModalCoverZoomVal')"
                           ".textContent = gpCoverFit.zoom + '%';", '')
                + '''
let OUT = '';
const cases = JSON.parse(process.argv[2]);
console.log(JSON.stringify(cases.map(a => {
    gpCoverFit = {zoom: a[0], focus_x: a[1], focus_y: a[2]};
    gpPaintCoverFit();
    // The cover img carries its own layout rules ahead of the framing.
    return OUT.replace('width:100%;max-height:180px;object-fit:cover;display:block;', '');
})));
''')
    gpath = os.path.join(_SCRATCH, 'gfit.js')
    with open(gpath, 'w') as f:
        f.write(gharness)
    r = subprocess.run(['node', gpath, json.dumps(cases)], capture_output=True, text=True)
    if r.returncode != 0:
        check(f'the guide cover maths runs — {r.stderr[:120]}', False)
    else:
        gjs = json.loads(r.stdout)
        mismatch = [(a, g, p) for a, g, p in zip(cases, gjs, py) if g != p]
        check(f'the guide cover preview matches the server on all '
              f'{len(cases)} cases too — {mismatch[:1]}', not mismatch)

    print('\n[5] framing saves and comes back')
    r = c.post(f"/admin/quizzes/{ids['quiz']}/update",
               json={'title': 'Safety', 'image_url': URL, 'image_zoom': 180,
                     'image_focus_x': 30, 'image_focus_y': 70})
    check(f'quiz — got {r.status_code}', r.status_code == 200)
    r = c.post(f"/admin/resources/{ids['resource']}/update",
               json={'title': 'Checklist', 'resource_type': 'page', 'content': '<p>x</p>',
                     'image_url': URL, 'image_zoom': 220,
                     'image_focus_x': 10, 'image_focus_y': 90})
    check(f'resource — got {r.status_code}', r.status_code == 200)
    r = c.post(f"/admin/guides/{ids['guide']}/update",
               json={'title': 'Soldering', 'cover_image_url': URL, 'cover_zoom': 140,
                     'cover_focus_x': 50, 'cover_focus_y': 20})
    check(f'guide cover — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        q = db.session.get(main.Quiz, ids['quiz'])
        rs = db.session.get(main.Resource, ids['resource'])
        g = db.session.get(main.Guide, ids['guide'])
        check(f'the quiz kept it ({q.image_zoom}%, {q.image_focus_x}/{q.image_focus_y})',
              (q.image_zoom, q.image_focus_x, q.image_focus_y) == (180, 30, 70))
        check(f'the resource kept it ({rs.image_zoom}%)',
              (rs.image_zoom, rs.image_focus_x, rs.image_focus_y) == (220, 10, 90))
        check(f'the guide kept it ({g.cover_zoom}%)',
              (g.cover_zoom, g.cover_focus_x, g.cover_focus_y) == (140, 50, 20))

    print('\n[6] the route clamps too, not just the helper')
    c.post(f"/admin/quizzes/{ids['quiz']}/update",
           json={'title': 'Safety', 'image_url': URL, 'image_zoom': 5000,
                 'image_focus_x': -80, 'image_focus_y': 'oops'})
    with app.app_context():
        q = db.session.get(main.Quiz, ids['quiz'])
        check(f'a wild payload lands in range ({q.image_zoom}%, '
              f'{q.image_focus_x}/{q.image_focus_y})',
              (q.image_zoom, q.image_focus_x, q.image_focus_y)
              == (main.IMAGE_ZOOM_MAX, 0, 50))
    # An older client that knows nothing about framing must not wipe it.
    c.post(f"/admin/quizzes/{ids['quiz']}/update",
           json={'title': 'Safety', 'image_url': URL})
    with app.app_context():
        check('and a payload with no framing leaves it alone',
              db.session.get(main.Quiz, ids['quiz']).image_zoom == main.IMAGE_ZOOM_MAX)

    print('\n[7] it reaches every page the picture appears on')
    c.post(f"/admin/quizzes/{ids['quiz']}/update",
           json={'title': 'Safety', 'image_url': URL, 'image_zoom': 180,
                 'image_focus_x': 30, 'image_focus_y': 70})
    from bs4 import BeautifulSoup
    anon = app.test_client()
    quiz_css = main.image_fit_style(180, 30, 70)
    guide_css = main.image_fit_style(140, 50, 20)

    soup = BeautifulSoup(anon.get('/guides').get_data(as_text=True), 'html.parser')
    imgs = [i for i in soup.select('.gi-rsc-pic img') if 'scale(1.8)' in (i.get('style') or '')]
    check(f'the education list styles the quiz picture ({len(imgs)})', len(imgs) == 1)
    covers = [i for i in soup.select('img.gi-cover') if 'scale(1.4)' in (i.get('style') or '')]
    check(f'and the guide card cover ({len(covers)})', len(covers) >= 1)

    page = anon.get(f"/quiz/{ids['quiz']}").get_data(as_text=True)
    check('the quiz page carries it', quiz_css in page)
    page = anon.get(f"/resource/{ids['resource']}").get_data(as_text=True)
    check('the resource page carries it', main.image_fit_style(220, 10, 90) in page)
    page = anon.get('/guides/sold').get_data(as_text=True)
    check('the guide page carries it', guide_css in page)
    page = c.get('/admin/resources').get_data(as_text=True)
    check('and the admin list shows the same framing',
          main.image_fit_style(220, 10, 90) in page)

    print('\n[8] a zoomed picture is clipped by its frame')
    # transform: scale() paints outside the element's own box, so every slot
    # that can be zoomed needs an ancestor that clips — otherwise a zoomed
    # picture spills over the title next to it.
    gi = open(os.path.join(_REPO, 'Templates', 'guides_index.html')).read()
    # The row styles moved to a shared stylesheet when the bundle page needed
    # them too, so the clipping rule is checked where it now lives.
    rowcss = open(os.path.join(_REPO, 'static', 'css', 'resource_rows.css')).read()
    check('the inline picture slot clips',
          re.search(r'\.gi-rsc-pic\s*\{[^}]*overflow:\s*hidden', rowcss))
    check('and every page showing those rows links that stylesheet',
          all('css/resource_rows.css' in open(
                  os.path.join(_REPO, 'Templates', t)).read()
              for t in ('guides_index.html', 'public_bundle_page.html')))
    check('the guide card clips its cover',
          re.search(r'\.gi-card\s*\{[^}]*overflow:\s*hidden', gi))
    gv = open(os.path.join(_REPO, 'Templates', 'guide_view.html')).read()
    check('the guide page wraps its cover in a clipping box',
          re.search(r'\.gv-cover-wrap\s*\{[^}]*overflow:\s*hidden', gv)
          and 'class="gv-cover-wrap"' in gv)
    for label, tpl in (('quiz', 'public_quiz_page.html'),
                       ('resource', 'public_resource_page.html')):
        src = open(os.path.join(_REPO, 'Templates', tpl)).read()
        soup = BeautifulSoup(src, 'html.parser')
        wrap = soup.select_one('span[style*="overflow:hidden"]')
        check(f'the {label} page heading picture is wrapped in a clipping box',
              wrap is not None and wrap.find('img') is not None)
    ra = open(os.path.join(_REPO, 'Templates', 'resources_admin.html')).read()
    check('and the admin list slot clips',
          re.search(r'\.ra-item-pic\s*\{[^}]*overflow:\s*hidden', ra))

    print('\n[9] the controls are in all three editors')
    for label, path, sel in (('quizzes', '/admin/quizzes', '[data-spot-zoom]'),
                             ('resources', '/admin/resources', '[data-spot-zoom]'),
                             ('guides', '/admin/guides', '#guideModalCoverZoom')):
        soup = BeautifulSoup(c.get(path).get_data(as_text=True), 'html.parser')
        slider = soup.select_one(sel)
        check(f'{label}: a zoom slider is there', slider is not None)
        check(f'{label}: with the same range the server enforces '
              f'({slider and slider.get("min")}–{slider and slider.get("max")})',
              slider is not None
              and int(slider['min']) == main.IMAGE_ZOOM_MIN
              and int(slider['max']) == main.IMAGE_ZOOM_MAX)
    body = c.get('/admin/resources').get_data(as_text=True)
    check('the saved framing is handed to the editor',
          'image_zoom' in body and 'image_focus_x' in body)
    body = c.get('/admin/guides').get_data(as_text=True)
    check('and so is the guide cover framing',
          'cover_zoom' in body or 'gpCoverFit' in body)

    print('\n[10] a backup carries the picture and its framing')
    # image_url was never in the backup at all before this, so restoring an
    # instance silently dropped every picture.
    with app.app_context():
        data = main._serialize_backup(ids['owner'])
    q = next(x for x in data['quizzes'] if x['id'] == ids['quiz'])
    rs = next(x for x in data['resources'] if x['id'] == ids['resource'])
    g = next(x for x in data['guides'] if x['id'] == ids['guide'])
    check(f'the quiz picture is in it ({q.get("image_url")})', q.get('image_url') == URL)
    check(f'with its framing ({q.get("image_zoom")}%)',
          (q.get('image_zoom'), q.get('image_focus_x'), q.get('image_focus_y'))
          == (180, 30, 70))
    check('the resource picture too', rs.get('image_url') == URL
          and rs.get('image_zoom') == 220)
    check('and the guide cover framing', g.get('cover_zoom') == 140
          and g.get('cover_focus_y') == 20)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
