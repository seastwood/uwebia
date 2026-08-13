"""Guides, quizzes and resources are tabs of one page.

    venv/bin/python tests/test_education_tabs.py

They share a category model and get used together constantly, so paying a full
page load to move between them made closely-related work feel like three jobs.

The three pages are NOT merged. They collide too much to combine safely — 14
duplicate element ids, 20 shared-but-drifted CSS classes, and three copies of a
category modal that no longer match — so each keeps its own document and the
shell shows them in panes.

What that buys, and therefore what this pins down:

  * every existing page still works untouched, and stays reachable on its own
    URL for bookmarks and direct links;
  * a pane drops its navbar, because the shell already draws one and two
    stacked bars would eat the top of every pane;
  * a pane that navigates itself (opening a guide editor, a redirect after a
    save) escapes to the whole window instead of stranding a full page inside
    a 900px box;
  * the tab is in the URL, so a reload or a bookmark comes back to it;
  * a tab you cannot view is not offered.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-education-tabs')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-edtabs-test-')
shutil.copy2(os.path.join(_REPO, 'main.py'), os.path.join(_SCRATCH, 'main.py'))
for _linked in ('Templates', 'icons'):
    _src = os.path.join(_REPO, _linked)
    if os.path.exists(_src):
        os.symlink(_src, os.path.join(_SCRATCH, _linked))
os.makedirs(os.path.join(_SCRATCH, 'static', 'uploads'), exist_ok=True)

sys.path.insert(0, _SCRATCH)
import main  # noqa: E402

assert os.path.dirname(os.path.abspath(main.__file__)) == _SCRATCH, \
    'refusing to run against the real checkout'

app, db = main.app, main.db
FAILURES = []


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
        db.session.add(main.Guide(website_id=site.id, title='Swerve', slug='swerve',
                                  status='published'))
        db.session.add(main.Quiz(website_id=site.id, title='Safety'))
        db.session.add(main.Resource(website_id=site.id, title='Handbook',
                                     resource_type='link', url='https://x/y'))
        db.session.commit()

        sub = main.User(username='helper', parent_user_id=owner.id)
        sub.set_password('helperpassword')
        sub.permissions = {'guides.view': True}     # guides only
        db.session.add(sub)
        db.session.commit()
        return dict(owner=owner.id, sub=sub.id, site=site.id)


def _active_tab(html):
    """Which tab the shell rendered as active, per the markup."""
    from bs4 import BeautifulSoup
    btn = BeautifulSoup(html, 'html.parser').select_one('.ed-tab.active')
    return btn.get('data-key') if btn else None


def client_for(uid, site_id):
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(uid)
        s['_fresh'] = True
        s['admin_website_id'] = site_id
    return c


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    ids = setup()
    c = client_for(ids['owner'], ids['site'])

    print('\n[1] one page carries all three')
    r = c.get('/admin/education')
    check(f'the shell loads ({r.status_code})', r.status_code == 200)
    html = r.get_data(as_text=True)
    for key in ('guides', 'quizzes', 'resources'):
        check(f'{key} has a tab and a pane',
              f'id="edTab-{key}"' in html and f'id="edPane-{key}"' in html)
    check(f'guides opens first ({_active_tab(html)})', _active_tab(html) == 'guides')
    check('panes point at the embedded pages',
          'data-src="/admin/guides?embed=1"' in html)

    print('\n[2] only the first pane loads up front')
    # Three iframes all fetching on page load would cost three full renders to
    # look at one tab.
    check('no iframe ships with a src', '<iframe class="ed-pane" id="edPane-guides" role="tabpanel"' in html
          and 'src=' not in html.split('<iframe class="ed-pane"')[1].split('>')[0])
    check('the src is filled in on first activation', 'pane.src = tab.dataset.src' in html)
    check('and a loaded pane is kept, not re-fetched', 'if (on && !pane.src)' in html)

    print('\n[3] the tab is in the URL')
    r = c.get('/admin/education/quizzes')
    check(f'a tab URL loads ({r.status_code})', r.status_code == 200)
    body = r.get_data(as_text=True)
    check(f'and opens that tab ({_active_tab(body)})', _active_tab(body) == 'quizzes')
    check('switching rewrites the address bar',
          "history.replaceState(null, '', `/admin/education/${key}`)" in body)
    r = c.get('/admin/education/nonsense')
    check(f'an unknown tab falls back rather than 404s ({r.status_code})',
          r.status_code == 200)

    print('\n[4] an embedded page drops its own navbar')
    plain = c.get('/admin/guides').get_data(as_text=True)
    embed = c.get('/admin/guides?embed=1').get_data(as_text=True)
    check('the standalone page still has one', 'class="navbar"' in plain)
    check('the embedded one does not', 'class="navbar"' not in embed)
    check('and reclaims the 52px the navbar reserved',
          '.content { padding-top: 0; }' in embed)
    check('but is otherwise the same page',
          'Swerve' in plain and 'Swerve' in embed)
    for path in ('/admin/quizzes', '/admin/resources'):
        e = c.get(f'{path}?embed=1').get_data(as_text=True)
        check(f'{path} embeds too', 'class="navbar"' not in e)

    print('\n[5] a stranded page escapes the pane')
    # A pane opening a guide editor must take the whole window, or you get a
    # full-page editor inside a 900px box with two navbars.
    editor = c.get('/admin/guides').get_data(as_text=True)
    check('every admin page carries the breakout', 'function breakOutOfPane' in editor)
    check('it only fires inside a frame', 'window.top === window.self' in editor)
    check('and leaves a page that asked to be embedded alone',
          "get('embed') === '1'" in editor)
    check('a cross-origin frame is not touched',
          'cross-origin frame' in editor)
    check('the embedded page keeps the guard too',
          'function breakOutOfPane' in embed)

    print('\n[6] the originals still stand on their own')
    for path in ('/admin/guides', '/admin/quizzes', '/admin/resources'):
        check(f'{path} still loads directly', c.get(path).status_code == 200)

    print('\n[7] a tab you cannot view is not offered')
    sc = client_for(ids['sub'], ids['site'])
    sub_html = sc.get('/admin/education').get_data(as_text=True)
    check('the granted tab is there', 'id="edTab-guides"' in sub_html)
    check('the others are not',
          'id="edTab-quizzes"' not in sub_html and 'id="edTab-resources"' not in sub_html)
    check('and asking for one by URL still lands somewhere usable',
          sc.get('/admin/education/quizzes').status_code == 200)
    r = sc.get('/admin/quizzes')
    check(f'while the page itself stays gated ({r.status_code})', r.status_code != 200)

    print('\n[8] the navbar points at the tabs')
    nav = c.get('/admin/education').get_data(as_text=True)
    check('Guides goes to its tab', '/admin/education/guides' in nav)
    check('Quizzes goes to its tab', '/admin/education/quizzes' in nav)
    check('Resources goes to its tab', '/admin/education/resources' in nav)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
