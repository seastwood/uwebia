"""A system page (Shop / Forum) may live inside a public-navbar dropdown.

    venv/bin/python tests/test_navbar_system_in_dropdown.py

Every part of the navbar assumed a dropdown child was a plain link:

  • the editor's collectNavbarItems() read child.querySelector('.navbar-url')
    .value — a system row has no such input, so it threw a TypeError on the
    first line of savePublicNavbar(), before the fetch. The Save button did
    nothing: no request, no alert, no error. That is the reported bug.
  • addNavbarGroup() rebuilt every saved child as a link row, so even a child
    that survived would come back blank and be dropped by the next save.
  • the public navbar template called child.url.split('#') — no url on a
    system child, so rendering one raised straight out of the template.

Both kinds now resolve through navbar_entry_target(), which also returns None
when the feature behind a system page is switched off, so a Shop entry
disappears with the store rather than pointing at a dead page.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import atexit
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-navbar-dropdown')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-navbar-test-')
# Each of these holds a ~2.5 MB copy of main.py and a SQLite database; nothing
# removed them, so repeated suite runs left GBs behind in /tmp.
atexit.register(shutil.rmtree, _SCRATCH, ignore_errors=True)
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


def check(label, cond):
    print(('  PASS  ' if cond else '  FAIL  ') + label)
    if not cond:
        FAILURES.append(label)


class _Site:
    """Just the attributes navbar_entry_target reads."""
    def __init__(self, **kw):
        self.store_enabled = kw.get('store_enabled', True)
        self.forum_enabled = kw.get('forum_enabled', True)
        self.url_prefix = kw.get('url_prefix')
        self.store_title = kw.get('store_title')
        self.forum_title = kw.get('forum_title')


def main_test():
    print('\n[1] resolving one navbar entry')
    with app.test_request_context('/'):
        f = main.navbar_entry_target
        site = _Site()
        check('a system shop child gets the shop URL',
              f({'type': 'system', 'key': 'shop'}, site) == ('/shop', 'Shop'))
        check('a custom name on it is kept',
              f({'type': 'system', 'key': 'shop', 'name': 'Merch'}, site)[1] == 'Merch')
        check('a system forum child resolves too',
              f({'type': 'system', 'key': 'forum'}, site)[0] == '/forum')
        check('a plain link child still works',
              f({'type': 'link', 'name': 'About', 'url': '/about'}, site) == ('/about', 'About'))
        check('an entry with no type is treated as a link',
              f({'name': 'About', 'url': '/about'}, site) == ('/about', 'About'))

        check('a link with no url is dropped, not rendered empty',
              f({'type': 'link', 'name': 'X', 'url': ''}, site) is None)
        check('an unknown system key is dropped',
              f({'type': 'system', 'key': 'bogus'}, site) is None)
        check('a shop entry hides when the store is off',
              f({'type': 'system', 'key': 'shop'},
                _Site(store_enabled=False)) is None)
        check('a forum entry hides when the forum is off',
              f({'type': 'system', 'key': 'forum'},
                _Site(forum_enabled=False)) is None)
        check('junk in the stored JSON does not raise',
              f('not-a-dict', site) is None and f(None, site) is None)

    print('\n[2] a prefixed site keeps its own forum URL')
    with app.test_request_context('/'):
        got = main.navbar_entry_target({'type': 'system', 'key': 'forum'},
                                       _Site(url_prefix='club'))
        check(f'the forum child points inside the prefix ({got[0]})',
              got[0] != '/forum' and 'club' in got[0])

    print('\n[3] the page renders with a system page inside a dropdown')
    with app.app_context():
        db.create_all()
        website = main.Website.query.filter_by(is_draft=False).first()
        if website is None:
            owner = main.User(username='owner', parent_user_id=None)
            owner.set_password('x')
            db.session.add(owner)
            db.session.commit()
            website = main.Website(user_id=owner.id, name='Site', is_draft=False,
                                   is_live=True)
            db.session.add(website)
            db.session.commit()
            # home_page() wants slug 'home', published, on a live site.
            db.session.add(main.PublicPageContent(website_id=website.id,
                                                  name='Home', slug='home',
                                                  site_active_status=True))
            db.session.commit()
        check('there is a live website to render', website is not None)
        website.store_enabled = True
        website.forum_enabled = True
        website.public_navbar_items = [
            {'type': 'link', 'name': 'Home', 'url': '/'},
            {'type': 'group', 'name': 'More', 'url': '', 'children': [
                {'type': 'link', 'name': 'About', 'url': '/about'},
                {'type': 'system', 'key': 'shop', 'name': 'Merch'},
            ]},
        ]
        db.session.commit()

    with app.test_client() as c:
        r = c.get('/')
        body = r.get_data(as_text=True)
    check(f'the public page renders (was a 500) — got {r.status_code}',
          r.status_code == 200)
    check('the dropdown itself is there', 'More' in body)
    check('the plain child is still rendered', '/about' in body)
    check('the SYSTEM child renders inside it', '/shop' in body)
    check('under its custom name', 'Merch' in body)

    print('\n[4] the same entry hides when the store is switched off')
    with app.app_context():
        website = main.Website.query.filter_by(is_draft=False).first()
        website.store_enabled = False
        db.session.commit()
    with app.test_client() as c:
        r = c.get('/')
        body = r.get_data(as_text=True)
    check('the page still renders', r.status_code == 200)
    check('the shop entry is gone rather than dead', 'Merch' not in body)
    check('and the rest of the dropdown survives', '/about' in body)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
