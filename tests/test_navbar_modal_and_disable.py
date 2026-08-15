"""One Navbar modal with tabs, and entries you can switch off instead of delete.

    venv/bin/python tests/test_navbar_modal_and_disable.py

Two changes to the website editor:

  * Routing and Style were two buttons opening two separate modals, so tuning
    the look of a navbar meant leaving the screen where you arranged it. They
    are tabs of one modal now.

  * Removing an entry for a while used to mean deleting it and rebuilding the
    name, URL, group and position later. An entry can be switched off instead:
    it stays in the stored JSON with `disabled: true` and is filtered out on
    the way to the public template.

The filtering happens in ONE place, visible_navbar_items(), because
public_navbar.html walks the list twice (desktop and mobile) and each pass
branches on link/system/group separately — six render sites that would
otherwise have to stay in step.

The round-trip is what this mostly guards. An earlier bug in this same code
had the editor rebuild saved children as blank link rows, so anything it did
not understand was silently dropped by the next save. A `disabled` flag that
collect() writes but load() ignores would fail exactly that way: switch an
item off, reload the editor, and it comes back on.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import atexit
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-navbar-modal')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-navmodal-test-')
# Each of these holds a ~2.5 MB copy of main.py and a SQLite database; nothing
# removed them, so repeated suite runs left GBs behind in /tmp.
atexit.register(shutil.rmtree, _SCRATCH, ignore_errors=True)
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
# The uploads path must live in the scratch dir: a test that reaches a delete
# path through a symlinked static/ removes the real instance's images.
assert os.path.realpath(main.uploads_folder).startswith(os.path.realpath(_SCRATCH)), \
    'uploads folder escapes the scratch directory'

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
        site = main.Website(user_id=owner.id, name='Site', is_draft=False,
                            is_live=True, store_enabled=True)
        db.session.add(site)
        db.session.commit()
        page = main.PublicPageContent(website_id=site.id, name='Home', slug='home',
                                      site_active_status=True)
        db.session.add(page)
        db.session.commit()
        return dict(owner=owner.id, site=site.id, page=page.id)


def as_owner(ids):
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(ids['owner'])
        s['_fresh'] = True
        s['admin_website_id'] = ids['site']
        s['editing_website_id'] = ids['site']
    return c


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    ids = setup()
    c = as_owner(ids)
    from bs4 import BeautifulSoup

    print('\n[1] one Navbar button, two tabs')
    soup = BeautifulSoup(c.get('/admin/websites').get_data(as_text=True), 'html.parser')
    labels = [b.get_text(strip=True) for b in soup.select('.website-action-button')
              if 'Navbar' in b.get_text()]
    check(f'the separate Navbar Style button is gone ({labels})', labels == ['Navbar'])
    modal = soup.select_one(f"#publicNavbarModal_{ids['site']}")
    check('the Navbar modal renders', modal is not None)
    check('the old style modal is gone',
          soup.select_one(f"#publicNavbarStyleModal_{ids['site']}") is None)
    tabs = [b.get_text(strip=True)
            for b in modal.select(':scope > .navbar-modal-tabs > .navbar-modal-tab')]
    check(f'it has both tabs ({tabs})', tabs == ['Routing', 'Style'])

    print('\n[2] both panes are there, with their own content and save button')
    panes = {p.get('data-navpane'): p for p in modal.select(':scope > .navbar-modal-pane')}
    check(f'two panes ({sorted(panes)})', sorted(panes) == ['routes', 'style'])
    check('Routing opens first', not panes['routes'].has_attr('hidden'))
    check('Style starts hidden', panes['style'].has_attr('hidden'))
    check('the routing pane still holds the item list',
          panes['routes'].select_one(f"#navbarItems_{ids['site']}") is not None)
    check('the style pane kept its controls',
          panes['style'].select_one(f"#navbarTextColor_{ids['site']}") is not None)
    check('and each pane saves its own half',
          'savePublicNavbar(' in str(panes['routes'])
          and 'savePublicNavbarStyle(' in str(panes['style']))
    # A button pointing at a removed element is a dead button, not an error.
    page_src = str(soup)
    check('nothing still targets the removed modal id',
          'publicNavbarStyleModal' not in page_src)

    print('\n[3] switching an entry off hides it from the public navbar')
    items = [
        {'type': 'link', 'name': 'Shown', 'url': '/a'},
        {'type': 'link', 'name': 'Hidden', 'url': '/b', 'disabled': True},
        {'type': 'system', 'key': 'shop', 'name': 'Store', 'disabled': True},
    ]
    with app.app_context():
        w = db.session.get(main.Website, ids['site'])
        w.public_navbar_items = items
        db.session.commit()
    vis = main.visible_navbar_items(items)
    check(f'the filter keeps only the live one ({[i["name"] for i in vis]})',
          [i['name'] for i in vis] == ['Shown'])
    check('a disabled system page is dropped even though its feature is on',
          all(i.get('key') != 'shop' for i in vis))
    check('and navbar_entry_target refuses it directly too',
          main.navbar_entry_target({'type': 'link', 'name': 'X', 'url': '/x',
                                    'disabled': True}, None) is None)

    print('\n[4] the filter must not eat the stored data')
    # It runs on the column value; mutating it would make hiding permanent.
    check(f'the original list is untouched ({len(items)} entries)', len(items) == 3)
    check('including the disabled flags', items[1].get('disabled') is True)

    print('\n[5] groups: children, and the group itself')
    grp = [{'type': 'group', 'name': 'More', 'url': '', 'children': [
        {'type': 'link', 'name': 'Kept', 'url': '/k'},
        {'type': 'link', 'name': 'Off', 'url': '/o', 'disabled': True},
    ]}]
    vis = main.visible_navbar_items(grp)
    check(f'a disabled child goes ({[ch["name"] for ch in vis[0]["children"]]})',
          [ch['name'] for ch in vis[0]['children']] == ['Kept'])
    check('the stored group still has both children',
          len(grp[0]['children']) == 2)

    off_grp = [dict(grp[0], disabled=True)]
    check('a disabled group takes its children with it',
          main.visible_navbar_items(off_grp) == [])

    empty = [{'type': 'group', 'name': 'More', 'url': '', 'children': [
        {'type': 'link', 'name': 'Off', 'url': '/o', 'disabled': True}]}]
    check('a group whose every child is off does not render as an empty dropdown',
          main.visible_navbar_items(empty) == [])
    linked = [{'type': 'group', 'name': 'More', 'url': '/more', 'children': [
        {'type': 'link', 'name': 'Off', 'url': '/o', 'disabled': True}]}]
    check('unless its own label is a link, which still works',
          len(main.visible_navbar_items(linked)) == 1)

    print('\n[6] the public page renders without the hidden entries')
    r = app.test_client().get('/')
    check(f'the site loads ({r.status_code})', r.status_code == 200)
    html = r.get_data(as_text=True)
    nav = html[:html.index('</nav>')] if '</nav>' in html else html
    check('the live link is in the navbar', 'Shown' in nav)
    check('the switched-off link is not', 'Hidden' not in nav)
    check('nor the switched-off system page', '>Store<' not in nav)

    print('\n[7] the flag survives a save — otherwise reloading turns it back on')
    r = c.post(f"/edit_public_navbar/{ids['site']}",
               json={'public_navbar_items': [
                   {'type': 'link', 'name': 'A', 'url': '/a', 'disabled': True},
                   {'type': 'group', 'name': 'G', 'url': '', 'disabled': True, 'children': [
                       {'type': 'link', 'name': 'B', 'url': '/b', 'disabled': True}]},
               ]})
    check(f'the save succeeds ({r.status_code})', r.status_code == 200)
    with app.app_context():
        stored = db.session.get(main.Website, ids['site']).public_navbar_items
    check(f'the top-level flag persisted ({stored[0].get("disabled")})',
          stored[0].get('disabled') is True)
    check('the group flag persisted', stored[1].get('disabled') is True)
    check('and the child flag persisted',
          stored[1]['children'][0].get('disabled') is True)

    print('\n[8] the editor reads the flag back, on every row type')
    src = open(os.path.join(_REPO, 'Templates', 'dashboard.html')).read()
    check('collect writes it for links and system pages',
          src.count('disabled: isNavbarRowDisabled(el)') >= 3)
    check('and for group children',
          'const off = isNavbarRowDisabled(child);' in src)
    for fn, arg in (('addNavbarItem', 'disabled = false'),
                    ('addSystemNavbarItem', 'disabled = false'),
                    ('addNavbarGroup', 'disabled = false')):
        at = src.index(f'function {fn}(')
        check(f'{fn} accepts the flag back',
              arg in src[at:at + 200])
    at = src.index('function loadNavbarItems(')
    body = src[at:src.index('function ', at + 10)]
    check('load passes it to all three',
          body.count('!!item.disabled') == 3)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
