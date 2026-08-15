"""The group permission editor is laid out like the per-user one.

    venv/bin/python tests/test_permission_editors_match.py

The per-user editor groups permissions into labelled categories and has a
search box. The group editor listed the raw schema in declaration order with
neither, which is the same 133 checkboxes but far harder to find anything in.

The check that matters is that regrouping did not quietly drop or duplicate a
permission: the two editors must offer exactly the same keys, in the same
order.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import atexit
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-perm-editors')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-permui-test-')
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


def setup():
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
        site = main.Website(user_id=owner.id, name='Site', is_draft=False)
        db.session.add(site)
        db.session.commit()
        return owner.id, site.id


def main_test():
    owner_id, site_id = setup()
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(owner_id)
        s['_fresh'] = True
        s['admin_website_id'] = site_id
    html = c.get('/admin/users').get_data(as_text=True)

    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')

    def keys(*ids):
        out = []
        for i in ids:
            el = soup.select_one('#' + i)
            if el:
                out += [inp.get('data-key') for inp in el.select('input[data-key]')]
        return out

    def cats(*ids):
        return [el.get_text(strip=True)
                for i in ids
                for el in (soup.select_one('#' + i) or soup.new_tag('div'))
                .select('.perm-category-label')]

    user = keys('permissionsContainer', 'permissionsContainerWebsite')
    group = keys('groupPermissionsContainer', 'groupPermissionsContainerWebsite')

    print('\n[1] both editors offer the same permissions')
    check(f'the per-user editor lists some ({len(user)})', len(user) > 50)
    check('no duplicates in the per-user editor', len(user) == len(set(user)))
    check('no duplicates in the group editor', len(group) == len(set(group)))
    check('the group editor offers exactly the same set',
          sorted(group) == sorted(user))
    check('in the same order', group == user)

    print('\n[2] and every permission the app defines is reachable')
    defined = set()
    for section_key, section in main.ADMIN_PERMISSIONS.items():
        for action_key in section['actions']:
            defined.add(f'{section_key}.{action_key}')
    missing = defined - set(group)
    for m in sorted(missing):
        print(f'         missing from the group editor: {m}')
    check(f'nothing in ADMIN_PERMISSIONS is missing ({len(defined)} defined)',
          not missing)

    print('\n[3] the group editor is grouped and searchable like the other')
    ucats = cats('permissionsContainer', 'permissionsContainerWebsite')
    gcats = cats('groupPermissionsContainer', 'groupPermissionsContainerWebsite')
    check(f'the per-user editor has category headings ({len(ucats)})', len(ucats) > 1)
    check('the group editor has the same headings, in order', gcats == ucats)
    check('the group editor has a search box',
          soup.select_one('#groupPermSearch') is not None)
    check('wired to its own filter',
          'filterGroupPermissions' in (soup.select_one('#groupPermSearch') or {}).get('oninput', ''))
    check('and its own result count',
          soup.select_one('#groupPermSearchCount') is not None)

    print('\n[4] one filter implementation, not two')
    check('the matching logic is shared', html.count('function _filterPermGrids') == 1)
    check('the per-user entry point still exists', 'function filterPermissions(' in html)
    check('the group entry point exists', 'function filterGroupPermissions(' in html)
    check('reopening a group clears a stale search',
          'clearGroupPermissionSearch();' in html)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
