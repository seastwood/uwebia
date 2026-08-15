"""The settings page splits into "Your account" and "Site settings".

    venv/bin/python tests/test_settings_tabs.py

Cards are tagged with data-settings-tab rather than moved, so each one keeps
the script that drives it as a neighbour, and both panes stay inside the single
form — a save still posts exactly the fields it always did.

Also pins down two things the split exposed: your own authenticator and your
own GitHub link were behind settings.edit, the org-settings permission, so a
sub-admin without it could not set up the second factor the org may require.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import atexit
import os
import re
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-settings-tabs')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-tabs-test-')
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


def card_tab(html, title):
    """Which pane the card carrying this heading is tagged for."""
    idx = html.find(f'settings-section-title">{title}<')
    if idx < 0:
        return None
    before = html[:idx]
    start = before.rfind('settings-card')
    m = re.search(r'data-settings-tab="(user|site)"', html[start:idx])
    return m.group(1) if m else None


def setup():
    with app.app_context():
        db.create_all()
        db.session.remove()
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        db.session.commit()

        owner = main.User(username='owner', parent_user_id=None,
                          email='owner@example.com')
        owner.set_password('x')
        db.session.add(owner)
        db.session.commit()

        # Both of these cards are conditional, so without their prerequisites
        # they'd be absent and "is it in the right pane" would pass vacuously.
        db.session.add(main.GitHubLoginSettings(client_id='Iv1.test',
                                                client_secret='shh'))
        site = main.Website(user_id=owner.id, name='Site', is_draft=False)
        db.session.add(site)
        db.session.commit()
        db.session.add(main.PublicUser(website_id=site.id, username='owner',
                                       mirrored_admin_user_id=owner.id))
        db.session.commit()

        # A sub-admin who may VIEW settings but not edit them — the case that
        # used to lose access to their own authenticator setup.
        sub = main.User(username='helper', parent_user_id=owner.id,
                        email='helper@example.com',
                        permissions={'settings.view': True})
        sub.set_password('x')
        db.session.add(sub)
        db.session.commit()
        return owner.id, sub.id


def main_test():
    owner_id, sub_id = setup()
    app.config['WTF_CSRF_ENABLED'] = False

    with app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(owner_id)
            s['_fresh'] = True
        html = c.get('/admin/dashboard/settings').get_data(as_text=True)

    print('\n[1] the page offers two tabs')
    check('the page renders', bool(html) and 'settings-title' in html)
    check('a "Your account" tab', 'data-tab="user"' in html)
    check('a "Site settings" tab', 'data-tab="site"' in html)
    check('the container carries the active tab',
          'data-active-tab="user"' in html)

    print('\n[2] cards land in the right pane')
    expected = {
        'Account': 'user',
        'Two-Factor Authentication': 'user',
        'Authenticator App (TOTP)': 'user',
        'GitHub Account': 'user',
        'Date and Time': 'user',
        'Public Display Names': 'user',
        # The org-wide admin switches moved to the Admins page, where the
        # equivalent public-member switches already live; a signpost stays here.
        'Admin Access &amp; Policy': 'site',
        'GitHub Sign-In': 'site',
        'Logging': 'site',
        'Visitor IP retention': 'site',
        'Admin URL Key': 'site',
        'Site Features': 'site',
        'Admin Navbar': 'site',
        'Admin Branding': 'site',
        'Content Moderation': 'site',
        'Backup &amp; Restore': 'site',
        'Automatic Backups': 'site',
        'Database': 'site',
    }
    for title, tab in expected.items():
        got = card_tab(html, title)
        check(f'{title} -> {tab}', got == tab)

    print('\n[3] the DOM the tab CSS depends on')
    # The rule is `.settings-page[data-active-tab=X] [data-settings-tab=X]`, so
    # a card outside the container never matches. This is not hypothetical: the
    # Date and Time card used to close AFTER </form>, which made the parser
    # pin that tag on .settings-page and dropped every card below it outside —
    # seven of them, all of which the string assertions above happily passed.
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')
    page = soup.select_one('.settings-page')
    check('the .settings-page container exists', page is not None)
    inside = {id(x) for x in page.descendants} if page else set()
    tagged = soup.select('[data-settings-tab]')
    stray = [t for t in tagged if id(t) not in inside]
    for t in stray:
        title = t.select_one('.settings-section-title')
        print(f'         outside the container: '
              f'{title.get_text(strip=True) if title else t.name}')
    check(f'all {len(tagged)} tagged elements are inside it', not stray)

    form = soup.select_one('form.settings-form')
    check('the form survived the restructure', form is not None)
    if form:
        posted = {i.get('name') for i in form.select('input[name], select[name]')}
        check('the site-wide URL key still posts with the user fields',
              {'admin_url_key', 'timezone', 'account_username'} <= posted)
        check('each tab has a save button (both submit the one form)',
              len(form.select('button[type=submit]')) == 2)

    print('\n[4] every card is tagged (an untagged one would vanish)')
    # The CSS hides [data-settings-tab] and shows only the active pane, so a
    # card that missed its attribute would never be visible on either tab.
    untagged = [m.start() for m in re.finditer(r'class="settings-card"(?! data-settings-tab)', html)]
    check(f'no untagged settings-card in the output ({len(untagged)} found)',
          not untagged)

    print('\n[5] your own second factor no longer needs settings.edit')
    with app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(sub_id)
            s['_fresh'] = True
        sub_html = c.get('/admin/dashboard/settings').get_data(as_text=True)
    with app.app_context():
        sub = db.session.get(main.User, sub_id)
        check('(this admin really cannot edit site settings)',
              sub.has_permission('settings.edit') is False)
    check('they can still reach their authenticator setup',
          'Authenticator App (TOTP)' in sub_html)
    check('and link their own GitHub account',
          'settings-section-title">GitHub Account<' in sub_html)
    check('and their own account card',
          card_tab(sub_html, 'Account') == 'user')
    check('but not the org GitHub app credentials',
          'GitHub Sign-In' not in sub_html)
    check('nor the admin URL key', 'Admin URL Key' not in sub_html)

    print('\n[6] saving still posts every field, from either tab')
    check('one form, not two', html.count('<form method="POST"') == 1)
    check('the form carries the tab to return to',
          'name="active_tab"' in html)
    for field in ('account_username', 'timezone', 'date_format', 'admin_url_key'):
        check(f'{field} is still inside the form', f'name="{field}"' in html)

    with app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(owner_id)
            s['_fresh'] = True
        r = c.post('/admin/dashboard/settings', data={
            'active_tab': 'site',
            'account_username': 'owner',
            'account_email': 'owner@example.com',
            'timezone': 'America/Chicago',
            'date_format': '%b %d, %Y %I:%M %p',
            'admin_url_key_enabled': 'on',
            'admin_url_key': 'h5Uc028V',
        })
        check('a save from the site tab redirects back to it',
              r.status_code == 302 and 'tab=site' in (r.headers.get('Location') or ''))
        with app.app_context():
            owner = db.session.get(main.User, owner_id)
            # normalize_admin_url_key lowercases what you type.
            check('the site-wide field saved', owner.admin_url_key == 'h5uc028v')
            check('and the user-side field saved in the same post',
                  owner.timezone == 'America/Chicago')


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
