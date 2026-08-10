"""The public access switches are tucked away, and cannot be flipped by accident.

    venv/bin/python tests/test_access_settings_guard.py

The Access Settings card sat open on the page with a dozen toggles that decide
who can sign up, sign in and see the site — and one of them, turning off Collect
Real Names, permanently deletes the names already on file. A stray tap did all
of that with nothing in the way.

Now: the card is collapsed until someone opens it, saving a change lists exactly
what is about to change, and the admin has to prove they are still there — their
authenticator code where they have one, otherwise their password. Saving with
nothing changed asks for neither.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import re
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-access-guard')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-access-test-')
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


def setup(with_password=True, with_totp=False):
    with app.app_context():
        db.create_all()
        db.session.remove()
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        db.session.commit()

        owner = main.User(username='owner', parent_user_id=None)
        if with_password:
            owner.set_password('ownerpassword')
        else:
            owner.password_hash = None
        secret = None
        if with_totp:
            secret = main.generate_totp_secret()
            owner.totp_secret = main.encrypt_api_key(secret)
            owner.totp_enabled = True
        db.session.add(owner)
        db.session.commit()

        site = main.Website(user_id=owner.id, name='Site', is_draft=False,
                            is_live=True, public_users_enabled=True,
                            collect_real_names=True)
        db.session.add(site)
        db.session.commit()

        # A member with a name on file, so the purge is observable.
        member = main.PublicUser(website_id=site.id, username='learner',
                                 first_name='Ada', last_name='Lovelace')
        member.set_password('memberpassword')
        db.session.add(member)
        db.session.commit()
        return owner.id, site.id, member.id, secret


def as_owner(owner_id, site_id):
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(owner_id)
        s['_fresh'] = True
        s['editing_website_id'] = site_id
    return c


def all_on(site_id, **overrides):
    """A full settings payload matching what the page posts."""
    with app.app_context():
        w = db.session.get(main.Website, site_id)
        payload = {'website_id': site_id}
        for key in main.PUBLIC_ACCESS_SETTINGS:
            payload[key] = bool(getattr(w, key, False))
    payload.update(overrides)
    return payload


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False

    print('\n[1] the card is collapsed until someone opens it')
    owner_id, site_id, member_id, _ = setup()
    page = as_owner(owner_id, site_id).get('/admin/users/public').get_data(as_text=True)
    check('there is a collapse toggle', 'toggleAccessSettings(' in page)
    body = re.search(r'<div class="pu-collapse-body" id="access-body-\d+"([^>]*)>', page)
    check('and the body starts hidden', bool(body) and 'hidden' in body.group(1))
    head = re.search(r'id="access-head-\d+"\s+aria-expanded="([^"]+)"', page)
    check(f'announced as collapsed to assistive tech ({head.group(1) if head else "?"})',
          bool(head) and head.group(1) == 'false')

    print('\n[2] saving with nothing changed asks for nothing')
    c = as_owner(owner_id, site_id)
    r = c.post('/admin/users/public/settings', json=all_on(site_id))
    check(f'it just saves — got {r.status_code}', r.status_code == 200)
    check('and reports no changes', (r.get_json() or {}).get('changed') == [])

    print('\n[3] but a change is refused until it is confirmed')
    r = c.post('/admin/users/public/settings',
               json=all_on(site_id, public_users_enabled=False))
    d = r.get_json() or {}
    check(f'refused without proof — got {r.status_code}', r.status_code == 401)
    check(f'saying what it wants ({d.get("needs_reauth")})',
          d.get('needs_reauth') == 'password')
    check('and listing what would change',
          [x['key'] for x in (d.get('changes') or [])] == ['public_users_enabled'])
    check('with the label the page shows',
          (d.get('changes') or [{}])[0].get('label') == 'Enable Public Users')
    with app.app_context():
        check('nothing was applied',
              db.session.get(main.Website, site_id).public_users_enabled is True)

    r = c.post('/admin/users/public/settings',
               json=all_on(site_id, public_users_enabled=False, password='wrong'))
    check(f'a wrong password is refused — got {r.status_code}', r.status_code == 401)
    with app.app_context():
        check('and still nothing applied',
              db.session.get(main.Website, site_id).public_users_enabled is True)

    r = c.post('/admin/users/public/settings',
               json=all_on(site_id, public_users_enabled=False,
                           password='ownerpassword'))
    check(f'the right password applies it — got {r.status_code}', r.status_code == 200)
    check('and says what changed',
          (r.get_json() or {}).get('changed') == ['public_users_enabled'])
    with app.app_context():
        check('the switch really moved',
              db.session.get(main.Website, site_id).public_users_enabled is False)

    print('\n[4] the setting that deletes data is guarded the same way')
    owner_id, site_id, member_id, _ = setup()
    c = as_owner(owner_id, site_id)
    r = c.post('/admin/users/public/settings',
               json=all_on(site_id, collect_real_names=False))
    check(f'refused without proof — got {r.status_code}', r.status_code == 401)
    with app.app_context():
        m = db.session.get(main.PublicUser, member_id)
        check('the member still has their name', m.first_name == 'Ada')

    r = c.post('/admin/users/public/settings',
               json=all_on(site_id, collect_real_names=False,
                           password='ownerpassword'))
    check(f'confirmed, it goes through — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        m = db.session.get(main.PublicUser, member_id)
        check('and only then is the name purged', m.first_name is None)

    print('\n[5] an authenticator is asked for in preference to a password')
    owner_id, site_id, member_id, secret = setup(with_totp=True)
    c = as_owner(owner_id, site_id)
    r = c.post('/admin/users/public/settings',
               json=all_on(site_id, require_login_to_view=True))
    d = r.get_json() or {}
    check(f'it asks for the code ({d.get("needs_reauth")})',
          d.get('needs_reauth') == 'totp')
    r = c.post('/admin/users/public/settings',
               json=all_on(site_id, require_login_to_view=True,
                           password='ownerpassword'))
    check(f'the password alone will not do — got {r.status_code}', r.status_code == 401)

    code = main._totp_at(secret, int(main.time.time()) // main._TOTP_STEP)
    r = c.post('/admin/users/public/settings',
               json=all_on(site_id, require_login_to_view=True, totp_code=code))
    check(f'the code does — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        check('and the switch moved',
              db.session.get(main.Website, site_id).require_login_to_view is True)

    # The same code must not open the door twice.
    r = c.post('/admin/users/public/settings',
               json=all_on(site_id, require_login_to_view=False, totp_code=code))
    check(f'the same code cannot be replayed — got {r.status_code}', r.status_code == 401)

    print('\n[6] an admin with neither still gets the confirmation')
    # GitHub-only admins hold no password and may hold no authenticator. There
    # is nothing to check them against, so the deliberate confirmation in the
    # page is the guard — refusing outright would lock them out of their own
    # settings.
    owner_id, site_id, member_id, _ = setup(with_password=False)
    with app.app_context():
        owner = db.session.get(main.User, owner_id)
        check('the account really has no password and no authenticator',
              main.admin_reauth_method(owner) is None)
    c = as_owner(owner_id, site_id)
    r = c.post('/admin/users/public/settings',
               json=all_on(site_id, public_approval_required=True))
    check(f'the change is allowed — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        check('and applied',
              db.session.get(main.Website, site_id).public_approval_required is True)

    print('\n[7] every switch on the card is covered by the guard')
    # A switch added to the page but not to PUBLIC_ACCESS_SETTINGS would save
    # silently, with no confirmation and no audit line.
    tpl = open(os.path.join(_REPO, 'Templates', 'admin_public_users.html')).read()
    keys = re.search(r'const ACCESS_KEYS = \[(.*?)\];', tpl, re.S)
    page_keys = set(re.findall(r"'([a-z0-9_]+)'", keys.group(1))) if keys else set()
    guarded = set(main.PUBLIC_ACCESS_SETTINGS)
    check(f'the page and the server agree on {len(guarded)} switches',
          page_keys == guarded)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
