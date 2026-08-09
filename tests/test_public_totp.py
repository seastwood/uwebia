"""Members can protect their account with an authenticator app.

    venv/bin/python tests/test_public_totp.py

Public-user 2FA was an emailed code and nothing else, which left it unavailable
to exactly the members most likely to want it: GitHub sign-ups and anyone on a
site that doesn't collect addresses hold no mailbox at all. An authenticator app
needs none.

Two things this has to get right beyond the enrolment itself:

  • Every path that starts a member session must ask for it. The magic link and
    GitHub sign-in used to log members straight in, on the reasoning that
    public 2FA *is* an emailed code so a link to that inbox already proved it.
    An authenticator is deliberately not in the mailbox, so that reasoning does
    not carry and skipping it would walk straight past the factor.

  • It has to survive promotion to staff and demotion back. The secret moves
    onto the admin row with the password hash it guards and returns on the way
    back, so the entry already in the person's app keeps working and nobody
    silently loses a factor they set up.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-public-totp')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-ptotp-test-')
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


def code_for(secret):
    """The code the member's app would be showing right now."""
    return main._totp_at(secret, int(main.time.time()) // main._TOTP_STEP)


def fresh_code(member_id, secret):
    """A code from a step that has not been spent yet.

    Enrolment burns the current step — that is the anti-replay guard doing its
    job — so a test that enrols and immediately signs in with the same code
    would be refused for the right reason. Rather than sleeping out the 30
    seconds, wind the spent-counter back to just before now, which is the state
    the next step would leave anyway.
    """
    with app.app_context():
        m = db.session.get(main.PublicUser, member_id)
        m.totp_last_counter = int(main.time.time()) // main._TOTP_STEP - 1
        db.session.commit()
    return code_for(secret)


def setup(totp_on=True):
    with app.app_context():
        db.create_all()
        db.session.remove()
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        db.session.commit()

        owner = main.User(username='owner', parent_user_id=None)
        owner.set_password('ownerpassword')
        db.session.add(owner)
        db.session.commit()
        site = main.Website(user_id=owner.id, name='Site', is_draft=False, is_live=True,
                            public_users_enabled=True, allow_public_signup=True,
                            public_totp_enabled=totp_on)
        db.session.add(site)
        db.session.commit()
        db.session.add(main.PublicPageContent(website_id=site.id, name='H', slug='home',
                                              site_active_status=True))

        member = main.PublicUser(website_id=site.id, username='learner',
                                 email='learner@example.com', email_verified=True)
        member.set_password('memberpassword')
        db.session.add(member)
        db.session.commit()
        return owner.id, site.id, member.id


def signed_in(member_id, site_id):
    c = app.test_client()
    with c.session_transaction() as s:
        s['public_user_id'] = member_id
        s['public_user_website_id'] = site_id
    return c


def enrol(member_id, site_id):
    """Walk the real enrolment flow. Returns (client, secret, recovery_codes)."""
    c = signed_in(member_id, site_id)
    r = c.get('/account/2fa/app/setup')
    assert r.status_code == 200, r.status_code
    with c.session_transaction() as s:
        secret = s.get('pub_totp_setup_secret')
    r = c.post('/account/2fa/app/setup', data={'code': code_for(secret)})
    codes_page = c.get('/account/2fa/app/recovery-codes').get_data(as_text=True)
    import re
    codes = re.findall(r'<code>([0-9a-f]{5}-[0-9a-f]{5})</code>', codes_page)
    return c, secret, codes


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False

    print('\n[1] a member enrols an app')
    owner_id, site_id, member_id = setup()
    c, secret, codes = enrol(member_id, site_id)
    with app.app_context():
        m = db.session.get(main.PublicUser, member_id)
        check('the authenticator is on', bool(m.totp_enabled))
        check('the secret is stored encrypted, not in the clear',
              bool(m.totp_secret) and m.totp_secret != secret)
        check('and it can be read back', main.user_totp_secret(m) == secret)
        check('recovery codes were generated', len(m.totp_recovery_codes or []) == 10)
    check(f'and shown to them exactly once ({len(codes)} codes)', len(codes) == 10)
    check('a second visit does not show them again',
          not __import__('re').findall(r'<code>([0-9a-f]{5}-[0-9a-f]{5})</code>',
                                       c.get('/account/2fa/app/recovery-codes')
                                       .get_data(as_text=True)))

    print('\n[2] the site has to allow it')
    owner_id2, site_id2, member_id2 = setup(totp_on=False)
    c2 = signed_in(member_id2, site_id2)
    r = c2.post('/account/2fa/app/setup', data={'code': '000000'})
    check(f'enrolment is refused when the site has it off — got {r.status_code}',
          r.status_code == 400)
    page = c2.get('/account/settings').get_data(as_text=True)
    check('and the settings page does not offer it', 'Authenticator App' not in page)

    print('\n[3] signing in with a password now asks for the code')
    owner_id, site_id, member_id = setup()
    c, secret, codes = enrol(member_id, site_id)

    login = app.test_client()
    r = login.post('/login', data={'login': 'learner', 'password': 'memberpassword'},
                   follow_redirects=False)
    check(f'the password alone does not sign them in — got {r.status_code}',
          r.status_code in (301, 302) and '/2fa/app' in (r.headers.get('Location') or ''))
    with login.session_transaction() as s:
        check('no session was established', not s.get('public_user_id'))

    r = login.post('/2fa/app', data={'code': '000000'}, follow_redirects=False)
    with login.session_transaction() as s:
        check('a wrong code is refused', not s.get('public_user_id'))

    r = login.post('/2fa/app', data={'code': fresh_code(member_id, secret)},
                   follow_redirects=False)
    with login.session_transaction() as s:
        check(f'the right code signs them in — got {r.status_code}',
              s.get('public_user_id') == member_id)

    print('\n[4] a code cannot be replayed')
    replay = app.test_client()
    replay.post('/login', data={'login': 'learner', 'password': 'memberpassword'})
    used = code_for(secret)
    replay.post('/2fa/app', data={'code': used})
    again = app.test_client()
    again.post('/login', data={'login': 'learner', 'password': 'memberpassword'})
    again.post('/2fa/app', data={'code': used})
    with again.session_transaction() as s:
        check('the same code a second time is refused', not s.get('public_user_id'))

    print('\n[5] a recovery code works once')
    rec = app.test_client()
    rec.post('/login', data={'login': 'learner', 'password': 'memberpassword'})
    rec.post('/2fa/app', data={'code': codes[0], 'use_recovery': '1'})
    with rec.session_transaction() as s:
        check('it signs them in', s.get('public_user_id') == member_id)
    rec2 = app.test_client()
    rec2.post('/login', data={'login': 'learner', 'password': 'memberpassword'})
    rec2.post('/2fa/app', data={'code': codes[0], 'use_recovery': '1'})
    with rec2.session_transaction() as s:
        check('and is spent — it will not work twice', not s.get('public_user_id'))

    print('\n[6] the magic link does not walk past it')
    # The link proves control of the mailbox. The authenticator is deliberately
    # not in the mailbox, so it still has to be asked for.
    with app.app_context():
        m = db.session.get(main.PublicUser, member_id)
        token = main.generate_public_user_login_link_token(m)
        db.session.commit()
    ml = app.test_client()
    r = ml.get(f'/login-link/{token}', follow_redirects=False)
    check(f'a GET only confirms, it does not consume — got {r.status_code}',
          r.status_code == 200)
    r = ml.post(f'/login-link/{token}', follow_redirects=False)
    with ml.session_transaction() as s:
        check('the Continue button does not sign them straight in',
              not s.get('public_user_id'))
        check('it hands off to the authenticator step',
              s.get('pub_totp_user_id') == member_id)
    ml.post('/2fa/app', data={'code': fresh_code(member_id, secret)})
    with ml.session_transaction() as s:
        check('and completing that does sign them in',
              s.get('public_user_id') == member_id)

    print('\n[6b] nor does GitHub sign-in')
    # Driving the real OAuth round-trip needs GitHub, so call the handler that
    # the callback hands off to — that is where the session would be created.
    owner_id, site_id, member_id = setup()
    c, secret, codes = enrol(member_id, site_id)
    with app.app_context():
        m = db.session.get(main.PublicUser, member_id)
        m.github_user_id = 4242
        db.session.get(main.Website, site_id).github_login_enabled = True
        db.session.commit()
    from flask import session as flask_session
    with app.test_request_context('/'):
        resp = main._github_public_login(4242, {'prefix': None, 'next': ''})
        check(f'it redirects to the authenticator step — got '
              f'{getattr(resp, "status_code", None)}',
              getattr(resp, 'status_code', None) in (301, 302)
              and '/2fa/app' in (resp.headers.get('Location') or ''))
        check('establishing no session of its own',
              not flask_session.get('public_user_id'))
        check('and handing the member to the challenge',
              flask_session.get('pub_totp_user_id') == member_id)

    print('\n[7] it survives promotion and demotion')
    owner_id, site_id, member_id = setup()
    c, secret, codes = enrol(member_id, site_id)
    admin = app.test_client()
    with admin.session_transaction() as s:
        s['_user_id'] = str(owner_id)
        s['_fresh'] = True
        s['editing_website_id'] = site_id

    r = admin.post(f'/admin/users/public/{member_id}/promote', json={'permissions': {}})
    check(f'promotion succeeds — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        mirror = db.session.get(main.PublicUser, member_id)
        staff = db.session.get(main.User, mirror.mirrored_admin_user_id)
        check('the admin account carries the authenticator', bool(staff.totp_enabled))
        check('with the same secret, so their app still works',
              main.user_totp_secret(staff) == secret)
        check('and the same recovery codes',
              len(staff.totp_recovery_codes or []) == 10)
        check('the mirror no longer holds a copy',
              not mirror.totp_enabled and mirror.totp_secret is None)
        staff_id = staff.id

    r = admin.post(f'/admin/users/{staff_id}/demote')
    check(f'demotion succeeds — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        m = db.session.get(main.PublicUser, member_id)
        check('it comes back to the member account', bool(m.totp_enabled))
        check('still the same secret', main.user_totp_secret(m) == secret)
        check('and the recovery codes come back too',
              len(m.totp_recovery_codes or []) == 10)

    back = app.test_client()
    back.post('/login', data={'login': 'learner', 'password': 'memberpassword'})
    back.post('/2fa/app', data={'code': fresh_code(member_id, secret)})
    with back.session_transaction() as s:
        check('so they can still sign in with the app they already had',
              s.get('public_user_id') == member_id)

    print('\n[8] turning it off')
    off = signed_in(member_id, site_id)
    r = off.post('/account/2fa/app/disable')
    check(f'the member can switch it off — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        m = db.session.get(main.PublicUser, member_id)
        check('and nothing is left behind',
              not m.totp_enabled and m.totp_secret is None
              and not m.totp_recovery_codes)
    plain = app.test_client()
    plain.post('/login', data={'login': 'learner', 'password': 'memberpassword'})
    with plain.session_transaction() as s:
        check('the password alone signs them in again',
              s.get('public_user_id') == member_id)

    print('\n[9] a site that turns the option off does not lock anyone out')
    owner_id, site_id, member_id = setup()
    c, secret, codes = enrol(member_id, site_id)
    with app.app_context():
        db.session.get(main.Website, site_id).public_totp_enabled = False
        db.session.commit()
    still = app.test_client()
    still.post('/login', data={'login': 'learner', 'password': 'memberpassword'})
    still.post('/2fa/app', data={'code': fresh_code(member_id, secret)})
    with still.session_transaction() as s:
        check('an already-enrolled member still signs in',
              s.get('public_user_id') == member_id)
    page = signed_in(member_id, site_id).get('/account/settings').get_data(as_text=True)
    check('and can still see the switch that turns it off',
          'disableTotp()' in page)
    r = signed_in(member_id, site_id).post('/account/2fa/app/disable')
    check(f'which works — got {r.status_code}', r.status_code == 200)

    print('\n[10] it round-trips through a backup')
    owner_id, site_id, member_id = setup()
    c, secret, codes = enrol(member_id, site_id)
    with app.app_context():
        data = main._serialize_backup(owner_id)
        pud = next((u for u in data['public_users'] if u['id'] == member_id), None)
        check('the member is in the backup', pud is not None)
        check('carrying the enrolment', bool(pud and pud.get('totp_enabled')))
        check('the encrypted secret', bool(pud and pud.get('totp_secret')))
        check('and the recovery-code hashes',
              len((pud or {}).get('totp_recovery_codes') or []) == 10)
        check('the secret is not exported in the clear',
              (pud or {}).get('totp_secret') != secret)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
