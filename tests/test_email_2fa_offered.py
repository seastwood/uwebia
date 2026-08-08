"""Email 2FA must only be offered where an emailed code could actually arrive.

    venv/bin/python tests/test_email_2fa_offered.py

The reported bug: a member who signed in with GitHub saw "Two-Factor
Authentication — Email verification code on login" in their account settings.
GitHub accounts are stored with no address and email_verified=True on purpose
(so the verification gate can't strand an account with no email to verify), and
the 2FA gate tested email_verified — a setting that could only ever fail.

The admin half of the same mistake was worse than cosmetic: the activation
route took the address straight from the form and confirm() wrote it to
two_factor_email, so an admin under the org email restriction could put a
mailbox on their row through the 2FA flow — the thing the account-email field
refuses them outright.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-email-2fa')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-2fa-offer-test-')
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
    """A site with public 2FA on, and three members with different mailboxes."""
    with app.app_context():
        db.create_all()
        db.session.remove()
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        db.session.commit()

        anchor = main.User(username='owner', parent_user_id=None, email='owner@example.com')
        anchor.set_password('x')
        db.session.add(anchor)
        db.session.commit()

        site = main.Website(user_id=anchor.id, name='Site', is_draft=False,
                            public_2fa_enabled=True)
        db.session.add(site)
        db.session.commit()

        # Exactly how _github_public_login stores a GitHub member: no address,
        # marked verified so the verification gate can't strand them.
        gh = main.PublicUser(website_id=site.id, username='ghuser',
                             github_user_id=99001, email=None, email_verified=True)
        # An ordinary member with a real, verified address.
        mailed = main.PublicUser(website_id=site.id, username='mailed',
                                 email='member@example.com', email_verified=True)
        mailed.set_password('secretpw123')
        # Had 2FA on, then lost the address — must not be locked out forever.
        stranded = main.PublicUser(website_id=site.id, username='stranded',
                                   email=None, email_verified=True,
                                   two_factor_enabled=True)
        stranded.set_password('secretpw123')
        db.session.add_all([gh, mailed, stranded])
        db.session.commit()
        return anchor.id, site.id, gh.id, mailed.id, stranded.id


def main_test():
    anchor_id, site_id, gh_id, mailed_id, stranded_id = setup()
    app.config['WTF_CSRF_ENABLED'] = False

    print('\n[1] who can be offered an emailed code')
    with app.app_context():
        gh = db.session.get(main.PublicUser, gh_id)
        mailed = db.session.get(main.PublicUser, mailed_id)
        check('a GitHub member with no address: no',
              main.public_email_2fa_possible(gh) is False)
        check('email_verified alone is not enough (the old test)',
              gh.email_verified is True)
        check('a member with a verified address: yes',
              main.public_email_2fa_possible(mailed) is True)

        unverified = main.PublicUser(website_id=site_id, username='unver',
                                     email='u@example.com', email_verified=False)
        check('an unverified address is still refused',
              main.public_email_2fa_possible(unverified) is False)

    print('\n[2] the settings page stops advertising it')
    with app.test_client() as c:
        with c.session_transaction() as s:
            s['public_user_id'] = gh_id
            s['public_user_website_id'] = site_id
        body = c.get('/account/settings').get_data(as_text=True)
        check('the 2FA card is gone for the GitHub member',
              'Email verification code on login' not in body)

    with app.test_client() as c:
        with c.session_transaction() as s:
            s['public_user_id'] = mailed_id
            s['public_user_website_id'] = site_id
        body = c.get('/account/settings').get_data(as_text=True)
        check('but still offered to a member who has an address',
              'Email verification code on login' in body)

    print('\n[3] the endpoint refuses it too, and says why')
    with app.test_client() as c:
        with c.session_transaction() as s:
            s['public_user_id'] = gh_id
            s['public_user_website_id'] = site_id
        r = c.post('/account/2fa/send')
        err = (r.get_json() or {}).get('error', '')
        check('sending a setup code is refused', r.status_code == 400)
        check('naming the real reason, not the mail server',
              'no email address' in err.lower())
        check('and not blaming email settings',
              'check email settings' not in err.lower())

    print('\n[4] an account already stranded on email 2FA can still log in')
    with app.test_client() as c:
        r = c.post('/login', data={'login': 'stranded', 'password': 'secretpw123'},
                   follow_redirects=False)
        check('the login is not bounced to the 2FA code page',
              '/2fa' not in (r.headers.get('Location') or ''))
        with app.app_context():
            check('the unusable factor was cleared',
                  db.session.get(main.PublicUser, stranded_id).two_factor_enabled is False)

    print('\n[5] admins: emailed codes follow the email permission')
    # With a working mail server configured, so the refusal below can only be
    # the permission check — the route rejects a missing server with a 400, and
    # against the previous commit this same request returned 200 and stashed
    # the address for confirm() to write to two_factor_email.
    main.send_two_factor_email = lambda *a, **k: None
    with app.app_context():
        db.session.add(main.EmailServerSettings(
            smtp_host='smtp.example.com', smtp_port=587, smtp_username='u',
            smtp_password='p', from_email='no-reply@example.com',
            is_active=True, is_default=True))
        anchor = db.session.get(main.User, anchor_id)
        anchor.org_admin_email_restricted = True
        sub = main.User(username='student', parent_user_id=anchor_id,
                        email=None, email_allowed=False)
        sub.set_password('x')
        db.session.add(sub)
        db.session.commit()
        sub_id = sub.id

        check('an admin without the email grant may not use emailed codes',
              main.admin_email_2fa_permitted(sub) is False)
        check('the primary owner always may (never lock out the policy holder)',
              main.admin_email_2fa_permitted(anchor) is True)

    with app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(sub_id)
            s['_fresh'] = True
        r = c.post('/admin/dashboard/settings/2fa/start',
                   data={'two_factor_email': 'sneaky@example.com'})
        check('posting an address to the activation route is refused',
              r.status_code == 403)
        check('and points at the authenticator app',
              'authenticator' in ((r.get_json() or {}).get('message') or '').lower())
        with app.app_context():
            after = db.session.get(main.User, sub_id)
            check('BYPASS CLOSED: no address was stashed for confirm() to save',
                  not after.two_factor_email and not after.email)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
