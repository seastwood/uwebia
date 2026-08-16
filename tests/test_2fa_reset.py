"""An admin with permission can clear someone's second factor after a lockout.

    venv/bin/python tests/test_2fa_reset.py

A lost phone, a wiped authenticator or a burnt-through recovery-code list left
an account unreachable with nothing anyone could do about it from the web —
only a shell on the server. This adds the recovery path for both admins and
members.

It removes factors; it never grants access. Where 2FA is required org-wide, the
account afterwards reads "required, nothing enrolled", which is the state
begin_admin_login already handles by stopping the next sign-in at enrolment
rather than letting it reach the dashboard.

Two things it must not become:

  • a way to reach further up than you already are — a sub-admin must not be
    able to strip an owner's second factor and leave that account defended by
    its password alone;
  • a way around the permission split — a staff profile's enrolment lives on
    the admin account behind it, so resetting it through the member route
    would be an admin reset gated on a member permission.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import atexit
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-2fa-reset')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-2fareset-test-')
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


def check(label, cond):
    print(('  PASS  ' if cond else '  FAIL  ') + label)
    if not cond:
        FAILURES.append(label)


def enrol_totp(account):
    """Give an account a working authenticator, as if they had set one up."""
    secret = main.generate_totp_secret()
    account.totp_secret = main.encrypt_api_key(secret)
    account.totp_enabled = True
    account.totp_activated_at = main.datetime.now(main.timezone.utc).replace(tzinfo=None)
    plain, hashed = main.generate_totp_recovery_codes()
    account.totp_recovery_codes = hashed
    return secret


def setup():
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
                            public_users_enabled=True, public_totp_enabled=True)
        db.session.add(site)
        db.session.commit()

        # The locked-out admin: authenticator enrolled, recovery codes issued.
        staff = main.User(username='staff', parent_user_id=owner.id,
                          permissions={'settings.2fa': True})
        staff.set_password('staffpassword')
        db.session.add(staff)
        db.session.commit()
        enrol_totp(staff)

        # A locked-out member.
        member = main.PublicUser(website_id=site.id, username='learner',
                                 email='l@example.com', email_verified=True)
        member.set_password('memberpassword')
        member.two_factor_enabled = True
        db.session.add(member)
        db.session.commit()
        enrol_totp(member)
        db.session.commit()
        return owner.id, site.id, staff.id, member.id


def as_admin(user_id, site_id):
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(user_id)
        s['_fresh'] = True
        s['editing_website_id'] = site_id
    return c


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False

    print('\n[1] resetting an admin who is locked out')
    owner_id, site_id, staff_id, member_id = setup()
    # They have also failed their way into a lockout, which is usually what
    # "locked out" means — resetting the factor and leaving that in place would
    # still refuse them.
    with app.app_context():
        db.session.add(main.LoginRateLimit(
            key='ip:203.0.113.7:id:staff', attempts=5,
            locked_until=main.datetime.now(main.timezone.utc).replace(tzinfo=None)
            + main.timedelta(minutes=15)))
        db.session.commit()

    owner = as_admin(owner_id, site_id)
    r = owner.post(f'/admin/users/{staff_id}/2fa/reset')
    d = r.get_json() or {}
    check(f'the reset succeeds — got {r.status_code}',
          r.status_code == 200 and d.get('success') is True)
    check(f"it reports what it removed ({d.get('cleared')})",
          'authenticator app' in (d.get('cleared') or []))
    check('and that it lifted the lockout', d.get('lockouts_lifted') == 1)

    with app.app_context():
        s = db.session.get(main.User, staff_id)
        check('the authenticator is gone', not s.totp_enabled and s.totp_secret is None)
        check('the recovery codes with it', not s.totp_recovery_codes)
        check('the emailed code too', not s.two_factor_enabled)
        check('nothing half-cleared is left to look like protection',
              s.totp_activated_at is None and s.totp_last_counter is None)
        check('they are told why they have to set it up again',
              bool(s.two_factor_disabled_reason))
        check('the lockout counter is gone',
              main.LoginRateLimit.query.filter(
                  main.LoginRateLimit.key.like('%:id:staff')).count() == 0)

    print('\n[2] it removes a factor, it does not grant access')
    check('with no org requirement they need not re-enrol',
          d.get('must_enrol_next_login') is False)
    owner_id, site_id, staff_id, member_id = setup()
    with app.app_context():
        anchor = db.session.get(main.User, owner_id)
        anchor.org_require_2fa = True
        db.session.commit()
    owner = as_admin(owner_id, site_id)
    d = (owner.post(f'/admin/users/{staff_id}/2fa/reset').get_json() or {})
    check('with 2FA required, the reset says they must enrol again',
          d.get('must_enrol_next_login') is True)
    with app.app_context():
        s = db.session.get(main.User, staff_id)
        state = main.admin_second_factor_state(s)
        check(f"and the login gate agrees ({state})",
              state['required'] is True and state['method'] is None)

    login = app.test_client()
    r = login.post('/admin/login', data={'username': 'staff', 'password': 'staffpassword'},
                   follow_redirects=False)
    dest = r.headers.get('Location') or ''
    check(f'so their next sign-in stops at enrolment — got {dest}',
          '/2fa/app/setup' in dest or '/add-email' in dest)

    print('\n[3] under the ticket policy it hands over a setup code')
    # Otherwise the reset would just trade one lockout for another: the policy
    # forbids enrolling without a code, and theirs was just cleared.
    owner_id, site_id, staff_id, member_id = setup()
    with app.app_context():
        anchor = db.session.get(main.User, owner_id)
        anchor.org_require_2fa = True
        anchor.org_require_enroll_ticket = True
        db.session.commit()
    owner = as_admin(owner_id, site_id)
    d = (owner.post(f'/admin/users/{staff_id}/2fa/reset').get_json() or {})
    check('a setup code comes back', bool(d.get('ticket')))
    check('with how long it lasts', bool(d.get('expires_hours')))
    with app.app_context():
        s = db.session.get(main.User, staff_id)
        check('it is the one that works for them',
              main.totp_enrollment_ticket_valid(s, d.get('ticket')))

    print('\n[4] it cannot be used to reach above your own level')
    owner_id, site_id, staff_id, member_id = setup()
    with app.app_context():
        # A sub-admin who may manage 2FA, and an owner-level target.
        co = main.User(username='coowner', parent_user_id=owner_id, is_co_owner=True)
        co.set_password('x')
        db.session.add(co)
        db.session.commit()
        enrol_totp(co)
        db.session.commit()
        co_id = co.id
        check('the co-owner counts as a full admin',
              db.session.get(main.User, co_id).is_full_admin)

    sub = as_admin(staff_id, site_id)   # has settings.2fa, is not a full admin
    r = sub.post(f'/admin/users/{co_id}/2fa/reset')
    check(f"a sub-admin cannot reset an owner's — got {r.status_code}",
          r.status_code == 403)
    r = sub.post(f'/admin/users/{owner_id}/2fa/reset')
    check(f"nor the primary owner's — got {r.status_code}", r.status_code == 403)
    with app.app_context():
        check('the co-owner keeps their authenticator',
              db.session.get(main.User, co_id).totp_enabled)

    r = as_admin(owner_id, site_id).post(f'/admin/users/{co_id}/2fa/reset')
    check(f'but an owner can — got {r.status_code}', r.status_code == 200)

    print('\n[5] and not without the permission')
    owner_id, site_id, staff_id, member_id = setup()
    with app.app_context():
        plain = main.User(username='plain', parent_user_id=owner_id,
                          permissions={'posts.view': True})
        plain.set_password('x')
        db.session.add(plain)
        db.session.commit()
        plain_id = plain.id
    r = as_admin(plain_id, site_id).post(f'/admin/users/{staff_id}/2fa/reset')
    check(f'an admin without settings.2fa is refused — got {r.status_code}',
          r.status_code in (302, 403))
    with app.app_context():
        check('and the factor survives',
              db.session.get(main.User, staff_id).totp_enabled)

    print('\n[6] resetting a member')
    owner_id, site_id, staff_id, member_id = setup()
    owner = as_admin(owner_id, site_id)
    r = owner.post(f'/admin/users/public/{member_id}/2fa/reset')
    d = r.get_json() or {}
    check(f'the reset succeeds — got {r.status_code}',
          r.status_code == 200 and d.get('success') is True)
    check(f"it names both factors ({d.get('cleared')})",
          set(d.get('cleared') or []) == {'emailed code', 'authenticator app'})
    with app.app_context():
        m = db.session.get(main.PublicUser, member_id)
        check('the authenticator is gone', not m.totp_enabled and m.totp_secret is None)
        check('the emailed code too', not m.two_factor_enabled)
        check('and the recovery codes', not m.totp_recovery_codes)

    plain_login = app.test_client()
    plain_login.post('/login', data={'login': 'learner', 'password': 'memberpassword'})
    with plain_login.session_transaction() as s:
        check('so their password alone gets them back in',
              s.get('public_user_id') == member_id)

    print("\n[7] a staff profile's 2FA is not resettable through the member route")
    # It lives on the admin account behind the mirror, and this route asks only
    # for a member permission — resetting it here would be an admin reset with
    # the wrong permission checked.
    owner_id, site_id, staff_id, member_id = setup()
    owner = as_admin(owner_id, site_id)
    owner.post(f'/admin/users/public/{member_id}/promote', json={'permissions': {}})
    with app.app_context():
        mirror = db.session.get(main.PublicUser, member_id)
        new_admin_id = mirror.mirrored_admin_user_id
        check('their authenticator moved to the admin row',
              db.session.get(main.User, new_admin_id).totp_enabled)
    r = owner.post(f'/admin/users/public/{member_id}/2fa/reset')
    check(f'the member route refuses — got {r.status_code}', r.status_code == 400)
    check('pointing at the Admin Users page',
          'Admin Users' in ((r.get_json() or {}).get('error') or ''))
    with app.app_context():
        check('and the factor is untouched',
              db.session.get(main.User, new_admin_id).totp_enabled)
    r = owner.post(f'/admin/users/{new_admin_id}/2fa/reset')
    check(f'the admin route does it — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        check('clearing it on the admin account',
              not db.session.get(main.User, new_admin_id).totp_enabled)

    print('\n[8] one org cannot reset another')
    owner_id, site_id, staff_id, member_id = setup()
    with app.app_context():
        stranger = main.User(username='stranger', parent_user_id=None)
        stranger.set_password('x')
        db.session.add(stranger)
        db.session.commit()
        enrol_totp(stranger)
        db.session.commit()
        stranger_id = stranger.id
    r = as_admin(owner_id, site_id).post(f'/admin/users/{stranger_id}/2fa/reset')
    check(f'refused — got {r.status_code}', r.status_code == 403)
    with app.app_context():
        check('their factor survives',
              db.session.get(main.User, stranger_id).totp_enabled)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
