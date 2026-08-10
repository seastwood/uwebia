"""Integration test for owner-provisioned 2FA enrolment tickets.

    venv/bin/python tests/test_2fa_enrollment_ticket.py

These run with the org-wide ticket policy turned ON. It is off by default:
requiring an owner-issued code before any admin could enrol an authenticator
stranded every newly created admin at their first sign-in, asking for a code
nobody had issued. See test_enroll_ticket_optional.py for that default.

The app derives every path from os.path.dirname(__file__), so this copies
main.py into a throwaway directory (with Templates/icons/static symlinked) and
imports it from there. It therefore builds its own SQLite database and CANNOT
touch the real instance — which matters, because this exercises state-changing
routes.
"""
import os
import shutil
import sys
import tempfile
import warnings

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-enrolment-tests')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-2fa-test-')
shutil.copy2(os.path.join(_REPO, 'main.py'), os.path.join(_SCRATCH, 'main.py'))
for _linked in ('Templates', 'icons', 'static'):
    _src = os.path.join(_REPO, _linked)
    if os.path.exists(_src):
        os.symlink(_src, os.path.join(_SCRATCH, _linked))

sys.path.insert(0, _SCRATCH)
import main  # noqa: E402

assert os.path.dirname(os.path.abspath(main.__file__)) == _SCRATCH, \
    'refusing to run against the real checkout'

app = main.app
db = main.db
User = main.User

FAILURES = []


def check(label, cond):
    print(('  PASS  ' if cond else '  FAIL  ') + label)
    if not cond:
        FAILURES.append(label)


def fresh_users():
    """An anchor (primary owner) plus one sub-admin, neither with 2FA."""
    # Clear child rows first — rendering the admin pages leaves rows that
    # reference user, and SQLite refuses the DELETE while they exist.
    db.session.rollback()
    with warnings.catch_warnings():
        # permission_group <-> user are mutually dependent; the sort order
        # doesn't matter here because each delete is tried independently.
        warnings.simplefilter('ignore')
        tables = list(reversed(db.metadata.sorted_tables))
    for tbl in tables:
        if tbl.name == 'user':
            continue
        try:
            db.session.execute(tbl.delete())
            db.session.commit()
        except Exception:
            db.session.rollback()
    db.session.query(User).delete()
    db.session.commit()
    anchor = User(username='owner', parent_user_id=None)
    anchor.set_password('ownerpass')
    # Tickets are an opt-in policy, not the default — requiring one of every
    # admin meant a newly created one could not finish their first sign-in.
    # This file is about the ticket mechanism, so it opts in; the default
    # (enrol yourself) is covered by test_enroll_ticket_optional.py.
    anchor.org_require_enroll_ticket = True
    db.session.add(anchor)
    db.session.commit()
    sub = User(username='student', parent_user_id=anchor.id)
    sub.set_password('studentpass')
    db.session.add(sub)
    db.session.commit()
    return anchor, sub


def main_test():
    with app.app_context():
        anchor, sub = fresh_users()
        anchor_id, sub_id = anchor.id, sub.id

        print('\n[1] ticket requirement')
        check('sub-admin needs a ticket to enrol mid-login',
              main.mid_login_enrollment_needs_ticket(sub) is True)
        check('primary owner is exempt (no deadlock on a fresh install)',
              main.mid_login_enrollment_needs_ticket(anchor) is False)

        print('\n[2] unprotected-admin listing')
        unprot = {u.id for u in main.admins_without_second_factor(anchor_id)}
        check('both accounts listed as having no second factor',
              unprot == {anchor_id, sub_id})

        print('\n[3] ticket issue / validate / single-use')
        plain = main.issue_totp_enrollment_ticket(sub, anchor)
        sub = db.session.get(User, sub_id)
        check('ticket looks like xxxx-xxxx', len(plain) == 9 and plain[4] == '-')
        check('ticket stored hashed, not in the clear',
              sub.totp_enroll_ticket_hash and plain not in sub.totp_enroll_ticket_hash)
        check('pending flag set', main.totp_enrollment_ticket_pending(sub) is True)
        check('correct ticket validates', main.totp_enrollment_ticket_valid(sub, plain) is True)
        check('case/space insensitive', main.totp_enrollment_ticket_valid(sub, ' ' + plain.upper() + ' ') is True)
        check('wrong ticket rejected', main.totp_enrollment_ticket_valid(sub, 'aaaa-bbbb') is False)
        check('empty ticket rejected', main.totp_enrollment_ticket_valid(sub, '') is False)
        check("another admin's ticket rejected",
              main.totp_enrollment_ticket_valid(db.session.get(User, anchor_id), plain) is False)

        print('\n[4] expiry')
        sub.totp_enroll_ticket_expires_at = (
            main.datetime.now(main.timezone.utc).replace(tzinfo=None) - main.timedelta(minutes=1))
        db.session.commit()
        check('expired ticket rejected', main.totp_enrollment_ticket_valid(sub, plain) is False)
        check('expired ticket not reported pending',
              main.totp_enrollment_ticket_pending(sub) is False)
        main.clear_totp_enrollment_ticket(sub)
        db.session.commit()
        check('cleared ticket rejected', main.totp_enrollment_ticket_valid(sub, plain) is False)

    print('\n[5] mid-login enrolment through the real route')
    app.config['WTF_CSRF_ENABLED'] = False
    with app.app_context():
        anchor, sub = fresh_users()
        anchor_id, sub_id = anchor.id, sub.id

    client = app.test_client()
    with client.session_transaction() as s:
        s['pre_2fa_user_id'] = sub_id
    r = client.get('/admin/2fa/app/setup')
    body = r.get_data(as_text=True)
    check('setup page asks for a setup code', 'Step 0' in body and 'enroll_ticket' in body)

    with client.session_transaction() as s:
        secret = s.get('totp_setup_secret')
    check('a TOTP secret was staged', bool(secret))
    good_code = main._totp_at(secret, int(main.time.time()) // main._TOTP_STEP)

    # Right TOTP code, no ticket → must not enrol.
    r = client.post('/admin/2fa/app/setup',
                    data={'code': good_code}, follow_redirects=True)
    with app.app_context():
        check('enrolment refused without a ticket',
              not db.session.get(User, sub_id).totp_enabled)

    # Right TOTP code, wrong ticket → must not enrol.
    r = client.post('/admin/2fa/app/setup',
                    data={'code': good_code, 'enroll_ticket': 'dead-beef'},
                    follow_redirects=True)
    with app.app_context():
        check('enrolment refused with a wrong ticket',
              not db.session.get(User, sub_id).totp_enabled)

    # Issue a real one and enrol.
    with app.app_context():
        sub = db.session.get(User, sub_id)
        plain = main.issue_totp_enrollment_ticket(sub, db.session.get(User, anchor_id))
    with client.session_transaction() as s:
        s['pre_2fa_user_id'] = sub_id
        secret = s.get('totp_setup_secret')
    good_code = main._totp_at(secret, int(main.time.time()) // main._TOTP_STEP)
    r = client.post('/admin/2fa/app/setup',
                    data={'code': good_code, 'enroll_ticket': plain},
                    follow_redirects=False)
    with app.app_context():
        sub = db.session.get(User, sub_id)
        check('enrolment succeeds with a valid ticket', bool(sub.totp_enabled))
        check('ticket burned after use (single use)',
              sub.totp_enroll_ticket_hash is None)
        check('enrolled admin drops off the unprotected list',
              sub_id not in {u.id for u in main.admins_without_second_factor(anchor_id)})

    print('\n[6] issuing route authorization')
    with app.app_context():
        anchor, sub = fresh_users()
        anchor_id, sub_id = anchor.id, sub.id

    c2 = app.test_client()
    r = c2.post(f'/admin/users/{sub_id}/2fa-enrollment-ticket')
    check('unauthenticated issue blocked (redirect to login)', r.status_code in (302, 401, 403))

    # Sub-admin (not a full admin) must not be able to issue their own.
    with app.app_context():
        s = db.session.get(User, sub_id)
        check('sub-admin is not a full admin', not s.is_full_admin)

    with app.test_client() as c3:
        with c3.session_transaction() as sess:
            sess['_user_id'] = str(anchor_id)
            sess['_fresh'] = True
        r = c3.post(f'/admin/users/{sub_id}/2fa-enrollment-ticket')
        ok = r.status_code == 200 and r.get_json().get('success')
        check('owner can issue a ticket', bool(ok))
        if ok:
            tk = r.get_json()['ticket']
            check('response carries the plaintext once', bool(tk))
            r2 = c3.delete(f'/admin/users/{sub_id}/2fa-enrollment-ticket')
            check('owner can revoke', r2.get_json().get('success') is True)
            with app.app_context():
                check('revoked ticket no longer valid',
                      main.totp_enrollment_ticket_valid(db.session.get(User, sub_id), tk) is False)

        # Already-enrolled target is rejected.
        with app.app_context():
            t = db.session.get(User, sub_id)
            t.totp_enabled = True
            t.totp_secret = main.encrypt_api_key(main.generate_totp_secret())
            db.session.commit()
        r3 = c3.post(f'/admin/users/{sub_id}/2fa-enrollment-ticket')
        check('refuses to issue for an admin who already has an authenticator',
              r3.status_code == 400)

    print('\n[7] admin users page renders')
    with app.app_context():
        anchor, sub = fresh_users()
        anchor_id, sub_id = anchor.id, sub.id
    with app.test_client() as c4:
        with c4.session_transaction() as sess:
            sess['_user_id'] = str(anchor_id)
            sess['_fresh'] = True
        r = c4.get('/admin/users')
        page = r.get_data(as_text=True)
        check('page renders 200', r.status_code == 200)
        check('warning banner shown', 'no second factor' in page)
        check('key button present for the unprotected sub-admin',
              f'issueEnrollmentTicket({sub_id}' in page)
        check('no-2FA badge present', 'au-no2fa-badge' in page)


def lockout_test():
    """A locked-out address must be refused even with a valid ticket, or the
    per-session budget could be refreshed by signing in again."""
    print('\n[8] rate limiting on the ticket field')
    with app.app_context():
        anchor, sub = fresh_users()
        anchor_id, sub_id = anchor.id, sub.id
        plain = main.issue_totp_enrollment_ticket(
            db.session.get(User, sub_id), db.session.get(User, anchor_id))

    client = app.test_client()
    with client.session_transaction() as s:
        s['pre_2fa_user_id'] = sub_id
    client.get('/admin/2fa/app/setup')
    with client.session_transaction() as s:
        secret = s.get('totp_setup_secret')
    good_code = main._totp_at(secret, int(main.time.time()) // main._TOTP_STEP)

    # Wrong tickets should feed the shared limiter.
    for _ in range(main._RL_LOCKOUT_THRESHOLD):
        client.post('/admin/2fa/app/setup',
                    data={'code': good_code, 'enroll_ticket': 'dead-beef'})
    with app.app_context():
        with app.test_request_context(environ_base={'REMOTE_ADDR': '127.0.0.1'}):
            locked = main.two_factor_lockout_active(db.session.get(User, sub_id))
    check('wrong tickets drive the shared limiter into lockout', locked)

    # Now even the CORRECT ticket must be refused while locked out.
    r = client.post('/admin/2fa/app/setup',
                    data={'code': good_code, 'enroll_ticket': plain},
                    follow_redirects=True)
    with app.app_context():
        check('valid ticket refused while locked out',
              not db.session.get(User, sub_id).totp_enabled)
        check('ticket survives the lockout for a later legitimate attempt',
              main.totp_enrollment_ticket_valid(db.session.get(User, sub_id), plain))
    check('lockout is explained to the user',
          'Too many incorrect setup codes' in r.get_data(as_text=True))


if __name__ == '__main__':
    main_test()
    lockout_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
