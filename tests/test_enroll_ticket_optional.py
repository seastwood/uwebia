"""A new admin can set up their own authenticator on their first sign-in.

    venv/bin/python tests/test_enroll_ticket_optional.py

The org can require every admin to pass a second factor. An admin who has none
yet is therefore sent to enrol one mid-login — and that enrolment used to demand
a single-use "setup code" issued by an owner. Every admin but the anchor needed
one, always, so creating an admin and promoting them produced an account that
could not complete its first sign-in: it asked for a code nobody had issued and
there was no way past the screen.

The ticket exists for a real reason — mid-login enrolment proves only the
password, so on its own a stolen password can satisfy the 2FA requirement by
enrolling the thief's device. So it is kept, as a policy an org opts into
(org_require_enroll_ticket) rather than the default, and issuing somebody a
ticket still makes it required for them until it is used or expires.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-enroll-tickets')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-ticket-test-')
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
        owner.set_password('ownerpassword')
        db.session.add(owner)
        db.session.commit()
        site = main.Website(user_id=owner.id, name='Site', is_draft=False, is_live=True)
        db.session.add(site)
        db.session.commit()

        # The account the report is about: created, promoted, never signed in,
        # holding no second factor of any kind.
        newbie = main.User(username='newbie', parent_user_id=owner.id)
        newbie.set_password('newbiepassword')
        db.session.add(newbie)
        db.session.commit()
        return owner.id, site.id, newbie.id


def enrol_page(user_id):
    """The mid-login enrolment screen, as that half-authenticated admin sees it."""
    c = app.test_client()
    with c.session_transaction() as s:
        s['pre_2fa_user_id'] = user_id
    return c, c.get('/admin/2fa/app/setup')


def main_test():
    owner_id, site_id, newbie_id = setup()
    app.config['WTF_CSRF_ENABLED'] = False

    print('\n[1] by default a new admin enrols themselves')
    with app.app_context():
        newbie = db.session.get(main.User, newbie_id)
        check('no setup code is demanded of them',
              main.mid_login_enrollment_needs_ticket(newbie) is False)
    c, r = enrol_page(newbie_id)
    body = r.get_data(as_text=True)
    check(f'the enrolment page opens — got {r.status_code}', r.status_code == 200)
    check('with no "Step 0 — setup code from an owner"', 'Step 0' not in body)
    check('and no field asking for one', 'enroll_ticket' not in body)
    check('it does show them a secret to scan', 'Step 1' in body)

    print('\n[2] and the enrolment actually completes')
    with c.session_transaction() as s:
        secret = s.get('totp_setup_secret')
    check('a secret was issued for the session', bool(secret))
    code = main.generate_totp_code(secret) if hasattr(main, 'generate_totp_code') else None
    if code is None:
        # Derive it the same way the verifier does, whatever the helper is named.
        import hmac, hashlib, struct, base64, time
        counter = int(time.time()) // 30
        key = base64.b32decode(secret, casefold=True)
        digest = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
        off = digest[-1] & 0x0F
        code = f'{(struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % 1000000:06d}'
    r = c.post('/admin/2fa/app/setup', data={'code': code}, follow_redirects=False)
    check(f'the POST is accepted — got {r.status_code}', r.status_code in (301, 302))
    with app.app_context():
        newbie = db.session.get(main.User, newbie_id)
        check('the authenticator is now enrolled', bool(newbie.totp_enabled))
        check('so they hold a real second factor',
              main.totp_secret_is_readable(newbie))

    print('\n[3] the org can still require a setup code')
    owner_id, site_id, newbie_id = setup()
    with app.app_context():
        anchor = db.session.get(main.User, owner_id)
        anchor.org_require_enroll_ticket = True
        db.session.commit()
        check('the policy applies to a sub-admin',
              main.mid_login_enrollment_needs_ticket(
                  db.session.get(main.User, newbie_id)) is True)
        check('but never to the primary owner — they issue them',
              main.mid_login_enrollment_needs_ticket(anchor) is False)
    c, r = enrol_page(newbie_id)
    body = r.get_data(as_text=True)
    check('the page asks for one', 'Step 0' in body and 'enroll_ticket' in body)
    r = c.post('/admin/2fa/app/setup', data={'code': '000000', 'enroll_ticket': 'wrong'},
               follow_redirects=False)
    with app.app_context():
        check('and a wrong code does not enrol anything',
              not db.session.get(main.User, newbie_id).totp_enabled)

    print('\n[4] the toggle is reachable from settings')
    admin = app.test_client()
    with admin.session_transaction() as s:
        s['_user_id'] = str(owner_id)
        s['_fresh'] = True
    r = admin.post('/admin/dashboard/settings/2fa/enroll-ticket-policy',
                   json={'enabled': False})
    d = r.get_json() or {}
    check(f'it can be turned off — got {r.status_code}',
          r.status_code == 200 and d.get('org_require_enroll_ticket') is False)
    with app.app_context():
        check('which is stored on the anchor, so it survives ownership changes',
              db.session.get(main.User, owner_id).org_require_enroll_ticket is False)
        check('and the admin is free to enrol again',
              main.mid_login_enrollment_needs_ticket(
                  db.session.get(main.User, newbie_id)) is False)

    r = admin.post('/admin/dashboard/settings/2fa/enroll-ticket-policy',
                   json={'enabled': True})
    d = r.get_json() or {}
    check('turning it on names who is left without a way in',
          'newbie' in (d.get('stranded') or []))

    print('\n[5] issuing somebody a code makes it required for them')
    owner_id, site_id, newbie_id = setup()
    with app.app_context():
        owner = db.session.get(main.User, owner_id)
        newbie = db.session.get(main.User, newbie_id)
        check('the org policy is off', not owner.org_require_enroll_ticket)
        check('so they would enrol freely',
              main.mid_login_enrollment_needs_ticket(newbie) is False)
        plain = main.issue_totp_enrollment_ticket(newbie, owner)
        db.session.commit()
        check('but once an owner issues one, it is the way in',
              main.mid_login_enrollment_needs_ticket(
                  db.session.get(main.User, newbie_id)) is True)
        check('and the issued code is the one that works',
              main.totp_enrollment_ticket_valid(
                  db.session.get(main.User, newbie_id), plain))

    print('\n[6] an expired code does not strand them')
    with app.app_context():
        from datetime import datetime, timezone, timedelta
        newbie = db.session.get(main.User, newbie_id)
        newbie.totp_enroll_ticket_expires_at = (
            datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1))
        db.session.commit()
        check('once it expires they can enrol themselves again',
              main.mid_login_enrollment_needs_ticket(
                  db.session.get(main.User, newbie_id)) is False)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
