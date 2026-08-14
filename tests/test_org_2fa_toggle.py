"""Turning off the org-wide 2FA requirement actually turns it off.

    venv/bin/python tests/test_org_2fa_toggle.py

The policy used to be `org_require_2fa OR anchor.two_factor_enabled`, kept for
back-compat with an older "the owner's 2FA forces everyone" behaviour. The
effect was that an owner with their own second factor could never switch the
org requirement off: the toggle saved, the page redrew, and the requirement was
still on with nothing explaining why.

The explicit toggle is the policy now. What this pins down:

  * with the toggle off, the org imposes nothing — even when the owner has
    their own 2FA;
  * turning it off does NOT weaken the owner's own account: anyone who enrolled
    a factor themselves still has to pass it;
  * the auto-disable on changed mail settings still works, since that is a
    genuine "nobody can receive a code" safeguard.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-org-2fa')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-org2fa-test-')
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

        # The anchor has their OWN 2FA on — the case that used to jam the toggle.
        owner = main.User(username='owner', parent_user_id=None,
                          email='owner@example.com',
                          two_factor_enabled=True, org_require_2fa=True)
        owner.set_password('ownerpassword')
        db.session.add(owner)
        db.session.commit()
        site = main.Website(user_id=owner.id, name='Site', is_draft=False)
        db.session.add(site)
        db.session.commit()

        # A plain sub-admin with nothing enrolled.
        helper = main.User(username='helper', parent_user_id=owner.id,
                           email='helper@example.com')
        helper.set_password('helperpassword')
        db.session.add(helper)
        db.session.commit()
        return dict(owner=owner.id, helper=helper.id, site=site.id)


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    ids = setup()

    with app.app_context():
        owner = db.session.get(main.User, ids['owner'])
        helper = db.session.get(main.User, ids['helper'])

        print('\n[1] with the policy on, everyone must pass it')
        check('the org requires it', main._org_requires_2fa() is True)
        check('including an admin with nothing enrolled',
              main.admin_requires_2fa(helper) is True)

        print('\n[2] turning the policy off actually turns it off')
        # This is the reported bug: the owner's personal 2FA used to keep the
        # org requirement on no matter what the toggle said.
        owner.org_require_2fa = False
        db.session.commit()
        check(f'the owner still has their own 2FA on ({owner.two_factor_enabled})',
              owner.two_factor_enabled is True)
        check('yet the org now requires nothing', main._org_requires_2fa() is False)
        check('and an admin with nothing enrolled is no longer forced',
              main.admin_requires_2fa(helper) is False)

        print('\n[3] but the owner is not made less safe')
        check("the owner's own enrollment still applies to them",
              main.admin_requires_2fa(owner) is True)
        totp_only = main.User(username='totp', parent_user_id=ids['owner'],
                              totp_enabled=True)
        totp_only.set_password('x')
        db.session.add(totp_only)
        db.session.commit()
        check('as does an authenticator someone set up themselves',
              main.admin_requires_2fa(totp_only) is True)

        print('\n[4] the mail-settings auto-disable still works')
        owner.org_require_2fa = True
        owner.org_2fa_email_settings_version = 'stale-fingerprint'
        owner.org_2fa_needs_attention = False
        db.session.commit()
        still_on = main._org_requires_2fa()
        db.session.refresh(owner)
        if main._org_2fa_independent_of_email():
            # Every admin holds an authenticator, so mail is irrelevant and the
            # safeguard correctly does nothing.
            check('a mail change is ignored when nobody depends on email',
                  still_on is True and owner.org_require_2fa is True)
        else:
            check('a changed mail fingerprint switches the policy off',
                  still_on is False and owner.org_require_2fa is False)
            check('and flags it for attention', owner.org_2fa_needs_attention is True)

    print('\n[5] the admin page reflects the toggle, not the owner')
    with app.app_context():
        db.session.get(main.User, ids['owner']).org_require_2fa = False
        db.session.commit()
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(ids['owner'])
        s['_fresh'] = True
        s['admin_website_id'] = ids['site']
    html = c.get('/admin/users').get_data(as_text=True)
    check('the page stops claiming an org-wide requirement',
          'Two-factor is required org-wide' not in html)
    with app.app_context():
        db.session.get(main.User, ids['owner']).org_require_2fa = True
        db.session.commit()
    html = c.get('/admin/users').get_data(as_text=True)
    from bs4 import BeautifulSoup
    toggle = BeautifulSoup(html, 'html.parser').select_one('#atog-org_require_2fa')
    check('and the toggle shows the stored value', toggle is not None
          and toggle.has_attr('checked'))


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
