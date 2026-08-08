"""Deleting/demoting an admin must explain itself when it can't.

    venv/bin/python tests/test_admin_delete_feedback.py

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-delete-feedback')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-del-test-')
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
    """Anchor + two sub-admins; one of them owns a website (the real blocker)."""
    with app.app_context():
        db.create_all()
        # SQLite only enforces FKs when asked, and the app enables them — make
        # sure they're on so this reproduces the production failure.
        from sqlalchemy import event as _ev

        @_ev.listens_for(db.engine, 'connect')
        def _fk_on(dbapi_con, _rec):     # noqa: ANN001
            cur = dbapi_con.cursor()
            cur.execute('PRAGMA foreign_keys=ON')
            cur.close()

        db.engine.dispose()

        for model in (main.Website, main.User):
            db.session.query(model).delete()
        db.session.commit()

        anchor = main.User(username='owner', parent_user_id=None)
        anchor.set_password('x')
        db.session.add(anchor)
        db.session.commit()

        blocked = main.User(username='ownsasite', parent_user_id=anchor.id,
                            permissions={'admin_users.delete': True,
                                         'admin_users.demote': True})
        blocked.set_password('x')
        clean = main.User(username='ownsnothing', parent_user_id=anchor.id)
        clean.set_password('x')
        db.session.add_all([blocked, clean])
        db.session.commit()

        # A saved colour belonging to that sub-admin. Its FK to user.id is
        # NO ACTION with no ORM cascade, so it genuinely blocks the delete —
        # one of 22 such tables.
        db.session.add(main.SavedColor(user_id=blocked.id, color='#ff0000'))

        # A site created by the same sub-admin. This does NOT block: the
        # User.websites relationship is cascade="all, delete-orphan", so the
        # website is destroyed along with the admin. Asserted below so the
        # behaviour is pinned down rather than assumed.
        db.session.add(main.Website(user_id=blocked.id, name='Their site',
                                    is_draft=False))
        # get_admin_website() resolves through the anchor's own sites, and the
        # demote path needs one to host the demoted account.
        db.session.add(main.Website(user_id=anchor.id, name='Main site',
                                    is_draft=False))
        db.session.commit()
        return anchor.id, blocked.id, clean.id


def main_test():
    anchor_id, blocked_id, clean_id = setup()
    app.config['WTF_CSRF_ENABLED'] = False

    print('\n[1] reference counting')
    with app.app_context():
        refs = dict(main._user_reference_counts(blocked_id))
        check('the blocking saved colour is counted', refs.get('saved colour') == 1)
        check('their website is counted too', refs.get('website or draft site') == 1)
        check('an admin owning nothing reports no references',
              main._user_reference_counts(clean_id) == [])

    print('\n[2] delete')
    with app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(anchor_id)
            s['_fresh'] = True

        r = c.post(f'/admin/users/{blocked_id}/delete')
        d = r.get_json()
        check('a blocked delete returns 409, not 500', r.status_code == 409)
        check('the response is JSON the browser can read', d is not None)
        check('it is flagged as blocked', d.get('blocked') is True)
        check('the message names what is blocking it',
              'saved colour' in (d.get('error') or '').lower())
        check('the message suggests a way forward',
              'demote' in (d.get('error') or '').lower())
        check('machine-readable references are included',
              any(x['what'] == 'saved colour' for x in d.get('references', [])))
        with app.app_context():
            check('the admin still exists after a blocked delete',
                  db.session.get(main.User, blocked_id) is not None)
            check('the session is usable afterwards (rollback happened)',
                  main.User.query.count() == 3)

        r = c.post(f'/admin/users/{clean_id}/delete')
        check('an unblocked delete still succeeds',
              r.status_code == 200 and r.get_json().get('success') is True)
        with app.app_context():
            check('that admin is gone', db.session.get(main.User, clean_id) is None)

        # Pin down the destructive cascade so a future change to
        # User.websites can't alter it unnoticed.
        with app.app_context():
            sites_before = main.Website.query.filter_by(user_id=blocked_id).count()
            db.session.query(main.SavedColor).filter_by(user_id=blocked_id).delete()
            db.session.commit()
        r = c.post(f'/admin/users/{blocked_id}/delete')
        check('removing the blocker lets the delete through',
              r.status_code == 200 and r.get_json().get('success') is True)
        with app.app_context():
            check('DESTRUCTIVE: deleting an admin also deletes their websites',
                  sites_before == 1
                  and main.Website.query.filter_by(user_id=blocked_id).count() == 0)

        r = c.post(f'/admin/users/{anchor_id}/delete')
        d = r.get_json()
        check('deleting the primary owner is refused', r.status_code == 403)
        check('and says why, not just "Unauthorized"',
              'primary owner' in (d.get('error') or '').lower())
        check('and points at ownership transfer',
              'transfer ownership' in (d.get('error') or '').lower())

    # Sections below need a live sub-admin again.
    anchor_id, blocked_id, clean_id = setup()

    print('\n[3] self-deletion')
    with app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(blocked_id)
            s['_fresh'] = True
        r = c.post(f'/admin/users/{blocked_id}/delete')
        check('you cannot delete the account you are signed in with',
              r.status_code == 400 and "signed in" in (r.get_json().get('error') or ''))

    print('\n[4] demote reports the same way')
    with app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(anchor_id)
            s['_fresh'] = True
        r = c.post(f'/admin/users/{blocked_id}/demote')
        check('a blocked demote is a clean 409 too', r.status_code == 409)
        d = r.get_json()
        check('with the same explanation',
              'saved colour' in (d.get('error') or '').lower())
        with app.app_context():
            check('the admin survives a blocked demote',
                  db.session.get(main.User, blocked_id) is not None)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
