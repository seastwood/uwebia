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

        # Empty everything, children first. Deleting only Website and User was
        # enough while a delete left nothing behind; now that an admin's rows
        # are re-homed to the anchor rather than blocking, they survive the
        # test and the next DELETE FROM user trips over them.
        db.session.remove()
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
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
        joined = ' | '.join(refs)
        check(f'the saved colour is counted ({joined[:60]})',
              any(k.startswith('saved colour') for k in refs))
        check('their website is counted too, and named',
              any(k.startswith('website or draft site') and 'Their site' in k
                  for k in refs))
        check('an admin owning nothing reports no references',
              main._user_reference_counts(clean_id) == [])

    print('\n[2] delete re-homes rather than refusing')
    # This used to assert a 409: a saved colour with a plain NO ACTION foreign
    # key made the account undeletable. Refusing on an org resource was the
    # wrong answer — those now move to the owner and the delete proceeds.
    with app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(anchor_id)
            s['_fresh'] = True

        with app.app_context():
            sites_before = main.Website.query.filter_by(user_id=blocked_id).count()

        r = c.post(f'/admin/users/{blocked_id}/delete')
        d = r.get_json()
        check('the response is JSON the browser can read', d is not None)
        check(f'the delete succeeds — got {r.status_code}',
              r.status_code == 200 and d.get('success') is True)
        check('and reports what it handed over',
              any('saved colour' in m['what'] for m in d.get('moved', [])))
        with app.app_context():
            check('the admin is gone', db.session.get(main.User, blocked_id) is None)
            check('their saved colour survives, under the anchor',
                  main.SavedColor.query.filter_by(user_id=anchor_id).count() == 1)
            check('DESTRUCTIVE: deleting an admin still deletes their websites',
                  sites_before == 1
                  and main.Website.query.filter_by(user_id=blocked_id).count() == 0)

        r = c.post(f'/admin/users/{clean_id}/delete')
        check('an admin owning nothing deletes too',
              r.status_code == 200 and r.get_json().get('success') is True)
        with app.app_context():
            check('that admin is gone', db.session.get(main.User, clean_id) is None)

        r = c.post(f'/admin/users/{anchor_id}/delete')
        d = r.get_json()
        check('deleting the primary owner is refused', r.status_code == 403)
        check('and says why, not just "Unauthorized"',
              'primary owner' in (d.get('error') or '').lower())
        check('and points at ownership transfer',
              'transfer ownership' in (d.get('error') or '').lower())

    # Sections below need a live sub-admin again.
    anchor_id, blocked_id, clean_id = setup()

    print('\n[3] closing your own account')
    # This used to assert the opposite — self-deletion was refused outright,
    # which left an admin unable to close their own account without asking
    # somebody else. Allowed now for everyone except the primary owner, which
    # section [2] already covers.
    with app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(blocked_id)
            s['_fresh'] = True
        r = c.post(f'/admin/users/{blocked_id}/delete')
        d = r.get_json() or {}
        check(f'an admin may delete their own account — got {r.status_code}',
              r.status_code == 200 and d.get('success') is True)
        check('and is told the session is over', d.get('self_deleted') is True)
    with app.app_context():
        check('the account is really gone',
              db.session.get(main.User, blocked_id) is None)

    # That admin no longer exists, so the demote section needs a fresh one.
    anchor_id, blocked_id, clean_id = setup()

    print('\n[4] demote re-homes the same way')
    with app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(anchor_id)
            s['_fresh'] = True
        r = c.post(f'/admin/users/{blocked_id}/demote')
        d = r.get_json() or {}
        check(f'the demote succeeds — got {r.status_code}', r.status_code == 200)
        check('and reports what it handed over',
              any('saved colour' in m['what'] for m in d.get('moved', [])))
        with app.app_context():
            check('the admin row is gone',
                  db.session.get(main.User, blocked_id) is None)
            check('their saved colour survives, under the anchor',
                  main.SavedColor.query.filter_by(user_id=anchor_id).count() == 1)

    print('\n[5] the 409 path still works when something truly cannot be moved')
    # Nothing in the schema blocks a delete now, so this exercises the message
    # builder directly — it is the safety net for a live database whose
    # foreign keys the model metadata does not know about.
    with app.app_context():
        class _Fake(Exception):
            pass
        exc = _Fake()
        exc.orig = ('update or delete on table "user" violates foreign key '
                    'constraint "widget_user_id_fkey" on table "widget"')
        msg = main._describe_delete_blockers(anchor_id, exc)
        check('it names the table holding the reference', 'widget' in msg)
        check('and still suggests a way forward', 'demote' in msg.lower())


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
