"""Deleting a sub-admin who used the public side must actually work.

    venv/bin/python tests/test_admin_mirror_delete.py

The production failure this pins down: a sub-admin's public mirror had posted
in the forum, so removing the mirror hit

    update or delete on table "public_user" violates foreign key constraint
    "forum_reply_public_user_id_fkey" on table "forum_reply"

The mirror delete was a bulk query.delete() sitting *outside* the try, so it
raised through the route as a 500 with an HTML body, `await r.json()` threw in
the browser, and the button did nothing at all — no message, nothing.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import atexit
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-mirror-delete')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-mirror-test-')
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
_FKS_ON = False


def check(label, cond):
    print(('  PASS  ' if cond else '  FAIL  ') + label)
    if not cond:
        FAILURES.append(label)


def setup():
    """An anchor, a sub-admin, and a mirror that has really used the site.

    The mirror gets one of each shape of reference: a nullable authorship
    column (thread, reply), a not-null row that only exists because of them
    (vote), and a not-null one with no ORM cascade at all (product review) —
    the last is the one a plain db.session.delete() cannot survive either.
    """
    with app.app_context():
        # SQLite only enforces FKs when asked, and the app enables them — make
        # sure they're on so this reproduces the production failure.
        global _FKS_ON
        if not _FKS_ON:
            from sqlalchemy import event as _ev

            @_ev.listens_for(db.engine, 'connect')
            def _fk_on(dbapi_con, _rec):     # noqa: ANN001
                cur = dbapi_con.cursor()
                cur.execute('PRAGMA foreign_keys=ON')
                cur.close()

            db.engine.dispose()
            _FKS_ON = True

        db.create_all()
        # Empty every table between phases, children first — sorted_tables is
        # ordered by foreign-key dependency, so reversed is a safe teardown.
        db.session.remove()
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        db.session.commit()

        anchor = main.User(username='owner', parent_user_id=None)
        anchor.set_password('x')
        db.session.add(anchor)
        db.session.commit()

        site = main.Website(user_id=anchor.id, name='Main site', is_draft=False)
        db.session.add(site)
        db.session.commit()

        sub = main.User(username='forumposter', parent_user_id=anchor.id)
        sub.set_password('x')
        db.session.add(sub)
        db.session.commit()

        mirror = main.PublicUser(website_id=site.id, username='forumposter',
                                 mirrored_admin_user_id=sub.id,
                                 password_hash=sub.password_hash)
        db.session.add(mirror)
        db.session.commit()

        thread = main.ForumThread(website_id=site.id, public_user_id=mirror.id,
                                  title='Welcome', body='Hello everyone')
        product = main.StoreProduct(website_id=site.id, name='A thing',
                                    slug='a-thing')
        db.session.add_all([thread, product])
        db.session.commit()
        db.session.add_all([
            main.ForumReply(thread_id=thread.id, website_id=site.id,
                            public_user_id=mirror.id, body='A reply'),
            main.ForumThreadVote(thread_id=thread.id, website_id=site.id,
                                 public_user_id=mirror.id),
            main.ProductReview(website_id=site.id, product_id=product.id,
                               public_user_id=mirror.id, rating=5),
        ])
        db.session.commit()
        return anchor.id, sub.id, site.id, mirror.id, thread.id


def main_test():
    anchor_id, sub_id, site_id, mirror_id, thread_id = setup()
    app.config['WTF_CSRF_ENABLED'] = False

    print('\n[1] deleting an admin whose mirror posted in the forum')
    with app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(anchor_id)
            s['_fresh'] = True

        r = c.post(f'/admin/users/{sub_id}/delete')
        check('the delete succeeds instead of raising a 500',
              r.status_code == 200)
        check('and says so in JSON the browser can read',
              (r.get_json() or {}).get('success') is True)

        with app.app_context():
            check('the admin is gone',
                  db.session.get(main.User, sub_id) is None)
            check('their public mirror is gone',
                  db.session.get(main.PublicUser, mirror_id) is None)

            thread = db.session.get(main.ForumThread, thread_id)
            check('their forum thread SURVIVES the delete', thread is not None)
            check('but has no author, so it renders as "Guest"',
                  thread is not None and thread.public_user_id is None)
            reply = main.ForumReply.query.filter_by(thread_id=thread_id).first()
            check('their reply survives too, also unattributed',
                  reply is not None and reply.public_user_id is None)

            check('their vote is removed (it cannot exist without them)',
                  main.ForumThreadVote.query.count() == 0)
            check('their product review is removed for the same reason',
                  main.ProductReview.query.count() == 0)

    print('\n[2] demote leaves the account and its history intact')
    anchor_id, sub_id, site_id, mirror_id, thread_id = setup()
    with app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(anchor_id)
            s['_fresh'] = True

        r = c.post(f'/admin/users/{sub_id}/demote')
        check('the demote succeeds', r.status_code == 200)
        d = r.get_json() or {}
        check('and reports the surviving public user',
              d.get('success') is True and d.get('public_user', {}).get('id') == mirror_id)

        with app.app_context():
            check('the admin row is gone',
                  db.session.get(main.User, sub_id) is None)
            survivor = db.session.get(main.PublicUser, mirror_id)
            check('the mirror survives as a real public user',
                  survivor is not None and survivor.mirrored_admin_user_id is None)
            thread = db.session.get(main.ForumThread, thread_id)
            check('and KEEPS authorship of their forum thread',
                  thread is not None and thread.public_user_id == mirror_id)
            check('their vote is untouched',
                  main.ForumThreadVote.query.count() == 1)

    print('\n[3] deleting a plain member with the same content')
    anchor_id, sub_id, site_id, mirror_id, thread_id = setup()
    with app.app_context():
        # Detach the mirror so the Members page will act on it at all.
        pu = db.session.get(main.PublicUser, mirror_id)
        pu.mirrored_admin_user_id = None
        db.session.commit()
    with app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(anchor_id)
            s['_fresh'] = True
        r = c.post(f'/admin/users/public/{mirror_id}/delete')
        check('a member with a product review deletes cleanly (was a 500)',
              r.status_code == 200 and (r.get_json() or {}).get('success') is True)
        with app.app_context():
            check('the member is gone',
                  db.session.get(main.PublicUser, mirror_id) is None)
            check('their thread survives, unattributed',
                  db.session.get(main.ForumThread, thread_id).public_user_id is None)

    print('\n[4] the blocker message names the referencing table')
    with app.app_context():
        class _Fake(Exception):
            pass
        exc = _Fake()
        exc.orig = (
            'update or delete on table "public_user" violates foreign key '
            'constraint "forum_reply_public_user_id_fkey" on table "forum_reply"\n'
            'DETAIL:  Key (id)=(148) is still referenced from table "forum_reply".')
        check('it reports forum_reply, not the row being deleted',
              main._blocking_table(exc) == 'forum_reply')


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
