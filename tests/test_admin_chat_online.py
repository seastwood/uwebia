"""The admin chat shows who else is in the admin panel right now.

    venv/bin/python tests/test_admin_chat_online.py

Read from User.last_seen_at, which a before_request hook already maintains on
every authenticated request — so this needs no new table and no new polling.
"Online" here means using the admin panel at all, which is the question the
chat raises, as opposed to the per-document presence the editors use.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import atexit
import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-chat-online')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-chat-test-')
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


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def setup():
    with app.app_context():
        db.create_all()
        db.session.remove()
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        db.session.commit()

        owner = main.User(username='owner', parent_user_id=None, last_seen_at=now())
        owner.set_password('x')
        db.session.add(owner)
        db.session.commit()

        here = main.User(username='rowan', parent_user_id=owner.id, last_seen_at=now())
        here.set_password('x')
        # Left a while ago: last_seen_at well past the window.
        gone = main.User(username='sam', parent_user_id=owner.id,
                         last_seen_at=now() - timedelta(seconds=main.ADMIN_ONLINE_SECONDS + 60))
        gone.set_password('x')
        # Never signed in at all.
        never = main.User(username='pat', parent_user_id=owner.id, last_seen_at=None)
        never.set_password('x')
        # Another organisation entirely.
        outsider_root = main.User(username='rival', parent_user_id=None, last_seen_at=now())
        outsider_root.set_password('x')
        db.session.add_all([here, gone, never, outsider_root])
        db.session.commit()
        return owner.id, here.id, gone.id, never.id, outsider_root.id


def main_test():
    owner_id, here_id, gone_id, never_id, rival_id = setup()
    app.config['WTF_CSRF_ENABLED'] = False

    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(owner_id)
        s['_fresh'] = True

    r = c.get('/admin/chat/online')
    d = r.get_json() or {}
    ids = {u['user_id'] for u in d.get('online', [])}

    print('\n[1] who counts as online')
    check(f'the endpoint answers — got {r.status_code}', r.status_code == 200)
    check('an admin seen just now is online', here_id in ids)
    check('one last seen past the window is not',
          gone_id not in ids)
    check('one who has never signed in is not', never_id not in ids)

    print('\n[2] scoping')
    check("another organisation's owner is never listed", rival_id not in ids)
    me = [u for u in d.get('online', []) if u['user_id'] == owner_id]
    check('you are included, flagged as yourself', me and me[0]['is_me'] is True)
    check('and sorted first so the strip can drop you',
          d['online'][0]['user_id'] == owner_id)

    print('\n[3] what the chip needs')
    row = next((u for u in d['online'] if u['user_id'] == here_id), None)
    check('a name to show', row and row['name'] == 'rowan')
    check('initials for the avatar', row and row['initials'] == 'R')

    print('\n[4] the window is the documented one')
    # The before_request hook writes last_seen_at at most once a minute, so a
    # window under two minutes would flicker people off while they sit there.
    check(f'ADMIN_ONLINE_SECONDS is {main.ADMIN_ONLINE_SECONDS}s, comfortably '
          f'over the 60s write throttle', main.ADMIN_ONLINE_SECONDS >= 120)
    with app.app_context():
        u = db.session.get(main.User, here_id)
        u.last_seen_at = now() - timedelta(seconds=main.ADMIN_ONLINE_SECONDS - 20)
        db.session.commit()
    still = {x['user_id'] for x in (c.get('/admin/chat/online').get_json() or {}).get('online', [])}
    check('someone just inside the window is still shown', here_id in still)
    with app.app_context():
        u = db.session.get(main.User, here_id)
        u.last_seen_at = now() - timedelta(seconds=main.ADMIN_ONLINE_SECONDS + 20)
        db.session.commit()
    after = {x['user_id'] for x in (c.get('/admin/chat/online').get_json() or {}).get('online', [])}
    check('and drops off once past it', here_id not in after)

    print('\n[5] it needs a session')
    anon = app.test_client()
    ra = anon.get('/admin/chat/online')
    check(f'signed out gets no admin list — got {ra.status_code}',
          ra.status_code in (301, 302, 401, 403))


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
