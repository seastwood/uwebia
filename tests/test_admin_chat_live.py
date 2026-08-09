"""The admin chat shows new messages without being closed and reopened.

    venv/bin/python tests/test_admin_chat_live.py

Two bugs behind that. Nothing polled while the panel was open — _chatPollTimer
was declared and never started — and the message query took the OLDEST hundred
rows, so past a hundred messages the panel showed the beginning of the
conversation and nothing said since.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-chat-live')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-chatlive-test-')
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
        owner.set_password('x')
        db.session.add(owner)
        db.session.commit()
        mate = main.User(username='rowan', parent_user_id=owner.id)
        mate.set_password('x')
        db.session.add(mate)
        db.session.commit()
        return owner.id, mate.id


def client_for(uid):
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(uid)
        s['_fresh'] = True
    return c


def main_test():
    owner_id, mate_id = setup()
    app.config['WTF_CSRF_ENABLED'] = False
    a, b = client_for(owner_id), client_for(mate_id)

    print('\n[1] new messages arrive without reopening')
    a.post('/admin/chat/send', json={'message': 'first'})
    msgs = a.get('/admin/chat/messages').get_json()
    cursor = msgs[-1]['id']
    check('the panel loads the conversation', [m['message'] for m in msgs] == ['first'])

    nothing = a.get(f'/admin/chat/messages?since={cursor}').get_json()
    check('polling with nothing new returns nothing', nothing == [])

    b.post('/admin/chat/send', json={'message': 'from rowan'})
    fresh = a.get(f'/admin/chat/messages?since={cursor}').get_json()
    check('a message sent by someone else is picked up',
          [m['message'] for m in fresh] == ['from rowan'])
    check('and is not marked as mine', fresh[0]['mine'] is False)
    check('and carries who said it', fresh[0]['username'] == 'rowan')

    cursor = fresh[-1]['id']
    check('the same message is not delivered twice',
          a.get(f'/admin/chat/messages?since={cursor}').get_json() == [])

    print('\n[2] nothing said in between is skipped')
    # The old client set its cursor to its OWN new id on send. Anything that
    # arrived just before had a LOWER id, so the next poll never asked for it.
    b.post('/admin/chat/send', json={'message': 'landed just before yours'})
    mine = a.post('/admin/chat/send', json={'message': 'mine'}).get_json()
    caught_up = a.get(f'/admin/chat/messages?since={cursor}').get_json()
    check('fetching from the held cursor returns BOTH',
          [m['message'] for m in caught_up] == ['landed just before yours', 'mine'])
    check('in the order they were said',
          caught_up[0]['id'] < caught_up[1]['id'] == mine['id'])

    print('\n[3] a long conversation still shows the recent end')
    with app.app_context():
        for n in range(140):
            db.session.add(main.AdminChatMessage(user_id=owner_id, message=f'msg {n}'))
        db.session.commit()
    recent = a.get('/admin/chat/messages').get_json()
    texts = [m['message'] for m in recent]
    check(f'it returns a capped window ({len(recent)})', len(recent) == 100)
    check('ending at the most recent message', texts[-1] == 'msg 139')
    check('NOT the first hundred ever said', 'first' not in texts)
    check('and still oldest-first for reading', recent[0]['id'] < recent[-1]['id'])

    print('\n[4] it needs a session')
    anon = app.test_client()
    r = anon.get('/admin/chat/messages')
    check(f'signed out gets no conversation — got {r.status_code}',
          r.status_code in (301, 302, 401, 403))


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
