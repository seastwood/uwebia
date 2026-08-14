"""A Discord channel can post into a thread instead of the channel itself.

    venv/bin/python tests/test_channel_thread_id.py

Discord takes the thread as a `thread_id` query parameter on the webhook. The
id is folded into the URL that `channel_webhook_url()` hands back, so every
sender — rules, feed releases, the follow-up video message, the test button —
inherits it without knowing threads exist.

The parts worth pinning down:

  * it composes with `?wait=true`, which the sender appends for ordering — two
    query parameters on one URL, not two `?`;
  * a non-numeric id is refused at save time. Discord ids are snowflakes, and
    storing a thread NAME would produce a URL that 404s at send time with
    nothing pointing at the cause;
  * it is not a secret, so unlike the webhook it survives a backup.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-thread-id')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-thread-test-')
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
POSTED = []          # every URL the fake sender was given

WEBHOOK = 'https://discord.com/api/webhooks/1/abc'


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

        owner = main.User(username='owner', parent_user_id=None)
        owner.set_password('ownerpassword')
        db.session.add(owner)
        db.session.commit()
        site = main.Website(user_id=owner.id, name='Site', is_draft=False, is_live=True)
        db.session.add(site)
        db.session.commit()
        return dict(owner=owner.id, site=site.id)


def admin_client(uid, site_id):
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(uid)
        s['_fresh'] = True
        s['admin_website_id'] = site_id
    return c


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    main._send_to_discord_webhook = lambda url, payload, wait=False: POSTED.append(url)
    ids = setup()
    c = admin_client(ids['owner'], ids['site'])

    print('\n[1] a channel can be created with a thread')
    r = c.post('/admin/notifications/channels/create',
               json={'label': '#build', 'webhook_url': WEBHOOK,
                     'thread_id': '1234567890123456789'})
    check(f'it saves ({r.get_json()})', r.get_json().get('success'))
    cid = r.get_json()['id']
    with app.app_context():
        ch = db.session.get(main.NotificationChannel, cid)
        url = main.channel_webhook_url(ch)
    check(f'and the thread is folded into the URL ({url})',
          url == f'{WEBHOOK}?thread_id=1234567890123456789')

    print('\n[2] it composes with the ordering parameter')
    POSTED.clear()
    r = c.post(f'/admin/notifications/channels/{cid}/test')
    check(f'a test send works ({r.get_json().get("message") or r.get_json().get("error")})',
          r.get_json().get('success'))
    check(f'and goes to the thread ({POSTED[0]})',
          POSTED[0].endswith('?thread_id=1234567890123456789'))
    # The sender appends ?wait=true for ordering; with a thread already in the
    # URL that has to become &wait=true, not a second ?.
    main._send_to_discord_webhook(url, {}, wait=True)
    with app.app_context():
        ch = db.session.get(main.NotificationChannel, cid)
        real = main.channel_webhook_url(ch)
    combined = real + ('&' if '?' in real else '?') + 'wait=true'
    check(f'two parameters, one query string ({combined.split("/")[-1]})',
          combined.count('?') == 1 and 'thread_id=' in combined
          and '&wait=true' in combined)

    print('\n[3] a thread that is not an id is refused')
    r = c.post(f'/admin/notifications/channels/{cid}/update',
               json={'thread_id': '#build-thread'})
    check(f'a name is rejected ({(r.get_json().get("error") or "")[:34]!r})',
          not r.get_json().get('success') and r.status_code == 400)
    r = c.post(f'/admin/notifications/channels/{cid}/update',
               json={'thread_id': 'https://discord.com/channels/1/2/3'})
    check('so is a pasted link', not r.get_json().get('success'))
    with app.app_context():
        ch = db.session.get(main.NotificationChannel, cid)
        check('and the good value is untouched',
              (ch.config or {}).get('thread_id') == '1234567890123456789')

    print('\n[4] it is optional, and clearable')
    r = c.post('/admin/notifications/channels/create',
               json={'label': '#plain', 'webhook_url': WEBHOOK})
    plain_id = r.get_json()['id']
    with app.app_context():
        plain = db.session.get(main.NotificationChannel, plain_id)
        check('a channel with no thread posts to the channel itself',
              main.channel_webhook_url(plain) == WEBHOOK)
    c.post(f'/admin/notifications/channels/{cid}/update', json={'thread_id': ''})
    with app.app_context():
        ch = db.session.get(main.NotificationChannel, cid)
        check('and clearing it goes back to the plain webhook',
              main.channel_webhook_url(ch) == WEBHOOK)

    print('\n[5] every sender inherits it, including feed follow-ups')
    with app.app_context():
        ch = db.session.get(main.NotificationChannel, cid)
        cfg = dict(ch.config)
        cfg['thread_id'] = '999'
        ch.config = cfg
        feed = main.NotificationFeed(
            user_id=ids['owner'], website_id=ids['site'], channel_id=ch.id,
            name='F', days_of_week=[1], send_time='18:00', is_active=True)
        db.session.add(feed)
        db.session.commit()
        db.session.add(main.NotificationFeedItem(
            feed_id=feed.id, sort_order=0, item_type='link',
            title='Clip', url='https://youtu.be/abc'))
        db.session.commit()
        POSTED.clear()
        ok, msg = main._feed_release(feed, 'manual:thread-test')
        check(f'the release goes out ({msg})', ok)
        check(f'both messages went to the thread ({len(POSTED)})',
              len(POSTED) == 2 and all('thread_id=999' in u for u in POSTED))

    print('\n[6] the thread survives a backup, the secret does not')
    with app.app_context():
        payload = main._serialize_backup(ids['owner'])
    saved = {ch['label']: ch['config'] for ch in payload['notification_channels']}
    check(f'the thread id is exported ({saved.get("#build")})',
          (saved.get('#build') or {}).get('thread_id') == '999')
    check('the webhook secret is not',
          'webhook_url' not in (saved.get('#build') or {}))

    print('\n[7] the admin page offers the field')
    html = c.get('/admin/notifications').get_data(as_text=True)
    check('there is a Thread ID input', 'id="chThreadId"' in html)
    check('explained in terms of what Discord shows you', 'Copy Link' in html)
    check('and a threaded channel says so on its card', 'thread 999' in html)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
