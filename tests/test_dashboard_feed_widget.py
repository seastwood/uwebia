"""The admin dashboard reports where each notification feed has got to.

    venv/bin/python tests/test_dashboard_feed_widget.py

A feed is the one thing on the dashboard with a *position* — you want to know
which item goes out next and how far through the run that is, without opening
each feed. A widget tile holds two numbers, so the feeds get their own strip
under the grid; the tile just counts channels and feeds.

What this pins down:

  * the position is 1-based and counts the ENABLED queue — a skipped item is
    not a step in the run, so counting all items would overstate it;
  * a feed with no channel, or that has run dry, says so on the dashboard
    rather than looking healthy;
  * running feeds sort above paused ones;
  * the whole strip obeys the same permission and per-feed grants as the
    notifications page — a scoped sub-admin must not learn about feeds they
    were not given.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import atexit
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-dashboard-feeds')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-dashfeed-test-')
# Each of these holds a ~2.5 MB copy of main.py and a SQLite database; nothing
# removed them, so repeated suite runs left GBs behind in /tmp.
atexit.register(shutil.rmtree, _SCRATCH, ignore_errors=True)
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

        owner = main.User(username='owner', parent_user_id=None)
        owner.set_password('ownerpassword')
        db.session.add(owner)
        db.session.commit()
        site = main.Website(user_id=owner.id, name='Site', is_draft=False, is_live=True)
        db.session.add(site)
        db.session.commit()

        channel = main.NotificationChannel(
            user_id=owner.id, label='#training',
            config={'webhook_url': main.encrypt_api_key(
                'https://discord.com/api/webhooks/1/a')})
        db.session.add(channel)
        db.session.commit()

        # Running, part way through, with one item skipped in the middle.
        running = main.NotificationFeed(
            user_id=owner.id, website_id=site.id, channel_id=channel.id,
            name='Weekly Training', days_of_week=[1], send_time='18:00',
            is_active=True, position=2)
        # Paused, and with no channel to send to.
        paused = main.NotificationFeed(
            user_id=owner.id, website_id=site.id, name='Offseason Reading',
            days_of_week=[3], send_time='09:00', is_active=False)
        db.session.add_all([running, paused])
        db.session.commit()

        for i in range(5):
            db.session.add(main.NotificationFeedItem(
                feed_id=running.id, sort_order=i, item_type='message',
                title=f'Session {i + 1}',
                # One skipped item, so "of N" must not count it.
                is_enabled=(i != 3)))
        db.session.add(main.NotificationFeedItem(
            feed_id=paused.id, sort_order=0, item_type='message', title='Book one'))
        db.session.commit()

        sub = main.User(username='helper', parent_user_id=owner.id)
        sub.set_password('helperpassword')
        sub.permissions = {'notifications.view': True,
                           'notifications.allowed_feed_ids': [paused.id]}
        db.session.add(sub)
        db.session.commit()

        blind = main.User(username='blind', parent_user_id=owner.id)
        blind.set_password('blindpassword')
        blind.permissions = {'pages.view': True}      # no notifications at all
        db.session.add(blind)
        db.session.commit()

        return dict(owner=owner.id, sub=sub.id, blind=blind.id, site=site.id,
                    running=running.id, paused=paused.id)


def client_for(uid, site_id):
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(uid)
        s['_fresh'] = True
        s['admin_website_id'] = site_id
    return c


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    ids = setup()
    c = client_for(ids['owner'], ids['site'])
    html = c.get('/admin/dashboard').get_data(as_text=True)

    print('\n[1] there is a notifications tile')
    check('the dashboard loads', '<h1>Dashboard</h1>' in html)
    check('with a Notifications widget', '>Notifications</span>' in html)
    check('counting channels and feeds',
          '>channels</div>' in html and '>feeds</div>' in html)

    print('\n[2] every feed reports its position in the run')
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')
    rows = soup.select('.fp-row')
    check(f'both feeds are listed ({len(rows)})', len(rows) == 2)
    by_name = {r.select_one('.fp-name').get_text(strip=True): r for r in rows}
    weekly = by_name.get('Weekly Training')
    check('the running one is there', weekly is not None)
    # 5 items, one skipped -> a 4-step run. Cursor 2 -> on step 3.
    check(f'position counts the enabled queue only '
          f'({weekly.select_one(".fp-count").get_text(strip=True)})',
          'on 3 of 4' in weekly.select_one('.fp-count').get_text(strip=True))
    check('and says what goes out next',
          'Session 3' in weekly.get_text())
    check('with a progress bar', weekly.select_one('.fp-bar span') is not None)

    print('\n[3] state is visible without opening anything')
    check('the running feed is badged Running', 'Running' in weekly.get_text())
    offseason = by_name.get('Offseason Reading')
    check('the paused one is badged Paused', 'Paused' in offseason.get_text())
    check('and a feed with nowhere to send says so',
          'no channel' in offseason.get_text())
    check('while one with a channel names it', '#training' in weekly.get_text())
    check('running feeds sort above paused ones',
          rows[0].select_one('.fp-name').get_text(strip=True) == 'Weekly Training')

    print('\n[4] a spent feed is not mistaken for a healthy one')
    with app.app_context():
        feed = db.session.get(main.NotificationFeed, ids['running'])
        feed.position = 99
        db.session.commit()
    spent = BeautifulSoup(c.get('/admin/dashboard').get_data(as_text=True), 'html.parser')
    weekly = next(r for r in spent.select('.fp-row')
                  if 'Weekly Training' in r.get_text())
    check('it reads as out of items', 'Out of items' in weekly.get_text())
    check('says all of them went', 'all 4 sent' in weekly.get_text())
    check('and tells you how to continue',
          'Add more items' in weekly.get_text())
    with app.app_context():
        db.session.get(main.NotificationFeed, ids['running']).position = 2
        db.session.commit()

    print('\n[5] the strip obeys the same grants as the feeds themselves')
    sc = client_for(ids['sub'], ids['site'])
    sub_html = sc.get('/admin/dashboard').get_data(as_text=True)
    check('a scoped sub-admin sees only their feed',
          'Offseason Reading' in sub_html and 'Weekly Training' not in sub_html)
    bc = client_for(ids['blind'], ids['site'])
    blind_html = bc.get('/admin/dashboard').get_data(as_text=True)
    # The CSS for the strip ships unconditionally, so look for rendered rows
    # rather than the class name appearing anywhere in the document.
    check('and one without the permission sees no strip at all',
          not BeautifulSoup(blind_html, 'html.parser').select('.fp-row')
          and 'Notification feeds' not in blind_html)
    check('nor the tile', '>Notifications</span>' not in blind_html)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
