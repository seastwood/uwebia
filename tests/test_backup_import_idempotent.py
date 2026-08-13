"""Restoring a backup twice must not duplicate anything.

    venv/bin/python tests/test_backup_import_idempotent.py

Restore wipes the instance and rebuilds it from the file. Website-owned rows
ride along with `_delete_website_all`, but the *user-scoped pools* — calendars,
newsletters, AI agents, shipping methods, storage connections, notification
channels, notification feeds — are only reachable by an explicit wipe. Miss one
and the restore recreates it on top of the surviving copy, so every import
doubles that table: 1 → 2 → 4 → 8.

That has already happened here more than once. It was found and patched one
table at a time (calendars and their events, AI agents, shipping, and then
notification channels — a live instance reached 128 copies of one Discord
channel, 2^7, one doubling per restore, each carrying 4 rules with it).

Patching the next one reactively is not a fix, because the failure is silent:
nothing errors, the table just grows. So this test asserts the general property
instead of the specific tables — import the same backup twice and every table
must hold exactly what it held before. Any pool table added later (the feed
tables are the newest) is covered automatically.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import io
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-import-idempotency')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-import-idem-test-')
shutil.copy2(os.path.join(_REPO, 'main.py'), os.path.join(_SCRATCH, 'main.py'))
# Templates/icons are read-only, so symlinking the real ones is safe. `static`
# is NOT: uploads_folder lives inside it, and the backup code this test drives
# DELETES and REWRITES files there. Symlinking it once destroyed the real
# instance's uploaded images. Give this test its own empty static tree instead.
for _linked in ('Templates', 'icons'):
    _src = os.path.join(_REPO, _linked)
    if os.path.exists(_src):
        os.symlink(_src, os.path.join(_SCRATCH, _linked))
os.makedirs(os.path.join(_SCRATCH, 'static', 'uploads'), exist_ok=True)

sys.path.insert(0, _SCRATCH)
import main  # noqa: E402

assert os.path.dirname(os.path.abspath(main.__file__)) == _SCRATCH, \
    'refusing to run against the real checkout'
# Belt and braces: this test writes and deletes files under uploads_folder, so
# refuse to run at all if that resolved back to the real checkout.
assert os.path.realpath(main.uploads_folder).startswith(os.path.realpath(_SCRATCH)), \
    f'uploads_folder escaped the sandbox: {main.uploads_folder}'

app, db = main.app, main.db
FAILURES = []

# Tables whose row count legitimately changes across a restore, so counting them
# would only produce noise. Everything else must come back identical.
IGNORED_TABLES = {
    'alembic_version',
    'admin_chat_message',      # restore itself can log activity
}


def check(label, cond):
    print(('  PASS  ' if cond else '  FAIL  ') + label)
    if not cond:
        FAILURES.append(label)


def table_counts():
    """{table: rows} for the whole database."""
    with app.app_context():
        out = {}
        for table in db.metadata.sorted_tables:
            if table.name in IGNORED_TABLES:
                continue
            out[table.name] = db.session.execute(
                db.select(db.func.count()).select_from(table)).scalar()
        return out


def setup():
    """An instance with at least one row in every user-scoped pool that a
    restore has to wipe — that is where the doubling bug lives."""
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

        db.session.add(main.PublicPageContent(website_id=site.id, name='Home',
                                              slug='home', site_active_status=True))
        guide = main.Guide(website_id=site.id, title='Soldering', slug='soldering',
                           status='published')
        quiz = main.Quiz(website_id=site.id, title='Safety', is_public=True)
        db.session.add_all([guide, quiz])

        # The user-scoped pools.
        cal = main.Calendar(user_id=owner.id, name='Season')
        newsletter = main.Newsletter(user_id=owner.id, name='Weekly', slug='weekly')
        channel = main.NotificationChannel(
            user_id=owner.id, label='Uwebia bot test',
            config={'webhook_url': main.encrypt_api_key(
                'https://discord.com/api/webhooks/1/abc')})
        db.session.add_all([cal, newsletter, channel])
        db.session.commit()

        db.session.add(main.CalendarEvent(calendar_id=cal.id, title='Kickoff',
                                          start=main.datetime(2026, 9, 1, 18, 0)))
        for ev in ('post.published', 'calendar.event_upcoming'):
            db.session.add(main.NotificationRule(channel_id=channel.id, event_type=ev,
                                                 config={}))
        feed = main.NotificationFeed(
            user_id=owner.id, website_id=site.id, channel_id=channel.id,
            name='Weekly Training', days_of_week=[1], send_time='18:00')
        db.session.add(feed)
        db.session.commit()
        db.session.add_all([
            main.NotificationFeedItem(feed_id=feed.id, sort_order=0,
                                      item_type='guide', ref_id=guide.id),
            main.NotificationFeedItem(feed_id=feed.id, sort_order=1,
                                      item_type='quiz', ref_id=quiz.id),
            main.NotificationFeedItem(feed_id=feed.id, sort_order=2,
                                      item_type='link', url='https://youtu.be/x'),
        ])
        db.session.commit()
        return owner.id, site.id


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    uid, sid = setup()

    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(uid)
        s['_fresh'] = True
        s['admin_website_id'] = sid

    baseline = table_counts()
    populated = {t: n for t, n in baseline.items() if n}
    print(f'\n[0] baseline has {len(populated)} non-empty tables')
    for pool in ('calendar', 'newsletter', 'notification_channel', 'notification_rule',
                 'notification_feed', 'notification_feed_item'):
        check(f'{pool} is populated, so a doubling would show ({baseline.get(pool)})',
              baseline.get(pool, 0) > 0)

    def restore():
        with app.app_context():
            z = main._build_backup_zip_bytes(uid, include_files=False)
        r = c.post('/admin/settings/backup/import',
                   data={'backup_file': (io.BytesIO(z), 'backup.zip')},
                   content_type='multipart/form-data')
        assert r.status_code == 200 and r.get_json().get('success'), r.get_data(as_text=True)

    print('\n[1] one restore round-trips every table unchanged')
    restore()
    after_one = table_counts()
    grew = {t: (baseline[t], after_one[t]) for t in baseline
            if after_one.get(t, 0) > baseline[t]}
    check(f'nothing grew ({grew if grew else "clean"})', not grew)
    shrank = {t: (baseline[t], after_one[t]) for t in baseline
              if after_one.get(t, 0) < baseline[t]}
    check(f'and nothing was lost ({shrank if shrank else "clean"})', not shrank)

    print('\n[2] a second and third restore still change nothing')
    # Doubling is invisible after one import for tables that started empty, so
    # run it until an unwiped pool would be unmistakable (1 → 2 → 4 → 8).
    restore()
    restore()
    after_three = table_counts()
    grew = {t: (baseline[t], after_three[t]) for t in baseline
            if after_three.get(t, 0) > baseline[t]}
    check(f'still nothing grew after three imports ({grew if grew else "clean"})',
          not grew)
    check('the notification channel did not multiply '
          f'({baseline["notification_channel"]} → {after_three["notification_channel"]})',
          after_three['notification_channel'] == baseline['notification_channel'])
    check('nor did its rules '
          f'({baseline["notification_rule"]} → {after_three["notification_rule"]})',
          after_three['notification_rule'] == baseline['notification_rule'])
    check('nor the feed and its items '
          f'({after_three["notification_feed"]}/{after_three["notification_feed_item"]})',
          after_three['notification_feed'] == baseline['notification_feed']
          and after_three['notification_feed_item'] == baseline['notification_feed_item'])
    check(f'nor calendars ({after_three["calendar"]})',
          after_three['calendar'] == baseline['calendar'])


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
