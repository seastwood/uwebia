"""Tests for the database TLS probe and the visitor-IP retention sweep.

    venv/bin/python tests/test_db_hardening.py

Copies main.py into a throwaway directory (Templates/icons/static symlinked)
and imports it from there, so it builds its own SQLite database and cannot
touch the real instance.
"""
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-db-hardening')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')
os.environ.pop('UWEBIA_DB_SSLMODE', None)
os.environ.pop('UWEBIA_DB_SSLROOTCERT', None)

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-dbsec-test-')
shutil.copy2(os.path.join(_REPO, 'main.py'), os.path.join(_SCRATCH, 'main.py'))
for _linked in ('Templates', 'icons', 'static'):
    _src = os.path.join(_REPO, _linked)
    if os.path.exists(_src):
        os.symlink(_src, os.path.join(_SCRATCH, _linked))

sys.path.insert(0, _SCRATCH)
import main  # noqa: E402

assert os.path.dirname(os.path.abspath(main.__file__)) == _SCRATCH, \
    'refusing to run against the real checkout'

app = main.app
db = main.db

FAILURES = []


def check(label, cond):
    print(('  PASS  ' if cond else '  FAIL  ') + label)
    if not cond:
        FAILURES.append(label)


def test_sslmode_resolution():
    print('\n[1] sslmode resolution')
    URL = 'postgresql://u:p@db.example.invalid:5432/x'

    check('detects sslmode already in the URL',
          main._url_declares_sslmode(URL + '?sslmode=verify-full') is True)
    check('detects its absence', main._url_declares_sslmode(URL) is False)
    check('strips the +psycopg2 driver for libpq',
          main._libpq_url('postgresql+psycopg2://u:p@h/x') == 'postgresql://u:p@h/x')
    check('leaves a plain postgresql:// URL alone',
          main._libpq_url(URL) == URL)

    # An explicit env setting is the only thing that turns TLS on.
    main._DB_SSLMODE_ENV = 'verify-full'
    mode, status = main._resolve_db_sslmode(URL)
    check('UWEBIA_DB_SSLMODE is honoured', mode == 'verify-full')
    check('status names the override', 'UWEBIA_DB_SSLMODE' in status)

    # A URL that already declares sslmode is left alone.
    main._DB_SSLMODE_ENV = ''
    mode, status = main._resolve_db_sslmode(URL + '?sslmode=disable')
    check('URL-declared sslmode is left untouched', mode is None)
    check('status says so', 'database URL' in status)

    # Nothing is imposed by default — TLS is opt-in.
    mode, status = main._resolve_db_sslmode(URL)
    check('nothing is added by default (TLS stays optional)', mode is None)
    check('status says it is unconfigured', 'not configured' in status)

    # Reporting is separate from enforcing and must never raise.
    try:
        main._report_db_tls(URL, None)
        check('status reporting survives an unreachable server', True)
    except Exception:
        check('status reporting survives an unreachable server', False)


def _seed_ip_rows():
    """One old and one recent row in every IP-bearing table."""
    now = main.datetime.now(main.timezone.utc).replace(tzinfo=None)
    old = now - main.timedelta(days=200)
    recent = now - main.timedelta(days=3)

    db.session.add_all([
        main.PageVisit(website_id=1, page_id=1, visitor_id='a',
                       ip_address='203.0.113.1', visited_at=old),
        main.PageVisit(website_id=1, page_id=1, visitor_id='b',
                       ip_address='203.0.113.2', visited_at=recent),
        main.ForumThread(website_id=1, title='t1', body='c',
                         ip_address='203.0.113.3', created_at=old, updated_at=old),
        main.ForumThread(website_id=1, title='t2', body='c',
                         ip_address='203.0.113.4', created_at=recent, updated_at=recent),
        main.ForumReply(thread_id=1, website_id=1, body='r1',
                        ip_address='203.0.113.5', created_at=old, updated_at=old),
        main.ContactMessage(section_id=1, sender_email='a@example.com',
                            subject='s', body='b',
                            ip_address='203.0.113.6', created_at=old),
        main.PageComment(website_id=1, page_id=1, section_id=1, display_name='n',
                         body='c', ip_address='203.0.113.8',
                         created_at=old, updated_at=old),
        main.CalendarFeedSubscriber(subscriber_hash='h1', ip_address='203.0.113.7',
                                    first_seen_at=old, last_seen_at=old),
    ])
    db.session.commit()


def test_prune():
    print('\n[2] IP retention sweep')
    with app.app_context():
        db.create_all()
        # Seed rows point at parent ids that don't exist. We're testing the
        # sweep, not referential integrity, so drop FK enforcement for this
        # SQLite scratch DB rather than building five object graphs.
        from sqlalchemy import event as _ev

        @_ev.listens_for(db.engine, 'connect')
        def _fk_off(dbapi_con, _rec):        # noqa: ANN001
            cur = dbapi_con.cursor()
            cur.execute('PRAGMA foreign_keys=OFF')
            cur.close()

        db.engine.dispose()                  # force fresh connections
        for model, ip_col, _ts in main._ip_retention_targets():
            db.session.query(model).delete()
        db.session.commit()
        _seed_ip_rows()

        total_rows_before = {
            m.__tablename__: db.session.query(m).count()
            for m, _i, _t in main._ip_retention_targets()}
        check('seeded rows carry IPs', main._stored_ip_count() == 8)

        anchor = main.User(username='owner', parent_user_id=None)
        anchor.set_password('x')
        db.session.add(anchor)
        db.session.commit()

        check('default retention is 90 days', anchor.ip_retention_days == 90)
        check('helper reads it from the anchor', main.ip_retention_days() == 90)

        cleared = main.prune_expired_ips()
        check('sweep erased the aged rows', sum(cleared.values()) == 6)
        check('all six tables were swept', len(cleared) == 6)
        check('recent IPs survive', main._stored_ip_count() == 2)

        total_rows_after = {
            m.__tablename__: db.session.query(m).count()
            for m, _i, _t in main._ip_retention_targets()}
        check('NO rows were deleted — only the IP column cleared',
              total_rows_before == total_rows_after)

        pv = db.session.query(main.PageVisit).filter_by(visitor_id='a').one()
        check('the aged row itself is intact, just de-identified',
              pv.ip_address is None and pv.visitor_id == 'a')

        check('a second sweep is a no-op', main.prune_expired_ips() == {})

        # 0 means keep forever.
        anchor.ip_retention_days = 0
        db.session.commit()
        _seed_ip_rows()
        before = main._stored_ip_count()
        check('retention 0 disables the sweep entirely',
              main.prune_expired_ips() == {} and main._stored_ip_count() == before)

        # An explicit window still works when the stored setting is 0.
        check('an explicit days argument overrides the stored setting',
              sum(main.prune_expired_ips(days=90).values()) > 0)


def test_route():
    print('\n[3] retention route')
    app.config['WTF_CSRF_ENABLED'] = False
    with app.app_context():
        anchor = main.User.query.filter_by(parent_user_id=None).first()
        anchor_id = anchor.id

    c = app.test_client()
    r = c.post('/admin/dashboard/settings/ip-retention', json={'days': 30})
    check('unauthenticated save blocked', r.status_code in (302, 401, 403))

    with app.test_client() as c2:
        with c2.session_transaction() as s:
            s['_user_id'] = str(anchor_id)
            s['_fresh'] = True
        for bad in ('abc', -1, 99999, None):
            r = c2.post('/admin/dashboard/settings/ip-retention', json={'days': bad})
            check(f'rejects days={bad!r}', r.status_code == 400)

        r = c2.post('/admin/dashboard/settings/ip-retention', json={'days': 30})
        d = r.get_json()
        check('owner can save a valid window', r.status_code == 200 and d['success'])
        with app.app_context():
            check('setting persisted to the anchor',
                  main.db.session.get(main.User, anchor_id).ip_retention_days == 30)
        check('save reports what it erased', 'cleared' in d)

        r = c2.post('/admin/dashboard/settings/ip-retention', json={'days': 0})
        check('0 is accepted (keep forever)', r.get_json()['days'] == 0)


def test_ip_recording_switch():
    print('\n[5] IP recording switch')
    with app.app_context():
        anchor = main.User.query.filter_by(parent_user_id=None).first()
        anchor.store_visitor_ips = True
        anchor.ip_retention_days = 90
        db.session.commit()
        check('recording is on by default', main.visitor_ip_storage_enabled() is True)

        _seed_ip_rows()
        seeded = main._stored_ip_count()
        check('rows were seeded with IPs', seeded > 0)

        anchor.store_visitor_ips = False
        db.session.commit()
        check('helper reflects the switch', main.visitor_ip_storage_enabled() is False)
        check('recordable_ip returns nothing while off',
              main.recordable_ip('203.0.113.99') is None)

        cleared = main.erase_all_visitor_ips()
        check('turning it off erases everything already stored',
              sum(cleared.values()) == seeded and main._stored_ip_count() == 0)

        anchor.store_visitor_ips = True
        db.session.commit()
        check('recordable_ip passes the address through when on',
              main.recordable_ip('203.0.113.99') == '203.0.113.99')

    # Saving with store_ips=false must erase, not just stop future writes.
    with app.app_context():
        _seed_ip_rows()
        before = main._stored_ip_count()
        anchor_id = main.User.query.filter_by(parent_user_id=None).first().id
    with app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(anchor_id)
            s['_fresh'] = True
        r = c.post('/admin/dashboard/settings/ip-retention',
                   json={'days': 90, 'store_ips': False})
        d = r.get_json()
        check('route accepts store_ips=false', d.get('success') is True)
        check('route reports the erase count', d.get('cleared') == before)
    with app.app_context():
        check('no IP survives the switch-off', main._stored_ip_count() == 0)
        check('setting persisted',
              main.db.session.get(main.User, anchor_id).store_visitor_ips is False)


def test_asset_usage():
    print('\n[6] asset usage counting')
    with app.app_context():
        db.session.query(main.Asset).delete()
        db.session.commit()

        used = main.Asset(user_id=1, original_filename='hero.png',
                          stored_filename='hero-abc.png',
                          url='/static/uploads/1/assets/hero-abc.png',
                          asset_type='image', file_size=10)
        unused = main.Asset(user_id=1, original_filename='old.png',
                            stored_filename='old-zzz.png',
                            url='/static/uploads/1/assets/old-zzz.png',
                            asset_type='image', file_size=10)
        db.session.add_all([used, unused])
        db.session.commit()

        # Reference the first asset from two different content rows.
        db.session.add(main.PageComment(
            website_id=1, page_id=1, section_id=1, display_name='n',
            body='<img src="/static/uploads/1/assets/hero-abc.png">',
            created_at=main.datetime.utcnow(), updated_at=main.datetime.utcnow()))
        db.session.add(main.ForumThread(
            website_id=1, title='t', body='see /static/uploads/1/assets/hero-abc.png',
            created_at=main.datetime.utcnow(), updated_at=main.datetime.utcnow()))
        db.session.commit()

        main._asset_usage_cache['index'] = None    # counts are cached for 60s
        counts = main.asset_usage_counts([used, unused])
        check('counts every reference to a used asset', counts.get(used.id) == 2)
        check('an unreferenced asset counts zero', counts.get(unused.id) == 0)
        check("an asset's own row does not count as a use",
              counts.get(unused.id) == 0)

        # A page view of the image is not a use of it.
        db.session.add(main.PageVisit(
            website_id=1, page_id=1, visitor_id='v',
            path='/static/uploads/1/assets/old-zzz.png',
            visited_at=main.datetime.utcnow()))
        db.session.commit()
        main._asset_usage_cache['index'] = None    # force a real rescan
        counts = main.asset_usage_counts([unused])
        check('analytics rows are excluded from the count',
              counts.get(unused.id) == 0)

        # The cache must actually serve repeat calls, not silently rescan.
        # The index maps a stored FILENAME to the (table, row) pairs that
        # reference it — it used to be URL -> count, and changed when the
        # library gained "show me where this is used".
        main._asset_usage_cache['index'] = {
            'sentinel.png': [('page_section', n) for n in range(7)]}
        main._asset_usage_cache['at'] = main.time.time()
        sentinel = main.Asset(user_id=1, original_filename='s.png',
                              stored_filename='sentinel.png',
                              url='/static/uploads/x/sentinel.png',
                              asset_type='image', file_size=1)
        check('a warm cache is reused rather than rescanned',
              main.asset_usage_counts([sentinel]).get(sentinel.id) == 7)
        main._asset_usage_cache['index'] = None

        check('empty input returns empty', main.asset_usage_counts([]) == {})


def test_backup_roundtrip():
    print('\n[4] backup round-trip')
    with app.app_context():
        anchor = main.User.query.filter_by(parent_user_id=None).first()
        anchor.ip_retention_days = 45
        db.session.commit()
        data = main._serialize_backup(anchor.id)
        check('retention is exported in owner_settings',
              data['owner_settings'].get('ip_retention_days') == 45)
        # The ticket itself is a live credential and must not travel in a
        # backup. The policy that decides whether tickets are required at all
        # is not a secret, and has to survive a restore like the other org
        # settings — so name the secret rather than matching on 'ticket'.
        check('the enrolment ticket itself is NOT exported',
              not any(k.startswith('totp_enroll_ticket') for k in data['owner_settings']))
        check('but the policy that requires one is',
              'org_require_enroll_ticket' in data['owner_settings'])
        check('the IP recording switch is exported',
              'store_visitor_ips' in data['owner_settings'])


if __name__ == '__main__':
    test_sslmode_resolution()
    test_prune()
    test_route()
    test_ip_recording_switch()
    test_asset_usage()
    test_backup_roundtrip()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
