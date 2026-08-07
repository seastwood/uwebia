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

    # An explicit env setting wins without probing anything.
    main._DB_SSLMODE_ENV = 'verify-full'
    mode, status = main._resolve_db_sslmode(URL)
    check('UWEBIA_DB_SSLMODE overrides the probe', mode == 'verify-full')
    check('status names the override', 'UWEBIA_DB_SSLMODE' in status)

    # A URL that already says wins over the probe, and we add nothing.
    main._DB_SSLMODE_ENV = ''
    mode, status = main._resolve_db_sslmode(URL + '?sslmode=disable')
    check('URL-declared sslmode is left untouched', mode is None)
    check('status says so', 'database URL' in status)

    # Unreachable host: no TLS verdict, and crucially no false warning.
    mode, status = main._resolve_db_sslmode(URL)
    check('unreachable server yields no mode', mode is None)
    check('unreachable is reported as undetermined, not as disabled',
          'undetermined' in status and 'DISABLED' not in status)

    # A server that answers "no SSL here" must fall back, loudly.
    real_connect = None
    try:
        import psycopg2
        real_connect = psycopg2.connect

        def _no_ssl(*a, **kw):
            raise psycopg2.OperationalError(
                'server does not support SSL, but SSL was required')

        psycopg2.connect = _no_ssl
        mode, status = main._resolve_db_sslmode(URL)
        check('plaintext-only server falls back rather than failing to boot',
              mode is None)
        check('plaintext-only server is flagged DISABLED', 'DISABLED' in status)

        # And the success path pins require.
        psycopg2.connect = lambda *a, **kw: type(
            'C', (), {'close': lambda self: None})()
        mode, status = main._resolve_db_sslmode(URL)
        check('server accepting TLS pins sslmode=require', mode == 'require')
        check('status reports enforcement', 'enforced' in status)
    finally:
        if real_connect is not None:
            import psycopg2
            psycopg2.connect = real_connect


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
        check('seeded rows carry IPs', main._stored_ip_count() == 7)

        anchor = main.User(username='owner', parent_user_id=None)
        anchor.set_password('x')
        db.session.add(anchor)
        db.session.commit()

        check('default retention is 90 days', anchor.ip_retention_days == 90)
        check('helper reads it from the anchor', main.ip_retention_days() == 90)

        cleared = main.prune_expired_ips()
        check('sweep erased the aged rows', sum(cleared.values()) == 5)
        check('all five tables were swept', len(cleared) == 5)
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


def test_backup_roundtrip():
    print('\n[4] backup round-trip')
    with app.app_context():
        anchor = main.User.query.filter_by(parent_user_id=None).first()
        anchor.ip_retention_days = 45
        db.session.commit()
        data = main._serialize_backup(anchor.id)
        check('retention is exported in owner_settings',
              data['owner_settings'].get('ip_retention_days') == 45)
        check('the enrolment ticket is NOT exported',
              not any('enroll_ticket' in k for k in data['owner_settings']))


if __name__ == '__main__':
    test_sslmode_resolution()
    test_prune()
    test_route()
    test_backup_roundtrip()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
