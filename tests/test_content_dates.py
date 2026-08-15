"""Guides and quizzes say when they were published and whether they are kept up.

    venv/bin/python tests/test_content_dates.py

A reader deciding whether to trust a page is asking two different questions:
how old is this, and does anyone still touch it. So the published date is
absolute — "12 Mar 2026", which is what "how old" wants — and the updated one
is relative — "3 days ago", which is what "still maintained" wants.

"Updated" is dropped when it lands on the same day as publication, or every
freshly published guide would claim to have been updated and the signal would
mean nothing.

Guides already carried published_at and updated_at, kept current by
_stamp_editor on every edit route including lesson saves. Quizzes had no
published date at all; they get one, stamped the first time the quiz is listed
publicly and kept if it is later unlisted — it records when readers could first
see it, not the current state of the switch.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import atexit
import os
import re
import shutil
import sys
import tempfile
from datetime import timedelta

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-content-dates')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-dates-test-')
# Each of these holds a ~2.5 MB copy of main.py and a SQLite database; nothing
# removed them, so repeated suite runs left GBs behind in /tmp.
atexit.register(shutil.rmtree, _SCRATCH, ignore_errors=True)
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
NOW = main.datetime.now(main.timezone.utc).replace(tzinfo=None)
FAILURES = []


def check(label, cond):
    print(('  PASS  ' if cond else '  FAIL  ') + label)
    if not cond:
        FAILURES.append(label)


def dates_on(html):
    """The freshness lines a visitor would read, flattened to text."""
    out = []
    for m in re.finditer(r'<span class="uw-dates[^"]*">(.*?)</span>\s*</span>', html, re.S):
        out.append(' '.join(re.sub(r'<[^>]+>', ' ', m.group(1)).split()))
    return out


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
        db.session.add(main.PublicPageContent(website_id=site.id, name='Home', slug='home',
                                              site_active_status=True))

        kept = main.Guide(website_id=site.id, title='Maintained Guide', slug='kept',
                          status='published', description='Looked after',
                          created_at=NOW - timedelta(days=400),
                          published_at=NOW - timedelta(days=400),
                          updated_at=NOW - timedelta(days=3))
        stale = main.Guide(website_id=site.id, title='Stale Guide', slug='stale',
                           status='published', description='Untouched',
                           created_at=NOW - timedelta(days=800),
                           published_at=NOW - timedelta(days=800),
                           updated_at=NOW - timedelta(days=800))
        db.session.add_all([kept, stale])
        db.session.commit()
        db.session.add(main.GuideNode(
            guide_id=kept.id, website_id=site.id, node_type='lesson',
            title='Lesson one', slug='l1', content='<p>Hi</p>', is_published=True,
            updated_at=NOW - timedelta(days=3)))
        quiz = main.Quiz(website_id=site.id, title='Safety Quiz', is_public=True,
                         description='Check yourself',
                         created_at=NOW - timedelta(days=200),
                         published_at=NOW - timedelta(days=200),
                         updated_at=NOW - timedelta(days=10))
        db.session.add(quiz)
        db.session.commit()
        return owner.id, site.id, kept.id, stale.id, quiz.id


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    owner_id, site_id, kept_id, stale_id, quiz_id = setup()
    c = app.test_client()

    print('\n[1] the two dates answer two different questions')
    d = NOW - timedelta(days=3)
    with app.app_context():
        check(f'published reads as a date ({main.public_date_filter(d)})',
              re.fullmatch(r'\d{1,2} \w{3} \d{4}', main.public_date_filter(d)))
        check(f'updated reads as an age ({main.time_ago_filter(d)})',
              main.time_ago_filter(d) == '3 days ago')
        for delta, expect in ((timedelta(hours=2), 'today'),
                              (timedelta(days=1), 'yesterday'),
                              (timedelta(days=45), '1 month ago'),
                              (timedelta(days=240), '7 months ago'),
                              (timedelta(days=400), '1 year ago'),
                              (timedelta(days=1100), '3 years ago')):
            got = main.time_ago_filter(NOW - delta)
            check(f'{delta.days or 0}d ago reads "{got}"', got == expect)
        check('and nothing is shown for a missing date',
              main.public_date_filter(None) == '' and main.time_ago_filter(None) == '')

    print('\n[2] the Education index shows them on every card')
    html = c.get('/guides').get_data(as_text=True)
    lines = dates_on(html)
    check(f'three cards carry a freshness line ({len(lines)})', len(lines) == 3)
    kept_line = next((l for l in lines if 'Updated 3 days ago' in l), '')
    check(f'a maintained guide shows both ({kept_line})',
          'Published' in kept_line and 'Updated 3 days ago' in kept_line)
    stale_line = [l for l in lines if 'Updated' not in l]
    check(f'a guide never touched since publishing shows only the date ({stale_line})',
          len(stale_line) == 1 and 'Published' in stale_line[0])
    quiz_line = next((l for l in lines if 'Updated 10 days ago' in l), '')
    check(f'and a quiz gets the same treatment ({quiz_line})',
          'Published' in quiz_line)

    print('\n[3] and so do the pages themselves')
    page = c.get('/guides/stale').get_data(as_text=True)
    check(f'the guide cover page ({dates_on(page)})', len(dates_on(page)) == 1)
    page = c.get('/guides/kept/l1').get_data(as_text=True)
    lesson = dates_on(page)
    check(f'a lesson, dated by when THAT lesson changed ({lesson})',
          lesson and 'Updated 3 days ago' in lesson[0])
    page = c.get(f'/quiz/{quiz_id}').get_data(as_text=True)
    check(f'the quiz page ({dates_on(page)})',
          dates_on(page) and 'Updated 10 days ago' in dates_on(page)[0])

    print('\n[4] a quiz gets its published date the first time it is listed')
    with app.app_context():
        fresh = main.Quiz(website_id=site_id, title='Brand new', is_public=False)
        db.session.add(fresh)
        db.session.commit()
        fresh_id = fresh.id
        check('an unlisted quiz has no published date', fresh.published_at is None)

    admin = app.test_client()
    with admin.session_transaction() as s:
        s['_user_id'] = str(owner_id)
        s['_fresh'] = True
        s['editing_website_id'] = site_id
    # The route saves the whole settings form, so the title travels with it —
    # posting is_public alone is a 400 and would make the checks below vacuous.
    def set_public(listed):
        return admin.post(f'/admin/quizzes/{fresh_id}/update',
                          json={'title': 'Brand new', 'is_public': listed})

    r = set_public(True)
    check(f'listing it succeeds — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        q = db.session.get(main.Quiz, fresh_id)
        check('and stamps the date', q.published_at is not None)
        first = q.published_at
    check('which is a real timestamp, not a placeholder', first is not None)

    # Unlisting and relisting must not rewrite history.
    r = set_public(False)
    check(f'unlisting succeeds — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        q = db.session.get(main.Quiz, fresh_id)
        check('the quiz really is unlisted now', q.is_public is False)
        check('but keeps the original published date', q.published_at == first)
    set_public(True)
    with app.app_context():
        check('and relisting does not move it',
              db.session.get(main.Quiz, fresh_id).published_at == first)

    print('\n[5] editing content moves the updated date')
    # This is what makes "Updated" mean anything — it has to follow real edits,
    # including edits to a lesson rather than the guide's own settings.
    with app.app_context():
        before = db.session.get(main.Guide, stale_id).updated_at
        node = main.GuideNode(guide_id=stale_id, website_id=site_id, node_type='lesson',
                              title='New lesson', slug='n1', content='<p>x</p>')
        db.session.add(node)
        db.session.commit()
        node_id = node.id
    r = admin.post(f'/admin/guides/{stale_id}/nodes/save',
                   json={'id': node_id, 'title': 'New lesson', 'content': '<p>edited</p>'})
    check(f'saving a lesson succeeds — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        after = db.session.get(main.Guide, stale_id).updated_at
        check(f'the guide counts as updated ({before} -> {after})',
              after is not None and (before is None or after > before))

    with app.app_context():
        q_before = db.session.get(main.Quiz, quiz_id).updated_at
    admin.post(f'/admin/quizzes/{quiz_id}/update', json={'title': 'Safety Quiz v2'})
    with app.app_context():
        q_after = db.session.get(main.Quiz, quiz_id).updated_at
        check(f'and so does editing a quiz ({q_before} -> {q_after})',
              q_after is not None and q_after > q_before)

    print('\n[6] a quiz published before the column existed still says something')
    with app.app_context():
        old = main.Quiz(website_id=site_id, title='Legacy', is_public=True,
                        published_at=None, created_at=NOW - timedelta(days=500))
        db.session.add(old)
        db.session.commit()
    html = c.get('/guides').get_data(as_text=True)
    check('it falls back to when it was created, rather than showing nothing',
          any('2025' in l or '2024' in l or 'Published' in l for l in dates_on(html)))


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
