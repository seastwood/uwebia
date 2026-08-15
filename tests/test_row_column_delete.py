"""Deleting a row or a column takes its contents with it, quietly.

    venv/bin/python tests/test_row_column_delete.py

These two routes used to print a wall of debug output on every call — one
helper walked EVERY row in the database and printed a line per column while
computing nothing. Removing that noise exposed two defects it had been hiding:

  * the section inside a column was looked up with
    PageSection.query.filter_by(column=column), which compares against
    column.section_id — None for an empty column. SQLAlchemy warned the
    comparison was meaningless; the lookup found nothing, so a deleted row
    could leave its sections orphaned;
  * every column was deleted twice, once through row.columns and again through
    a second query, raising "expected to delete 1 row(s); 0 were matched".

So this checks the outcome AND that the routes stay quiet — the noise is what
made the bugs invisible in the first place.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import io
import atexit
import os
import shutil
import sys
import tempfile
import warnings
from contextlib import redirect_stderr, redirect_stdout

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-row-delete')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-rowdel-test-')
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


def build():
    """A row with one filled column and one empty one — the empty column is
    what made the old relationship comparison meaningless."""
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
        site = main.Website(user_id=owner.id, name='Site', is_draft=False)
        db.session.add(site)
        db.session.commit()
        page = main.PublicPageContent(website_id=site.id, name='Home', slug='home')
        db.session.add(page)
        db.session.commit()

        row = main.Row(page_content_id=page.id, row_number=1)
        db.session.add(row)
        db.session.commit()
        section = main.PageSection(page_content_id=page.id, section_type='text',
                                   order=0, content={'html': 'keep me'})
        db.session.add(section)
        db.session.commit()
        filled = main.Column(row_id=row.id, column_number=1, width=50,
                             section_id=section.id)
        empty = main.Column(row_id=row.id, column_number=2, width=50)
        db.session.add_all([filled, empty])
        db.session.commit()
        return dict(owner=owner.id, site=site.id, page=page.id, row=row.id,
                    filled=filled.id, empty=empty.id, section=section.id)


def client_for(ids):
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(ids['owner'])
        s['_fresh'] = True
        s['admin_website_id'] = ids['site']
    return c


def capture(fn):
    """Run fn, returning (result, anything it wrote to stdout/stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always')
        with redirect_stdout(out), redirect_stderr(err):
            result = fn()
    noise = out.getvalue() + err.getvalue()
    return result, noise, [str(w.message) for w in caught]


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False

    print('\n[1] deleting a column removes it and rebalances the rest')
    ids = build()
    c = client_for(ids)
    r, noise, warns = capture(lambda: c.delete(f'/delete_column/{ids["empty"]}'))
    check(f'it succeeds ({r.status_code})', r.status_code == 200)
    with app.app_context():
        check('the column is gone',
              db.session.get(main.Column, ids['empty']) is None)
        left = main.Column.query.filter_by(row_id=ids['row']).all()
        check(f'the remaining one takes the full width ({[c2.width for c2 in left]})',
              len(left) == 1 and left[0].width == 100)
    check(f'and it printed nothing ({noise.strip()[:60]!r})', noise.strip() == '')

    print('\n[2] deleting a row takes its columns AND their sections')
    ids = build()
    c = client_for(ids)
    r, noise, warns = capture(lambda: c.delete(f'/delete_row/{ids["row"]}'))
    check(f'it succeeds ({r.status_code})', r.status_code == 200)
    with app.app_context():
        check('the row is gone', db.session.get(main.Row, ids['row']) is None)
        check('both columns are gone',
              main.Column.query.filter_by(row_id=ids['row']).count() == 0)
        # This is the one the broken lookup silently skipped.
        check('the section that lived in a column is gone too',
              db.session.get(main.PageSection, ids['section']) is None)

    print('\n[3] and neither route is noisy or warns any more')
    check(f'nothing on stdout/stderr ({noise.strip()[:60]!r})', noise.strip() == '')
    sa_warns = [w for w in warns if 'SAWarning' in w or 'unsupported for a relationship' in w
                or 'expected to delete' in w]
    check(f'no SQLAlchemy warnings ({sa_warns[:1]})', not sa_warns)
    legacy = [w for w in warns if 'legacy' in w.lower()]
    check(f'and none about legacy APIs ({legacy[:1]})', not legacy)

    print('\n[4] a missing row is reported, not crashed on')
    r = c.delete('/delete_row/999999')
    check(f'it 404s cleanly ({r.status_code})', r.status_code == 404)

    print('\n[5] the debug helper that walked the whole database is gone')
    src = open(os.path.join(_REPO, 'main.py')).read()
    check('check_for_undefined_columns no longer exists',
          'def check_for_undefined_columns' not in src)
    check('nor find_undefined_columns, which had a latent NameError',
          'def find_undefined_columns' not in src)
    check('but the one that actually repairs columns stays',
          'def delete_undefined_columns' in src)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
