"""Deleting an admin hands the organisation's things over, it doesn't refuse.

    venv/bin/python tests/test_admin_delete_rehome.py

Reported case: a sub-admin could not be deleted or demoted, and the only thing
holding it up was

    Cannot delete this admin — records in "asset" still point at them.
    They still own: 1 asset.

They didn't own it. The asset library is a shared pool keyed on the ROOT admin
— Asset.user_id is always the root id and Asset.uploaded_by_user_id exists
purely for audit (see the comment above pool_user_id in main.py). Their name
was on the audit field of one file, and that was enough to make the account
undeletable. "1 asset" gave no clue which file, or that ownership was never
the issue.

Now: ownership columns move to the owner, attribution columns are simply
cleared, and settings rows that allow only one per user go with the admin.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-rehome')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-rehome-test-')
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
_FKS_ON = False


def check(label, cond):
    print(('  PASS  ' if cond else '  FAIL  ') + label)
    if not cond:
        FAILURES.append(label)


def setup():
    global _FKS_ON
    with app.app_context():
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
        db.session.remove()
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        db.session.commit()

        owner = main.User(username='owner', parent_user_id=None)
        owner.set_password('x')
        db.session.add(owner)
        db.session.commit()

        sub = main.User(username='helper', parent_user_id=owner.id)
        sub.set_password('x')
        db.session.add(sub)
        db.session.commit()

        # The reported blocker, exactly: the file belongs to the root pool and
        # only the audit field names the sub-admin.
        asset = main.Asset(user_id=owner.id, uploaded_by_user_id=sub.id,
                           original_filename='team-photo.jpg',
                           stored_filename='abc123.jpg', url='/x/abc123.jpg',
                           asset_type='image')
        # An org resource they really do own — must survive, under the owner.
        cal = main.Calendar(user_id=sub.id, name='Practice schedule')
        colour = main.SavedColor(user_id=sub.id, color='#ff0000')
        db.session.add_all([asset, cal, colour])
        db.session.commit()
        return owner.id, sub.id, asset.id, cal.id


def main_test():
    owner_id, sub_id, asset_id, cal_id = setup()
    app.config['WTF_CSRF_ENABLED'] = False

    print('\n[1] the blocked-delete message identifies the file')
    with app.app_context():
        refs = dict(main._user_reference_counts(sub_id))
        joined = ' | '.join(refs)
        check('it says "uploaded", not that they own it',
              any('uploaded' in k for k in refs))
        check(f'and names the file ({joined[:70]})',
              any('team-photo.jpg' in k for k in refs))

    print('\n[2] the delete now goes through')
    with app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(owner_id)
            s['_fresh'] = True
        r = c.post(f'/admin/users/{sub_id}/delete')
        d = r.get_json() or {}
        check(f'no longer blocked (was 409) — got {r.status_code}',
              r.status_code == 200 and d.get('success') is True)
        moved = {m['what']: m['count'] for m in d.get('moved', [])}
        check(f'it reports what it did ({list(moved)})', bool(moved))

    print('\n[3] nothing of the organisation\'s was lost')
    with app.app_context():
        check('the admin is gone', db.session.get(main.User, sub_id) is None)

        asset = db.session.get(main.Asset, asset_id)
        check('the asset SURVIVES', asset is not None)
        check('still in the owner\'s pool, untouched',
              asset is not None and asset.user_id == owner_id)
        check('and the uploader field is simply cleared',
              asset is not None and asset.uploaded_by_user_id is None)

        cal = db.session.get(main.Calendar, cal_id)
        check('their calendar survives', cal is not None)
        check('re-homed to the owner rather than deleted',
              cal is not None and cal.user_id == owner_id)

        check('their saved colour moved too',
              main.SavedColor.query.filter_by(user_id=owner_id).count() == 1)

    print('\n[4] a settings singleton goes with the admin, not onto the owner')
    owner_id, sub_id, asset_id, cal_id = setup()
    with app.app_context():
        # One row per user is enforced here, and the owner already has theirs.
        db.session.add_all([
            main.AnalyticsSettings(user_id=owner_id),
            main.AnalyticsSettings(user_id=sub_id),
        ])
        db.session.commit()
    with app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(owner_id)
            s['_fresh'] = True
        r = c.post(f'/admin/users/{sub_id}/delete')
        check(f'the delete still succeeds — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        check('the owner keeps exactly one analytics row',
              main.AnalyticsSettings.query.filter_by(user_id=owner_id).count() == 1)
        check('and the departing admin\'s is gone',
              main.AnalyticsSettings.query.count() == 1)

    print('\n[5] demote re-homes the same way')
    owner_id, sub_id, asset_id, cal_id = setup()
    with app.app_context():
        site = main.Website(user_id=owner_id, name='Main', is_draft=False)
        db.session.add(site)
        db.session.commit()
    with app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(owner_id)
            s['_fresh'] = True
        r = c.post(f'/admin/users/{sub_id}/demote')
        check(f'the demote succeeds — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        asset = db.session.get(main.Asset, asset_id)
        check('the asset survives a demote too',
              asset is not None and asset.uploaded_by_user_id is None)
        check('and their calendar is the owner\'s now',
              db.session.get(main.Calendar, cal_id).user_id == owner_id)


    print('\n[6] demoting hands the GitHub link back')
    # Promotion MOVES the link from the mirror onto the admin row and clears it
    # from the mirror. Demotion deleted that row without moving it back, so an
    # admin who signs in with GitHub was left with no way in at all.
    owner_id, sub_id, asset_id, cal_id = setup()
    with app.app_context():
        site = main.Website(user_id=owner_id, name='Main', is_draft=False)
        db.session.add(site)
        db.session.commit()
        sub = db.session.get(main.User, sub_id)
        sub.github_user_id = 987654
        mirror = main.PublicUser(website_id=site.id, username=sub.username,
                                 mirrored_admin_user_id=sub.id)
        db.session.add(mirror)
        db.session.commit()
        site_id, mirror_id = site.id, mirror.id
        check('the admin holds the link, the mirror does not',
              sub.github_user_id == 987654 and mirror.github_user_id is None)

    with app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(owner_id)
            s['_fresh'] = True
            s['admin_website_id'] = site_id
        r = c.post(f'/admin/users/{sub_id}/demote')
        check(f'the demote succeeds — got {r.status_code}', r.status_code == 200)

    with app.app_context():
        survivor = db.session.get(main.PublicUser, mirror_id)
        check('the surviving member account still exists', survivor is not None)
        check('and now carries the GitHub link',
              survivor is not None and survivor.github_user_id == 987654)
        check('so signing in with GitHub still finds them',
              main.PublicUser.query.filter_by(website_id=site_id,
                                              github_user_id=987654).first() is not None)
        check('and no admin row holds it any more',
              main.User.query.filter_by(github_user_id=987654).first() is None)

    print('\n[7] a colliding link is dropped rather than crashing')
    owner_id, sub_id, asset_id, cal_id = setup()
    with app.app_context():
        site = main.Website(user_id=owner_id, name='Main', is_draft=False)
        db.session.add(site)
        db.session.commit()
        sub = db.session.get(main.User, sub_id)
        sub.github_user_id = 555
        db.session.add_all([
            main.PublicUser(website_id=site.id, username=sub.username,
                            mirrored_admin_user_id=sub.id),
            # Somebody else on the same site already holds it, which the unique
            # (website_id, github_user_id) index would refuse.
            main.PublicUser(website_id=site.id, username='someoneelse',
                            github_user_id=555),
        ])
        db.session.commit()
        site_id = site.id
    with app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(owner_id)
            s['_fresh'] = True
            s['admin_website_id'] = site_id
        r = c.post(f'/admin/users/{sub_id}/demote')
        check(f'the demote still succeeds — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        check('and the existing holder keeps it',
              main.PublicUser.query.filter_by(username='someoneelse').first()
              .github_user_id == 555)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
