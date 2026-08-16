"""Display names keep their capitals, and an admin can close their own account.

    venv/bin/python tests/test_display_name_and_self_delete.py

Two unrelated fixes that happen to share a session:

  • A @validates hook lower-cased every public display name on the way in, so
    "Seth Eastwood" appeared beside somebody's forum posts as "seth eastwood".
    Stored as typed now; uniqueness is still case-insensitive so nobody can
    pass for somebody else by capitalising differently.

  • Deleting the account you are signed in with was refused outright, which
    left an admin unable to close their own account without asking someone
    else. Allowed now for everyone except the primary owner.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import atexit
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-names-and-self-delete')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-name-test-')
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
        site = main.Website(user_id=owner.id, name='Site', is_draft=False)
        db.session.add(site)
        db.session.commit()

        member = main.PublicUser(website_id=site.id, username='seastwood')
        other = main.PublicUser(website_id=site.id, username='rowan')
        db.session.add_all([member, other])
        db.session.commit()
        return owner.id, site.id, member.id, other.id


def main_test():
    owner_id, site_id, member_id, other_id = setup()
    app.config['WTF_CSRF_ENABLED'] = False

    print('\n[1] a display name is stored the way it was typed')
    with app.app_context():
        m = db.session.get(main.PublicUser, member_id)
        m.display_username = 'Seth Eastwood'
        db.session.commit()
        stored = db.session.get(main.PublicUser, member_id).display_username
        check(f'capitals survive ({stored!r})', stored == 'Seth Eastwood')
        check('and that is what the site shows',
              db.session.get(main.PublicUser, member_id).effective_display_name == 'Seth Eastwood')

        m = db.session.get(main.PublicUser, member_id)
        m.display_username = '   Padded  Name   '
        db.session.commit()
        check('surrounding whitespace is still trimmed',
              db.session.get(main.PublicUser, member_id).display_username == 'Padded  Name')

        m = db.session.get(main.PublicUser, member_id)
        m.display_username = '   '
        db.session.commit()
        m = db.session.get(main.PublicUser, member_id)
        check('a blank name becomes NULL, not an empty string',
              m.display_username is None)
        check('and it falls back to the login username',
              m.effective_display_name == 'seastwood')

    print('\n[2] but nobody can impersonate by capitalising differently')
    with app.app_context():
        m = db.session.get(main.PublicUser, member_id)
        m.display_username = 'Seth Eastwood'
        db.session.commit()
        clash = main.display_username_collision('SETH EASTWOOD', site_id,
                                                exclude_public_user_id=other_id)
        check('a differently-cased duplicate is refused', bool(clash))
        check('an unrelated name is fine',
              main.display_username_collision('Totally Different', site_id,
                                              exclude_public_user_id=other_id) is None)
        check("another member's LOGIN name is refused too, whatever the case",
              bool(main.display_username_collision('RoWaN', site_id,
                                                   exclude_public_user_id=member_id)))
        check("an admin's username is still reserved",
              bool(main.display_username_collision('OWNER', site_id)))
        check('your own current name does not clash with itself',
              main.display_username_collision('Seth Eastwood', site_id,
                                              exclude_public_user_id=member_id) is None)

    print('\n[3] an admin can close their own account')
    with app.app_context():
        helper = main.User(username='helper', parent_user_id=owner_id,
                           permissions={'settings.view': True})
        helper.set_password('x')
        db.session.add(helper)
        db.session.commit()
        helper_id = helper.id
        # Something of the organisation's, to prove it is handed over not lost.
        db.session.add(main.Calendar(user_id=helper_id, name='Their calendar'))
        db.session.commit()

    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(helper_id)
        s['_fresh'] = True
        s['admin_website_id'] = site_id

    r = c.post(f'/admin/users/{helper_id}/delete')
    d = r.get_json() or {}
    check(f'no admin_users.delete permission needed — got {r.status_code}',
          r.status_code == 200 and d.get('success') is True)
    check('the response says it was a self-deletion', d.get('self_deleted') is True)
    check('and where to go next', bool(d.get('redirect')))
    with app.app_context():
        check('the account is gone', db.session.get(main.User, helper_id) is None)
        check("the organisation's calendar moved to the owner",
              main.Calendar.query.filter_by(user_id=owner_id).count() == 1)

    print('\n[4] the session really ends')
    after = c.get('/admin/users')
    check(f'the old session no longer reaches the admin panel — got {after.status_code}',
          after.status_code in (301, 302, 401, 403, 404))

    print('\n[5] and from the public account settings page too')
    # The route allowed it but the page still said "ask an owner" and rendered
    # no button, so the only way to reach the route was to call it by hand.

    with app.app_context():
        helper2 = main.User(username='helper2', parent_user_id=owner_id)
        helper2.set_password('x')
        db.session.add(helper2)
        db.session.commit()
        mirror = main.PublicUser(website_id=site_id, username='helper2',
                                 mirrored_admin_user_id=helper2.id)
        db.session.add(mirror)
        db.session.commit()
        # Their own chat message, and one from the owner, to prove authorship
        # is not handed over.
        db.session.add_all([
            main.AdminChatMessage(user_id=helper2.id, message='from the leaver'),
            main.AdminChatMessage(user_id=owner_id, message='from the owner'),
        ])
        db.session.commit()
        helper2_id, mirror_id = helper2.id, mirror.id

    pc = app.test_client()
    with pc.session_transaction() as s:
        s['public_user_id'] = mirror_id
        s['public_user_website_id'] = site_id

    page = pc.get('/account/settings').get_data(as_text=True)
    check('the page no longer tells them to ask an owner',
          'Ask an owner to remove your staff account' not in page)
    check('it offers the Delete button',
          'btn-danger" onclick="openDeleteModal()' in page)
    check('and warns that the admin account goes with it',
          'also closes your admin account' in page)

    r = pc.post('/account/delete')
    d = r.get_json() or {}
    check(f'a staff mirror can close its admin account — got {r.status_code}',
          r.status_code == 200 and d.get('success') is True)
    with app.app_context():
        check('the admin account is gone',
              db.session.get(main.User, helper2_id) is None)
        check('and its mirror with it',
              db.session.get(main.PublicUser, mirror_id) is None)

    print('\n[6] authorship is not handed to somebody else')
    with app.app_context():
        msgs = {m.message: m.user_id for m in main.AdminChatMessage.query.all()}
        check('both messages survive', len(msgs) == 2)
        check("the leaver's message is no longer attributed to anyone",
              msgs.get('from the leaver') is None)
        check("and was NOT re-attributed to the owner",
              msgs.get('from the leaver') != owner_id)
        check("the owner's own message is untouched",
              msgs.get('from the owner') == owner_id)

    print('\n[7] but the primary owner is still refused, on that page too')
    with app.app_context():
        owner_mirror = main.PublicUser(website_id=site_id, username='owner',
                                       mirrored_admin_user_id=owner_id)
        db.session.add(owner_mirror)
        db.session.commit()
        owner_mirror_id = owner_mirror.id
    oc = app.test_client()
    with oc.session_transaction() as s:
        s['public_user_id'] = owner_mirror_id
        s['public_user_website_id'] = site_id
    page = oc.get('/account/settings').get_data(as_text=True)
    check('the owner gets no Delete button',
          'btn-danger" onclick="openDeleteModal()' not in page)
    check('and is told to transfer ownership first',
          'Transfer ownership' in page)
    ro = oc.post('/account/delete')
    check(f'calling it directly is refused too — got {ro.status_code}',
          ro.status_code == 403)
    with app.app_context():
        check('the owner survives', db.session.get(main.User, owner_id) is not None)

    print('\n[8] the primary owner still cannot delete themselves')
    o = app.test_client()
    with o.session_transaction() as s:
        s['_user_id'] = str(owner_id)
        s['_fresh'] = True
        s['admin_website_id'] = site_id
    ro = o.post(f'/admin/users/{owner_id}/delete')
    do = ro.get_json() or {}
    check(f'refused — got {ro.status_code}', ro.status_code == 403)
    check('and told why', 'primary owner' in (do.get('error') or '').lower())
    with app.app_context():
        check('the owner is still there', db.session.get(main.User, owner_id) is not None)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
