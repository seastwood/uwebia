"""Usernames and display names are letters, numbers, short, and not profane.

    venv/bin/python tests/test_username_rules.py

A username had no constraints at all — an entire URL fitted, so did markup, an
email address, or 150 characters of anything. These names print beside forum
posts and comments and share a namespace with admin accounts.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-username-rules')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-uname-test-')
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
        site = main.Website(user_id=owner.id, name='Site', is_draft=False, is_live=True,
                            public_users_enabled=True, allow_public_signup=True,
                            profanity_filter_enabled=True,
                            post_profanity_words='badword\nrudeword')
        db.session.add(site)
        db.session.commit()
        return owner.id, site.id


def main_test():
    owner_id, site_id = setup()
    app.config['WTF_CSRF_ENABLED'] = False

    with app.app_context():
        site = db.session.get(main.Website, site_id)

        print('\n[1] what a username may be')
        ok, err = main.validate_username('seth123', website=site)
        check('letters and numbers are fine', err is None and ok == 'seth123')
        check('and it is stored lower-cased',
              main.validate_username('SethEastwood', website=site)[0] == 'setheastwood')

        print('\n[2] and what it may not')
        cases = [
            ('https://example.com/some/path', 'a whole URL'),
            ('seth eastwood', 'spaces'),
            ('seth.eastwood', 'a dot'),
            ('seth_eastwood', 'an underscore'),
            ('seth@example.com', 'an email address'),
            ('<b>seth</b>', 'markup'),
            ('sethʼs', 'a smart quote'),
            ('日本語', 'characters outside A-Z0-9'),
        ]
        for value, what in cases:
            _, e = main.validate_username(value, website=site)
            check(f'{what} is refused ({value[:24]!r})', bool(e))

        print('\n[2b] but a single dash between words is a name, not an attack')
        ok, err = main.validate_username('anne-marie', website=site)
        check('a hyphenated name is allowed', err is None and ok == 'anne-marie')
        check('and more than one dash is fine',
              main.validate_username('a-b-c', website=site)[1] is None)
        for value, what in [('-seth', 'a leading dash'),
                            ('seth-', 'a trailing dash'),
                            ('seth--eastwood', 'a doubled dash'),
                            ('-', 'a dash on its own')]:
            check(f'{what} is still refused ({value!r})',
                  bool(main.validate_username(value, website=site)[1]))
        check('a URL is still refused now that dashes are legal',
              bool(main.validate_username('https://ex-ample.com/p', website=site)[1]))

        print('\n[3] length')
        check('too short is refused',
              bool(main.validate_username('ab', website=site)[1]))
        check(f'at the minimum ({main.USERNAME_MIN_LENGTH}) is fine',
              main.validate_username('a' * main.USERNAME_MIN_LENGTH, website=site)[1] is None)
        check(f'at the maximum ({main.USERNAME_MAX_LENGTH}) is fine',
              main.validate_username('a' * main.USERNAME_MAX_LENGTH, website=site)[1] is None)
        check('one over the maximum is refused',
              bool(main.validate_username('a' * (main.USERNAME_MAX_LENGTH + 1), website=site)[1]))
        check('and it cannot exceed the column it is stored in',
              main.USERNAME_MAX_LENGTH <= 80)
        check('blank is refused', bool(main.validate_username('', website=site)[1]))

        print('\n[4] the profanity list applies to names too')
        _, e = main.validate_username('badword99', website=site)
        check('a banned word anywhere in the name is refused', bool(e))
        check('the message does not repeat the word back',
              e and 'badword' not in e.lower())
        check('an innocent name is unaffected',
              main.validate_username('goodname', website=site)[1] is None)
        with app.app_context():
            off = main.Website(user_id=owner_id, name='Off', is_draft=False,
                               url_prefix='off', profanity_filter_enabled=False,
                               post_profanity_words='badword')
            db.session.add(off)
            db.session.commit()
            check('a site with the filter switched off does not apply it',
                  main.validate_username('badword99', website=off)[1] is None)

        print('\n[5] display names are names, not identifiers')
        ok, err = main.validate_display_name('Seth Eastwood', website=site)
        check('a real name with a space and capitals is allowed',
              err is None and ok == 'Seth Eastwood')
        check('blank is allowed — it falls back to the username',
              main.validate_display_name('', website=site) == ('', None))
        check('doubled spaces are collapsed, not rejected',
              main.validate_display_name('Seth   Eastwood', website=site)[0] == 'Seth Eastwood')
        check('a hyphenated display name is allowed',
              main.validate_display_name('Anne-Marie Smith', website=site)
              == ('Anne-Marie Smith', None))
        for value, what in [('Seth.Eastwood', 'punctuation'),
                            ('Seth--Eastwood', 'a doubled dash'),
                            ('-Seth', 'a leading dash'),
                            ('<b>Seth</b>', 'markup'),
                            ('http://x.com', 'a URL'),
                            ('badword', 'a banned word')]:
            check(f'{what} is refused in a display name',
                  bool(main.validate_display_name(value, website=site)[1]))
        check('and it is length-capped',
              bool(main.validate_display_name(
                  'a' * (main.DISPLAY_NAME_MAX_LENGTH + 1), website=site)[1]))

    print('\n[6] the rules are enforced at the door, not just in the helper')
    c = app.test_client()
    r = c.post('/register', data={
        'username': 'https://evil.example.com/path',
        'password': 'longenoughpw', 'email': 'a@b.com',
        'website_prefix': ''}, follow_redirects=True)
    body = r.get_data(as_text=True)
    check('a URL cannot be registered as a username',
          'only contain' in body.lower())
    with app.app_context():
        check('and no such account was created',
              main.PublicUser.query.filter(
                  main.PublicUser.username.like('%evil%')).count() == 0)

    admin = app.test_client()
    with admin.session_transaction() as s:
        s['_user_id'] = str(owner_id)
        s['_fresh'] = True
        s['admin_website_id'] = site_id
    r = admin.post('/admin/users/create', json={
        'username': 'bad user name!', 'password': 'longenoughpw'})
    check(f'nor created as an admin account — got {r.status_code}',
          r.status_code == 400 and 'only contain' in
          ((r.get_json() or {}).get('error') or '').lower())


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
