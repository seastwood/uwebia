"""The Guides / Quizzes / Resources tabs can be searched, and cleared again.

    venv/bin/python tests/test_education_tab_search.py

Each Education tab filters its own list as you type. Two things about that were
wrong on a phone.

The field is <input type="search">, whose clear button exists only on desktop
WebKit — mobile Safari and Chrome for Android never draw one — and the styling
had `-webkit-appearance: none`, which removes it even there. So on a phone the
only way to get back to the full list was to select the text and delete it. The
field now carries a real clear button, sized for a fingertip.

Clearing has to run the same code path a keystroke does. The filter hides both
the row and the wrapper holding its favourite star; a clear that only emptied
the value would leave the list filtered, and one that re-implemented the reset
would be a second place for the two to disagree.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import atexit
import os
import re
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-tab-search')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-tabsearch-test-')
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
        site = main.Website(user_id=owner.id, name='Site', is_draft=False,
                            is_live=True, public_users_enabled=True)
        db.session.add(site)
        db.session.commit()
        db.session.add(main.PublicPageContent(website_id=site.id, name='Home',
                                              slug='home', site_active_status=True))
        db.session.add(main.Guide(website_id=site.id, title='Soldering', slug='sold',
                                  status='published', description='d'))
        db.session.add(main.Quiz(website_id=site.id, title='Safety', is_public=True))
        db.session.add(main.Resource(website_id=site.id, title='Checklist',
                                     resource_type='link', url='http://e.com',
                                     is_public=True))
        db.session.commit()
        return dict(site=site.id, owner=owner.id)


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    setup()
    from bs4 import BeautifulSoup
    body = app.test_client().get('/guides').get_data(as_text=True)
    soup = BeautifulSoup(body, 'html.parser')

    print('\n[1] every searchable tab has a clear button')
    bars = soup.select('.gi-search')
    check(f'all three tabs have a search bar ({len(bars)})', len(bars) == 3)
    buttons = soup.select('.gi-search .gi-search-clear')
    check(f'and each has its own clear button ({len(buttons)})', len(buttons) == 3)
    check('it sits inside the field, after the input',
          all(b.find_previous_sibling('input') is not None for b in buttons))
    check('each is labelled for a screen reader',
          all((b.get('aria-label') or '').lower().startswith('clear') for b in buttons))
    labels = sorted((b.get('aria-label') or '') for b in buttons)
    check(f'and says which list it clears ({labels})', len(set(labels)) == 3)
    check('it is a button, so it never submits anything',
          all(b.get('type') == 'button' for b in buttons))

    print('\n[2] it stays out of the way until there is something to clear')
    check('hidden on load', all(b.has_attr('hidden') for b in buttons))
    src = open(os.path.join(_REPO, 'Templates', 'guides_index.html')).read()
    filt = src[src.index('function giSetupSearch'):src.index("giSetupSearch('guides'")]
    check('shown exactly while the field has text',
          'clear.hidden = !searching' in filt)

    print('\n[3] clearing goes through the same path as typing')
    # The filter hides the row AND the wrapper holding its star. A clear that
    # re-implemented the reset would be a second place for those to disagree.
    check('it empties the field', "input.value = ''" in filt)
    check('then re-runs the real filter rather than repeating it',
          "dispatchEvent(new Event('input'" in filt)
    check('and hands focus back so you can keep typing',
          'input.focus()' in filt)

    print('\n[4] the native button was never going to do this')
    # -webkit-appearance:none removes it on desktop WebKit, and no mobile
    # browser draws one at all — which is why this had to be built.
    css = src[src.index('.gi-search {'):src.index('.gi-search-empty')]
    check('the field still suppresses the native one',
          '-webkit-appearance: none' in css)
    check('and explicitly hides the WebKit cancel button',
          '::-webkit-search-cancel-button' in css)
    m = re.search(r'\.gi-search-clear \{([^}]*)\}', src)
    rule = m.group(1) if m else ''
    size = re.search(r'width:\s*(\d+)px;\s*height:\s*(\d+)px', rule)
    check(f'the tap target is finger-sized, not cursor-sized '
          f'({size and size.group(0)})',
          size is not None and int(size.group(1)) >= 28 and int(size.group(2)) >= 28)
    check('it inherits the page colour rather than assuming a dark theme',
          'color: inherit' in rule)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
