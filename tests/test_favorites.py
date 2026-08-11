"""Members can star guides, quizzes and resources, and filter down to them.

    venv/bin/python tests/test_favorites.py

The Education section can grow to hundreds of items across three tabs, with no
way for a member to mark the handful they keep coming back to. A star on every
card and a Favourites filter on every tab is that way.

Two things the implementation has to get right:

  • The star must not be inside the card. Every card is an <a>, so a button
    inside it is invalid HTML and its click would navigate instead of saving.
    It sits beside the card in a positioned wrapper.

  • Starring is only offered for things the member can already see. Without
    that check, the favourites endpoint would confirm that a members-only or
    unpublished guide exists to anyone who guessed its id.

Favourites belong to an account, so they are offered only to a signed-in
member — a star that always bounced to the login page would be clutter.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import re
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-favorites')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-fav-test-')
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
        site = main.Website(user_id=owner.id, name='Site', is_draft=False, is_live=True,
                            public_users_enabled=True)
        db.session.add(site)
        db.session.commit()
        db.session.add(main.PublicPageContent(website_id=site.id, name='Home', slug='home',
                                              site_active_status=True))

        guide = main.Guide(website_id=site.id, title='Soldering', slug='sold',
                           status='published', description='d')
        other = main.Guide(website_id=site.id, title='Wiring', slug='wire',
                           status='published', description='d')
        hidden = main.Guide(website_id=site.id, title='Members only', slug='mem',
                            status='published', members_only=True)
        draft = main.Guide(website_id=site.id, title='Draft', slug='draft', status='draft')
        quiz = main.Quiz(website_id=site.id, title='Safety', is_public=True)
        unlisted = main.Quiz(website_id=site.id, title='Unlisted', is_public=False)
        res = main.Resource(website_id=site.id, title='Checklist', resource_type='link',
                            url='http://example.com', is_public=True)
        db.session.add_all([guide, other, hidden, draft, quiz, unlisted, res])
        db.session.commit()

        member = main.PublicUser(website_id=site.id, username='learner')
        member.set_password('memberpassword')
        db.session.add(member)
        db.session.commit()
        return dict(site=site.id, member=member.id, guide=guide.id, other=other.id,
                    hidden=hidden.id, draft=draft.id, quiz=quiz.id,
                    unlisted=unlisted.id, resource=res.id, owner=owner.id)


def as_member(ids):
    c = app.test_client()
    with c.session_transaction() as s:
        s['public_user_id'] = ids['member']
        s['public_user_website_id'] = ids['site']
    return c


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    ids = setup()

    print('\n[1] a member can star one of each kind')
    c = as_member(ids)

    def toggle(kind, item_id):
        r = c.post('/api/favorites/toggle', json={'type': kind, 'id': item_id})
        return r.status_code, (r.get_json() or {})

    for kind, key in (('guide', 'guide'), ('quiz', 'quiz'), ('resource', 'resource')):
        status, d = toggle(kind, ids[key])
        check(f'{kind} can be starred — got {status}',
              status == 200 and d.get('favorited') is True)
    with app.app_context():
        check('all three are stored',
              main.PublicUserFavorite.query.filter_by(
                  public_user_id=ids['member']).count() == 3)

    print('\n[2] and unstar it again')
    status, d = toggle('guide', ids['guide'])
    check(f'the same call turns it off — got {status}',
          status == 200 and d.get('favorited') is False)
    # It reports where things ENDED UP, so a repeated tap settles rather than
    # flip-flopping on a slow connection.
    status, d = toggle('guide', ids['guide'])
    check('and on again', d.get('favorited') is True)
    with app.app_context():
        check('never stored twice',
              main.PublicUserFavorite.query.filter_by(
                  public_user_id=ids['member'], item_type='guide',
                  item_id=ids['guide']).count() == 1)

    print('\n[3] you can only star what you can already see')
    for label, kind, key in (('a members-only guide', 'guide', 'hidden'),
                             ('an unpublished guide', 'guide', 'draft'),
                             ('an unlisted quiz', 'quiz', 'unlisted')):
        status, d = toggle(kind, ids[key])
        check(f'{label} is refused — got {status}', status == 404)
    status, _ = toggle('nope', ids['guide'])
    check(f'an unknown kind is refused — got {status}', status == 400)
    anon = app.test_client()
    r = anon.post('/api/favorites/toggle', json={'type': 'guide', 'id': ids['guide']})
    check(f'and a signed-out visitor is asked to sign in — got {r.status_code}',
          r.status_code == 401 and (r.get_json() or {}).get('needs_login') is True)
    with app.app_context():
        check('none of that stored anything',
              main.PublicUserFavorite.query.filter_by(
                  public_user_id=ids['member']).count() == 3)

    print('\n[4] the page shows the star beside the card, never inside it')
    from bs4 import BeautifulSoup
    html = c.get('/guides').get_data(as_text=True)
    soup = BeautifulSoup(html, 'html.parser')
    stars = soup.select('button.gi-fav')
    check(f'every visible item gets a star ({len(stars)})', len(stars) == 4)
    # Parsed, not pattern-matched: an <a> written inside a script comment makes
    # a regex over the raw page claim a nesting that isn't there.
    check('no star is nested inside a card link', not soup.select('a .gi-fav'))
    check('each star sits directly in its wrapper, beside the card',
          len(soup.select('.gi-fav-wrap > button.gi-fav')) == len(stars))
    check('every card is still wrapped',
          len(soup.select('.gi-fav-wrap')) == len(stars))
    check(f'the starred ones are marked as such '
          f'({len(soup.select("button.gi-fav[aria-pressed=true]"))})',
          len(soup.select('button.gi-fav[aria-pressed="true"]')) == 3)
    check('and the Favourites filter is offered', bool(soup.select('.gi-chip-fav')))

    print('\n[5] searching hides each star with its row')
    # The star is a SIBLING of the row inside the wrapper, not a child, so
    # hiding the row alone left every star behind. With nothing to give the
    # wrapper height they collapsed into one stack — nine stars piled up over
    # the single result. Confirmed in a browser: one match used to leave five
    # stars visible, 8px apart.
    import re as _re
    src = open(os.path.join(_REPO, 'Templates', 'guides_index.html')).read()
    wrapped = soup.select('.gi-fav-wrap > .gi-rsc-row, .gi-fav-wrap > .gi-card')
    check(f'rows really do sit inside a wrapper ({len(wrapped)})', len(wrapped) >= 1)
    filt = src[src.index('function giSetupSearch'):src.index("giSetupSearch('guides'")]
    check('the filter hides the row', "row.style.display = match" in filt)
    check('and the wrapper holding its star',
          _re.search(r"gi-fav-wrap[\s\S]{0,160}style\.display = match", filt) is not None)
    # Every searchable tab shares this one filter, so all three are covered.
    check('all three tabs use that same filter',
          src.count('giSetupSearch(') == 4)

    print('\n[6] the star is quiet enough to sit on every item')
    css = open(os.path.join(_REPO, 'static', 'css', 'resource_rows.css')).read()
    rule = _re.search(r'\.gi-fav \{([^}]*)\}', css).group(1)
    # It was a filled black disc, which on a light page was the loudest thing
    # in the list.
    check(f'no filled backing plate ({rule.strip().splitlines()[-3:][0].strip()[:40]}…)',
          'background: transparent' in rule and 'rgba(0,0,0,0.5)' not in rule)
    check('and no ring around it', 'border: 1px solid transparent' in rule)
    check('it is dimmed until wanted', _re.search(r'opacity:\s*0\.[1-6]', rule))
    check('legible over a cover image without one', 'drop-shadow' in rule)
    # Neutral grey, because these pages render light as well as dark.
    check('themed neutrally, not white-on-dark', 'rgba(127,127,127' in rule)
    check('saved is the state that gets colour',
          _re.search(r'\.gi-fav\.is-on \{[^}]*color:\s*#', css) is not None)

    print('\n[7] a signed-out visitor is offered none of it')
    page = BeautifulSoup(anon.get('/guides').get_data(as_text=True), 'html.parser')
    check('no stars', not page.select('button.gi-fav'))
    check('and no Favourites chip', not page.select('.gi-chip-fav'))

    print('\n[8] favourites are per member')
    with app.app_context():
        other_member = main.PublicUser(website_id=ids['site'], username='someoneelse')
        other_member.set_password('memberpassword')
        db.session.add(other_member)
        db.session.commit()
        other_id = other_member.id
    c2 = app.test_client()
    with c2.session_transaction() as s:
        s['public_user_id'] = other_id
        s['public_user_website_id'] = ids['site']
    page = c2.get('/guides').get_data(as_text=True)
    check('another member sees nothing starred',
          'aria-pressed="true"' not in page)

    print('\n[9] deleting an item clears it from everyone\'s list')
    admin = app.test_client()
    with admin.session_transaction() as s:
        s['_user_id'] = str(ids['owner'])
        s['_fresh'] = True
        s['editing_website_id'] = ids['site']
    with app.app_context():
        before = main.PublicUserFavorite.query.filter_by(
            item_type='quiz', item_id=ids['quiz']).count()
        check('the quiz is starred to begin with', before == 1)
    r = admin.post(f"/admin/quizzes/{ids['quiz']}/delete")
    check(f'deleting it succeeds — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        check('and no favourite is left pointing at it',
              main.PublicUserFavorite.query.filter_by(
                  item_type='quiz', item_id=ids['quiz']).count() == 0)

    print('\n[10] closing an account takes its favourites with it')
    with app.app_context():
        member = db.session.get(main.PublicUser, ids['member'])
        main._delete_public_user_row(member)
        db.session.commit()
        check('nothing of theirs is left',
              main.PublicUserFavorite.query.filter_by(
                  public_user_id=ids['member']).count() == 0)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
