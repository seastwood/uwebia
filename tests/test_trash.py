"""Deleted things land in a bin they can be recovered from.

    venv/bin/python tests/test_trash.py

Until now every delete was final. This puts a snapshot of the row and its
children in a trash table first, so a wrong click is recoverable.

A snapshot rather than a soft-delete flag, deliberately: nothing else in the app
has to learn to filter out deleted rows, so no listing can ever accidentally
show something that is in the bin. The cost is that restoring rebuilds the row,
which is what the type registry describes.

Two things it has to get right:

  • Restoring must ask before it collides. Anything with a name can find that
    name taken while it was in the bin, and discovering that halfway through a
    restore is worse than being asked up front.

  • Accounts are people, not content. However long an org chooses to keep its
    deleted pages — the default is forever — a deleted member or admin goes
    within 60 days, and the org setting cannot extend that.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import re
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-trash')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-trash-test-')
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
        site = main.Website(user_id=owner.id, name='Site', is_draft=False, is_live=True)
        db.session.add(site)
        db.session.commit()

        guide = main.Guide(website_id=site.id, title='Soldering', slug='sold',
                           status='published', description='How to solder')
        db.session.add(guide)
        db.session.commit()
        db.session.add(main.GuideNode(guide_id=guide.id, website_id=site.id,
                                      node_type='lesson', title='Tinning', slug='tin',
                                      content='<p>Tin the iron.</p>'))
        quiz = main.Quiz(website_id=site.id, title='Safety')
        res = main.Resource(website_id=site.id, title='Checklist', resource_type='link',
                            url='http://example.com')
        cal = main.Calendar(user_id=owner.id, website_id=site.id, name='Practice')
        db.session.add_all([quiz, res, cal])
        db.session.commit()

        member = main.PublicUser(website_id=site.id, username='learner')
        member.set_password('memberpassword')
        db.session.add(member)
        db.session.commit()

        # A second site with a page tree on it. The main site cannot be deleted,
        # so a website test needs one that can.
        second = main.Website(user_id=owner.id, name='Second', url_prefix='second',
                              is_draft=False, is_live=True)
        db.session.add(second)
        db.session.commit()
        home = main.PublicPageContent(website_id=second.id, name='Home', slug='home',
                                      site_active_status=True)
        about = main.PublicPageContent(website_id=second.id, name='About', slug='about',
                                       site_active_status=True)
        db.session.add_all([home, about])
        db.session.commit()
        group = main.SectionGroup(page_content_id=about.id, name='G', group_order=0)
        db.session.add(group)
        db.session.commit()
        section = main.PageSection(page_content_id=about.id, section_type='text', order=0,
                                   content={'html': '<p>About us</p>'})
        db.session.add(section)
        db.session.commit()
        prow = main.Row(page_content_id=about.id, row_number=0, section_group_id=group.id)
        db.session.add(prow)
        db.session.commit()
        db.session.add(main.Column(row_id=prow.id, column_number=0,
                                   section_id=section.id, width=100))
        site_guide = main.Guide(website_id=second.id, title='Site guide', slug='sg',
                                status='published')
        db.session.add(site_guide)
        db.session.commit()

        return dict(owner=owner.id, site=site.id, guide=guide.id, quiz=quiz.id,
                    resource=res.id, calendar=cal.id, member=member.id,
                    second=second.id, about=about.id, section=section.id,
                    site_guide=site_guide.id)


def as_owner(ids):
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(ids['owner'])
        s['_fresh'] = True
        s['editing_website_id'] = ids['site']
    return c


def listing(c, **params):
    from urllib.parse import urlencode
    r = c.get('/admin/trash/list' + ('?' + urlencode(params) if params else ''))
    return r.get_json() or {}


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    ids = setup()
    c = as_owner(ids)

    print('\n[1] deleting puts things in the bin instead of losing them')
    for label, url in (('guide', f"/admin/guides/{ids['guide']}/delete"),
                       ('quiz', f"/admin/quizzes/{ids['quiz']}/delete"),
                       ('resource', f"/admin/resources/{ids['resource']}/delete"),
                       ('calendar', f"/admin/calendars/{ids['calendar']}/delete")):
        r = c.post(url)
        check(f'{label} deletes — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        check('the guide really is gone from its table',
              db.session.get(main.Guide, ids['guide']) is None)
    d = listing(c)
    kinds = sorted(i['type'] for i in d.get('items', []))
    check(f'all four are in the bin ({kinds})',
          kinds == ['calendar', 'guide', 'quiz', 'resource'])
    entry = next(i for i in d['items'] if i['type'] == 'guide')
    check(f"it remembers what it was called ({entry['label']})",
          entry['label'] == 'Soldering')
    check('and when it went', bool(entry['deleted_at']))
    check(f"and who did it ({entry['deleted_by']})", entry['deleted_by'] == 'owner')

    print('\n[2] restoring brings it back, children and all')
    r = c.post(f"/admin/trash/{entry['id']}/restore", json={})
    check(f'the restore succeeds — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        g = main.Guide.query.filter_by(slug='sold').first()
        check('the guide is back', g is not None)
        check('under its original id, so anything pointing at it still lines up',
              g is not None and g.id == ids['guide'])
        check('with its description intact',
              g is not None and g.description == 'How to solder')
        check('and its lesson came back too',
              main.GuideNode.query.filter_by(guide_id=g.id).count() == 1)
        check('the bin entry is spent',
              db.session.get(main.TrashItem, entry['id']) is None)

    print('\n[3] a name taken meanwhile stops the restore and asks')
    c.post(f"/admin/guides/{ids['guide']}/delete")
    with app.app_context():
        db.session.add(main.Guide(website_id=ids['site'], title='Something else',
                                  slug='sold', status='draft'))
        db.session.commit()
    entry = next(i for i in listing(c)['items'] if i['type'] == 'guide')
    conflicts = (c.get(f"/admin/trash/{entry['id']}/conflicts").get_json() or {}).get('conflicts')
    check(f'the clash is reported before anything is written ({conflicts})',
          conflicts and conflicts[0]['field'] == 'slug')
    r = c.post(f"/admin/trash/{entry['id']}/restore", json={})
    check(f'restoring anyway is refused — got {r.status_code}', r.status_code == 409)
    with app.app_context():
        check('and nothing was half-written',
              main.Guide.query.filter_by(slug='sold').count() == 1)
    r = c.post(f"/admin/trash/{entry['id']}/restore",
               json={'resolutions': {'slug': 'sold-restored'}})
    check(f'renaming it lets it back — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        check('both now exist',
              main.Guide.query.filter_by(slug='sold').count() == 1
              and main.Guide.query.filter_by(slug='sold-restored').count() == 1)

    print('\n[4] accounts are capped at 60 days whatever the org sets')
    r = c.post(f"/admin/users/public/{ids['member']}/delete")
    check(f'deleting a member succeeds — got {r.status_code}', r.status_code == 200)
    person = next(i for i in listing(c)['items'] if i['type'] == 'public_user')
    check(f"it is flagged as a person ({person['is_person']})", person['is_person'] is True)
    check(f"with a countdown from the day it went ({person['days_left']})",
          person['days_left'] == main.TRASH_MAX_DAYS_PEOPLE)

    r = c.post('/admin/trash/retention', json={'days': 365})
    check(f'the org can ask for a year — got {r.status_code}', r.status_code == 200)
    items = {i['type']: i['days_left'] for i in listing(c)['items']}
    check(f"content follows the setting ({items.get('quiz')})", items.get('quiz') == 365)
    check(f"but the account does not ({items.get('public_user')})",
          items.get('public_user') == main.TRASH_MAX_DAYS_PEOPLE)

    r = c.post('/admin/trash/retention', json={'days': 7})
    items = {i['type']: i['days_left'] for i in listing(c)['items']}
    check(f"a shorter window DOES apply to accounts ({items.get('public_user')})",
          items.get('public_user') == 7)

    c.post('/admin/trash/retention', json={'days': 0})
    items = {i['type']: i['days_left'] for i in listing(c)['items']}
    check('back to forever, content is kept until emptied',
          items.get('quiz') is None)
    check(f"and the account is still capped ({items.get('public_user')})",
          items.get('public_user') == main.TRASH_MAX_DAYS_PEOPLE)

    print('\n[5] the countdown actually runs out')
    with app.app_context():
        row = main.TrashItem.query.filter_by(item_type='public_user').first()
        row.expires_at = (main.datetime.now(main.timezone.utc).replace(tzinfo=None)
                          - main.timedelta(days=1))
        db.session.commit()
        check('one expired item is swept', main.purge_expired_trash() == 1)
        check('and it is gone for good',
              main.TrashItem.query.filter_by(item_type='public_user').count() == 0)

    print('\n[6] selecting, deleting and emptying')
    d = listing(c)
    check(f"several things are in the bin ({d['total']})", d['total'] >= 2)
    some = [i['id'] for i in d['items'][:1]]
    r = c.post('/admin/trash/delete', json={'ids': some})
    check(f'chosen items can be deleted for good — got {r.status_code}',
          r.status_code == 200 and (r.get_json() or {}).get('deleted') == 1)
    r = c.post('/admin/trash/delete', json={})
    check(f'deleting nothing is refused rather than emptying — got {r.status_code}',
          r.status_code == 400)
    r = c.post('/admin/trash/delete', json={'all': True})
    check(f'and the bin can be emptied — got {r.status_code}', r.status_code == 200)
    check('leaving it empty', listing(c)['total'] == 0)

    print('\n[7] the list is paginated and filterable')
    with app.app_context():
        for i in range(7):
            db.session.add(main.TrashItem(
                root_user_id=ids['owner'], item_type='quiz', label=f'Quiz {i}',
                payload={'row': {}, 'children': {}}))
        db.session.commit()
    d = listing(c, per_page=5, page=1)
    check(f"page one holds five of seven ({len(d['items'])}/{d['total']})",
          len(d['items']) == 5 and d['total'] == 7 and d['pages'] == 2)
    d = listing(c, per_page=5, page=2)
    check(f"page two holds the rest ({len(d['items'])})", len(d['items']) == 2)
    d = listing(c, q='Quiz 3')
    check(f"search narrows it ({d['total']})", d['total'] == 1)
    d = listing(c, type='guide')
    check(f'filtering by type narrows it ({d["total"]})', d['total'] == 0)

    print('\n[8] one org cannot see or touch another\'s bin')
    with app.app_context():
        stranger = main.User(username='stranger', parent_user_id=None)
        stranger.set_password('x')
        db.session.add(stranger)
        db.session.commit()
        stranger_id = stranger.id
        mine = main.TrashItem.query.first()
        mine_id = mine.id
    other = app.test_client()
    with other.session_transaction() as s:
        s['_user_id'] = str(stranger_id)
        s['_fresh'] = True
    check(f"their bin is empty ({listing(other)['total']})", listing(other)['total'] == 0)
    r = other.post(f'/admin/trash/{mine_id}/restore', json={})
    check(f'and they cannot restore ours — got {r.status_code}', r.status_code == 404)
    r = other.post('/admin/trash/delete', json={'ids': [mine_id]})
    check('nor delete it',
          (r.get_json() or {}).get('deleted') == 0)
    with app.app_context():
        check('it is still there', db.session.get(main.TrashItem, mine_id) is not None)

    print('\n[9] it needs permission, and cannot be hidden by a setting')
    with app.app_context():
        helper = main.User(username='helper', parent_user_id=ids['owner'],
                           permissions={'posts.view': True})
        helper.set_password('x')
        db.session.add(helper)
        db.session.commit()
        helper_id = helper.id
    limited = app.test_client()
    with limited.session_transaction() as s:
        s['_user_id'] = str(helper_id)
        s['_fresh'] = True
        s['editing_website_id'] = ids['site']
    r = limited.get('/admin/trash')
    check(f'an admin without the permission cannot open it — got {r.status_code}',
          r.status_code in (302, 403))
    r = limited.post('/admin/trash/delete', json={'all': True})
    check(f'nor empty it — got {r.status_code}', r.status_code in (302, 403))
    with app.app_context():
        check('so nothing was lost', main.TrashItem.query.count() > 0)

    navbar = open(os.path.join(_REPO, 'Templates', 'components', 'navbar.html')).read()
    at = navbar.index('admin_trash_page')
    block = navbar[at - 500:at + 200]
    check('the navbar entry is not gated on the disable list',
          "'trash' not in _nd" not in block)
    check('and it lives in the dropdown, not the inline bar',
          'nav-tools-item' in block)

    # Pinned to the foot of the dropdown: it is where you go when something has
    # gone wrong, not somewhere to hit on the way past. Checked against the
    # rendered page, since source order alone would not prove it.
    page = c.get('/admin/users').get_data(as_text=True)
    from bs4 import BeautifulSoup
    menu = BeautifulSoup(page, 'html.parser').select_one('#navToolsDropdownContent')
    check('the dropdown renders', menu is not None)
    if menu:
        items = [i.get_text(' ', strip=True) for i in menu.select('.nav-tools-item')
                 if 'nav-tools-subitem' not in (i.get('class') or [])]
        check(f'Trash is the last entry ({items[-1] if items else None})',
              items and items[-1] == 'Trash')
        check('and is set apart from what sits above it',
              'nav-tools-item--last' in str(menu))

    print('\n[10] a page goes to the bin with everything on it')
    ids2 = setup()
    c = as_owner(ids2)
    r = c.post(f"/delete_page/{ids2['second']}/{ids2['about']}")
    check(f'the page deletes — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        check('the page is gone',
              db.session.get(main.PublicPageContent, ids2['about']) is None)
        check('and its section with it',
              db.session.get(main.PageSection, ids2['section']) is None)
    entry = next(i for i in listing(c)['items'] if i['type'] == 'page')
    check(f"it is in the bin as a page ({entry['label']})", entry['label'] == 'About')
    r = c.post(f"/admin/trash/{entry['id']}/restore", json={})
    check(f'restoring succeeds — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        check('the page is back',
              db.session.get(main.PublicPageContent, ids2['about']) is not None)
        check('its section is back',
              db.session.get(main.PageSection, ids2['section']) is not None)
        check('and so are the row and column that laid it out',
              main.Row.query.filter_by(page_content_id=ids2['about']).count() == 1
              and main.Column.query.count() == 1)

    print('\n[11] and so does a whole website')
    # Deleting a website clears around thirty tables, so the snapshot is swept
    # off the schema rather than a hand-written list.
    r = c.post(f"/delete_website/{ids2['second']}", json={'password': 'ownerpassword'})
    check(f'the website deletes — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        check('the site is gone', db.session.get(main.Website, ids2['second']) is None)
        check('its pages went with it',
              main.PublicPageContent.query.filter_by(website_id=ids2['second']).count() == 0)
        check('and its guide',
              db.session.get(main.Guide, ids2['site_guide']) is None)
    entry = next(i for i in listing(c)['items'] if i['type'] == 'website')
    check(f"it is in the bin as a website ({entry['label']})", entry['label'] == 'Second')
    r = c.post(f"/admin/trash/{entry['id']}/restore", json={})
    check(f'restoring succeeds — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        site = db.session.get(main.Website, ids2['second'])
        check('the site is back', site is not None)
        check(f'with its address ({site.url_prefix if site else None})',
              site is not None and site.url_prefix == 'second')
        check('both pages came back',
              main.PublicPageContent.query.filter_by(website_id=ids2['second']).count() == 2)
        check('its guide came back',
              db.session.get(main.Guide, ids2['site_guide']) is not None)
        check('and the page tree beneath it',
              main.PageSection.query.count() == 1 and main.Column.query.count() == 1)

    print('\n[12] the page itself renders')
    r = c.get('/admin/trash')
    body = r.get_data(as_text=True)
    check(f'it opens — got {r.status_code}', r.status_code == 200)
    check('with the retention control', 'trRetention' in body)
    check('the conflict dialog', 'trConflictOverlay' in body)
    check('and the timer legend', 'fa-hourglass-half' in body)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
