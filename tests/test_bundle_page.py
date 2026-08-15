"""A resource bundle opens on its own page when you click its title.

    venv/bin/python tests/test_bundle_page.py

Bundles group related resources inside a category — a how-to video, its written
steps, a checklist. On the Resources tab they were only ever an inline box:
fine for three items, unreadable for fifteen, and with nowhere to link a
colleague to.

The title is now a link to the bundle on its own page. The contents stay listed
inline as well, deliberately — the tab's search filters those rows, and
collapsing bundles to a card would have quietly made everything inside them
unfindable.

The page repeats the index's visibility rules rather than trusting the id in
the URL. A bundle id is a small number and easy to guess, so an unlisted or
members-only resource must not become readable just because it sits in one.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import atexit
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-bundles')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-bundle-test-')
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
        cat = main.ResourceCategory(website_id=site.id, name='Workshop',
                                    slug='workshop')
        db.session.add(cat)
        db.session.commit()
        bundle = main.ResourceBundle(website_id=site.id, category_id=cat.id,
                                     name='Soldering kit',
                                     description='Everything for a first joint',
                                     icon='fa-fire', color='#ff8844')
        empty = main.ResourceBundle(website_id=site.id, category_id=cat.id,
                                    name='Nothing visible')
        db.session.add_all([bundle, empty])
        db.session.commit()

        rows = [
            main.Resource(website_id=site.id, category_id=cat.id, bundle_id=bundle.id,
                          title='How to solder', resource_type='video',
                          url='https://www.youtube.com/watch?v=abc123',
                          is_public=True, sort_order=1),
            main.Resource(website_id=site.id, category_id=cat.id, bundle_id=bundle.id,
                          title='Written steps', resource_type='page',
                          content='<h2>Tin the tip</h2><p>A clean tip transfers heat.</p>'
                                  '<table><tr><th>Alloy</th></tr></table>',
                          is_public=True, sort_order=2),
            # Present but not for everybody, and not listed on the tab.
            main.Resource(website_id=site.id, category_id=cat.id, bundle_id=bundle.id,
                          title='Instructor notes', resource_type='page',
                          content='<p>Secret</p>', is_public=True,
                          members_only=True, sort_order=3),
            main.Resource(website_id=site.id, category_id=cat.id, bundle_id=bundle.id,
                          title='Unlisted draft', resource_type='page',
                          content='<p>Draft</p>', is_public=False, sort_order=4),
            # Same category, no bundle — must not appear on the bundle page.
            main.Resource(website_id=site.id, category_id=cat.id, title='Loose item',
                          resource_type='link', url='http://e.com', is_public=True),
            # Content behind a login: listed, but never inlined for a visitor.
            main.Resource(website_id=site.id, category_id=cat.id, bundle_id=bundle.id,
                          title='Members-first article', resource_type='page',
                          content='<p>Gated body text</p>', is_public=True,
                          require_login_to_view=True, sort_order=5),
            # A members-only resource is the ONLY thing in this bundle.
            main.Resource(website_id=site.id, category_id=cat.id, bundle_id=empty.id,
                          title='Members handbook', resource_type='page',
                          content='<p>x</p>', is_public=True, members_only=True),
        ]
        db.session.add_all(rows)
        db.session.commit()

        member = main.PublicUser(website_id=site.id, username='learner',
                                 membership_status='member')
        member.set_password('memberpassword')
        visitor = main.PublicUser(website_id=site.id, username='guest')
        visitor.set_password('memberpassword')
        db.session.add_all([member, visitor])
        db.session.commit()
        return dict(site=site.id, cat=cat.id, bundle=bundle.id, empty=empty.id,
                    member=member.id, visitor=visitor.id, owner=owner.id)


def as_public(ids, key):
    c = app.test_client()
    with c.session_transaction() as s:
        s['public_user_id'] = ids[key]
        s['public_user_website_id'] = ids['site']
    return c


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    ids = setup()
    anon = app.test_client()
    from bs4 import BeautifulSoup

    print('\n[1] the bundle title on the Resources tab is a link')
    soup = BeautifulSoup(anon.get('/guides').get_data(as_text=True), 'html.parser')
    head = soup.select_one('a.gi-bundle-head')
    check('the header is a link', head is not None)
    check(f'pointing at that bundle ({head and head.get("href")})',
          head is not None and head['href'].endswith(f"/resources/bundle/{ids['bundle']}"))
    check('the title is inside it',
          head is not None and 'Soldering kit' in head.get_text())
    # Deliberate: the tab's search filters these rows, so hiding them behind the
    # link would make everything inside a bundle unsearchable.
    check('and the contents are still listed inline',
          'How to solder' in soup.get_text())

    print('\n[2] the page presents everything in the bundle')
    r = anon.get(f"/resources/bundle/{ids['bundle']}")
    check(f'it opens — got {r.status_code}', r.status_code == 200)
    body = r.get_data(as_text=True)
    page = BeautifulSoup(body, 'html.parser')
    check('the bundle name is the heading',
          (page.select_one('.bp-title') or page).get_text().strip() == 'Soldering kit')
    check('its description is shown',
          'Everything for a first joint' in page.get_text())
    check('its own icon and colour are used',
          page.select_one('.bp-icon i.fa-fire') is not None
          and '#ff8844' in (page.select_one('.bp-icon') or {}).get('style', ''))
    check('the category is named as a breadcrumb',
          'Workshop' in (page.select_one('.bp-crumb') or page).get_text())
    # Inlined sections carry their own heading; only link/file items stay rows.
    titles = ([t.get_text().strip() for t in page.select('.bp-item-title')]
              + [t.get_text().strip() for t in page.select('.gi-rsc-title')])
    check(f'everything a visitor may see is listed, in order ({titles})',
          titles == ['How to solder', 'Written steps', 'Members-first article'])
    check(f'the count matches what is shown',
          '3 items' in page.get_text())
    check('and there is a way back',
          page.select_one('a.bp-back') is not None)

    print('\n[3] videos and articles open out in place, from the list')
    # It stays a list — a video or an article expands where it is rather than
    # sending you to another page and back.
    drawers = page.select('details.bp-item')
    check(f'each is a disclosure row ({len(drawers)})', len(drawers) == 2)
    check('closed to begin with, so it reads as a list',
          not any(d.has_attr('open') for d in drawers))
    check('each has a summary you click',
          all(d.select_one('summary.bp-item-row') is not None for d in drawers))
    # <details> rather than a hand-rolled accordion: it works with no
    # JavaScript, is keyboard-operable, and the browser's own find-in-page
    # reaches inside it.
    check('the content is really in the page, not fetched on click',
          'A clean tip transfers heat.' in body)
    check('the video is embedded, not linked',
          page.select_one('.rsc-video iframe') is not None)
    check('through the same embed builder its own page uses',
          'youtube.com/embed/abc123' in body)
    # Ten collapsed videos must not mean ten players loading up front.
    check('and the player is deferred until it is shown',
          page.select_one('.rsc-video iframe').get('loading') == 'lazy')
    check('the article keeps its formatting', page.select_one('.rsc-rich h2') is not None)
    # A wide table used to drag the whole page sideways on a phone.
    check('and a wide table scrolls inside itself',
          page.select_one('.rsc-rich table') is not None
          and page.select_one('.uw-table-scroll, [style*="overflow-x"]') is not None)
    check('anchored so it can be linked to directly',
          page.select_one('details.bp-item[id^="resource-"]') is not None)
    check('and a link to one opens it rather than scrolling to a shut drawer',
          'hashchange' in body and 'el.open = true' in body)
    check('each offers its own page as well',
          len(page.select('.bp-item-open')) == 2)
    # Links and files are pointers — there is nothing to open out, so they stay
    # as ordinary rows that navigate.
    check('a link is still a row that navigates', len(page.select('a.gi-rsc-row')) == 1)
    check('and it points at the resource route',
          '/resource/' in page.select_one('a.gi-rsc-row')['href'])
    check('the star sits outside the drawer, not inside the summary',
          not page.select('summary .gi-fav'))

    print('\n[4] a resource behind a login is listed but never inlined')
    # Inlining it would hand out exactly the content the /resource/<id> gate
    # exists to withhold.
    check('it is listed', 'Members-first article' in body)
    check('but its body is not on the page', 'Gated body text' not in body)
    check('it is shown as a locked row, not a drawer',
          page.select_one('.gi-rsc-lock') is not None
          and len(page.select('details.bp-item')) == 2)
    signed_in = as_public(ids, 'visitor')
    body_in = signed_in.get(f"/resources/bundle/{ids['bundle']}").get_data(as_text=True)
    check('and it opens out once signed in', 'Gated body text' in body_in)

    print('\n[5] nothing leaks that the tab would not show')
    body = r.get_data(as_text=True)
    check('a members-only resource is not on the page', 'Instructor notes' not in body)
    check('nor an unlisted one', 'Unlisted draft' not in body)
    check('nor a resource from the same category outside the bundle',
          'Loose item' not in body)

    print('\n[6] a member sees their own material')
    mc = as_public(ids, 'member')
    page = BeautifulSoup(mc.get(f"/resources/bundle/{ids['bundle']}").get_data(as_text=True),
                         'html.parser')
    titles = ([t.get_text().strip() for t in page.select('.bp-item-title')]
              + [t.get_text().strip() for t in page.select('.gi-rsc-title')])
    check(f'the members-only item appears for them ({titles})',
          'Instructor notes' in titles)
    check('but the unlisted one still does not', 'Unlisted draft' not in titles)
    vc = as_public(ids, 'visitor')
    body = vc.get(f"/resources/bundle/{ids['bundle']}").get_data(as_text=True)
    check('a signed-in non-member is treated like a visitor',
          'Instructor notes' not in body)

    print('\n[7] a bundle with nothing to show is a plain 404')
    # Saying "this bundle is empty" would confirm the hidden material exists.
    r = anon.get(f"/resources/bundle/{ids['empty']}")
    check(f'not an empty page — got {r.status_code}', r.status_code == 404)
    r = mc.get(f"/resources/bundle/{ids['empty']}")
    check(f'but a member can open it — got {r.status_code}', r.status_code == 200)
    r = anon.get('/resources/bundle/99999')
    check(f'an id that does not exist — got {r.status_code}', r.status_code == 404)

    print('\n[8] members can star from the bundle page too')
    check('signed out, there are no stars',
          not BeautifulSoup(anon.get(f"/resources/bundle/{ids['bundle']}")
                            .get_data(as_text=True), 'html.parser').select('button.gi-fav'))
    page = BeautifulSoup(mc.get(f"/resources/bundle/{ids['bundle']}").get_data(as_text=True),
                         'html.parser')
    stars = page.select('button.gi-fav')
    check(f'signed in, every item has one — rows and inlined sections alike '
          f'({len(stars)} for {len(titles)} items)', len(stars) == len(titles))
    # Same rule as the index: the row is a link, so a button inside it would be
    # invalid HTML and would navigate instead of saving.
    check('and none is nested inside the row link', not page.select('a .gi-fav'))
    r = mc.post('/api/favorites/toggle',
                json={'type': 'resource', 'id': int(page.select_one('button.gi-fav')['data-fav-id'])})
    check(f'starring from here works — got {r.status_code}',
          r.status_code == 200 and (r.get_json() or {}).get('favorited') is True)
    page = BeautifulSoup(mc.get(f"/resources/bundle/{ids['bundle']}").get_data(as_text=True),
                         'html.parser')
    check('and it comes back starred',
          len(page.select('button.gi-fav[aria-pressed="true"]')) == 1)

    print('\n[9] an offline or draft site does not serve it')
    with app.app_context():
        site = db.session.get(main.Website, ids['site'])
        site.is_live = False
        db.session.commit()
    r = app.test_client().get(f"/resources/bundle/{ids['bundle']}")
    check(f'taken offline — got {r.status_code}', r.status_code == 404)
    with app.app_context():
        db.session.get(main.Website, ids['site']).is_live = True
        db.session.commit()


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
