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
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-bundles')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-bundle-test-')
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
                          url='https://youtu.be/x', is_public=True, sort_order=1),
            main.Resource(website_id=site.id, category_id=cat.id, bundle_id=bundle.id,
                          title='Written steps', resource_type='page',
                          content='<p>Steps</p>', is_public=True, sort_order=2),
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
    page = BeautifulSoup(r.get_data(as_text=True), 'html.parser')
    check('the bundle name is the heading',
          (page.select_one('.bp-title') or page).get_text().strip() == 'Soldering kit')
    check('its description is shown',
          'Everything for a first joint' in page.get_text())
    check('its own icon and colour are used',
          page.select_one('.bp-icon i.fa-fire') is not None
          and '#ff8844' in (page.select_one('.bp-icon') or {}).get('style', ''))
    check('the category is named as a breadcrumb',
          'Workshop' in (page.select_one('.bp-crumb') or page).get_text())
    titles = [t.get_text() for t in page.select('.gi-rsc-title')]
    check(f'both public resources are listed ({titles})',
          titles == ['How to solder', 'Written steps'])
    check('the count matches what is shown',
          '2 items' in page.get_text())
    check('rows use the same markup as the tab',
          len(page.select('a.gi-rsc-row')) == 2)
    check('and there is a way back',
          page.select_one('a.bp-back') is not None)

    print('\n[3] nothing leaks that the tab would not show')
    body = r.get_data(as_text=True)
    check('a members-only resource is not on the page', 'Instructor notes' not in body)
    check('nor an unlisted one', 'Unlisted draft' not in body)
    check('nor a resource from the same category outside the bundle',
          'Loose item' not in body)

    print('\n[4] a member sees their own material')
    mc = as_public(ids, 'member')
    page = BeautifulSoup(mc.get(f"/resources/bundle/{ids['bundle']}").get_data(as_text=True),
                         'html.parser')
    titles = [t.get_text() for t in page.select('.gi-rsc-title')]
    check(f'the members-only item appears for them ({titles})',
          'Instructor notes' in titles)
    check('but the unlisted one still does not', 'Unlisted draft' not in titles)
    vc = as_public(ids, 'visitor')
    body = vc.get(f"/resources/bundle/{ids['bundle']}").get_data(as_text=True)
    check('a signed-in non-member is treated like a visitor',
          'Instructor notes' not in body)

    print('\n[5] a bundle with nothing to show is a plain 404')
    # Saying "this bundle is empty" would confirm the hidden material exists.
    r = anon.get(f"/resources/bundle/{ids['empty']}")
    check(f'not an empty page — got {r.status_code}', r.status_code == 404)
    r = mc.get(f"/resources/bundle/{ids['empty']}")
    check(f'but a member can open it — got {r.status_code}', r.status_code == 200)
    r = anon.get('/resources/bundle/99999')
    check(f'an id that does not exist — got {r.status_code}', r.status_code == 404)

    print('\n[6] members can star from the bundle page too')
    check('signed out, there are no stars',
          not BeautifulSoup(anon.get(f"/resources/bundle/{ids['bundle']}")
                            .get_data(as_text=True), 'html.parser').select('button.gi-fav'))
    page = BeautifulSoup(mc.get(f"/resources/bundle/{ids['bundle']}").get_data(as_text=True),
                         'html.parser')
    stars = page.select('button.gi-fav')
    check(f'signed in, every row has one ({len(stars)})', len(stars) == 3)
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

    print('\n[7] an offline or draft site does not serve it')
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
