"""A feed can publish its whole run as a public schedule page.

    venv/bin/python tests/test_feed_public_schedule.py

The hopper is a plan, and the people it is aimed at benefit from seeing the
plan — catching up on what they missed, or working ahead. The page shows every
item in order with the current one highlighted, the same way the admin hopper
marks it.

What matters here:

  * position in the run is the only source of truth for state — before the
    cursor is released, the cursor is current, after it is upcoming;
  * released dates come from what actually happened (the run log), upcoming
    ones are projected forward from the schedule;
  * a schedule tied to a division belongs to that division: it must not be
    listed to, or openable by, anyone else — while staff always pass;
  * publishing is opt-in, and a slug is unique per site or a second schedule
    silently shadows the first.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import shutil
import sys
import tempfile
from datetime import datetime

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-public-schedule')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-schedule-test-')
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

        owner = main.User(username='owner', parent_user_id=None,
                          timezone='America/Chicago')
        owner.set_password('ownerpassword')
        db.session.add(owner)
        db.session.commit()
        site = main.Website(user_id=owner.id, name='Team', is_draft=False,
                            is_live=True, public_users_enabled=True)
        db.session.add(site)
        db.session.commit()
        db.session.add(main.PublicPageContent(website_id=site.id, name='Home',
                                              slug='home', site_active_status=True))

        build = main.Division(website_id=site.id, name='Build', slug='build')
        drive = main.Division(website_id=site.id, name='Drive', slug='drive')
        db.session.add_all([build, drive])
        db.session.commit()

        guides = []
        for n in range(1, 5):
            g = main.Guide(website_id=site.id, title=f'Week {n}', slug=f'week-{n}',
                           status='published', description=f'Lesson {n}.')
            guides.append(g)
        db.session.add_all(guides)
        db.session.commit()

        feed = main.NotificationFeed(
            user_id=owner.id, website_id=site.id, name='Internal name',
            days_of_week=[1], send_time='18:00', is_active=True,
            public_enabled=True, public_title='Build Training Schedule',
            public_slug='build-training-schedule',
            public_description='Everything the build crew works through.',
            division_id=build.id, position=2)
        db.session.add(feed)
        db.session.commit()
        for i, g in enumerate(guides):
            db.session.add(main.NotificationFeedItem(
                feed_id=feed.id, sort_order=i, item_type='guide', ref_id=g.id))
        db.session.commit()

        # Two of them have actually gone out.
        items = feed.items.order_by(main.NotificationFeedItem.sort_order).all()
        for i, it in enumerate(items[:2]):
            db.session.add(main.NotificationFeedRun(
                feed_id=feed.id, slot_key=f'2026-08-{11 + i} 18:00', item_id=it.id,
                item_title=f'Week {i + 1}', status='sent', success=True,
                sent_at=datetime(2026, 8, 11 + i, 23, 0)))
        db.session.commit()

        members = {}
        for name, div in (('builder', build), ('driver', drive), ('nobody', None)):
            pu = main.PublicUser(website_id=site.id, username=name,
                                 membership_status='member')
            pu.set_password('memberpassword')
            db.session.add(pu)
            db.session.commit()
            if div is not None:
                db.session.add(main.DivisionMembership(
                    public_user_id=pu.id, division_id=div.id, status='active'))
                db.session.commit()
            members[name] = pu.id

        return dict(owner=owner.id, site=site.id, feed=feed.id,
                    build=build.id, drive=drive.id, **members)


def as_member(uid, site_id):
    # get_public_user() needs BOTH keys — the website id is what stops a
    # session from one site being honoured on another.
    c = app.test_client()
    with c.session_transaction() as s:
        s['public_user_id'] = uid
        s['public_user_website_id'] = site_id
    return c


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    ids = setup()
    URL = '/training/build-training-schedule'

    print('\n[1] the page shows the whole run, current one marked')
    c = as_member(ids['builder'], ids['site'])
    r = c.get(URL)
    check(f'a division member can open it ({r.status_code})', r.status_code == 200)
    html = r.get_data(as_text=True)
    check('titled the way the admin named it', 'Build Training Schedule' in html)
    check('not by the feed\'s internal name', 'Internal name' not in html)
    check('the blurb is shown', 'Everything the build crew works through' in html)
    for n in range(1, 5):
        check(f'week {n} is listed', f'Week {n}' in html)

    from bs4 import BeautifulSoup
    rows = BeautifulSoup(html, 'html.parser').select('.fs-row')
    states = [' '.join(sorted(set(r.get('class')) - {'fs-row'})) for r in rows]
    check(f'four rows, in order ({states})', len(rows) == 4)
    check('the first two read as released', states[0] == 'released' and states[1] == 'released')
    check('the third is the current one', states[2] == 'next')
    check('the fourth is still upcoming', states[3] == 'upcoming')
    check('and the current one is badged', 'Current' in rows[2].get_text())

    print('\n[2] dates come from what happened, and what is planned')
    check('a released row says when it went out',
          'Released Aug 11, 2026' in rows[0].get_text())
    check('the current one shows when it is due', 'Due' in rows[2].get_text())
    check('progress is spelled out', '2 of 4 released so far' in html)

    print('\n[3] items link out so you can work ahead')
    links = [a.get('href') for a in BeautifulSoup(html, 'html.parser').select('.fs-name a')]
    check(f'every row links to its guide ({len(links)})', len(links) == 4)
    check('including ones that have not been released yet',
          any(l.endswith('/guides/week-4') for l in links))

    print('\n[4] a division schedule belongs to that division')
    other = as_member(ids['driver'], ids['site'])
    check(f'another division cannot open it ({other.get(URL).status_code})',
          other.get(URL).status_code == 404)
    check('nor is it listed for them',
          'Build Training Schedule' not in other.get('/guides').get_data(as_text=True))
    check('while its own division sees it listed',
          'Build Training Schedule' in c.get('/guides').get_data(as_text=True))
    anon = app.test_client()
    check(f'a signed-out visitor cannot open it ({anon.get(URL).status_code})',
          anon.get(URL).status_code == 404)

    print('\n[4b] "all members" reaches every member, whatever their division')
    # The capability existed (no division + members-only) but was not sayable:
    # two unrelated controls you had to combine. It is one choice now.
    ac0 = app.test_client()
    with ac0.session_transaction() as s:
        s['_user_id'] = str(ids['owner'])
        s['_fresh'] = True
        s['admin_website_id'] = ids['site']
    r = ac0.post(f'/admin/notifications/feeds/{ids["feed"]}/update',
                 json={'public_audience': 'members'})
    check(f'the audience can be set to all members ({r.get_json().get("error")})',
          r.get_json().get('success'))
    with app.app_context():
        f = db.session.get(main.NotificationFeed, ids['feed'])
        check('which means no division and members-only',
              f.division_id is None and f.public_members_only is True)
    check('the other division now sees it too',
          'Build Training Schedule' in other.get('/guides').get_data(as_text=True)
          or 'Renamed' in other.get('/guides').get_data(as_text=True))
    check(f'and can open it ({other.get(URL).status_code})',
          other.get(URL).status_code == 200)
    check('while a signed-out visitor still cannot',
          app.test_client().get(URL).status_code in (302, 403, 404))

    r = ac0.post(f'/admin/notifications/feeds/{ids["feed"]}/update',
                 json={'public_audience': 'everyone'})
    check('opening it to everyone drops the members gate',
          r.get_json().get('success'))
    check(f'so a visitor can read it ({app.test_client().get(URL).status_code})',
          app.test_client().get(URL).status_code == 200)

    r = ac0.post(f'/admin/notifications/feeds/{ids["feed"]}/update',
                 json={'public_audience': f'division:{ids["build"]}'})
    check('and picking a division puts it back', r.get_json().get('success'))
    with app.app_context():
        f = db.session.get(main.NotificationFeed, ids['feed'])
        check('with membership implied — a division is made of members',
              f.division_id == ids['build'] and f.public_members_only is True)
    check(f'the other division is shut out again ({other.get(URL).status_code})',
          other.get(URL).status_code == 404)
    r = ac0.post(f'/admin/notifications/feeds/{ids["feed"]}/update',
                 json={'public_audience': 'division:999999'})
    check(f'an unknown division is refused ({r.status_code})', r.status_code == 404)
    r = ac0.post(f'/admin/notifications/feeds/{ids["feed"]}/update',
                 json={'public_audience': 'nonsense'})
    check(f'as is an unknown audience ({r.status_code})', r.status_code == 400)

    print('\n[4c] an open schedule reaches people with no account at all')
    ac0.post(f'/admin/notifications/feeds/{ids["feed"]}/update',
             json={'public_audience': 'everyone'})
    anon = app.test_client()
    r = anon.get(URL)
    check(f'a signed-out visitor can open it ({r.status_code})', r.status_code == 200)
    check('and read the whole run', 'Week 4' in r.get_data(as_text=True))
    anon_index = anon.get('/guides').get_data(as_text=True)
    check('it is listed for them too', 'data-tab="training"' in anon_index)
    # "My Training" belongs to someone. A visitor with no account is reading a
    # published schedule, not theirs.
    check('but the tab is not called "My Training" for them',
          '> Training</button>' in anon_index and 'My Training' not in anon_index)
    member_index = c.get('/guides').get_data(as_text=True)
    check('while a member still sees it as theirs', 'My Training' in member_index)

    visitor = main.PublicUser(website_id=ids['site'], username='justlooking',
                              membership_status='visitor')
    with app.app_context():
        visitor.set_password('x')
        db.session.add(visitor)
        db.session.commit()
        vid = visitor.id
    vc = as_member(vid, ids['site'])
    check(f'a logged-in non-member can open it too ({vc.get(URL).status_code})',
          vc.get(URL).status_code == 200)
    check('and it is listed for them',
          'data-tab="training"' in vc.get('/guides').get_data(as_text=True))

    print('\n[4d] rows carry the detail you need before opening one')
    with app.app_context():
        site_id = ids['site']
        g1 = main.Guide.query.filter_by(slug='week-1').first()
        g1.cover_image_url = '/static/uploads/1/assets/w1.webp'
        # Two lessons, so the row can say how long it is.
        for n, t in enumerate(['Intro', 'Practice']):
            db.session.add(main.GuideNode(guide_id=g1.id, website_id=site_id,
                                          title=t, slug=f'n{n}',
                                          node_type='lesson', sort_order=n,
                                          is_published=True))
        quiz = main.Quiz(website_id=site_id, title='Shop safety check',
                         pass_threshold=0.8, max_attempts=2)
        db.session.add(quiz)
        db.session.commit()
        for n in range(3):
            db.session.add(main.QuizQuestion(quiz_id=quiz.id, prompt=f'Q{n}',
                                             question_type='single_choice',
                                             points=1, sort_order=n))
        feed = db.session.get(main.NotificationFeed, ids['feed'])
        db.session.add_all([
            main.NotificationFeedItem(feed_id=feed.id, sort_order=90,
                                      item_type='quiz', ref_id=quiz.id),
            main.NotificationFeedItem(feed_id=feed.id, sort_order=91,
                                      item_type='link', title='Vendor docs',
                                      url='https://www.example.com/docs'),
        ])
        feed.public_members_only = False
        feed.division_id = None
        db.session.commit()

    page = as_member(ids['builder'], ids['site']).get(URL).get_data(as_text=True)
    soup = BeautifulSoup(page, 'html.parser')
    check('a guide with a cover shows the picture',
          soup.select_one('.fs-thumb img') is not None
          and 'w1.webp' in soup.select_one('.fs-thumb img')['src'])
    check('rows with no picture fall back to a glyph for their kind',
          soup.select_one('.fs-thumb.is-glyph i') is not None)
    text = soup.get_text(' ', strip=True)
    check(f'a guide says how long it is ({"2 lessons" in text})', '2 lessons' in text)
    check('a quiz says how many questions', '3 questions' in text)
    check('and what it takes to pass', '80% to pass' in text)
    check('and how many attempts you get', '2 attempts' in text)
    check('a link says where it goes', 'example.com' in text)
    check('without the noisy www', 'www.example.com' not in text)

    print('\n[4e] the page shows the reader their own progress')
    with app.app_context():
        g1 = main.Guide.query.filter_by(slug='week-1').first()
        nodes = main.GuideNode.query.filter_by(guide_id=g1.id).order_by(
            main.GuideNode.sort_order).all()
        # visitor_id_hash is NOT NULL even for a logged-in reader — progress is
        # recorded against both, and the query matches on either.
        db.session.add(main.GuideProgress(
            guide_id=g1.id, guide_node_id=nodes[0].id, website_id=site_id,
            visitor_id_hash='builder-visitor-hash',
            public_user_id=ids['builder'],
            completed_at=datetime(2026, 8, 12, 10, 0)))
        db.session.commit()
    page = as_member(ids['builder'], ids['site']).get(URL).get_data(as_text=True)
    check('a part-finished guide shows how far through', '1 of 2 lessons done' in page)
    check('and the header counts what YOU have completed',
          "You've completed" in page)
    # Someone else's progress is not theirs.
    other_page = as_member(ids['driver'], ids['site']).get(URL).get_data(as_text=True)
    check('another reader does not inherit it', '1 of 2 lessons done' not in other_page)

    print('\n[4f] only training feeds belong in the training tab')
    # The same machinery drives a reading list or a run of announcements. Those
    # are not somebody's course material, so they must not be listed as it.
    ac0.post(f'/admin/notifications/feeds/{ids["feed"]}/update',
             json={'public_audience': 'members'})
    member_index = c.get('/guides').get_data(as_text=True)
    check('a training feed is listed', 'data-tab="training"' in member_index)

    r = ac0.post(f'/admin/notifications/feeds/{ids["feed"]}/update',
                 json={'feed_type': 'announcements'})
    check('the type can be changed', r.get_json().get('success'))
    after = c.get('/guides').get_data(as_text=True)
    check('an announcements feed drops out of the tab',
          'data-tab="training"' not in after)
    check('but its page still works — it is published, just not course material',
          c.get(URL).status_code == 200)

    r = ac0.post(f'/admin/notifications/feeds/{ids["feed"]}/update',
                 json={'feed_type': 'nonsense'})
    check(f'an unknown type is refused ({r.status_code})', r.status_code == 400)
    with app.app_context():
        check('and the feed keeps the type it had',
              db.session.get(main.NotificationFeed, ids['feed']).feed_type
              == 'announcements')

    editor = ac0.get(f'/admin/notifications/feeds/{ids["feed"]}').get_data(as_text=True)
    check('the editor offers the type', 'id="feedType"' in editor)
    check('listing every kind', all(k in editor for k in main.FEED_TYPES))
    check('and says a non-training feed will not be listed',
          'still gets its page' in editor)

    ac0.post(f'/admin/notifications/feeds/{ids["feed"]}/update',
             json={'feed_type': 'training'})
    check('switching back puts it in the tab',
          'data-tab="training"' in c.get('/guides').get_data(as_text=True))

    print('\n[5] publishing is opt-in')
    with app.app_context():
        feed = db.session.get(main.NotificationFeed, ids['feed'])
        feed.public_enabled = False
        db.session.commit()
    check(f'unpublished 404s ({c.get(URL).status_code})', c.get(URL).status_code == 404)
    check('and drops off the learning index',
          'Build Training Schedule' not in c.get('/guides').get_data(as_text=True))
    with app.app_context():
        db.session.get(main.NotificationFeed, ids['feed']).public_enabled = True
        db.session.commit()

    print('\n[6] the admin controls it from the feed editor')
    ac = app.test_client()
    with ac.session_transaction() as s:
        s['_user_id'] = str(ids['owner'])
        s['_fresh'] = True
        s['admin_website_id'] = ids['site']
    editor = ac.get(f'/admin/notifications/feeds/{ids["feed"]}').get_data(as_text=True)
    check('the editor offers the public page controls', 'id="publicEnabled"' in editor)
    check('a title, address and blurb',
          'id="publicTitle"' in editor and 'id="publicSlug"' in editor
          and 'id="publicDescription"' in editor)
    check('one audience picker rather than two switches to combine',
          'id="publicAudience"' in editor and 'publicMembersOnly' not in editor)
    check('offering all members and each division',
          '>All members' in editor and 'Build division' in editor)
    check('and links to the live page', URL in editor)

    r = ac.post(f'/admin/notifications/feeds/{ids["feed"]}/update',
                json={'public_title': 'Renamed Schedule'})
    check('the title can be changed', r.get_json().get('success'))
    check('which the page picks up',
          'Renamed Schedule' in c.get(URL).get_data(as_text=True))

    print('\n[7] a slug cannot shadow another schedule')
    with app.app_context():
        owner_id = db.session.get(main.NotificationFeed, ids['feed']).user_id
        rival = main.NotificationFeed(user_id=owner_id, website_id=ids['site'],
                                      name='Other', days_of_week=[2],
                                      send_time='18:00')
        db.session.add(rival)
        db.session.commit()
        rival_id = rival.id
    r = ac.post(f'/admin/notifications/feeds/{rival_id}/update',
                json={'public_slug': 'build-training-schedule'})
    check(f'a duplicate address is refused ({r.get_json().get("error", "")[:34]!r})',
          not r.get_json().get('success'))
    r = ac.post(f'/admin/notifications/feeds/{rival_id}/update',
                json={'public_slug': 'Drive Training!!'})
    check(f'and a messy one is slugified ({r.get_json()})', r.get_json().get('success'))
    with app.app_context():
        check('into something URL-safe',
              db.session.get(main.NotificationFeed, rival_id).public_slug
              == 'drive-training')


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
