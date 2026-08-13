"""Sub-admins can be scoped to specific notification channels and feeds.

    venv/bin/python tests/test_notification_access.py

Mirrors the guide/quiz access pattern, with one deliberate difference: channels
and feeds are different KINDS of object, not two ways of naming one, so the two
grant lists are independent. Leaving a side unchecked means "all of that kind",
which is what lets someone own one feed while still reaching every channel.

The parts worth pinning down:

  * a grant hides the other objects from the listing AND blocks the routes —
    a scoped admin must not be able to reach a feed by typing its URL;
  * being pinned to specific feeds also stops you creating new ones, since a
    new feed would be outside everyone's grant;
  * an admin granted a feed but NOT the channel it posts to can still edit the
    feed. The editor sends the whole settings block on every save, so a naive
    "validate channel_id every time" would lock them out of their own feed;
  * the picker only offers guides/quizzes the admin is allowed to manage, and
    the create route enforces that too — the panel is not the security boundary.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-notif-access')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-notifaccess-test-')
shutil.copy2(os.path.join(_REPO, 'main.py'), os.path.join(_SCRATCH, 'main.py'))
# Templates/icons are read-only so the real ones are safe to reuse; `static` is
# never symlinked — see test_backup_import_idempotent.py for why.
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
    """An owner with two channels and two feeds, plus a sub-admin we re-scope
    through the test."""
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

        cat_a = main.GuideCategory(website_id=site.id, name='Build', slug='build')
        cat_b = main.GuideCategory(website_id=site.id, name='Safety', slug='safety')
        db.session.add_all([cat_a, cat_b])
        db.session.commit()
        g_open = main.Guide(website_id=site.id, title='Swerve drive', slug='swerve',
                            status='published', category_id=cat_a.id)
        g_shut = main.Guide(website_id=site.id, title='Mill safety', slug='mill',
                            status='published', category_id=cat_b.id)
        db.session.add_all([g_open, g_shut])

        ch_mine = main.NotificationChannel(
            user_id=owner.id, label='#mine',
            config={'webhook_url': main.encrypt_api_key(
                'https://discord.com/api/webhooks/1/a')})
        ch_other = main.NotificationChannel(
            user_id=owner.id, label='#other',
            config={'webhook_url': main.encrypt_api_key(
                'https://discord.com/api/webhooks/2/b')})
        db.session.add_all([ch_mine, ch_other])
        db.session.commit()

        f_mine = main.NotificationFeed(user_id=owner.id, website_id=site.id,
                                       channel_id=ch_other.id, name='Mine',
                                       days_of_week=[1], send_time='18:00')
        f_other = main.NotificationFeed(user_id=owner.id, website_id=site.id,
                                        channel_id=ch_mine.id, name='Not mine',
                                        days_of_week=[2], send_time='19:00')
        db.session.add_all([f_mine, f_other])
        db.session.commit()

        sub = main.User(username='helper', parent_user_id=owner.id)
        sub.set_password('helperpassword')
        sub.permissions = {'notifications.view': True, 'notifications.manage': True}
        db.session.add(sub)
        db.session.commit()

        return dict(owner=owner.id, sub=sub.id, site=site.id,
                    ch_mine=ch_mine.id, ch_other=ch_other.id,
                    f_mine=f_mine.id, f_other=f_other.id,
                    g_open=g_open.id, g_shut=g_shut.id,
                    cat_a=cat_a.id, cat_b=cat_b.id)


def scope(sub_id, **perms):
    """Replace the sub-admin's permission dict, keeping the base two."""
    with app.app_context():
        sub = db.session.get(main.User, sub_id)
        p = {'notifications.view': True, 'notifications.manage': True}
        p.update(perms)
        sub.permissions = p
        db.session.commit()


def client_for(uid, site_id):
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(uid)
        s['_fresh'] = True
        s['admin_website_id'] = site_id
    return c


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    main._send_to_discord_webhook = lambda url, payload, wait=False: None
    ids = setup()

    print('\n[1] with no grant, a sub-admin sees everything')
    scope(ids['sub'])
    c = client_for(ids['sub'], ids['site'])
    html = c.get('/admin/notifications').get_data(as_text=True)
    check('both channels listed', '#mine' in html and '#other' in html)
    check('both feeds listed', 'Not mine' in html)
    check('and they may create feeds',
          c.post('/admin/notifications/feeds/create',
                 json={'name': 'New one'}).get_json().get('success'))

    print('\n[2] a feed grant scopes the listing and the routes')
    scope(ids['sub'], **{'notifications.allowed_feed_ids': [ids['f_mine']]})
    c = client_for(ids['sub'], ids['site'])
    html = c.get('/admin/notifications').get_data(as_text=True)
    check('the granted feed is listed', 'Mine' in html)
    check('the other feed is not', 'Not mine' not in html)
    check('opening the granted feed works',
          c.get(f'/admin/notifications/feeds/{ids["f_mine"]}').status_code == 200)
    check('opening the other one 404s, not just hidden from the list',
          c.get(f'/admin/notifications/feeds/{ids["f_other"]}').status_code == 404)
    r = c.post(f'/admin/notifications/feeds/{ids["f_other"]}/update', json={'name': 'hijack'})
    check(f'and it cannot be edited by URL ({r.status_code})', r.status_code == 404)
    r = c.post('/admin/notifications/feeds/create', json={'name': 'Sneaky'})
    check(f'creating new feeds is blocked while pinned ({r.status_code})',
          r.status_code == 403 and not r.get_json().get('success'))
    check('channels are still all visible — the lists are independent',
          '#mine' in html and '#other' in html)

    print("\n[3] a feed grant without its channel still lets you edit the feed")
    # f_mine posts to ch_other, which this admin is NOT granted.
    scope(ids['sub'], **{'notifications.allowed_feed_ids': [ids['f_mine']],
                         'notifications.allowed_channel_ids': [ids['ch_mine']]})
    c = client_for(ids['sub'], ids['site'])
    check('the editor still opens',
          c.get(f'/admin/notifications/feeds/{ids["f_mine"]}').status_code == 200)
    # The editor posts the whole settings block, including the unchanged channel.
    r = c.post(f'/admin/notifications/feeds/{ids["f_mine"]}/update',
               json={'name': 'Mine', 'channel_id': ids['ch_other'],
                     'days_of_week': [3], 'send_time': '20:00'})
    check(f'saving with the unchanged foreign channel is allowed ({r.get_json().get("error")})',
          r.get_json().get('success'))
    with app.app_context():
        feed = db.session.get(main.NotificationFeed, ids['f_mine'])
        check('and the edit landed', feed.send_time == '20:00' and feed.days_of_week == [3])
    r = c.post(f'/admin/notifications/feeds/{ids["f_mine"]}/update',
               json={'channel_id': ids['ch_other'], 'name': 'Mine'})
    check('re-saving it still works', r.get_json().get('success'))
    # But MOVING a feed onto a channel they don't hold is refused.
    with app.app_context():
        db.session.get(main.NotificationFeed, ids['f_mine']).channel_id = ids['ch_mine']
        db.session.commit()
    r = c.post(f'/admin/notifications/feeds/{ids["f_mine"]}/update',
               json={'channel_id': ids['ch_other']})
    check(f'but moving it to an ungranted channel is refused ({r.status_code})',
          r.status_code == 404)

    print('\n[4] a channel grant scopes channels the same way')
    scope(ids['sub'], **{'notifications.allowed_channel_ids': [ids['ch_mine']]})
    c = client_for(ids['sub'], ids['site'])
    html = c.get('/admin/notifications').get_data(as_text=True)
    check('the granted channel is listed', '#mine' in html)
    check('the other channel is not', '#other' not in html)
    r = c.post(f'/admin/notifications/channels/{ids["ch_other"]}/update', json={'label': 'x'})
    check(f'the other cannot be edited by URL ({r.status_code})', r.status_code == 404)
    r = c.post(f'/admin/notifications/channels/{ids["ch_other"]}/delete')
    check(f'nor deleted ({r.status_code})', r.status_code == 404)
    r = c.post('/admin/notifications/channels/create',
               json={'label': 'New', 'webhook_url': 'https://discord.com/api/webhooks/9/z'})
    check(f'creating channels is blocked while pinned ({r.status_code})', r.status_code == 403)
    check('feeds remain fully visible', 'Not mine' in html)

    print('\n[5] the owner is never restricted')
    oc = client_for(ids['owner'], ids['site'])
    html = oc.get('/admin/notifications').get_data(as_text=True)
    check('sees every channel', '#mine' in html and '#other' in html)
    check('sees every feed', 'Not mine' in html)

    print('\n[6] the picker only offers what the admin may manage')
    scope(ids['sub'], **{'guides.allowed_category_ids': [ids['cat_a']]})
    c = client_for(ids['sub'], ids['site'])
    body = c.get(f'/admin/notifications/feeds/{ids["f_mine"]}').get_data(as_text=True)
    check('a guide in the granted category is offered', 'Swerve drive' in body)
    check('one outside it is not', 'Mill safety' not in body)
    check('and the categories are named in the panel', 'Build' in body)
    r = c.post(f'/admin/notifications/feeds/{ids["f_mine"]}/items/create',
               json={'item_type': 'guide', 'ref_id': ids['g_shut']})
    check(f'adding the ungranted guide is refused by the route too ({r.status_code})',
          r.status_code == 403)
    r = c.post(f'/admin/notifications/feeds/{ids["f_mine"]}/items/create',
               json={'item_type': 'guide', 'ref_id': ids['g_open']})
    check('the granted one adds fine', r.get_json().get('success'))

    print('\n[7] channels and feeds are separate tabs')
    page = oc.get('/admin/notifications').get_data(as_text=True)
    check('both tab buttons render', 'tabBtn-channels' in page and 'tabBtn-feeds' in page)
    check('and each has its own panel', 'id="tab-channels"' in page and 'id="tab-feeds"' in page)
    check('the feeds panel starts hidden so channels open first',
          'id="tab-feeds" role="tabpanel" aria-labelledby="tabBtn-feeds" hidden' in page)

    print('\n[8] the picker panel is searchable, and filters by category and membership')
    check('it has a search box', 'id="drawerSearch"' in body)
    check('with a type switcher', 'setDrawerKind(' in body)
    check('a category filter', 'id="drawerCat"' in body and 'All categories' in body)
    check('and an in-feed filter with both directions',
          'id="drawerInFeed"' in body
          and 'Not in the feed' in body and 'Already in the feed' in body)
    check('the category list is rebuilt per kind, since categories are kind-specific',
          'function syncCategoryOptions' in body and 'syncCategoryOptions();' in body)
    check('all three filters compose in one pass',
          "membership === 'out' && added" in body
          and "membership === 'in' && !added" in body
          and 'String(group.cat_id) !== wantCat' in body)
    check('and it reports how many of the total are showing', 'id="drawerCount"' in body)
    # cat_id has to come from the server: category names are not unique across
    # websites, so filtering on the label would be wrong. Read it off the page
    # rather than calling the helper, so this covers what is actually shipped.
    import json as _json
    blob = body[body.index('const CATALOG = ') + len('const CATALOG = '):]
    catalog = _json.loads(blob[:blob.index(';\n')])
    guide_groups = catalog['guide']
    check(f'the catalog carries real category ids ({[g["cat_id"] for g in guide_groups]})',
          guide_groups and all('cat_id' in g for g in guide_groups))
    check('and Uncategorized uses 0, which no real category row can be',
          all(g['cat_id'] != 0 or g['category'] == 'Uncategorized' for g in guide_groups))
    check('every kind is present so the switcher never hits an undefined',
          set(catalog) == {'guide', 'quiz', 'resource', 'bundle'})
    check('the drawer offers a Bundles tab', "setDrawerKind('bundle')" in body)

    print('\n[9] long lists scroll inside their card')
    # A hopper with a year of training in it should not push the settings and
    # the action buttons off the bottom of the page.
    tpl = open(os.path.join(_REPO, 'Templates', 'notification_feed_editor.html')).read()
    check('the hopper is capped and scrolls', 'id="itemList" class="fd-scroll"' in body)
    # The history block only renders when the feed has fired, which this
    # fixture hasn't — so read it off the template rather than the page.
    check('so is the release history', 'class="fd-runs fd-scroll"' in tpl)
    scroll = body[body.index('.fd-scroll {'):body.index('}', body.index('.fd-scroll {'))]
    check(f'with a viewport-relative cap, not a fixed one ({scroll.strip()[:46]!r})',
          'max-height' in scroll and 'vh' in scroll and 'overflow-y: auto' in scroll)
    check('dragging carries the list with it, or rows past the fold are unreachable',
          'scroll: list' in body)
    check('and the item going out next is scrolled into view on load',
          'function showNextItem' in body)
    check('showing where the marker sits in the run',
          'on {{ overview.next_position }} of {{ overview.queue_len }}' in tpl)
    check('and saying so plainly once everything has gone out',
          'all {{ overview.queue_len }} sent' in tpl)

    print('\n[10] fixed panels clear the admin navbar')
    # The navbar is position:fixed, 52px tall, z-index 100000 — anything pinned
    # to top:0 has its header swallowed by it rather than out-stacking it.
    navbar_css = open(os.path.join(_REPO, 'static', 'css', 'navbar.css')).read()
    bar = navbar_css[navbar_css.index('.navbar {'):navbar_css.index('}', navbar_css.index('.navbar {'))]
    check('the navbar is still 52px and fixed on top',
          'height: 52px' in bar and 'position: fixed' in bar and 'z-index: 100000' in bar)
    drawer = body[body.index('.fd-drawer {'):body.index('}', body.index('.fd-drawer {'))]
    check(f'the drawer starts below it, not at 0 ({"top: 52px" in drawer})',
          'top: 52px' in drawer and 'top: 0' not in drawer)
    scrim = body[body.index('.fd-drawer-scrim {'):body.index('}', body.index('.fd-drawer-scrim {'))]
    check('so does its scrim, leaving the navbar usable', 'inset: 52px 0 0 0' in scrim)
    overlay = body[body.index('.fd-overlay {'):body.index('}', body.index('.fd-overlay {'))]
    check('and the modals centre below it too', 'inset: 52px 0 0 0' in overlay)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
