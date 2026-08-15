"""Notification feeds: a hopper that releases one item per scheduled slot.

    venv/bin/python tests/test_notification_feeds.py

A feed is the inverse of a notification rule. A rule reacts to something that
happened; a feed is filled ahead of time with guides, quizzes, resources, links
or plain messages, and drips one out on the days and time the admin picked.

The things that actually matter and are easy to get wrong:

  * the schedule is wall-clock in the owner's timezone, and a slot must fire
    once — a scheduler that runs every two minutes must not re-send the same
    Tuesday all afternoon;
  * the cursor walks only the enabled items, and re-sorting the list must not
    make a running feed re-send something or skip ahead;
  * items resolve live, so a renamed guide announces its current title, and a
    deleted one degrades instead of taking the release down;
  * a finished feed can be rewound and run again next year with its contents
    intact — that is the whole point of saving one.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import atexit
import os
import shutil
import sys
import tempfile
from datetime import date, datetime, timedelta

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-feeds')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-feeds-test-')
# Each of these holds a ~2.5 MB copy of main.py and a SQLite database; nothing
# removed them, so repeated suite runs left GBs behind in /tmp.
atexit.register(shutil.rmtree, _SCRATCH, ignore_errors=True)
shutil.copy2(os.path.join(_REPO, 'main.py'), os.path.join(_SCRATCH, 'main.py'))
# Templates/icons are read-only, so symlinking the real ones is safe. `static`
# is NOT: uploads_folder lives inside it, and the backup code this test drives
# DELETES and REWRITES files there. Symlinking it once destroyed the real
# instance's uploaded images. Give this test its own empty static tree instead.
for _linked in ('Templates', 'icons'):
    _src = os.path.join(_REPO, _linked)
    if os.path.exists(_src):
        os.symlink(_src, os.path.join(_SCRATCH, _linked))
os.makedirs(os.path.join(_SCRATCH, 'static', 'uploads'), exist_ok=True)

sys.path.insert(0, _SCRATCH)
import main  # noqa: E402

assert os.path.dirname(os.path.abspath(main.__file__)) == _SCRATCH, \
    'refusing to run against the real checkout'
# Belt and braces: this test writes and deletes files under uploads_folder, so
# refuse to run at all if that resolved back to the real checkout.
assert os.path.realpath(main.uploads_folder).startswith(os.path.realpath(_SCRATCH)), \
    f'uploads_folder escaped the sandbox: {main.uploads_folder}'

app, db = main.app, main.db
FAILURES = []
SENT = []          # every payload the fake webhook received
WAITED = []        # whether each send asked Discord to confirm creation first


def check(label, cond):
    print(('  PASS  ' if cond else '  FAIL  ') + label)
    if not cond:
        FAILURES.append(label)


def fake_send(webhook_url, payload, wait=False):
    # `wait` mirrors the real sender's ?wait=true, used to force ordering.
    SENT.append(payload)
    WAITED.append(bool(wait))


def setup():
    """One admin, one site, one channel, and a feed holding a guide, a quiz,
    a resource, a link and a bare message."""
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

        site = main.Website(user_id=owner.id, name='Site', is_draft=False, is_live=True)
        db.session.add(site)
        db.session.commit()

        guide = main.Guide(website_id=site.id, title='Soldering', slug='soldering',
                           status='published', description='Irons and safety.')
        quiz = main.Quiz(website_id=site.id, title='Safety check', is_public=True)
        res = main.Resource(website_id=site.id, title='Shop checklist',
                            resource_type='link', url='http://example.com/c')
        db.session.add_all([guide, quiz, res])
        db.session.commit()

        channel = main.NotificationChannel(
            user_id=owner.id, label='#training', provider='discord_webhook',
            config={'webhook_url': main.encrypt_api_key(
                'https://discord.com/api/webhooks/1/abc')})
        db.session.add(channel)
        db.session.commit()

        feed = main.NotificationFeed(
            user_id=owner.id, website_id=site.id, channel_id=channel.id,
            name='2026 Weekly Training',
            days_of_week=[1],            # Tuesdays
            send_time='18:00',
            default_message=main.DEFAULT_FEED_MESSAGE,
            is_active=True,
        )
        db.session.add(feed)
        db.session.commit()

        for order, (kind, ref, url, title) in enumerate([
            ('guide', guide.id, None, None),
            ('quiz', quiz.id, None, None),
            ('resource', res.id, None, None),
            ('link', None, 'https://youtu.be/xyz', 'Week 4 video'),
            ('message', None, None, 'Wrap-up'),
        ]):
            db.session.add(main.NotificationFeedItem(
                feed_id=feed.id, sort_order=order, item_type=kind,
                ref_id=ref, url=url, title=title))
        db.session.commit()

        return dict(owner=owner.id, site=site.id, channel=channel.id,
                    feed=feed.id, guide=guide.id, quiz=quiz.id, res=res.id)


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    main._send_to_discord_webhook = fake_send
    ids = setup()

    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(ids['owner'])
        s['_fresh'] = True
        s['admin_website_id'] = ids['site']

    with app.app_context():
        feed = db.session.get(main.NotificationFeed, ids['feed'])
        tz = main._feed_owner_timezone(feed)

        print('\n[1] the schedule is wall-clock in the owner\'s timezone')
        # 2026-08-11 is a Tuesday. Ask from Monday, expect that Tuesday 18:00.
        monday = tz.localize(datetime(2026, 8, 10, 9, 0))
        nxt = main._feed_next_slot(feed, after=monday)
        check(f'next slot from Monday is Tue 18:00 ({nxt})',
              nxt is not None and nxt.weekday() == 1 and (nxt.hour, nxt.minute) == (18, 0)
              and nxt.date() == date(2026, 8, 11))
        # Asking from just after that slot rolls to the following week.
        after = tz.localize(datetime(2026, 8, 11, 18, 1))
        check('asking again just after it rolls to next Tuesday',
              main._feed_next_slot(feed, after=after).date() == date(2026, 8, 18))
        check('a slot earlier the same day is not "due" yet',
              main._feed_due_slot(feed, tz.localize(datetime(2026, 8, 11, 9, 0))) is None)
        due = main._feed_due_slot(feed, tz.localize(datetime(2026, 8, 11, 18, 30)))
        check(f'half an hour after it, it is due ({due})',
              due is not None and due.date() == date(2026, 8, 11))
        check('a slot missed by a week is too stale to catch up on',
              main._feed_due_slot(feed, tz.localize(datetime(2026, 8, 18, 17, 0))) is None)
        check('an embargoed feed stays quiet until its start date',
              _with_start_date(feed, date(2026, 9, 1),
                               lambda: main._feed_due_slot(
                                   feed, tz.localize(datetime(2026, 8, 11, 18, 30)))) is None)

        print('\n[2] a due slot releases exactly one item, once')
        SENT.clear(); WAITED.clear()
        slot = tz.localize(datetime(2026, 8, 11, 18, 0))
        key = main._feed_slot_key(slot)
        ok, msg = main._feed_release(feed, key, slot_local=slot)
        check(f'the release reports success ({msg})', ok)
        check(f'one payload went out ({len(SENT)})', len(SENT) == 1)
        again_ok, again_msg = main._feed_release(feed, key, slot_local=slot)
        check(f're-running the same slot is refused ({again_msg})', not again_ok)
        check('and nothing extra was sent', len(SENT) == 1)

        embed = SENT[0]['embeds'][0]
        check(f'it announced the first item ({embed["title"]!r})',
              embed['title'] == 'Soldering')
        check(f'the default message was filled in ({embed["description"][:60]!r})',
              "Here is Tuesday's training" in embed['description'])
        check('{next_date} resolved to the following Tuesday',
              'Tuesday, Aug 18' in embed['description'])
        check(f'the footer counts position in the run ({embed["footer"]["text"]!r})',
              '1 of 5' in embed['footer']['text'])

        print('\n[3] the cursor advances, and only over enabled items')
        db.session.refresh(feed)
        check(f'the cursor moved to the second item ({feed.position})', feed.position == 1)
        items = feed.items.order_by(main.NotificationFeedItem.sort_order).all()
        check('the guide records that it was sent', items[0].sent_count == 1)
        # Skip the quiz — the next release should jump straight to the resource.
        items[1].is_enabled = False
        db.session.commit()
        SENT.clear(); WAITED.clear()
        slot2 = tz.localize(datetime(2026, 8, 18, 18, 0))
        main._feed_release(feed, main._feed_slot_key(slot2), slot_local=slot2)
        check(f'a skipped item is passed over ({SENT[0]["embeds"][0]["title"]!r})',
              SENT[0]['embeds'][0]['title'] == 'Shop checklist')
        items[1].is_enabled = True
        db.session.commit()

        print('\n[4] items resolve live against their source')
        guide = db.session.get(main.Guide, ids['guide'])
        guide.title = 'Soldering (revised)'
        db.session.commit()
        title, url, kind, _blurb = main._feed_item_target(feed, items[0])
        check(f'a renamed guide announces its current title ({title!r})',
              title == 'Soldering (revised)')
        check(f'and links to its public page ({url})', url.endswith('/guides/soldering'))
        check(f'the quiz links by id ({main._feed_item_target(feed, items[1])[1]})',
              main._feed_item_target(feed, items[1])[1].endswith(f'/quiz/{ids["quiz"]}'))
        check('a pasted link is used as-is',
              main._feed_item_target(feed, items[3])[1] == 'https://youtu.be/xyz')
        check('a message-only item has no link',
              main._feed_item_target(feed, items[4])[1] == '')
        db.session.delete(db.session.get(main.Resource, ids['res']))
        db.session.commit()
        gone = main._feed_item_target(feed, items[2])
        check(f'a deleted source degrades instead of raising ({gone[0]!r})',
              gone[0] == 'Resource (deleted)')

        print('\n[5] running out is a pause, not an ending')
        # Parked exactly one past the end — where _feed_advance leaves it.
        feed.position = len(main._feed_queue(feed))
        feed.is_active = True
        # Make a slot due right now so the scan actually looks at this feed.
        just_passed = datetime.now(tz) - timedelta(minutes=5)
        feed.days_of_week = [just_passed.weekday()]
        feed.send_time = just_passed.strftime('%H:%M')
        db.session.commit()
        check('the cursor past the end means nothing is queued',
              main._feed_next_item(feed)[0] is None)
        SENT.clear(); WAITED.clear()
        main._run_feed_scan()
        db.session.refresh(feed)
        check('the feed stays ACTIVE when it runs dry', feed.is_active is True)
        check('and nothing was sent', len(SENT) == 0)
        empty_run = main.NotificationFeedRun.query.filter_by(
            feed_id=feed.id, status='empty').first()
        check('the empty slot is logged so it is not retried all day',
              empty_run is not None and empty_run.item_id is None)
        # Adding an item must resume the run — that is the whole point.
        resumed = main.NotificationFeedItem(feed_id=feed.id, sort_order=200,
                                            item_type='message', title='Late addition')
        db.session.add(resumed)
        db.session.commit()
        item_now, pos_now = main._feed_next_item(feed)
        check(f'adding an item picks straight up from the cursor ({item_now and item_now.title!r})',
              item_now is not None and item_now.id == resumed.id)
        check('at the position the cursor already held', pos_now == len(main._feed_queue(feed)) - 1)
        # But it waits for the next slot rather than firing off the spent one.
        main._run_feed_scan()
        check('and it does not fire off the slot that already came and went',
              len(SENT) == 0)
        # Deleting items can leave the cursor further out than one-past-the-end;
        # it must clamp back so "add one item and it resumes" stays true.
        db.session.delete(resumed)
        db.session.flush()
        feed.position = 99
        main._feed_clamp_cursor(feed)
        db.session.commit()
        check(f'a drifted cursor clamps to the end ({feed.position})',
              feed.position == len(main._feed_queue(feed)))

        print('\n[5b] auto-restart wraps instead of idling')
        feed.loop_when_finished = True
        feed.position = 0
        db.session.commit()
        q = main._feed_queue(feed)
        main._feed_advance(feed, len(q) - 1, len(q))
        check(f'the cursor wraps to the top ({feed.position})', feed.position == 0)
        check('and the feed is still active', feed.is_active is True)
        feed.loop_when_finished = False
        feed.position = len(q) - 1
        db.session.commit()
        main._feed_advance(feed, len(q) - 1, len(q))
        check(f'without it the cursor parks past the end ({feed.position})',
              feed.position == len(q))
        check('still active, waiting for more', feed.is_active is True)

        print('\n[5c] rewinding is still available on demand')
        feed.position = 99
        db.session.commit()
        total_before = feed.items.count()
        c.post(f'/admin/notifications/feeds/{feed.id}/reset',
               json={'clear_history': True})
        db.session.refresh(feed)
        check(f'rewinding puts the cursor back at the top ({feed.position})',
              feed.position == 0)
        check(f'and keeps every item ({feed.items.count()})',
              feed.items.count() == total_before)
        check('the send history was cleared as asked', feed.runs.count() == 0)
        check('and the per-item counters with it',
              all(i.sent_count == 0 for i in feed.items.all()))

    print('\n[6] re-sorting a running feed keeps the same item up next')
    with app.app_context():
        feed = db.session.get(main.NotificationFeed, ids['feed'])
        feed.position = 2                     # pointing at the third item
        db.session.commit()
        queue = main._feed_queue(feed)
        expected = queue[2].id
        reversed_ids = [i.id for i in reversed(queue)]
    r = c.post(f'/admin/notifications/feeds/{ids["feed"]}/items/reorder',
               json={'order': reversed_ids})
    check(f'the reorder is accepted ({r.status_code})', r.get_json().get('success'))
    with app.app_context():
        feed = db.session.get(main.NotificationFeed, ids['feed'])
        queue = main._feed_queue(feed)
        check(f'the order actually changed ({[i.id for i in queue]})',
              [i.id for i in queue] == reversed_ids)
        check('and the cursor followed the item it was pointing at, not the index',
              queue[feed.position].id == expected)

    print('\n[7] starting a feed is guarded, and "send now" is manual')
    with app.app_context():
        feed = db.session.get(main.NotificationFeed, ids['feed'])
        feed.days_of_week = []
        feed.is_active = False
        db.session.commit()
    r = c.post(f'/admin/notifications/feeds/{ids["feed"]}/update', json={'is_active': True})
    j = r.get_json()
    check(f'a feed with no days refuses to start ({j.get("error")!r})',
          not j.get('success') and 'day' in (j.get('error') or ''))
    c.post(f'/admin/notifications/feeds/{ids["feed"]}/update',
           json={'days_of_week': [1], 'is_active': True})
    with app.app_context():
        check('with a day picked it starts',
              db.session.get(main.NotificationFeed, ids['feed']).is_active is True)

    SENT.clear(); WAITED.clear()
    r = c.post(f'/admin/notifications/feeds/{ids["feed"]}/send-now')
    check(f'send-now reports what went out ({r.get_json().get("message")!r})',
          r.get_json().get('success'))
    check('and one payload was sent', len(SENT) == 1)
    with app.app_context():
        feed = db.session.get(main.NotificationFeed, ids['feed'])
        run = feed.runs.order_by(main.NotificationFeedRun.id.desc()).first()
        check(f'it is logged under a manual key ({run.slot_key})',
              run.slot_key.startswith('manual:'))
        # A hand-sent release must not consume the scheduled slot.
        tz = main._feed_owner_timezone(feed)
        slot = tz.localize(datetime(2026, 8, 25, 18, 0))
        check('so the scheduled slot is still free to fire',
              main.NotificationFeedRun.query.filter_by(
                  feed_id=feed.id, slot_key=main._feed_slot_key(slot)).first() is None)

    print('\n[8] duplicating saves the run for next year')
    r = c.post(f'/admin/notifications/feeds/{ids["feed"]}/duplicate')
    copy_id = r.get_json().get('id')
    check(f'a copy is created ({copy_id})', bool(copy_id))
    with app.app_context():
        original = db.session.get(main.NotificationFeed, ids['feed'])
        copy = db.session.get(main.NotificationFeed, copy_id)
        check(f'with the same items ({copy.items.count()})',
              copy.items.count() == original.items.count())
        check('starting from the top', copy.position == 0)
        check('paused until the admin says otherwise', copy.is_active is False)
        check('with no inherited history', copy.runs.count() == 0)
        check('and the original is untouched',
              original.items.count() > 0 and original.id != copy.id)

    print('\n[8b] releases carry the item\'s picture, and videos get a player')
    with app.app_context():
        feed = db.session.get(main.NotificationFeed, ids['feed'])
        site = db.session.get(main.Website, ids['site'])
        guide = db.session.get(main.Guide, ids['guide'])
        guide.cover_image_url = '/static/uploads/1/assets/cover.webp'
        vid = main.Resource(website_id=site.id, title='Swerve teardown',
                            resource_type='video',
                            items=[{'url': 'https://youtu.be/abc123', 'label': ''}])
        db.session.add(vid)
        db.session.commit()

        g_item = main.NotificationFeedItem(feed_id=feed.id, sort_order=90,
                                           item_type='guide', ref_id=guide.id)
        v_item = main.NotificationFeedItem(feed_id=feed.id, sort_order=91,
                                           item_type='resource', ref_id=vid.id)
        l_item = main.NotificationFeedItem(feed_id=feed.id, sort_order=92,
                                           item_type='link',
                                           url='https://www.youtube.com/watch?v=zzz')
        p_item = main.NotificationFeedItem(feed_id=feed.id, sort_order=93,
                                           item_type='link',
                                           url='https://example.com/poster.png')
        db.session.add_all([g_item, v_item, l_item, p_item])
        db.session.commit()

        # No request context here, so absolute URLs come from the last known
        # host — which is exactly the background-scheduler situation.
        main._LAST_KNOWN_HOST = 'https://team.example.org/'

        img, vids = main._feed_item_media(feed, g_item)
        check(f"a guide's cover rides along, made absolute ({img})",
              img == 'https://team.example.org/static/uploads/1/assets/cover.webp')
        check('and it is not mistaken for a video', vids == [])

        img, vids = main._feed_item_media(feed, v_item)
        check(f'a video resource yields its video URL ({vids})',
              vids == ['https://youtu.be/abc123'])
        img, vids = main._feed_item_media(feed, l_item)
        check(f'so does a pasted YouTube link ({vids})',
              vids == ['https://www.youtube.com/watch?v=zzz'])
        img, vids = main._feed_item_media(feed, p_item)
        check(f'a pasted image link becomes the picture, not a video ({img})',
              img == 'https://example.com/poster.png' and vids == [])

        embed, _t, video = main._feed_build_embed(feed, g_item, 0, 5)
        # Which SLOT the picture lands in decides whether it is clickable.
        # `thumbnail` sits beside the title and inherits the embed's url, so
        # tapping it opens the page; `image` (large, bottom) only opens the
        # picture. So the thumbnail is used whenever there's somewhere to go.
        check(f'the picture goes in the clickable thumbnail slot ({embed.get("thumbnail")})',
              embed.get('thumbnail', {}).get('url', '').endswith('cover.webp'))
        check('and not in the large image slot, which would be inert and double it',
              'image' not in embed)
        check('the title links to the page', embed.get('url', '').endswith('/guides/soldering'))
        check('and the body carries an explicit way in too',
              f"[Open the guide →]({embed['url']})" in embed['description'])
        # With nothing to click, the big image is the better rendering. Reachable
        # when the cover is hosted elsewhere but no public base URL is set, so
        # the picture is absolute while the page link is not.
        guide.cover_image_url = 'https://cdn.example.com/cover.png'
        db.session.commit()
        main._LAST_KNOWN_HOST = ''
        inert = main._feed_build_embed(feed, g_item, 0, 5)[0]
        check(f'with no link, the picture uses the large image slot ({inert.get("image")})',
              inert.get('image', {}).get('url') == 'https://cdn.example.com/cover.png')
        check('and no dead thumbnail is emitted', 'thumbnail' not in inert)
        check('nor a bogus title link', 'url' not in inert)
        main._LAST_KNOWN_HOST = 'https://team.example.org/'
        guide.cover_image_url = '/static/uploads/1/assets/cover.webp'
        db.session.commit()
        embed, _t, videos = main._feed_build_embed(feed, l_item, 0, 5)
        check('a video item reports its URL back to the sender', videos == [l_item.url])
        check('but never fakes an embed video field — Discord ignores that',
              'video' not in embed)

        # Discord refuses to build a link preview for a message that already
        # carries an embed. Rather than give up the card, a video sends BOTH:
        # the styled card, then a follow-up carrying only the URL.
        channel = db.session.get(main.NotificationChannel, ids['channel'])
        feed.prepend_text = '<@&1>'
        db.session.commit()
        vpays, _t = main._feed_payload_for(feed, channel, l_item, 0, 5)
        check(f'a video release sends two messages ({len(vpays)})', len(vpays) == 2)
        check('the first is the styled card', len(vpays[0]['embeds']) == 1)
        check('carrying the ping', vpays[0].get('content') == '<@&1>')
        check(f'the second is nothing but the URL ({vpays[1].get("content")!r})',
              vpays[1]['embeds'] == [] and vpays[1]['content'] == l_item.url)
        check('and does NOT ping again', '<@&1>' not in vpays[1]['content'])

        gpays, _t = main._feed_payload_for(feed, channel, g_item, 0, 5)
        check('a library item still sends exactly one message', len(gpays) == 1)
        check('a rich embed with the clickable thumbnail',
              len(gpays[0]['embeds']) == 1 and gpays[0]['embeds'][0].get('thumbnail'))
        check('with just the ping as content', gpays[0]['content'] == '<@&1>')

        # A bare web link: we can't know what's on the page, but Discord can
        # read its Open Graph tags — so hand it over rather than wrapping it in
        # an embed that would both say nothing and suppress the preview.
        web = main.NotificationFeedItem(feed_id=feed.id, sort_order=94,
                                        item_type='link',
                                        url='https://example.com/handbook')
        db.session.add(web)
        db.session.commit()
        wpays, wtarget = main._feed_payload_for(feed, channel, web, 0, 5)
        check(f'a web link is one plain message so the page previews ({len(wpays)})',
              len(wpays) == 1 and wpays[0]['embeds'] == [])
        check('with the URL last so the card renders under the text',
              wpays[0]['content'].split('\n')[-1] == 'https://example.com/handbook')
        check('and the URL is not also repeated as a bold title',
              wpays[0]['content'].count('https://example.com/handbook') == 1)
        db.session.delete(web)
        feed.prepend_text = None
        db.session.commit()

        print('\n[8d] a resource says what it actually is')
        # "Resource" tells a reader nothing. Name the real thing, and when a
        # resource holds several, say how many.
        kinds = {}
        for rtype, urls, label in [
            ('video', ['https://youtu.be/a'], 'Video'),
            ('video', ['https://youtu.be/a', 'https://youtu.be/b',
                       'https://youtu.be/c'], '3 videos'),
            ('file',  ['https://x/a.pdf'], 'File'),
            ('file',  ['https://x/a.pdf', 'https://x/b.pdf'], '2 files'),
            ('link',  ['https://x/one'], 'Link'),
            ('page',  [], 'Page'),
        ]:
            res = main.Resource(website_id=ids['site'], title=f'{rtype} sample',
                                resource_type=rtype,
                                items=[{'url': u, 'label': ''} for u in urls] or None,
                                content='<p>hi</p>' if rtype == 'page' else None)
            db.session.add(res)
            db.session.commit()
            it = main.NotificationFeedItem(feed_id=feed.id, sort_order=300,
                                           item_type='resource', ref_id=res.id)
            db.session.add(it)
            db.session.commit()
            kinds[label] = main._feed_item_target(feed, it)[2]
            if rtype == 'video':
                _img, vids = main._feed_item_media(feed, it)
                check(f'{label}: every video goes out, not just the first ({len(vids)})',
                      len(vids) == len(urls))
            db.session.delete(it)
            db.session.delete(res)
            db.session.commit()
        for expected, got in kinds.items():
            check(f'a resource reads as “{expected}” ({got!r})', got == expected)
        check('and a plain page is never counted', kinds['Page'] == 'Page')

        # The footer puts the position first, so a counted kind reads as a
        # description instead of colliding with the numbers.
        multi = main.Resource(website_id=ids['site'], title='Teardown series',
                              resource_type='video',
                              items=[{'url': f'https://youtu.be/{n}', 'label': ''}
                                     for n in 'abc'])
        db.session.add(multi)
        db.session.commit()
        m_item = main.NotificationFeedItem(feed_id=feed.id, sort_order=301,
                                           item_type='resource', ref_id=multi.id)
        db.session.add(m_item)
        db.session.commit()
        embed, _t, vids = main._feed_build_embed(feed, m_item, 2, 12)
        check(f'the footer reads position then kind ({embed["footer"]["text"]!r})',
              embed['footer']['text'].endswith('3 of 12 · 3 videos'))
        mpays, _t = main._feed_payload_for(feed, channel, m_item, 2, 12)
        check(f'all three videos ride in ONE follow-up ({len(mpays)} messages)',
              len(mpays) == 2)
        check('one per line, so Discord builds a player for each',
              mpays[1]['content'].split('\n') == ['https://youtu.be/a',
                                                  'https://youtu.be/b',
                                                  'https://youtu.be/c'])
        db.session.delete(m_item)
        db.session.delete(multi)
        db.session.commit()

        print('\n[8e] a whole resource bundle can be sent as one item')
        bundle = main.ResourceBundle(website_id=ids['site'], name='Week 1 pack',
                                     description='<p>Everything for week one.</p>')
        db.session.add(bundle)
        db.session.commit()
        inside = [
            main.Resource(website_id=ids['site'], bundle_id=bundle.id, sort_order=0,
                          title='Intro video', resource_type='video',
                          items=[{'url': 'https://youtu.be/w1', 'label': ''}],
                          image_url='https://cdn.example.com/w1.png', is_public=True),
            main.Resource(website_id=ids['site'], bundle_id=bundle.id, sort_order=1,
                          title='Checklist', resource_type='file',
                          items=[{'url': 'https://x/c.pdf', 'label': ''}], is_public=True),
            # Neither of these may be named in a public announcement.
            main.Resource(website_id=ids['site'], bundle_id=bundle.id, sort_order=2,
                          title='Secret notes', resource_type='page',
                          content='<p>x</p>', is_public=True, members_only=True),
            main.Resource(website_id=ids['site'], bundle_id=bundle.id, sort_order=3,
                          title='Unlisted draft', resource_type='page',
                          content='<p>x</p>', is_public=False),
        ]
        db.session.add_all(inside)
        db.session.commit()
        b_item = main.NotificationFeedItem(feed_id=feed.id, sort_order=400,
                                           item_type='bundle', ref_id=bundle.id)
        db.session.add(b_item)
        db.session.commit()

        title, url, kind, blurb = main._feed_item_target(feed, b_item)
        check(f'the bundle announces its name ({title!r})', title == 'Week 1 pack')
        check(f'and links to its page ({url})', url.endswith(f'/resources/bundle/{bundle.id}'))
        check(f'the kind says how much is in it ({kind!r})', kind == '2 resources')
        check('the contents are listed', 'Intro video' in blurb and 'Checklist' in blurb)
        check('each with its own type', 'Video' in blurb and 'File' in blurb)
        # The bundle page hides these, so the announcement must not name them —
        # it would advertise titles the link then refuses to show.
        check('a members-only resource is NOT named', 'Secret notes' not in blurb)
        check('nor an unlisted one', 'Unlisted draft' not in blurb)

        img, vids = main._feed_item_media(feed, b_item)
        check(f'the picture is borrowed from inside the bundle ({img})',
              img == 'https://cdn.example.com/w1.png')
        check('and its videos are not unfurled — the card already lists them',
              vids == [])
        bpays, _t = main._feed_payload_for(feed, channel, b_item, 0, 5)
        check(f'so a bundle is a single message ({len(bpays)})', len(bpays) == 1)
        check('with the clickable thumbnail',
              bpays[0]['embeds'][0].get('thumbnail', {}).get('url', '').endswith('w1.png'))
        check('and a way in worded for a bundle',
              '[Open the bundle →]' in bpays[0]['embeds'][0]['description'])

        for r in inside:
            db.session.delete(r)
        db.session.delete(b_item)
        db.session.delete(bundle)
        db.session.commit()

        print('\n[8c] a video release actually puts both messages on the wire')
        feed = db.session.get(main.NotificationFeed, ids['feed'])
        vid_item = main.NotificationFeedItem(
            feed_id=feed.id, sort_order=95, item_type='link',
            title='Week 4 teardown', url='https://youtu.be/two-msg')
        db.session.add(vid_item)
        db.session.commit()
        feed.position = len(main._feed_queue(feed)) - 1   # point at it
        db.session.commit()

        SENT.clear(); WAITED.clear()
        ok, msg = main._feed_release(feed, 'manual:two-message-test')
        check(f'the release reports success ({msg})', ok)
        check(f'two payloads went out ({len(SENT)})', len(SENT) == 2)
        check('card first', SENT[0]['embeds'] and 'Week 4 teardown' in SENT[0]['embeds'][0]['title'])
        check('video second', SENT[1]['content'] == 'https://youtu.be/two-msg')
        # Discord does not promise to CREATE two rapid webhook messages in the
        # order they arrive, and the card is the slower one (it has an embed
        # image to fetch), so the video can overtake it. ?wait=true on the first
        # blocks until Discord has actually made it.
        check(f'the card is sent with ?wait=true so it lands first ({WAITED})',
              WAITED[0] is True)
        check('and the follow-up does not need to wait', WAITED[1] is False)
        db.session.refresh(feed)
        check('and the cursor advanced once, not twice',
              feed.position == len(main._feed_queue(feed)))

        # If only the follow-up fails the item HAS gone out, so the release must
        # stand — failing would re-send the whole thing at the next slot.
        calls = {'n': 0}

        def flaky(url, payload, wait=False):
            calls['n'] += 1
            if calls['n'] > 1:
                raise RuntimeError('Discord said no')
            SENT.append(payload)

        main._send_to_discord_webhook = flaky
        feed.position = len(main._feed_queue(feed)) - 1
        db.session.commit()
        SENT.clear(); WAITED.clear()
        ok, msg = main._feed_release(feed, 'manual:flaky-follow-up')
        check(f'a failed follow-up still counts as released ({ok})', ok)
        check('the card did go out', len(SENT) == 1)
        run = main.NotificationFeedRun.query.filter_by(
            feed_id=feed.id, slot_key='manual:flaky-follow-up').first()
        check('the run is marked successful', run is not None and run.success is True)
        check(f'but records what failed ({(run.error or "")[:40]!r})',
              'follow-up' in (run.error or ''))
        db.session.refresh(feed)
        check('and the cursor still advanced, so it will not re-send',
              feed.position == len(main._feed_queue(feed)))

        main._send_to_discord_webhook = fake_send
        db.session.delete(vid_item)
        db.session.flush()
        # Those two releases walked the cursor to the end; put it back so the
        # later sections see a feed with something queued.
        feed.position = 0
        db.session.commit()

        # A relative image with no reachable host must be dropped, not sent
        # half-formed — Discord fetches embed images from its own servers.
        main._LAST_KNOWN_HOST = ''
        img, _vids = main._feed_item_media(feed, g_item)
        check('a relative picture is dropped when no public host is known', img == '')
        main._LAST_KNOWN_HOST = 'https://team.example.org/'
        for it in (g_item, v_item, l_item, p_item):
            db.session.delete(it)
        db.session.delete(vid)
        guide.cover_image_url = None
        db.session.commit()

    print('\n[9] items are authored through the admin API')
    fid = ids['feed']
    r = c.post(f'/admin/notifications/feeds/{fid}/items/create',
               json={'item_type': 'guide', 'ref_id': ids['guide'],
                     'message': 'Read this one first.'})
    new_item = r.get_json().get('id')
    check(f'a guide can be added ({new_item})', r.get_json().get('success'))
    r = c.post(f'/admin/notifications/feeds/{fid}/items/create',
               json={'item_type': 'link', 'url': 'youtu.be/no-scheme'})
    link_item = r.get_json().get('id')
    check('a link can be added', r.get_json().get('success'))
    r = c.post(f'/admin/notifications/feeds/{fid}/items/create',
               json={'item_type': 'guide', 'ref_id': 99999})
    check(f'a bogus reference is refused ({r.get_json().get("error")!r})',
          not r.get_json().get('success'))
    r = c.post(f'/admin/notifications/feeds/{fid}/items/create',
               json={'item_type': 'link', 'url': ''})
    check('so is a link with no URL', not r.get_json().get('success'))
    with app.app_context():
        li = db.session.get(main.NotificationFeedItem, link_item)
        check(f'a pasted link gets a scheme ({li.url})', li.url == 'https://youtu.be/no-scheme')
    c.post(f'/admin/notifications/feed-items/{new_item}/update',
           json={'title': 'Week 1', 'is_enabled': False})
    with app.app_context():
        it = db.session.get(main.NotificationFeedItem, new_item)
        check('an item can be retitled', it.title == 'Week 1')
        check('and skipped', it.is_enabled is False)
    c.post(f'/admin/notifications/feed-items/{new_item}/delete')
    with app.app_context():
        check('and deleted',
              db.session.get(main.NotificationFeedItem, new_item) is None)

    print('\n[10] the editor and the list page render')
    html = c.get(f'/admin/notifications/feeds/{ids["feed"]}').get_data(as_text=True)
    check('the editor loads', 'The hopper' in html)
    check('it shows the placeholder cheat-sheet', '{next_date}' in html)
    check('and offers the drag handles', 'fd-grip' in html)
    listing = c.get('/admin/notifications').get_data(as_text=True)
    check('the notifications page lists feeds', '2026 Weekly Training' in listing)
    preview = c.get(f'/admin/notifications/feeds/{ids["feed"]}/preview').get_json()
    check(f'preview renders the next message ({str(preview.get("body"))[:40]!r})',
          preview.get('success') and 'training' in preview.get('body', ''))

    # Last: a real backup round-trip wipes and rebuilds the whole instance.
    print('\n[11] a feed survives a backup round-trip')
    with app.app_context():
        feed = db.session.get(main.NotificationFeed, ids['feed'])
        before = dict(
            name=feed.name, days=list(feed.days_of_week or []),
            send_time=feed.send_time, position=feed.position,
            message=feed.default_message,
            titles=[main._feed_item_target(feed, i)[0] for i in
                    feed.items.order_by(main.NotificationFeedItem.sort_order).all()],
        )
        payload = main._serialize_backup(ids['owner'])
        check(f'feeds are exported ({len(payload.get("notification_feeds") or [])})',
              len(payload.get('notification_feeds') or []) >= 2)
        check(f'with their items ({len(payload.get("notification_feed_items") or [])})',
              len(payload.get('notification_feed_items') or []) >= 5)
        zip_bytes = main._build_backup_zip_bytes(ids['owner'], include_files=False)

    import io
    r = c.post('/admin/settings/backup/import',
               data={'backup_file': (io.BytesIO(zip_bytes), 'backup.zip')},
               content_type='multipart/form-data')
    check(f'the restore succeeds ({r.status_code})',
          r.status_code == 200 and r.get_json().get('success'))

    with app.app_context():
        restored = main.NotificationFeed.query.filter_by(name=before['name']).first()
        check('the feed came back', restored is not None)
        if restored:
            check(f'with its schedule ({restored.days_of_week} @ {restored.send_time})',
                  list(restored.days_of_week or []) == before['days']
                  and restored.send_time == before['send_time'])
            check(f'its cursor ({restored.position})', restored.position == before['position'])
            check('its default message', restored.default_message == before['message'])
            # References were remapped to the restored guide/quiz rows — if they
            # weren't, these would read "(deleted)".
            after_titles = [main._feed_item_target(restored, i)[0] for i in
                            restored.items.order_by(main.NotificationFeedItem.sort_order).all()]
            check(f'and its items still resolve ({after_titles})',
                  after_titles == before['titles'])
            check('restored paused, since the webhook secret did not survive',
                  restored.is_active is False)


def _with_start_date(feed, when, fn):
    """Run fn with a temporary start_date, then put it back."""
    original = feed.start_date
    feed.start_date = when
    try:
        return fn()
    finally:
        feed.start_date = original


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
