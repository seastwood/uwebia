"""The asset library says WHERE a file is used, not just how many times.

    venv/bin/python tests/test_asset_usage_places.py

The count already existed. What it could not tell you was which page, lesson or
article to go and look at — so the badge is now clickable and resolves each
reference to a named thing with a link into the editor that owns it.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import atexit
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-asset-usage')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-usage-test-')
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

        site = main.Website(user_id=owner.id, name='Main site', is_draft=False)
        db.session.add(site)
        db.session.commit()

        url = f'/static/uploads/{owner.id}/assets/hero777.jpg'
        used = main.Asset(user_id=owner.id, original_filename='hero.jpg',
                          stored_filename='hero777.jpg', url=url,
                          asset_type='image', file_size=100)
        lonely = main.Asset(user_id=owner.id, original_filename='lonely.png',
                            stored_filename='lonely999.png',
                            url=f'/static/uploads/{owner.id}/assets/lonely999.png',
                            asset_type='image', file_size=50)
        db.session.add_all([used, lonely])
        db.session.commit()

        page = main.PublicPageContent(website_id=site.id, name='Welcome', slug='home')
        db.session.add(page)
        db.session.commit()
        # A section is found in the builder by its group, so the fixture builds
        # the real path: page > group > row > column > section.
        group = main.SectionGroup(page_content_id=page.id, name='Hero banner')
        db.session.add(group)
        db.session.commit()
        row = main.Row(page_content_id=page.id, row_number=1,
                       section_group_id=group.id)
        db.session.add(row)
        db.session.commit()
        # Twice in ONE section: still one place to go and fix.
        section = main.PageSection(
            page_content_id=page.id, section_type='images', order=1, label='Gallery',
            content={'images': [{'src': url}, {'src': url}]})
        db.session.add(section)
        db.session.commit()
        db.session.add(main.Column(row_id=row.id, column_number=1,
                                   section_id=section.id))

        guide = main.Guide(website_id=site.id, title='Build a robot', slug='robot')
        db.session.add(guide)
        db.session.commit()
        chapter = main.GuideNode(guide_id=guide.id, website_id=site.id,
                                 node_type='chapter', title='Electrics', slug='electrics')
        db.session.add(chapter)
        db.session.commit()
        db.session.add(main.GuideNode(guide_id=guide.id, website_id=site.id,
                                      node_type='lesson', title='Wiring', slug='wiring',
                                      parent_id=chapter.id,
                                      content=f'<img src="{url}">'))

        # The image lives in the THIRD question, which is the bit worth saying.
        quiz = main.Quiz(website_id=site.id, title='Safety check')
        db.session.add(quiz)
        db.session.commit()
        cfg = {'options': [{'id': 1, 'text': 'Yes', 'correct': True},
                           {'id': 2, 'text': 'No', 'correct': False}]}
        for i, prompt in enumerate([
                '<p>First</p>', '<p>Second</p>',
                f'<p>Which shows the correct wiring layout?</p><img src="{url}">']):
            db.session.add(main.QuizQuestion(
                quiz_id=quiz.id, question_type='true_false', prompt=prompt,
                config=cfg, points=1, sort_order=i))

        coll = main.PostCollection(website_id=site.id, user_id=owner.id,
                                   name='Blog', slug='blog')
        db.session.add(coll)
        db.session.commit()
        db.session.add(main.Post(collection_id=coll.id, website_id=site.id,
                                 title='Season recap', slug='recap',
                                 content=f'<p><img src="{url}?v=3"></p>'))
        db.session.commit()

        # Another organisation, with its own asset — must stay invisible.
        rival = main.User(username='rival', parent_user_id=None)
        rival.set_password('x')
        db.session.add(rival)
        db.session.commit()
        theirs = main.Asset(user_id=rival.id, original_filename='theirs.jpg',
                            stored_filename='theirs555.jpg',
                            url=f'/static/uploads/{rival.id}/assets/theirs555.jpg',
                            asset_type='image', file_size=10)
        db.session.add(theirs)
        db.session.commit()
        return owner.id, site.id, used.id, lonely.id, theirs.id


def main_test():
    owner_id, site_id, used_id, lonely_id, theirs_id = setup()
    app.config['WTF_CSRF_ENABLED'] = False

    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(owner_id)
        s['_fresh'] = True
        s['admin_website_id'] = site_id

    r = c.get(f'/admin/assets/{used_id}/usage')
    d = r.get_json() or {}
    places = d.get('places') or []
    by_kind = {p['kind']: p for p in places}
    for p in places:
        print(f"         {p['kind']:14} {str(p['name'])[:40]:42} x{p['times']}  {p['link']}")

    print('\n[1] it names the actual things')
    check(f'the endpoint answers — got {r.status_code}', r.status_code == 200)
    check('the guide lesson, by lesson AND guide name',
          'Guide' in by_kind and 'Wiring' in by_kind['Guide']['name']
          and 'Build a robot' in by_kind['Guide']['name'])
    check('the article, by title',
          'Article' in by_kind and by_kind['Article']['name'] == 'Season recap')
    check('the page section, by label and page',
          'Page section' in by_kind
          and 'Gallery' in by_kind['Page section']['name']
          and 'Welcome' in by_kind['Page section']['name'])

    print('\n[1b] enough detail to actually find it')
    check('the section names the group it sits in',
          'Hero banner' in by_kind.get('Page section', {}).get('name', ''))
    check('the lesson names its chapter',
          'Electrics' in by_kind.get('Guide', {}).get('name', ''))
    q = by_kind.get('Quiz question', {}).get('name', '')
    check(f'the quiz question is numbered as in the editor ({q[:20]}…)',
          q.startswith('Q3'))
    check('and quotes what it asks',
          'correct wiring layout' in q)
    check('and names its quiz', 'Safety check' in q)

    print('\n[2] each row links to where you would go and fix it')
    check('the guide links to its editor',
          (by_kind.get('Guide', {}).get('link') or '').startswith('/admin/guides/'))
    check('the article links to its editor',
          '/articles/' in (by_kind.get('Article', {}).get('link') or ''))
    check('the page section links to the page builder',
          bool(by_kind.get('Page section', {}).get('link')))

    print('\n[3] counting stays honest')
    check('two references in one section are ONE place',
          by_kind.get('Page section', {}).get('times') == 2 and len(places) == 4)
    check('the total still counts every reference', d.get('total') == 5)
    with app.app_context():
        a = db.session.get(main.Asset, used_id)
        check('the badge number agrees with the modal',
              main.asset_usage_counts([a])[used_id] == d['total'])

    print('\n[4] an unused file says so plainly')
    d2 = c.get(f'/admin/assets/{lonely_id}/usage').get_json() or {}
    check('no places, no total', d2.get('places') == [] and d2.get('total') == 0)

    print('\n[5] you only get your own library')
    r3 = c.get(f'/admin/assets/{theirs_id}/usage')
    check(f"another organisation's asset is not found — got {r3.status_code}",
          r3.status_code == 404)
    r4 = c.get('/admin/assets/999999/usage')
    check('nor is one that does not exist', r4.status_code == 404)
    anon = app.test_client()
    ra = anon.get(f'/admin/assets/{used_id}/usage')
    check(f'signed out gets nothing — got {ra.status_code}',
          ra.status_code in (301, 302, 401, 403))


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
