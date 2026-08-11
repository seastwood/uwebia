"""One-click "Generate with AI" pictures for guides, quizzes and resources.

    venv/bin/python tests/test_ai_content_images.py

Writing a prompt for every quiz is work nobody will keep doing, and the thing
the prompt should say is already typed into the form above it — the title and
the blurb. The button reads those and draws from them.

Details that matter:

  • It sends the title as CURRENTLY TYPED rather than reading it back from the
    database, so it works on something not yet saved — which is exactly when
    you want a picture for it.

  • The prompt forbids text in the image. Left alone, image models letter the
    picture with a mangled copy of the title, which looks broken sitting next
    to the real title.

  • Generated files land in the same folder as hand-picked ones for quizzes and
    resources, so the library picker still opens where they are; guide covers
    are a different shape and job, so they get their own folder.

  • The agent is chosen automatically — a chat-only agent cannot make an image,
    and Claude cannot either, so neither is eligible.

Copies main.py into a throwaway directory, with its own uploads folder, so it
builds its own SQLite database and writes no files into the real instance.
"""
import base64
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-ai-images')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-aiimg-test-')
shutil.copy2(os.path.join(_REPO, 'main.py'), os.path.join(_SCRATCH, 'main.py'))
for _linked in ('Templates', 'icons'):
    os.symlink(os.path.join(_REPO, _linked), os.path.join(_SCRATCH, _linked))
# static is rebuilt rather than symlinked: uploads_folder lives inside it, and
# a symlink would put every generated file in the real project's static/uploads.
os.mkdir(os.path.join(_SCRATCH, 'static'))
for _child in os.listdir(os.path.join(_REPO, 'static')):
    if _child != 'uploads':
        os.symlink(os.path.join(_REPO, 'static', _child),
                   os.path.join(_SCRATCH, 'static', _child))
os.mkdir(os.path.join(_SCRATCH, 'static', 'uploads'))

sys.path.insert(0, _SCRATCH)
import main  # noqa: E402

assert os.path.dirname(os.path.abspath(main.__file__)) == _SCRATCH, \
    'refusing to run against the real checkout'
assert main.uploads_folder.startswith(_SCRATCH), 'uploads must be sandboxed'

app, db = main.app, main.db
FAILURES = []
CALLS = []

# A real 1x1 PNG — the route runs it through PIL, so it has to decode.
PNG = bytes.fromhex('89504e470d0a1a0a0000000d4948445200000001000000010806000000'
                    '1f15c4890000000a49444154789c630001000005000'
                    '10d0a2db40000000049454e44ae426082')


def check(label, cond):
    print(('  PASS  ' if cond else '  FAIL  ') + label)
    if not cond:
        FAILURES.append(label)


class FakeResponse:
    ok = True
    status_code = 200
    headers = {'Content-Type': 'application/json'}

    def json(self):
        return {'data': [{'b64_json': base64.b64encode(PNG).decode()}]}


def fake_post(url, **kwargs):
    CALLS.append({'url': url, 'json': kwargs.get('json') or {},
                  'data': kwargs.get('data') or {},
                  'headers': kwargs.get('headers') or {}})
    return FakeResponse()


def sent_prompt():
    if not CALLS:
        return ''
    last = CALLS[-1]
    return (last['json'].get('prompt') or last['data'].get('prompt') or '')


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
        db.session.add(main.PublicPageContent(website_id=site.id, name='Home',
                                              slug='home', site_active_status=True))
        guide = main.Guide(website_id=site.id, title='Soldering', slug='sold',
                           status='published', description='<p>Irons &amp; tips</p>')
        quiz = main.Quiz(website_id=site.id, title='Safety', is_public=True)
        res = main.Resource(website_id=site.id, title='Checklist',
                            resource_type='link', url='http://e.com', is_public=True)
        db.session.add_all([guide, quiz, res])
        db.session.commit()
        return dict(owner=owner.id, site=site.id, guide=guide.id,
                    quiz=quiz.id, resource=res.id)


def as_owner(ids):
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(ids['owner'])
        s['_fresh'] = True
        s['editing_website_id'] = ids['site']
    return c


def add_agent(ids, name, capabilities, provider='openai_compatible'):
    with app.app_context():
        a = main.AIAgent(user_id=ids['owner'], name=name, provider=provider,
                         api_url='http://ai.example', model='sd',
                         api_key=main.encrypt_api_key('sk-test'),
                         capabilities=capabilities)
        db.session.add(a)
        db.session.commit()
        return a.id


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    ids = setup()
    c = as_owner(ids)
    gen = '/admin/assets/ai-generate-for-content'

    print('\n[1] the prompt is built from the title and the blurb')
    p = main.content_image_prompt('quiz', 'Ladder Safety',
                                  '<p>Setting up &amp; climbing safely</p>')
    check(f'the title is in it ({p[:48]}…)', 'Ladder Safety' in p)
    check('so is the blurb, as plain text',
          'Setting up & climbing safely' in p and '<p>' not in p)
    # Otherwise the picture arrives with a garbled title lettered across it,
    # right next to the real title.
    check('and it rules out text in the image', 'Do not include any text' in p)
    check('a guide is framed as a cover, not an icon',
          'cover illustration' in main.content_image_prompt('guide', 'X'))
    check('a quiz is framed as a small icon',
          'icon-style' in main.content_image_prompt('quiz', 'X'))
    check('nothing to work from yields no prompt',
          main.content_image_prompt('quiz', '', '') == '')
    check('an unknown kind yields no prompt',
          main.content_image_prompt('bogus', 'Title') == '')

    print('\n[2] with no image-capable agent it says so plainly')
    add_agent(ids, 'Chatter', 'chat')
    add_agent(ids, 'Claude', 'both', provider='anthropic')
    r = c.post(gen, json={'kind': 'quiz', 'title': 'Safety'})
    d = r.get_json() or {}
    check(f'refused — got {r.status_code}', r.status_code == 400)
    check(f'and points at the fix ({(d.get("error") or "")[:52]}…)',
          'AI Agents' in (d.get('error') or ''))

    print('\n[3] it picks an agent that can actually draw')
    image_agent = add_agent(ids, 'Painter', 'image')
    with app.app_context():
        names = [a.name for a in main.AIAgent.query.all()]
    import requests as _requests
    real_post = _requests.post
    _requests.post = fake_post
    try:
        CALLS.clear()
        r = c.post(gen, json={'kind': 'quiz', 'title': 'Ladder Safety',
                              'description': 'Setting up and climbing safely'})
        d = r.get_json() or {}
        check(f'generating succeeds — got {r.status_code} {d.get("error") or ""}',
              r.status_code == 200 and d.get('success'))
        check(f'the chat-only and Claude agents were skipped ({d.get("agent")}) '
              f'out of {names}', d.get('agent') == 'Painter')
        check(f'it hands back a url ({d.get("url")})',
              (d.get('url') or '').startswith('/static/uploads/'))
        check('the title reached the provider', 'Ladder Safety' in sent_prompt())
        check('and the prompt is reported back', 'Ladder Safety' in (d.get('prompt') or ''))

        print('\n[4] the file lands where that kind of picture belongs')
        with app.app_context():
            asset = main.Asset.query.order_by(main.Asset.id.desc()).first()
            folder = main.AssetFolder.query.get(asset.folder_id) if asset.folder_id else None
            check(f'a quiz picture joins the hand-picked ones ({folder and folder.name})',
                  folder is not None and folder.name == main.EDUCATION_IMAGE_FOLDER)
            check('and the file really exists on disk',
                  os.path.exists(os.path.join(main.uploads_folder, str(ids['owner']),
                                              'assets', asset.stored_filename)))
        r = c.post(gen, json={'kind': 'resource', 'title': 'Checklist'})
        with app.app_context():
            asset = main.Asset.query.order_by(main.Asset.id.desc()).first()
            folder = main.AssetFolder.query.get(asset.folder_id)
            check(f'so does a resource picture ({folder.name})',
                  folder.name == main.EDUCATION_IMAGE_FOLDER)
        r = c.post(gen, json={'kind': 'guide', 'title': 'Soldering',
                              'description': 'Irons and tips'})
        d = r.get_json() or {}
        check(f'a guide cover succeeds — got {r.status_code} {d.get("error") or ""}',
              r.status_code == 200 and d.get('success'))
        with app.app_context():
            asset = main.Asset.query.order_by(main.Asset.id.desc()).first()
            folder = main.AssetFolder.query.get(asset.folder_id)
            check(f'but a cover gets its own folder ({folder.name})',
                  folder.name == main.GUIDE_COVER_FOLDER)

        print('\n[5] bad input is refused before anything is generated')
        CALLS.clear()
        r = c.post(gen, json={'kind': 'quiz', 'title': '   '})
        d = r.get_json() or {}
        check(f'no title — got {r.status_code}', r.status_code == 400)
        check(f'and says why ({(d.get("error") or "")[:40]}…)',
              'title' in (d.get('error') or '').lower())
        r = c.post(gen, json={'kind': 'newsletter', 'title': 'Hello'})
        check(f'an unknown kind — got {r.status_code}', r.status_code == 400)
        check('and neither reached the provider', not CALLS)

        print('\n[6] an explicit agent must still belong to you')
        with app.app_context():
            stranger = main.User(username='stranger', parent_user_id=None)
            stranger.set_password('ownerpassword')
            db.session.add(stranger)
            db.session.commit()
            theirs = main.AIAgent(user_id=stranger.id, name='Theirs',
                                  provider='openai_compatible',
                                  api_url='http://x', capabilities='image')
            db.session.add(theirs)
            db.session.commit()
            theirs_id = theirs.id
        CALLS.clear()
        r = c.post(gen, json={'kind': 'quiz', 'title': 'X', 'agent_id': theirs_id})
        check(f"someone else's agent is refused — got {r.status_code}",
              r.status_code == 403)
        check('and was never called', not CALLS)
        r = c.post(gen, json={'kind': 'quiz', 'title': 'X', 'agent_id': image_agent})
        check(f'your own is accepted — got {r.status_code}', r.status_code == 200)
    finally:
        _requests.post = real_post

    print('\n[7] the button is on all three editors')
    # Parsed, not pattern-matched: the component's own script contains
    # querySelector('[data-spot-ai]'), so searching the raw page for that
    # string reports a button that may never have rendered.
    from bs4 import BeautifulSoup
    for label, path, sel in (
            ('quizzes', '/admin/quizzes', 'button[data-spot-ai]'),
            ('resources', '/admin/resources', 'button[data-spot-ai]'),
            ('guides', '/admin/guides', 'button#gpAiCoverBtn')):
        body = c.get(path).get_data(as_text=True)
        soup = BeautifulSoup(body, 'html.parser')
        check(f'{label}: the Generate button renders', bool(soup.select(sel)))
        check(f'{label}: and it calls the one-click endpoint',
              'ai-generate-for-content' in body)

    # The button is only as good as the field it reads: a renamed input would
    # leave it silently generating from an empty title.
    for label, path, spot_sel, field_id, desc_id in (
            ('quiz', '/admin/quizzes', '#quizImage', 'quizModalTitleInput', 'quizModalDesc'),
            ('resource', '/admin/resources', '#resImage', 'resTitle', 'resDesc')):
        soup = BeautifulSoup(c.get(path).get_data(as_text=True), 'html.parser')
        spot = soup.select_one(spot_sel)
        check(f'{label}: the spot knows what it is generating for',
              spot is not None and spot.get('data-spot-kind') == label)
        check(f'{label}: it points at a title field that exists',
              spot is not None and spot.get('data-spot-title-field') == field_id
              and soup.find(id=field_id) is not None)
        check(f'{label}: and a description field that exists',
              spot is not None and spot.get('data-spot-desc-field') == desc_id
              and soup.find(id=desc_id) is not None)
    guides = BeautifulSoup(c.get('/admin/guides').get_data(as_text=True), 'html.parser')
    check('guides: the cover button reads the guide title field',
          guides.find(id='guideModalTitleInput') is not None
          and guides.find(id='guideModalDesc') is not None)

    print('\n[8] without the permission there is no button')
    with app.app_context():
        grp = main.PermissionGroup(owner_user_id=ids['owner'], name='Editors',
                                   # Everything they need to edit a quiz —
                                   # but not assets.ai_generate.
                                   permissions={'quizzes.view': True,
                                                'quizzes.edit': True,
                                                'quizzes.create': True,
                                                'assets.view': True})
        db.session.add(grp)
        db.session.commit()
        sub = main.User(username='helper', parent_user_id=ids['owner'],
                        permission_group_id=grp.id)
        sub.set_password('helperpassword')
        db.session.add(sub)
        db.session.commit()
        sub_id = sub.id
    sc = app.test_client()
    with sc.session_transaction() as s:
        s['_user_id'] = str(sub_id)
        s['_fresh'] = True
        s['editing_website_id'] = ids['site']
    soup = BeautifulSoup(sc.get('/admin/quizzes').get_data(as_text=True), 'html.parser')
    check('they can still reach the quiz editor',
          soup.find(id='quizModalTitleInput') is not None)
    check('the button is hidden', not soup.select('button[data-spot-ai]'))
    check('but the rest of the picture box is still there',
          bool(soup.select('[data-image-spot]')))
    r = sc.post(gen, json={'kind': 'quiz', 'title': 'X'})
    check(f'and the endpoint refuses them too — got {r.status_code}',
          r.status_code in (302, 403))


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
