"""Quizzes and resources can carry a picture, shown beside the title.

    venv/bin/python tests/test_education_images.py

A row of identical glyphs tells a reader nothing about which worksheet is which.
A quiz or resource can now carry a small picture, sitting where the icon was —
inline, to the left of the title.

Three ways to set one, because each is the obvious one in a different moment:
paste an image straight into the box, pick one already in the library, or choose
a file. All three land in the same folder so they stay together, and the library
picker opens straight to it rather than the root of a library holding thousands
of files. The folder is found-or-created on first upload, so nothing has to be
set up in advance.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import io
import json
import os
import re
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-edu-images')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-eduimg-test-')
shutil.copy2(os.path.join(_REPO, 'main.py'), os.path.join(_SCRATCH, 'main.py'))
for _linked in ('Templates', 'icons', 'static'):
    _src = os.path.join(_REPO, _linked)
    if os.path.exists(_src):
        os.symlink(os.path.join(_REPO, _linked), os.path.join(_SCRATCH, _linked))

sys.path.insert(0, _SCRATCH)
import main  # noqa: E402

assert os.path.dirname(os.path.abspath(main.__file__)) == _SCRATCH, \
    'refusing to run against the real checkout'

app, db = main.app, main.db
FAILURES = []

# The smallest real PNG, standing in for something pasted from the clipboard.
PNG = bytes.fromhex('89504e470d0a1a0a0000000d4948445200000001000000010806000000'
                    '1f15c4890000000a49444154789c630001000005000'
                    '10d0a2db40000000049454e44ae426082')


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
        owner.set_password('ownerpassword')
        db.session.add(owner)
        db.session.commit()
        site = main.Website(user_id=owner.id, name='Site', is_draft=False, is_live=True)
        db.session.add(site)
        db.session.commit()
        db.session.add(main.PublicPageContent(website_id=site.id, name='Home', slug='home',
                                              site_active_status=True))
        quiz = main.Quiz(website_id=site.id, title='Safety', is_public=True)
        res = main.Resource(website_id=site.id, title='Checklist', resource_type='link',
                            url='http://example.com', is_public=True)
        plain = main.Resource(website_id=site.id, title='No picture', resource_type='link',
                              url='http://example.com', is_public=True)
        db.session.add_all([quiz, res, plain])
        db.session.commit()
        return dict(owner=owner.id, site=site.id, quiz=quiz.id,
                    resource=res.id, plain=plain.id)


def as_owner(ids):
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(ids['owner'])
        s['_fresh'] = True
        s['editing_website_id'] = ids['site']
    return c


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    ids = setup()
    c = as_owner(ids)

    print('\n[1] an uploaded picture lands in its own folder')
    with app.app_context():
        check('which does not exist until one is uploaded',
              main.AssetFolder.query.filter_by(
                  name=main.EDUCATION_IMAGE_FOLDER).first() is None)
    r = c.post('/admin/assets/upload', data={
        'asset': (io.BytesIO(PNG), 'pasted.png'),
        'folder_name': main.EDUCATION_IMAGE_FOLDER,
    }, content_type='multipart/form-data')
    d = r.get_json() or {}
    check(f'the upload succeeds — got {r.status_code}',
          r.status_code == 200 and d.get('status') == 'success')
    url = (d.get('assets') or [{}])[0].get('url')
    check(f'and comes back with a url ({url})', bool(url))
    with app.app_context():
        folder = main.AssetFolder.query.filter_by(
            name=main.EDUCATION_IMAGE_FOLDER).first()
        check(f'the folder was created on demand ({main.EDUCATION_IMAGE_FOLDER})',
              folder is not None)
        asset = main.Asset.query.first()
        check('and the picture is in it',
              folder is not None and asset is not None and asset.folder_id == folder.id)

    print('\n[2] it can be attached to a quiz and a resource')
    r = c.post(f"/admin/quizzes/{ids['quiz']}/update",
               json={'title': 'Safety', 'image_url': url})
    check(f'saving on a quiz — got {r.status_code}', r.status_code == 200)
    r = c.post(f"/admin/resources/{ids['resource']}/update",
               json={'title': 'Checklist', 'resource_type': 'link',
                     'url': 'http://example.com', 'image_url': url})
    check(f'saving on a resource — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        check('the quiz keeps it',
              db.session.get(main.Quiz, ids['quiz']).image_url == url)
        check('the resource keeps it',
              db.session.get(main.Resource, ids['resource']).image_url == url)

    r = c.post(f"/admin/quizzes/{ids['quiz']}/update",
               json={'title': 'Safety', 'image_url': ''})
    with app.app_context():
        check('and clearing it removes it rather than storing an empty string',
              db.session.get(main.Quiz, ids['quiz']).image_url is None)
    c.post(f"/admin/quizzes/{ids['quiz']}/update",
           json={'title': 'Safety', 'image_url': url})

    print('\n[3] it shows to the LEFT of the title, inline')
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(app.test_client().get('/guides').get_data(as_text=True),
                         'html.parser')
    tiles = soup.select('.gi-rsc-pic img')
    check(f'both items show their picture ({len(tiles)})', len(tiles) == 2)
    check('pointing at the uploaded file',
          all(t.get('src') == url for t in tiles))
    row = soup.select_one('.gi-rsc-row:has(.gi-rsc-pic)')
    check('the row renders', row is not None)
    if row:
        kids = [k.get('class') or [] for k in row.find_all(recursive=False)]
        check(f'the picture comes before the title block ({kids[0]})',
              'gi-rsc-pic' in kids[0])
    check('an item without one keeps its glyph',
          len(soup.select('.gi-rsc-ic:not(.gi-rsc-pic) i')) >= 1)

    page = app.test_client().get(f"/quiz/{ids['quiz']}").get_data(as_text=True)
    check('the quiz page shows it beside the heading',
          url in page and 'align-items: center' in page)
    # A link resource redirects to its target, so the page that actually renders
    # a heading is a rich-text one.
    with app.app_context():
        article = main.Resource(website_id=ids['site'], title='Guidance',
                                resource_type='page', content='<p>Read me</p>',
                                is_public=True, image_url=url)
        db.session.add(article)
        db.session.commit()
        article_id = article.id
    page = app.test_client().get(f'/resource/{article_id}').get_data(as_text=True)
    check('and the resource page does too',
          url in page and 'align-items: center' in page)

    print('\n[4] the admin pages offer all three ways in')
    for label, path in (('resources', '/admin/resources'), ('quizzes', '/admin/quizzes')):
        body = c.get(path).get_data(as_text=True)
        check(f'{label}: the picture box is on the page',
              'data-image-spot' in body)
        check(f'{label}: it accepts a paste', "addEventListener('paste'" in body)
        check(f'{label}: it offers the library', 'data-spot-pick' in body)
        check(f'{label}: it offers a file upload', 'data-spot-file' in body)
        check(f'{label}: and a way to remove it', 'data-spot-clear' in body)
        m = re.search(r'const FOLDER = (".*?");', body)
        check(f'{label}: the script really rendered', bool(m))
        if m:
            check(f'{label}: pointing at the same folder as the server '
                  f'({json.loads(m.group(1))})',
                  json.loads(m.group(1)) == main.EDUCATION_IMAGE_FOLDER)
        check(f'{label}: uploads target that folder by name',
              "fd.append('folder_name', FOLDER)" in body)
        check(f'{label}: and the picker opens straight to it',
              'folderName: FOLDER' in body)

    print('\n[5] the type glyph still rides on top of the picture')
    # A picture says which item this is; the glyph says what opening it will do
    # — a video, a download, a link. Losing the second to gain the first would
    # be a bad trade, so it sits over the image on a scrim.
    badges = soup.select('.gi-rsc-pic .gi-rsc-pic-badge')
    check(f'every picture carries its type glyph ({len(badges)})',
          len(badges) == len(tiles))
    icons = sorted({c for b in badges for c in (b.get('class') or [])
                    if c.startswith('fa-')})
    check(f'and they are the real type icons, not one generic mark ({icons})',
          len(icons) >= 2)
    index_css = open(os.path.join(_REPO, 'Templates', 'guides_index.html')).read()
    check('the glyph is laid over the image rather than beside it',
          re.search(r'\.gi-rsc-pic-badge\s*\{[^}]*position:\s*absolute', index_css))
    check('on a scrim, so it reads on a light picture as well as a dark one',
          re.search(r'\.gi-rsc-pic-badge\s*\{[^}]*background:\s*rgba\(0,0,0', index_css))
    admin_css = open(os.path.join(_REPO, 'Templates', 'resources_admin.html')).read()
    check('the admin list overlays it the same way',
          re.search(r'\.ra-item-pic i\s*\{[^}]*position:\s*absolute', admin_css))

    print('\n[6] the picker hands back a payload, not a list')
    # It is named onConfirm(assets) but receives {assets, assetUrls, mode, …}.
    # Reading it as an array picked nothing at all, silently — pasting worked,
    # so the box looked functional right up until you used the library.
    spot_src = open(os.path.join(_REPO, 'Templates', 'components',
                                 'image_spot.html')).read()
    check('the component reads payload.assets', 'payload && payload.assets' in spot_src)
    check('with the url list as a fallback', 'payload.assetUrls' in spot_src)
    check('and says so when nothing came back',
          "Nothing was selected." in spot_src)

    print('\n[7] the picker knows how to open a named folder')
    js = open(os.path.join(_REPO, 'static', 'js', 'photo_library_modal.js')).read()
    check('it accepts a folder name', 'options.folderName' in js)
    # The folder only exists once somebody has uploaded, so asking for one that
    # is not there must land on the root rather than fail.
    check('and falls back to the root when that folder does not exist yet',
          'if (match) loadFolder' in js)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
