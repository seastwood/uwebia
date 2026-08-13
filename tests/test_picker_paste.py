"""An image can be pasted straight into the asset picker.

    venv/bin/python tests/test_picker_paste.py

The picker offered two ways in: choose a file, or pick something already in the
library. A screenshot is usually on the clipboard rather than saved to disk, so
using one meant Save As, then Upload, then finding it, then deleting the stray
file afterwards.

Pasting now uploads it directly — by Ctrl+V while the picker is open, by the
Paste Image button, or by dragging an image onto the window. All three go
through the same uploadFiles() the file input uses, so the folder it lands in,
the progress bar, the refresh and the error handling are the same by
construction rather than by three implementations agreeing.

Reading the clipboard needs a secure context and permission — over plain http
the API is absent entirely — so the button always falls back to naming the
shortcut, which the paste listener handles.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-picker-paste')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-pickerpaste-test-')
shutil.copy2(os.path.join(_REPO, 'main.py'), os.path.join(_SCRATCH, 'main.py'))
# `static` is NOT symlinked: uploads_folder lives inside it, and this test
# UPLOADS files. Through a symlink those land in the real instance's asset
# folder, where they linger as orphans nobody can see or clean up from the UI.
for _linked in ('Templates', 'icons'):
    _src = os.path.join(_REPO, _linked)
    if os.path.exists(_src):
        os.symlink(_src, os.path.join(_SCRATCH, _linked))
os.makedirs(os.path.join(_SCRATCH, 'static', 'uploads'), exist_ok=True)

sys.path.insert(0, _SCRATCH)
import main  # noqa: E402

# This test writes into uploads_folder; refuse to run if that resolved back to
# the real checkout.
assert os.path.realpath(main.uploads_folder).startswith(os.path.realpath(_SCRATCH)), \
    f'uploads_folder escaped the sandbox: {main.uploads_folder}'

assert os.path.dirname(os.path.abspath(main.__file__)) == _SCRATCH, \
    'refusing to run against the real checkout'

app, db = main.app, main.db
FAILURES = []
_JS = open(os.path.join(_REPO, 'static', 'js', 'photo_library_modal.js')).read()
# The clipboard handling these depend on lives in its own file, shared with
# the asset library page and the page editor.
_CLIP = open(os.path.join(_REPO, 'static', 'js', 'clipboard_image.js')).read()


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
        page = main.PublicPageContent(website_id=site.id, name='Home', slug='home',
                                      site_active_status=True)
        db.session.add(page)
        db.session.commit()
        return dict(owner=owner.id, site=site.id, page=page.id)


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
    from bs4 import BeautifulSoup

    print('\n[1] the picker offers pasting alongside uploading')
    body = c.get(f"/admin/{ids['site']}/{ids['page']}").get_data(as_text=True)
    soup = BeautifulSoup(body, 'html.parser')
    check('the picker is on the page editor',
          soup.select_one('#libraryModal') is not None)
    btn = soup.select_one('[onclick*="pasteFromClipboard"]')
    check('a Paste button sits in its toolbar', btn is not None)
    check('beside the existing Upload button',
          soup.select_one('[onclick*="modalLibraryFileInput"]') is not None)
    check('the shortcut and drag are spelled out, not left to be guessed',
          'Ctrl+V' in body and 'drag' in body)
    check('and there is somewhere to report progress',
          soup.select_one('#modalPasteStatus') is not None)

    print('\n[2] all three routes share one upload')
    # Three implementations of "send this file" would be three places for the
    # folder, the progress bar or the refresh to drift apart.
    check('the upload was split into a reusable function',
          'function uploadFiles(' in _JS)
    check('the file input goes through it', re.search(
        r'function handleUpload[\s\S]{0,240}uploadFiles\(', _JS) is not None)
    check('so does a paste', re.search(
        r"addEventListener\('paste'[\s\S]{0,900}uploadFiles\(", _JS) is not None)
    check('so does a drop', re.search(
        r"addEventListener\('drop'[\s\S]{0,600}uploadFiles\(", _JS) is not None)
    check('so does the button', re.search(
        r'function pasteFromClipboard[\s\S]{0,900}uploadFiles\(', _JS) is not None)
    check('it still uploads to the one endpoint',
          _JS.count("'/admin/assets/upload'") == 1)
    check('and a pasted image lands in the folder you are looking at',
          re.search(r'function uploadFiles[\s\S]{0,600}formData\.append\('
                    r"'folder_id', currentFolderId\)", _JS) is not None)

    print('\n[3] it only ever uploads images')
    check('non-images are dropped before anything is sent',
          'ClipboardImage.onlyImages' in _JS
          and re.search(r'function onlyImages[\s\S]{0,200}image\\/', _CLIP) is not None)
    check('and pasting text is not hijacked',
          'ClipboardImage.isTextTarget' in _JS
          and "tagName === 'INPUT'" in _CLIP)
    # Ctrl+V on any other page must not upload to a picker that is not showing.
    check('nor does a paste anywhere else on the page',
          'function modalIsOpen(' in _JS
          and re.search(r"addEventListener\('paste'[\s\S]{0,120}modalIsOpen\(\)", _JS)
          is not None)

    print('\n[4] the clipboard API is never assumed to be there')
    # Over plain http on a LAN — a self-hosted instance without TLS — the whole
    # API is absent, and a reader can always refuse.
    check('it checks before using the API',
          '!navigator.clipboard || !navigator.clipboard.read' in _CLIP)
    check('and falls back to naming the shortcut',
          'Ctrl+V' in _CLIP and 'ClipboardImage.hint()' in _JS)
    check('a clipboard with no image says so',
          'no image on the clipboard' in _JS)
    # The keyboard path needs no permission at all, which is what makes it a
    # real fallback rather than a second thing to be refused.
    check('the fallback it names does not go through the API',
          re.search(r'function fromEvent[\s\S]{0,400}clipboardData', _CLIP) is not None)

    print('\n[5] the upload endpoint accepts what the picker sends')
    # The picker posts multipart with the field name "asset"; the paste path
    # reuses it, so this is the contract both sides depend on.
    png = bytes.fromhex('89504e470d0a1a0a0000000d4948445200000001000000010806000000'
                        '1f15c4890000000a49444154789c630001000005000'
                        '10d0a2db40000000049454e44ae426082')
    import io
    r = c.post('/admin/assets/upload',
               data={'asset': (io.BytesIO(png), 'pasted.png')},
               content_type='multipart/form-data')
    d = r.get_json() or {}
    check(f'a pasted-style upload succeeds — got {r.status_code}',
          r.status_code == 200 and d.get('status') == 'success')
    check('and comes back with a usable url',
          (d.get('assets') or [{}])[0].get('url', '').startswith('/static/'))
    with app.app_context():
        check('the asset really exists', main.Asset.query.count() == 1)

    print('\n[6] the asset library page takes a paste too')
    lib = c.get('/admin/dashboard/assets').get_data(as_text=True)
    libsoup = BeautifulSoup(lib, 'html.parser')
    check('a Paste Image button is in its toolbar',
          libsoup.select_one('#libPasteBtn') is not None)
    check('Ctrl+V anywhere on the page uploads',
          "addEventListener('paste'" in lib and 'uploadAssetFiles' in lib)
    check('so does dragging an image onto it',
          "addEventListener('drop'" in lib)
    check('all of them reuse the file input\'s upload, error banner and all',
          'function uploadAssetFiles(' in lib
          and re.search(r'function handleUpload[\s\S]{0,200}uploadAssetFiles\(', lib))
    check('it does not upload behind the picker when that is open',
          "getElementById('libraryModal')" in lib)
    check('and pasting into a field is left alone', 'isTextTarget' in lib)

    print('\n[7] the image section has a Paste button beside Pick from Library')
    pe = open(os.path.join(_REPO, 'Templates', 'page_editor.html')).read()
    head = pe[pe.index('<div class="image-editor-header">'):]
    head = head[:head.index('</div>\n\n                <div class="image-layout-panel">')]
    check('the picker button is there', 'openLibraryPicker' in head)
    check('and a Paste button sits next to it, in the same header',
          'pasteImageIntoSection' in head and 'data-paste-into-section' in head)
    # Uploading is only half of it: the image has to end up IN the section.
    check('pasting uploads the image', re.search(
        r'function uploadImageIntoSection[\s\S]{0,700}/admin/assets/upload', pe) is not None)
    check('then attaches it the way the picker does', re.search(
        r'function uploadImageIntoSection[\s\S]{0,2000}/add_assets_to_section', pe) is not None)
    check('with the CSRF token, or the attach is rejected',
        re.search(r'function uploadImageIntoSection[\s\S]{0,2000}X-CSRFToken', pe) is not None)
    check('and refreshes the section afterwards', re.search(
        r'function uploadImageIntoSection[\s\S]{0,2600}loadUploadedImages', pe) is not None)

    print('\n[8] one clipboard implementation, shared by all of them')
    # Three copies of "read an image off the clipboard" would be three places
    # for the permission handling and the fallbacks to drift.
    shared = open(os.path.join(_REPO, 'static', 'js', 'clipboard_image.js')).read()
    check('the helpers live in their own file', 'window.ClipboardImage' in shared)
    check('read() reports why it failed rather than throwing',
          "'unavailable'" in shared and "'denied'" in shared and "'empty'" in shared)
    for label, path in (('the asset library', 'Templates/asset_library.html'),
                        ('the page editor', 'Templates/page_editor.html'),
                        ('the quiz editor', 'Templates/quizzes_admin.html'),
                        ('the resource editor', 'Templates/resources_admin.html'),
                        ('the product editor', 'Templates/store/product_edit.html'),
                        ('the dashboard', 'Templates/dashboard.html')):
        body = open(os.path.join(_REPO, path)).read()
        check(f'{label} loads it', 'js/clipboard_image.js' in body)
    check('the picker uses it rather than its own copy',
          'ClipboardImage.fromEvent' in _JS and 'ClipboardImage.read()' in _JS)
    check('and nobody re-implements the clipboard read',
          _JS.count('navigator.clipboard.read') == 0)

    print('\n[9] the scripts still parse')
    # It is served as a static file, so a syntax error would break the whole
    # picker rather than only the new part.
    for name in ('photo_library_modal.js', 'clipboard_image.js'):
        tmp = os.path.join(_SCRATCH, name)
        shutil.copy2(os.path.join(_REPO, 'static', 'js', name), tmp)
        pr = subprocess.run(['node', '--check', tmp], capture_output=True, text=True)
        check(f'{name}: node --check passes — {pr.stderr.strip()[:70]}',
              pr.returncode == 0)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
