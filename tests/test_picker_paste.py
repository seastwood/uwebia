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
_JS = open(os.path.join(_REPO, 'static', 'js', 'photo_library_modal.js')).read()


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
          re.search(r'function uploadFiles[\s\S]{0,240}\/\^image\\\/\/\.test', _JS)
          is not None)
    check('and pasting text is not hijacked',
          "t.tagName === 'INPUT'" in _JS)
    # Ctrl+V on any other page must not upload to a picker that is not showing.
    check('nor does a paste anywhere else on the page',
          'function modalIsOpen(' in _JS
          and re.search(r"addEventListener\('paste'[\s\S]{0,120}modalIsOpen\(\)", _JS)
          is not None)

    print('\n[4] the clipboard API is never assumed to be there')
    # Over plain http on a LAN — a self-hosted instance without TLS — the whole
    # API is absent, and a reader can always refuse.
    check('the button checks before using it',
          'navigator.clipboard || !navigator.clipboard.read' in _JS)
    check('and falls back to naming the shortcut', 'Ctrl+V' in _JS)
    check('a clipboard with no image says so',
          'no image on the clipboard' in _JS)

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

    print('\n[6] the script still parses')
    # It is served as a static file, so a syntax error would break the whole
    # picker rather than only the new part.
    tmp = os.path.join(_SCRATCH, 'plm.js')
    shutil.copy2(os.path.join(_REPO, 'static', 'js', 'photo_library_modal.js'), tmp)
    p = subprocess.run(['node', '--check', tmp], capture_output=True, text=True)
    check(f'node --check passes — {p.stderr.strip()[:80]}', p.returncode == 0)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
