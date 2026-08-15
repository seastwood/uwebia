"""Tests for encrypted backups.

    venv/bin/python tests/test_backup_encryption.py

Copies main.py into a throwaway directory (Templates/icons symlinked; static is its own)
and imports it from there, so it builds its own SQLite database and cannot
touch the real instance.
"""
import io
import atexit
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-backup-encryption')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-bkenc-test-')
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

FAILURES = []
PASS = 'correct horse battery staple'


def check(label, cond):
    print(('  PASS  ' if cond else '  FAIL  ') + label)
    if not cond:
        FAILURES.append(label)


def enc(plain, passphrase=PASS):
    out = io.BytesIO()
    main.encrypt_backup_stream(io.BytesIO(plain), out, passphrase)
    return out.getvalue()


def dec(blob, passphrase=PASS):
    out = io.BytesIO()
    main.decrypt_backup_stream(io.BytesIO(blob), out, passphrase)
    return out.getvalue()


def test_roundtrip():
    print('\n[1] round-trip')
    for label, payload in [
        ('empty payload', b''),
        ('small payload', b'backup.json contents'),
        ('exactly one chunk', b'x' * main._BACKUP_CHUNK_SIZE),
        ('one chunk + 1 byte', b'x' * (main._BACKUP_CHUNK_SIZE + 1)),
        ('several chunks', os.urandom(main._BACKUP_CHUNK_SIZE * 3 + 517)),
    ]:
        blob = enc(payload)
        check(f'{label} survives a round-trip', dec(blob) == payload)

    payload = b'sensitive' * 1000
    blob = enc(payload)
    check('ciphertext does not contain the plaintext', b'sensitive' not in blob)
    check('output is recognised as an encrypted backup',
          main.backup_is_encrypted(blob[:len(main._BACKUP_MAGIC)]) is True)
    check('a plain zip is not mistaken for one',
          main.backup_is_encrypted(b'PK\x03\x04and so on') is False)

    check('the same input twice gives different ciphertext (fresh salt/nonce)',
          enc(payload) != enc(payload))


def test_wrong_passphrase():
    print('\n[2] wrong passphrase and tampering')
    payload = b'member emails and password hashes' * 50
    blob = enc(payload)

    for label, attempt in [('a wrong passphrase', 'not the passphrase'),
                           ('an empty passphrase', ''),
                           ('a near-miss', PASS + ' ')]:
        try:
            dec(blob, attempt)
            check(f'{label} is rejected', False)
        except main.BackupPassphraseError:
            check(f'{label} is rejected', True)
        except Exception as e:
            check(f'{label} is rejected with the right error (got {type(e).__name__})', False)

    # Flip a byte in the ciphertext body.
    tampered = bytearray(blob)
    tampered[-20] ^= 0x01
    try:
        dec(bytes(tampered))
        check('a modified byte is detected', False)
    except main.BackupPassphraseError:
        check('a modified byte is detected', True)

    # Truncation must not silently yield a short-but-valid backup.
    try:
        dec(blob[:len(blob) // 2])
        check('a truncated file is detected', False)
    except main.BackupPassphraseError:
        check('a truncated file is detected', True)

    # Dropping only the final chunk is the dangerous case: every remaining
    # chunk still authenticates on its own.
    multi = enc(os.urandom(main._BACKUP_CHUNK_SIZE * 2 + 10))
    import struct
    pos = main._BACKUP_HEADER_LEN
    ends = []
    while pos < len(multi):
        (n,) = struct.unpack('>I', multi[pos:pos + 4])
        pos += 4 + n
        ends.append(pos)
    try:
        dec(multi[:ends[-2]])          # every chunk but the last
        check('dropping the final chunk is detected', False)
    except main.BackupPassphraseError:
        check('dropping the final chunk is detected', True)

    # Not one of ours at all.
    try:
        dec(b'PK\x03\x04 just a zip')
        check('a non-encrypted file is reported clearly', False)
    except main.BackupPassphraseError as e:
        check('a non-encrypted file is reported clearly',
              'not an encrypted' in str(e))

    # A future format version must say so rather than fail as "wrong passphrase".
    bumped = bytearray(blob)
    bumped[len(main._BACKUP_MAGIC)] = 99
    try:
        dec(bytes(bumped))
        check('an unknown format version is reported clearly', False)
    except main.BackupPassphraseError as e:
        check('an unknown format version is reported clearly', 'format v99' in str(e))


def test_real_backup_roundtrip():
    print('\n[3] a real backup through the whole path')
    import zipfile
    with main.app.app_context():
        main.db.create_all()
        anchor = main.User.query.filter_by(parent_user_id=None).first()
        if not anchor:
            anchor = main.User(username='owner', parent_user_id=None)
            anchor.set_password('x')
            main.db.session.add(anchor)
            main.db.session.commit()
        zip_bytes = main._build_backup_zip_bytes(anchor.id, include_files=False)

    check('a real backup zip was produced', zip_bytes[:2] == b'PK')
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        check('it contains backup.json', 'backup.json' in zf.namelist())

    blob = enc(zip_bytes)
    check('the encrypted form is not a readable zip', blob[:2] != b'PK')
    restored = dec(blob)
    check('decrypting reproduces the zip byte for byte', restored == zip_bytes)
    with zipfile.ZipFile(io.BytesIO(restored)) as zf:
        data = zf.read('backup.json')
    check('the restored zip still opens and reads', b'"meta"' in data)


def test_routes():
    print('\n[4] export / import routes')
    main.app.config['WTF_CSRF_ENABLED'] = False
    with main.app.app_context():
        anchor = main.User.query.filter_by(parent_user_id=None).first()
        anchor_id = anchor.id

    with main.app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(anchor_id)
            s['_fresh'] = True

        r = c.get('/admin/settings/backup/export?include_files=0')
        check('plain export still works', r.status_code == 200 and r.data[:2] == b'PK')

        # POSTed so the passphrase never reaches a URL / access log.
        r = c.post('/admin/settings/backup/export',
                   data={'include_files': '0', 'passphrase': PASS})
        check('encrypted export returns an encrypted file',
              r.status_code == 200 and main.backup_is_encrypted(r.data[:8]))
        check('encrypted export is offered as .uwbak',
              '.uwbak' in r.headers.get('Content-Disposition', ''))
        encrypted_blob = r.data

        # Importing it without a passphrase must ask, not fail obscurely.
        r = c.post('/admin/settings/backup/import', data={
            'backup_file': (io.BytesIO(encrypted_blob), 'b.uwbak')},
            content_type='multipart/form-data')
        d = r.get_json()
        check('import without a passphrase asks for one',
              r.status_code == 400 and d.get('encrypted') is True)

        r = c.post('/admin/settings/backup/import', data={
            'backup_file': (io.BytesIO(encrypted_blob), 'b.uwbak'),
            'passphrase': 'wrong passphrase entirely'},
            content_type='multipart/form-data')
        d = r.get_json()
        check('import with a wrong passphrase is a clean 400',
              r.status_code == 400 and 'passphrase' in (d.get('error') or '').lower())
        check('a wrong passphrase is flagged as an encryption problem',
              d.get('encrypted') is True)


def test_auto_backup_settings():
    print('\n[5] scheduled-backup passphrase storage')
    with main.app.app_context():
        anchor_id = main.User.query.filter_by(parent_user_id=None).first().id
        cfg = main._get_auto_backup_settings(anchor_id, create=True)
        check('encryption is off by default', cfg.encrypt_enabled is False)

    main.app.config['WTF_CSRF_ENABLED'] = False
    with main.app.test_client() as c:
        with c.session_transaction() as s:
            s['_user_id'] = str(anchor_id)
            s['_fresh'] = True

        r = c.post('/admin/settings/backup/auto/save', data={
            'enabled': '0', 'folder_path': '', 'frequency': 'daily',
            'max_backups': '5', 'encrypt_enabled': '1', 'encrypt_passphrase': 'short'})
        check('a too-short passphrase is rejected', r.status_code == 400)

        r = c.post('/admin/settings/backup/auto/save', data={
            'enabled': '0', 'folder_path': '', 'frequency': 'daily',
            'max_backups': '5', 'encrypt_enabled': '1'})
        check('enabling encryption with no passphrase at all is rejected',
              r.status_code == 400)

        r = c.post('/admin/settings/backup/auto/save', data={
            'enabled': '0', 'folder_path': '', 'frequency': 'daily',
            'max_backups': '5', 'encrypt_enabled': '1',
            'encrypt_passphrase': PASS})
        check('a good passphrase is accepted', r.get_json().get('success') is True)

        with main.app.app_context():
            cfg = main._get_auto_backup_settings(anchor_id)
            check('the passphrase is not stored in the clear',
                  cfg.encrypt_passphrase and PASS not in cfg.encrypt_passphrase)
            check('it decrypts back to the original',
                  main.decrypt_api_key(cfg.encrypt_passphrase) == PASS)

        # Saving again with a blank field keeps the stored passphrase.
        c.post('/admin/settings/backup/auto/save', data={
            'enabled': '0', 'folder_path': '', 'frequency': 'daily',
            'max_backups': '7', 'encrypt_enabled': '1'})
        with main.app.app_context():
            cfg = main._get_auto_backup_settings(anchor_id)
            check('a blank field keeps the existing passphrase',
                  main.decrypt_api_key(cfg.encrypt_passphrase) == PASS)

        # Turning encryption off clears it.
        c.post('/admin/settings/backup/auto/save', data={
            'enabled': '0', 'folder_path': '', 'frequency': 'daily',
            'max_backups': '7', 'encrypt_enabled': '0'})
        with main.app.app_context():
            cfg = main._get_auto_backup_settings(anchor_id)
            check('turning encryption off drops the stored passphrase',
                  cfg.encrypt_passphrase is None and cfg.encrypt_enabled is False)


def test_auto_backup_file():
    print('\n[6] scheduled backup on disk')
    folder = tempfile.mkdtemp(prefix='uwebia-autobk-')
    with main.app.app_context():
        anchor_id = main.User.query.filter_by(parent_user_id=None).first().id
        cfg = main._get_auto_backup_settings(anchor_id, create=True)
        cfg.folder_path = folder
        cfg.max_backups = 10
        cfg.encrypt_enabled = True
        cfg.encrypt_passphrase = main.encrypt_api_key(PASS)
        main.db.session.commit()

        ok, path = main._run_auto_backup_for(cfg)
        check('the scheduled backup ran', ok is True)
        check('it was written with the .uwbak extension', str(path).endswith('.uwbak'))
        if ok:
            with open(path, 'rb') as fh:
                head = fh.read(8)
            check('the file on disk is encrypted', main.backup_is_encrypted(head))
            mode = os.stat(path).st_mode & 0o777
            check(f'the file is not world-readable (mode {oct(mode)})', mode == 0o600)
            with open(path, 'rb') as fh:
                out = io.BytesIO()
                main.decrypt_backup_stream(fh, out, PASS)
            check('it decrypts to a valid zip', out.getvalue()[:2] == b'PK')

        # A stored passphrase that can't be decrypted must fail loudly rather
        # than quietly writing plaintext.
        cfg.encrypt_passphrase = 'not-decryptable-garbage'
        main.db.session.commit()
        ok, err = main._run_auto_backup_for(cfg)
        check('an unreadable stored passphrase fails instead of writing plaintext',
              ok is False)
        plain = [f for f in os.listdir(folder) if f.endswith('.zip')]
        check('no unencrypted file was left behind', not plain)

    shutil.rmtree(folder, ignore_errors=True)


if __name__ == '__main__':
    test_roundtrip()
    test_wrong_passphrase()
    test_real_backup_roundtrip()
    test_routes()
    test_auto_backup_settings()
    test_auto_backup_file()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
