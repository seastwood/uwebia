"""Saving a page section must not report a conflict with yourself.

    venv/bin/python tests/test_section_self_conflict.py

Reported symptom: editing alone, every save popped "noken changed this section
while you were editing it", sometimes repeatedly.

Two separate defects produced that one message.

1. THE CONFLICT WAS REAL, and self-inflicted. Several things save the same
   section — the Save button, and the image/calendar/product autosaves, which
   call requestSubmit() into the same handler. Two in flight at once means the
   second carries the version it read BEFORE the first reply landed, so the
   server rightly calls it stale. Sending "the newest version" is no fix: the
   value is only fresh once the previous response has been applied. The client
   now runs one save per section at a time and builds the payload at send time.

2. THE NAME WAS WRONG. The message named the PAGE's last editor — whoever last
   touched anything on that page, which is almost always the person reading it.
   Sections now record their own writer, and a clash with yourself says so.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import re
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-self-conflict')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-selfconflict-test-')
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

        noken = main.User(username='noken', parent_user_id=None)
        noken.set_password('nokenpassword')
        db.session.add(noken)
        db.session.commit()
        other = main.User(username='momodou', parent_user_id=noken.id)
        other.set_password('otherpassword')
        # A sub-admin needs the permission explicitly, or the save 403s.
        other.permissions = {'sections.edit': True, 'sections.view': True,
                             'pages.view': True}
        db.session.add(other)
        db.session.commit()

        site = main.Website(user_id=noken.id, name='Site', is_draft=False, is_live=True)
        db.session.add(site)
        db.session.commit()
        page = main.PublicPageContent(website_id=site.id, name='Home', slug='home')
        db.session.add(page)
        db.session.commit()
        section = main.PageSection(page_content_id=page.id, section_type='text',
                                   order=0, content={'text': 'hello'}, version=1)
        db.session.add(section)
        db.session.commit()
        # The page's last editor is noken — the value the old message used.
        page.last_edited_by_id = noken.id
        db.session.commit()
        return dict(noken=noken.id, other=other.id, site=site.id,
                    page=page.id, section=section.id)


def client_for(uid, site_id):
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(uid)
        s['_fresh'] = True
        s['admin_website_id'] = site_id
    return c


def save(c, sid, text, version, force=False):
    data = {'section_id': sid, 'section_type': 'text', 'text': text,
            '_version': str(version)}
    if force:
        data['_force'] = '1'
    r = c.post('/update_section', data=data)
    return r.status_code, (r.get_json() or {})


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    ids = setup()
    c = client_for(ids['noken'], ids['site'])

    print('\n[1] ordinary saves never conflict')
    version = 1
    for n in range(1, 6):
        st, body = save(c, ids['section'], f'edit {n}', version)
        if body.get('version') is not None:
            version = body['version']
        if st != 200:
            check(f'save {n} went through (HTTP {st}: {body.get("error")})', False)
            break
    else:
        check('five saves in a row all went through', True)
    check(f'each one advanced the version (now {version})', version == 6)

    print('\n[2] a stale save is still caught — the guard still works')
    st, body = save(c, ids['section'], 'stale write', version - 3)
    check(f'an out-of-date version is refused ({st})', st == 409 and body.get('conflict'))

    print('\n[3] but a clash with YOURSELF says so')
    check(f'it is flagged as self ({body.get("self_conflict")})',
          body.get('self_conflict') is True)
    check(f'and does not claim someone else did it ({body.get("error")!r})',
          'another tab' in body.get('error', '')
          and 'noken changed this section' not in body.get('error', ''))

    print('\n[4] a real clash names the person who actually wrote it')
    # momodou writes the section; the PAGE's last editor stays noken, which is
    # what the old code read and why it named the wrong person.
    oc = client_for(ids['other'], ids['site'])
    st, body = save(oc, ids['section'], 'momodou was here', version)
    check(f'the other admin saves cleanly ({st})', st == 200)
    with app.app_context():
        # Make the page's last editor DIFFER from the section's writer — that is
        # the exact case the old code got wrong, since it read the page.
        page = db.session.get(main.PublicPageContent, ids['page'])
        page.last_edited_by_id = ids['noken']
        db.session.commit()
        sec = db.session.get(main.PageSection, ids['section'])
        check('section writer and page editor now differ',
              sec.updated_by_id == ids['other'] and page.last_edited_by_id == ids['noken'])
    st, body = save(c, ids['section'], 'noken retry', version)
    check(f'noken now gets a real conflict ({st})', st == 409)
    check(f'named for the actual writer ({body.get("saved_by")!r})',
          body.get('saved_by') == 'momodou')
    check('and not treated as a self-clash', not body.get('self_conflict'))

    print('\n[5] overwriting deliberately still works')
    st, body = save(c, ids['section'], 'noken insists', version, force=True)
    check(f'force saves through the conflict ({st})', st == 200)
    with app.app_context():
        sec = db.session.get(main.PageSection, ids['section'])
        # update_text_section stores the body under 'html', not 'text'.
        check(f"the content is theirs now ({sec.content.get('html')!r})",
              'noken insists' in (sec.content.get('html') or ''))
        check('and the section records who wrote it',
              sec.updated_by_id == ids['noken'])

    print('\n[6] the client runs one save per section at a time')
    # The root cause: two overlapping saves of one section, the second carrying
    # a version the first had already superseded.
    editor = open(os.path.join(_REPO, 'Templates', 'page_editor.html')).read()
    check('there is a per-section save queue', 'function queueSectionSave' in editor)
    check('only the newest queued save runs', '_sectionSavePending[id] = run' in editor)
    # Every section save now funnels through saveSection, which is the only
    # caller of the queue — so there is one place that can get this wrong.
    check('saveSection is what uses the queue',
          re.search(r'function saveSection\([^)]*\)[^{]*\{\s*\n\s*return queueSectionSave\(',
                    editor) is not None)
    check('and the version is stamped when the request goes out, not when queued',
          re.search(r'return queueSectionSave\(id, async \(\) => \{[\s\S]{0,400}?'
                    r"body\.set\('_version', _sectionVersion\(id\)\)", editor) is not None)
    check('the force flag is read at the same moment',
          "if (_takeForce(id)) body.set('_force', '1');" in editor)
    # An image form autosaves via requestSubmit(), i.e. straight into the same
    # handler as the Save button — that is how two saves overlapped.
    check('the image autosave still uses requestSubmit, now safely queued',
          'form.requestSubmit()' in editor)

    print('\n[6b] every section save goes through one path')
    # Four paths used to save sections, each with its own idea of what a reply
    # looks like and whether to tell you anything. 38 of 44 .catch() blocks
    # only reached the console, so a failed save was indistinguishable from a
    # successful one.
    check('there is a single saveSection entry point', 'function saveSection(' in editor)
    check('it understands BOTH reply dialects',
          'function _readSaveReply' in editor
          and "d.success === false" in editor and "d.status === 'error'" in editor)
    check('a dropped connection is reported, not logged and forgotten',
          "_setSaveState(id, 'failed', 'no connection')" in editor)
    check('and a refused save says so on the section',
          "_setSaveState(id, 'failed', res.error)" in editor)
    check('the Save button uses it',
          'saveSection(sectionId, { body: formData, endpoint: endpoint })' in editor)
    check('so do the autosaves',
          editor.count('saveSection(sectionId, {') >= 3)
    check('autosaves stay quiet on success but not on failure',
          'quiet: true' in editor)
    # showMessage was defined twice; the second (alert) shadowed the first, so
    # the #message element in the markup was dead and every message blocked.
    check('showMessage is defined once', editor.count('function showMessage') == 1)
    check('and no longer a blocking alert',
          'function showMessage(message) {\n            alert(message);' not in editor)
    check('the inline message element it uses still exists', 'id="messageContent"' in editor)

    print('\n[6c] nothing blocks the page to report a failure')
    # 39 alert() calls froze the editor for every failure — including ones
    # raised by a background autosave nobody asked for.
    real_alerts = [ln for ln in editor.splitlines()
                   if 'alert(' in ln and not ln.strip().startswith(('//', '*'))]
    check(f'no alert() calls are left ({len(real_alerts)})', not real_alerts)
    check('there is one notify() to replace them', 'function notify(msg, kind)' in editor)
    check('errors persist until dismissed',
          "if (kind !== 'error') setTimeout(dismiss, 2400);" in editor)
    check('and carry a dismiss control', 'editor-toast-close' in editor)
    check('success still fades on its own', "data-kind=\"success\"" in editor)
    check('the old toast callers keep working',
          'function showEditorToast(msg, kind) { return notify(' in editor)
    # confirm()/prompt() are DECISIONS, not messages — they have to block.
    check('confirmations were left blocking, because they ask a question',
          editor.count('confirm(') >= 8)

    print('\n[7] the dialog no longer accuses a lone editor')
    presence = open(os.path.join(_REPO, 'Templates', 'components', 'presence.html')).read()
    check('the shared dialog handles the self case', 'd.self_conflict' in presence)
    check('using the server wording rather than "someone else"',
          "(d.error || 'You changed this '" in presence)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
