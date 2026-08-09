"""Two admins in one guide: see each other, and never silently overwrite.

    venv/bin/python tests/test_collab_presence.py

Phase 1 of multiplayer editing. Two separate things:

  • presence — a heartbeat table saying who is on which document and where
    inside it. Polled over HTTP against Postgres because the app runs on sync
    gunicorn workers with no Redis and no websocket layer: in-memory state
    would be per-worker, and an SSE stream would pin one of three workers per
    open editor.

  • conflict detection — guide lesson saves post the WHOLE Quill body with no
    version check, so two admins in one lesson meant the second save silently
    destroyed the first. The editor now echoes the version it loaded and a
    stale write is refused instead of landing.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-collab')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-collab-test-')
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

        # A real colleague, not a bystander: they need guides.edit to save, or
        # the "two people writing at once" case never actually happens.
        mate = main.User(username='rowan', parent_user_id=owner.id,
                         permissions={'guides.view': True, 'guides.edit': True})
        mate.set_password('x')
        db.session.add(mate)
        db.session.commit()

        site = main.Website(user_id=owner.id, name='Site', is_draft=False)
        db.session.add(site)
        db.session.commit()

        guide = main.Guide(website_id=site.id, title='Build a robot',
                           slug='build-a-robot')
        db.session.add(guide)
        db.session.commit()

        node = main.GuideNode(guide_id=guide.id, website_id=site.id,
                              node_type='lesson', title='Lesson 1: Wiring',
                              slug='wiring', content='<p>original</p>')
        db.session.add(node)
        db.session.commit()
        return owner.id, mate.id, site.id, guide.id, node.id


def client_for(user_id, website_id):
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(user_id)
        s['_fresh'] = True
        s['admin_website_id'] = website_id
    return c


def main_test():
    owner_id, mate_id, site_id, guide_id, node_id = setup()
    app.config['WTF_CSRF_ENABLED'] = False

    print('\n[1] presence: two admins on one guide see each other')
    a = client_for(owner_id, site_id)
    b = client_for(mate_id, site_id)

    ra = a.post('/admin/presence/ping', json={
        'resource_type': 'guide', 'resource_id': guide_id,
        'context_id': node_id, 'context_label': 'Lesson 1: Wiring',
        'is_editing': True})
    da = ra.get_json() or {}
    check(f'the heartbeat is accepted — got {ra.status_code}', ra.status_code == 200)
    check('alone at first, nobody else is reported', da.get('peers') == [])

    db_ = b.post('/admin/presence/ping', json={
        'resource_type': 'guide', 'resource_id': guide_id,
        'context_id': node_id, 'context_label': 'Lesson 1: Wiring'}).get_json() or {}
    peers = db_.get('peers') or []
    check('the second admin sees the first', len(peers) == 1)
    check('by name', peers and peers[0]['name'] == 'owner')
    check('with where they are', peers and peers[0]['context_label'] == 'Lesson 1: Wiring')
    check('and that they are actively typing', peers and peers[0]['is_editing'] is True)
    check('initials for the avatar chip', peers and peers[0]['initials'] == 'O')

    print('\n[2] presence is scoped and self-excluding')
    da2 = a.post('/admin/presence/ping', json={
        'resource_type': 'guide', 'resource_id': guide_id}).get_json() or {}
    check('you never appear in your own peer list',
          all(p['user_id'] != owner_id for p in da2.get('peers', [])))
    check('the other admin does', any(p['user_id'] == mate_id for p in da2.get('peers', [])))

    other = a.post('/admin/presence/ping', json={
        'resource_type': 'guide', 'resource_id': guide_id + 999}).get_json() or {}
    check('a different document has its own room', other.get('peers') == [])

    bad = a.post('/admin/presence/ping', json={
        'resource_type': 'nonsense', 'resource_id': 1})
    check('an unknown resource type is rejected', bad.status_code == 400)

    print('\n[3] one row per person per document, however many beats')
    with app.app_context():
        for _ in range(3):
            a.post('/admin/presence/ping', json={
                'resource_type': 'guide', 'resource_id': guide_id})
        check('repeated heartbeats update rather than pile up',
              main.EditingPresence.query.filter_by(
                  user_id=owner_id, resource_id=guide_id).count() == 1)

    print('\n[4] a stale heartbeat stops counting')
    with app.app_context():
        from datetime import timedelta
        row = main.EditingPresence.query.filter_by(user_id=mate_id).first()
        row.last_seen_at = (row.last_seen_at
                            - timedelta(seconds=main.PRESENCE_STALE_SECONDS + 5))
        db.session.commit()
    gone = a.post('/admin/presence/ping', json={
        'resource_type': 'guide', 'resource_id': guide_id}).get_json() or {}
    check('someone who stopped beating drops off the list',
          all(p['user_id'] != mate_id for p in gone.get('peers', [])))

    print('\n[5] leaving clears the chip immediately')
    b.post('/admin/presence/ping', json={
        'resource_type': 'guide', 'resource_id': guide_id})
    b.post('/admin/presence/leave', json={
        'resource_type': 'guide', 'resource_id': guide_id})
    left = a.post('/admin/presence/ping', json={
        'resource_type': 'guide', 'resource_id': guide_id}).get_json() or {}
    check('they are gone at once, not after a timeout',
          all(p['user_id'] != mate_id for p in left.get('peers', [])))

    print('\n[6] THE DATA LOSS BUG: a stale save is refused')
    # Both load version 1. Rowan saves. Owner then saves the copy they loaded
    # before Rowan's write — which used to land silently on top of it.
    loaded = a.get(f'/admin/guides/{guide_id}/nodes/{node_id}').get_json() or {}
    base = (loaded.get('node') or {}).get('version')
    check(f'the editor is told which version it loaded ({base})', base == 1)

    r_mate = b.post(f'/admin/guides/{guide_id}/nodes/save', json={
        'id': node_id, 'title': 'Lesson 1: Wiring', 'node_type': 'lesson',
        'content': '<p>rowan rewrote this</p>', 'base_version': base})
    check(f'the first save goes through — got {r_mate.status_code}',
          r_mate.status_code == 200)

    r_owner = a.post(f'/admin/guides/{guide_id}/nodes/save', json={
        'id': node_id, 'title': 'Lesson 1: Wiring', 'node_type': 'lesson',
        'content': '<p>owner rewrote this</p>', 'base_version': base})
    d = r_owner.get_json() or {}
    check(f'the stale save is REFUSED — got {r_owner.status_code}',
          r_owner.status_code == 409)
    check('flagged as a conflict, not a generic error', d.get('conflict') is True)
    check('it names who got there first', d.get('saved_by') == 'rowan')
    check('and hands back their text so nothing is stranded',
          'rowan rewrote this' in (d.get('current_content') or ''))
    with app.app_context():
        node = db.session.get(main.GuideNode, node_id)
        check('the first writer\'s work is still what is stored',
              'rowan rewrote this' in (node.content or ''))

    print('\n[7] resolving the conflict')
    fresh = a.get(f'/admin/guides/{guide_id}/nodes/{node_id}').get_json() or {}
    newbase = (fresh.get('node') or {}).get('version')
    check(f'the version moved on ({base} -> {newbase})', newbase == base + 1)
    r_retry = a.post(f'/admin/guides/{guide_id}/nodes/save', json={
        'id': node_id, 'title': 'Lesson 1: Wiring', 'node_type': 'lesson',
        'content': '<p>owner merged both</p>', 'base_version': newbase})
    check('saving on top of the current version works',
          r_retry.status_code == 200)

    r_force = b.post(f'/admin/guides/{guide_id}/nodes/save', json={
        'id': node_id, 'title': 'Lesson 1: Wiring', 'node_type': 'lesson',
        'content': '<p>rowan insisted</p>', 'base_version': 1, 'force': True})
    check('an explicit overwrite is still possible when chosen',
          r_force.status_code == 200)

    print('\n[8] older editors keep working')
    # A page loaded before this shipped sends no base_version and must not be
    # locked out of saving.
    r_old = a.post(f'/admin/guides/{guide_id}/nodes/save', json={
        'id': node_id, 'title': 'Lesson 1: Wiring', 'node_type': 'lesson',
        'content': '<p>no version sent</p>'})
    check('a save with no base_version is accepted', r_old.status_code == 200)
    with app.app_context():
        check('and still bumps the version for everyone else',
              (db.session.get(main.GuideNode, node_id).version or 0) >= 4)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
