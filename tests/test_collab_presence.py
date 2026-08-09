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
from datetime import timedelta

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
                         permissions={'guides.view': True, 'guides.edit': True,
                                      'sections.edit': True})
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

    print('\n[8] the same guard on quiz questions, articles and campaigns')
    with app.app_context():
        site = db.session.get(main.Website, site_id)
        quiz = main.Quiz(website_id=site.id, title='Safety check')
        coll = main.PostCollection(website_id=site.id, user_id=owner_id,
                                   name='Blog', slug='blog')
        news = main.Newsletter(website_id=site.id, user_id=owner_id,
                               name='News', slug='news')
        db.session.add_all([quiz, coll, news])
        db.session.commit()
        # true_false is validated server-side: exactly two options, one correct.
        question = main.QuizQuestion(quiz_id=quiz.id, question_type='true_false',
                                     prompt='<p>original</p>',
                                     config={'options': [{'id': 1, 'text': 'True', 'correct': True},
                        {'id': 2, 'text': 'False', 'correct': False}]}, points=1)
        article = main.Post(collection_id=coll.id, website_id=site.id,
                            title='Draft', slug='draft', content='<p>original</p>')
        campaign = main.NewsletterCampaign(newsletter_id=news.id, subject='Hello',
                                           html_body='<p>original</p>')
        db.session.add_all([question, article, campaign])
        db.session.commit()
        qz_id, qq_id = quiz.id, question.id
        coll_id, art_id = coll.id, article.id
        nl_id, camp_id = news.id, campaign.id

    cases = [
        ('quiz question',
         f'/admin/quizzes/{qz_id}/questions/save',
         {'id': qq_id, 'question_type': 'true_false', 'prompt': '<p>{who} wrote this</p>',
          'config': {'options': [{'id': 1, 'text': 'True', 'correct': True},
                        {'id': 2, 'text': 'False', 'correct': False}]}, 'points': 1}),
        ('article',
         f'/admin/posts/{coll_id}/articles/save',
         {'id': art_id, 'title': 'Draft', 'content': '<p>{who} wrote this</p>'}),
        ('campaign',
         f'/admin/newsletters/{nl_id}/campaigns/save',
         {'id': camp_id, 'subject': 'Hello', 'html_body': '<p>{who} wrote this</p>'}),
    ]
    for label, url, payload in cases:
        first = dict(payload, base_version=1)
        first = {k: (v.format(who='rowan') if isinstance(v, str) else v)
                 for k, v in first.items()}
        r1 = a.post(url, json=first)
        check(f'{label}: the first save lands — got {r1.status_code}',
              r1.status_code == 200)

        second = dict(payload, base_version=1)
        second = {k: (v.format(who='owner') if isinstance(v, str) else v)
                  for k, v in second.items()}
        r2 = a.post(url, json=second)
        d2 = r2.get_json() or {}
        check(f'{label}: the stale save is refused — got {r2.status_code}',
              r2.status_code == 409 and d2.get('conflict') is True)
        check(f'{label}: it hands back the current text',
              'rowan wrote this' in (d2.get('current_content') or ''))

        forced = dict(second, base_version=1, force=True)
        check(f'{label}: an explicit overwrite still works',
              a.post(url, json=forced).status_code == 200)

    print('\n[9] presence works for every editor type')
    for rtype in ('guide', 'quiz', 'page', 'post', 'newsletter', 'resource'):
        rr = a.post('/admin/presence/ping',
                    json={'resource_type': rtype, 'resource_id': 1})
        check(f'{rtype} is an accepted presence type', rr.status_code == 200)

    print('\n[10] page builder sections')
    # The scaffolding for this existed and was switched off with a note that
    # enforcing it would false-positive, because several save paths bumped the
    # version without telling the card. Those paths send and refresh it now.
    with app.app_context():
        page = main.PublicPageContent(website_id=site_id, name='Home', slug='home')
        db.session.add(page)
        db.session.commit()
        sec = main.PageSection(page_content_id=page.id, section_type='text',
                               content={'text': 'original'}, order=1)
        db.session.add(sec)
        db.session.commit()
        page_id, sec_id = page.id, sec.id
        start_version = sec.version or 0

    def save_text(client, body, version, force=False):
        form = {'section_id': str(sec_id), 'section_type': 'text', 'text': body}
        if version is not None:
            form['_version'] = str(version)
        if force:
            form['_force'] = '1'
        return client.post('/update_section', data=form)

    r1 = save_text(b, 'rowan wrote this', start_version)
    d1 = r1.get_json() or {}
    check(f'a save at the current version lands — got {r1.status_code}',
          r1.status_code == 200)
    check('and reports the new version', d1.get('version') == start_version + 1)

    r2 = save_text(a, 'owner had a stale copy', start_version)
    d2 = r2.get_json() or {}
    check(f'a save at the OLD version is refused — got {r2.status_code}',
          r2.status_code == 409)
    check('flagged as a conflict', d2.get('conflict') is True)
    check('naming the section so the editor can point at it',
          d2.get('section_id') == sec_id)
    with app.app_context():
        kept = db.session.get(main.PageSection, sec_id).content
        check("the first writer's text survived",
              'rowan' in str(kept))

    check('an explicit overwrite still works',
          save_text(a, 'owner insisted', start_version, force=True).status_code == 200)

    print('\n[11] the false positive the old comment warned about')
    # A second save from the SAME person, using the version handed back by the
    # first, must go straight through. This is what broke when side-channel
    # saves bumped the version without refreshing the card.
    with app.app_context():
        v = db.session.get(main.PageSection, sec_id).version
    again = save_text(a, 'same person, next edit', v)
    check(f'consecutive saves by one person do not conflict — got {again.status_code}',
          again.status_code == 200)
    v2 = (again.get_json() or {}).get('version')
    check('each save hands back the next version', v2 == v + 1)
    check('and that version is immediately usable',
          save_text(a, 'and again', v2).status_code == 200)

    print('\n[12] a caller that sends no version is not locked out')
    check('an omitted version still saves (older clients, other callers)',
          save_text(a, 'no version supplied', None).status_code == 200)

    print('\n[13] live co-editing relay')
    import base64 as _b64
    dk = f'guide_node:{node_id}'

    r = a.post('/admin/collab/sync', json={'doc_key': dk, 'since': 0})
    d = r.get_json() or {}
    check(f'the relay accepts a known document — got {r.status_code}',
          r.status_code == 200 and d.get('success') is True)
    check('and reports the saved version so everyone stays in step',
          isinstance(d.get('record_version'), int))

    bad = a.post('/admin/collab/sync', json={'doc_key': 'guide_node:999999', 'since': 0})
    check('an unknown document is refused', bad.status_code == 403)
    junk = a.post('/admin/collab/sync', json={'doc_key': 'not-a-key', 'since': 0})
    check('a malformed key is refused, not crashed on', junk.status_code == 403)
    other = a.post('/admin/collab/sync', json={'doc_key': 'secret:1', 'since': 0})
    check('an unmapped type cannot be used as a channel', other.status_code == 403)

    # Opaque bytes: the server never interprets them, which is the point.
    up1 = _b64.b64encode(b'\x01update-from-rowan').decode()
    p1 = b.post('/admin/collab/sync', json={'doc_key': dk, 'since': 0, 'update': up1})
    check(f'a peer can push an update — got {p1.status_code}', p1.status_code == 200)

    pulled = a.post('/admin/collab/sync', json={'doc_key': dk, 'since': 0}).get_json() or {}
    check('the other side receives it', up1 in (pulled.get('updates') or []))
    cursor = pulled.get('since')
    again = a.post('/admin/collab/sync', json={'doc_key': dk, 'since': cursor}).get_json() or {}
    check('and is not handed the same update twice', (again.get('updates') or []) == [])

    print('\n[14] cursors are exchanged but never pile up')
    aw = _b64.b64encode(b'cursor-of-rowan').decode()
    b.post('/admin/collab/sync', json={'doc_key': dk, 'since': 0, 'awareness': aw})
    seen = a.post('/admin/collab/sync', json={'doc_key': dk, 'since': cursor}).get_json() or {}
    check("a peer's cursor comes back", aw in (seen.get('awareness') or []))
    mine = b.post('/admin/collab/sync', json={'doc_key': dk, 'since': 0}).get_json() or {}
    check('but never your own', aw not in (mine.get('awareness') or []))
    with app.app_context():
        b.post('/admin/collab/sync', json={'doc_key': dk, 'since': 0, 'awareness': aw})
        check('one row per person per document, however many beats',
              main.CollabAwareness.query.filter_by(doc_key=dk).count() == 1)

    print('\n[15] the log is compacted, not grown forever')
    # Push a few more so the count before compaction is actually meaningful.
    for n in range(4):
        b.post('/admin/collab/sync', json={
            'doc_key': dk, 'since': 0,
            'update': _b64.b64encode(f'edit-{n}'.encode()).decode()})
    with app.app_context():
        before = main.CollabUpdate.query.filter_by(doc_key=dk).count()
    check(f'the log really did grow first ({before} rows)', before >= 5)
    snap = _b64.b64encode(b'\x02whole-document-state').decode()
    with app.app_context():
        upto = db.session.query(db.func.max(main.CollabUpdate.id)).filter_by(
            doc_key=dk).scalar()
    a.post('/admin/collab/sync', json={'doc_key': dk, 'since': 0,
                                       'snapshot': snap, 'upto': upto})
    with app.app_context():
        rows = main.CollabUpdate.query.filter_by(doc_key=dk).all()
        check(f'a snapshot replaces what it subsumes ({before} rows -> {len(rows)})',
              len(rows) == 1 and rows[0].is_snapshot is True)
    fresh = a.post('/admin/collab/sync', json={'doc_key': dk, 'since': 0}).get_json() or {}
    check('a newcomer gets the whole state in one go',
          (fresh.get('updates') or []) == [snap])

    print('\n[16] only one client may seed a fresh document')
    # The reported bug: everything in the lesson appeared twice as soon as a
    # second admin opened it. A client's first update only ships on its NEXT
    # beat, so anyone attaching inside that window saw an empty log, decided
    # nobody had seeded, and seeded again — and Yjs faithfully merged both.
    with app.app_context():
        fresh_node = main.GuideNode(guide_id=guide_id, website_id=site_id,
                                    node_type='lesson', title='Lesson 2',
                                    slug='lesson-2', content='<p>stored copy</p>')
        db.session.add(fresh_node)
        db.session.commit()
        fresh_key = f'guide_node:{fresh_node.id}'

    first = a.post('/admin/collab/sync', json={'doc_key': fresh_key, 'since': 0}).get_json() or {}
    check('the first client to arrive is told to seed', first.get('may_seed') is True)

    second = b.post('/admin/collab/sync', json={'doc_key': fresh_key, 'since': 0}).get_json() or {}
    check('a second client arriving before the seed ships is NOT',
          second.get('may_seed') is False)

    retry = a.post('/admin/collab/sync', json={'doc_key': fresh_key, 'since': 0}).get_json() or {}
    check('the holder keeps its grant across beats', retry.get('may_seed') is True)

    # Once anything is in the log there is nothing to seed, for anybody.
    a.post('/admin/collab/sync', json={
        'doc_key': fresh_key, 'since': 0,
        'update': _b64.b64encode(b'seeded-content').decode()})
    after_a = a.post('/admin/collab/sync', json={'doc_key': fresh_key, 'since': 0}).get_json() or {}
    after_b = b.post('/admin/collab/sync', json={'doc_key': fresh_key, 'since': 0}).get_json() or {}
    check('nobody may seed once the document has content',
          after_a.get('may_seed') is False and after_b.get('may_seed') is False)

    print('\n[17] a browser that dies mid-seed does not strand the document')
    with app.app_context():
        main.CollabUpdate.query.filter_by(doc_key=fresh_key).delete()
        row = main.CollabDoc.query.filter_by(doc_key=fresh_key).first()
        row.seed_granted_at = row.seed_granted_at - timedelta(seconds=30)
        db.session.commit()
    rescued = b.post('/admin/collab/sync', json={'doc_key': fresh_key, 'since': 0}).get_json() or {}
    check('the grant expires so someone else can seed', rescued.get('may_seed') is True)

    print('\n[18] older editors keep working')
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
