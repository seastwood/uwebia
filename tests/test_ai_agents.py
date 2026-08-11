"""An AI agent can be used, edited and deleted once it has been created.

    venv/bin/python tests/test_ai_agents.py

Every route that touched an agent authorised it the same way:

    Website.query.get_or_404(agent.website_id).user_id != current_user.root_user_id

but create_ai_agent never sets website_id — agents are a user-scoped pool, keyed
by user_id, shared across all of that account's websites. So website_id was
always NULL, get_or_404(None) always 404'd, and every agent was unusable the
moment it existed: no edit, no delete, no chat, no test, no image generation,
no AI assist. Creating one worked, which is what made it look configured.

The second failure this covers is quieter. API keys are Fernet-encrypted with a
key derived from SECRET_KEY, and decrypt_api_key() returns the ciphertext
unchanged when it cannot decrypt — correct for a key saved before encryption
existed, wrong when SECRET_KEY has since changed. The Fernet token then gets
sent to the provider as the credential, and the provider says the key is
invalid, so a perfectly good key looks like a typo.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-ai-agents')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-agents-test-')
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
CALLS = []


def check(label, cond):
    print(('  PASS  ' if cond else '  FAIL  ') + label)
    if not cond:
        FAILURES.append(label)


class FakeResponse:
    """Stands in for the provider so no test ever reaches the network."""
    ok = True
    status_code = 200

    def json(self):
        return {'choices': [{'message': {'content': 'OK'}}],
                'content': [{'text': 'OK'}],
                'data': [{'url': 'http://example.com/i.png'}]}


def fake_post(url, **kwargs):
    CALLS.append({'url': url, 'headers': kwargs.get('headers') or {},
                  'json': kwargs.get('json') or {}})
    return FakeResponse()


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

        ids = {}
        for tag in ('owner', 'stranger'):
            u = main.User(username=tag, parent_user_id=None)
            u.set_password('ownerpassword')
            db.session.add(u)
            db.session.commit()
            w = main.Website(user_id=u.id, name=f'{tag} site', is_draft=False,
                             is_live=True, url_prefix=None if tag == 'owner' else tag)
            db.session.add(w)
            db.session.commit()
            ids[tag] = u.id
            ids[tag + '_site'] = w.id
        return ids


def client_for(ids, tag):
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(ids[tag])
        s['_fresh'] = True
        s['editing_website_id'] = ids[tag + '_site']
    return c


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    ids = setup()
    c = client_for(ids, 'owner')

    print('\n[1] a created agent is owned by the account, not a website')
    r = c.post('/admin/ai-agents/create',
               json={'name': 'Helper', 'provider': 'openai_compatible',
                     'api_url': 'http://ai.example', 'model': 'llama3',
                     'api_key': 'sk-real-key', 'capabilities': 'both'})
    check(f'creating it succeeds — got {r.status_code}', r.status_code == 201)
    agent_id = ((r.get_json() or {}).get('agent') or {}).get('id')
    with app.app_context():
        a = db.session.get(main.AIAgent, agent_id)
        check('it is stamped with the owner', a.user_id == ids['owner'])
        # Not a bug to fix by backfilling: the pool is deliberately user-scoped,
        # so authorisation has to read user_id.
        check('and carries no website link, as the pool is user-scoped',
              a.website_id is None)

    print('\n[2] every route that touches it still works')
    r = c.post(f'/admin/ai-agents/{agent_id}/update',
               json={'name': 'Renamed', 'provider': 'openai_compatible',
                     'api_url': 'http://ai.example', 'model': 'llama3',
                     'capabilities': 'both'})
    check(f'edit — got {r.status_code}',
          r.status_code == 200 and (r.get_json() or {}).get('success'))
    with app.app_context():
        check('and the change stuck',
              db.session.get(main.AIAgent, agent_id).name == 'Renamed')

    import requests as _requests
    real_post = _requests.post
    _requests.post = fake_post
    try:
        r = c.post(f'/admin/ai-agents/{agent_id}/test', json={})
        d = r.get_json() or {}
        check(f'test — got {r.status_code} {d.get("error") or ""}',
              r.status_code == 200 and d.get('success'))
        r = c.post(f'/admin/ai-agents/{agent_id}/chat',
                   json={'messages': [{'role': 'user', 'content': 'hi'}]})
        d = r.get_json() or {}
        check(f'chat — got {r.status_code} {d.get("error") or ""}',
              r.status_code == 200 and d.get('success'))

        print('\n[3] the real API key reaches the provider, decrypted')
        check(f'the provider was actually called ({len(CALLS)}x)', len(CALLS) >= 1)
        auth = (CALLS[-1]['headers'] or {}).get('Authorization', '')
        check(f'with the key as entered ({auth[:14]}…)', auth == 'Bearer sk-real-key')
        check('never the stored ciphertext', 'gAAAAA' not in auth)
    finally:
        _requests.post = real_post

    print('\n[4] an unreadable key is reported, not sent as the credential')
    # What a Docker deploy with no fixed SECRET_KEY does on every restart.
    from cryptography.fernet import Fernet
    real_fernet = main._get_fernet
    main._get_fernet = lambda: Fernet(Fernet.generate_key())
    CALLS.clear()
    _requests.post = fake_post
    try:
        r = c.post(f'/admin/ai-agents/{agent_id}/test', json={})
        d = r.get_json() or {}
        msg = d.get('error') or ''
        check(f'the test fails rather than pretending — got {r.status_code}',
              not d.get('success'))
        check(f'and says why ({msg[:60]}…)', 'SECRET_KEY' in msg)
        check('telling the admin to re-enter it', 'again' in msg.lower())
        check('and no garbage credential was sent to the provider', not CALLS)
    finally:
        main._get_fernet = real_fernet
        _requests.post = real_post

    print('\n[5] a key stored before encryption existed still works')
    with app.app_context():
        legacy = main.AIAgent(user_id=ids['owner'], name='Legacy',
                              provider='openai_compatible',
                              api_url='http://ai.example', model='m',
                              api_key='sk-plaintext-legacy', capabilities='chat')
        db.session.add(legacy)
        db.session.commit()
        legacy_id = legacy.id
    CALLS.clear()
    _requests.post = fake_post
    try:
        r = c.post(f'/admin/ai-agents/{legacy_id}/test', json={})
        d = r.get_json() or {}
        check(f'it is used as-is — got {r.status_code} {d.get("error") or ""}',
              r.status_code == 200 and d.get('success'))
        check('and reaches the provider unchanged',
              CALLS and CALLS[-1]['headers'].get('Authorization')
              == 'Bearer sk-plaintext-legacy')
    finally:
        _requests.post = real_post

    print("\n[6] another account still cannot touch it")
    # The broken check did do this much, by refusing everyone. Replacing it
    # must not open the pool up.
    other = client_for(ids, 'stranger')
    for label, path, body in (
            ('edit', f'/admin/ai-agents/{agent_id}/update', {'name': 'Stolen'}),
            ('chat', f'/admin/ai-agents/{agent_id}/chat',
             {'messages': [{'role': 'user', 'content': 'hi'}]}),
            ('test', f'/admin/ai-agents/{agent_id}/test', {}),
            ('delete', f'/admin/ai-agents/{agent_id}/delete', {})):
        r = other.post(path, json=body)
        check(f'{label} is refused — got {r.status_code}', r.status_code == 403)
    with app.app_context():
        check('the agent is untouched',
              db.session.get(main.AIAgent, agent_id).name == 'Renamed')
    listed = (other.get('/admin/ai-agents/list').get_json() or {}).get('agents', [])
    check(f'and it is not in their list ({len(listed)})', listed == [])

    print('\n[7] and the owner can delete it')
    r = c.post(f'/admin/ai-agents/{agent_id}/delete')
    check(f'delete — got {r.status_code}',
          r.status_code == 200 and (r.get_json() or {}).get('success'))
    with app.app_context():
        check('it is gone', db.session.get(main.AIAgent, agent_id) is None)
    r = c.post(f'/admin/ai-agents/{agent_id}/delete')
    check(f'deleting it twice is a plain 404, not a crash — got {r.status_code}',
          r.status_code == 404)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
