"""Admin GitHub sign-in can require membership of a GitHub organization.

    venv/bin/python tests/test_github_org_gate.py

A per-user "does this account have 2FA" check reads a boolean off the profile
at one moment in time and needs a scope that hands over private profile data.
Requiring org membership is better on both counts: GitHub's own org-level
"Require two-factor authentication" keeps enforcing it — removing members who
drop 2FA — and `read:org` reads membership, not people.

It also gives deprovisioning, which storing a bare numeric GitHub id otherwise
leaves entirely manual: remove someone from the org and they lose admin access.

What this pins down:

  * the gate FAILS CLOSED — anything short of a confirmed active membership
    refuses the sign-in, including GitHub being unreachable. A requirement that
    lapses when the network does is not a requirement;
  * "we could not check" is never reported as "you were removed", and an
    unaccepted invitation says so, because those are three different fixes;
  * the scope only widens when an org is actually configured;
  * public member sign-in is not gated — the org is an admin control, and the
    students it would lock out are who GitHub login was built for.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import atexit
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-github-org')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-ghorg-test-')
# Each of these holds a ~2.5 MB copy of main.py and a SQLite database; nothing
# removed them, so repeated suite runs left GBs behind in /tmp.
atexit.register(shutil.rmtree, _SCRATCH, ignore_errors=True)
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


class FakeResponse:
    def __init__(self, status, payload=None, scopes=''):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.text = str(payload)
        # GitHub reports what the token was ACTUALLY granted here — which is
        # not necessarily what was asked for.
        self.headers = {'X-OAuth-Scopes': scopes}

    def json(self):
        return self._payload


def fake_requests(status, payload=None, boom=False, scopes=''):
    """Stand in for the requests module inside the GitHub helpers."""
    class _R:
        @staticmethod
        def get(url, headers=None, timeout=None, params=None):
            CALLS.append(url)
            if boom:
                raise RuntimeError('network down')
            return FakeResponse(status, payload, scopes)
    return _R


CALLS = []


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
        site = main.Website(user_id=owner.id, name='Site', is_draft=False)
        db.session.add(site)
        db.session.commit()
        cfg = main.GitHubLoginSettings(client_id='Iv1.test',
                                       client_secret=main.encrypt_api_key('s3cret'))
        db.session.add(cfg)
        db.session.commit()
        return dict(owner=owner.id, site=site.id)


def set_org(org):
    with app.app_context():
        cfg = main.GitHubLoginSettings.query.first()
        cfg.required_org = org
        db.session.commit()


def _with_fake_github(fn, status=None, payload=None, boom=False, scopes=''):
    import sys as _sys
    real = _sys.modules.get('requests')
    _sys.modules['requests'] = fake_requests(status, payload, boom, scopes)
    try:
        with app.app_context():
            return fn()
    finally:
        if real is not None:
            _sys.modules['requests'] = real
        else:
            _sys.modules.pop('requests', None)


def gate(status=None, payload=None, boom=False):
    """Run the org gate with a stubbed GitHub."""
    return _with_fake_github(lambda: main.github_org_gate('tok'),
                             status, payload, boom)


def list_orgs(status=200, payload=None, scopes='read:org', boom=False):
    """Run the org listing with a stubbed GitHub."""
    return _with_fake_github(lambda: main._github_user_orgs('tok'),
                             status, payload, boom, scopes)


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    ids = setup()

    print('\n[1] with no org set, nothing changes')
    set_org(None)
    CALLS.clear()
    ok, err = gate(200, {'state': 'active'})
    check('the gate passes', ok is True and err is None)
    check('and GitHub is not called at all', CALLS == [])
    # github_authorize_url builds an external callback URL, so it needs a
    # request context to know the host.
    with app.test_request_context('https://team.example.org/login'):
        url = main.github_authorize_url('state123')
    check(f'the OAuth request stays scopeless ({"scope=&" in url or url.endswith("scope=")})',
          'scope=&' in url or 'scope=read' not in url)

    print('\n[2] with an org set, membership is checked')
    set_org('acme-robotics')
    # github_authorize_url builds an external callback URL, so it needs a
    # request context to know the host.
    with app.test_request_context('https://team.example.org/login'):
        url = main.github_authorize_url('state123')
    check(f'the scope widens to read:org only ({"read%3Aorg" in url})',
          'read%3Aorg' in url or 'read:org' in url)
    check('and not to anything touching profile data',
          'user' not in url.split('scope=')[1].split('&')[0])

    CALLS.clear()
    ok, err = gate(200, {'state': 'active'})
    check('an active member gets in', ok is True and err is None)
    check(f'via the memberships endpoint ({CALLS[0].split("/user")[-1]})',
          CALLS[0].endswith('/user/memberships/orgs/acme-robotics'))

    print('\n[3] anything short of active membership is refused')
    ok, err = gate(404)
    check('a non-member is refused', ok is False)
    check(f'and told which org to ask about ({err[:46]!r})', 'acme-robotics' in err)

    ok, err = gate(200, {'state': 'pending'})
    check('an unaccepted invitation is refused', ok is False)
    check(f'and told to accept it ({err[:40]!r})', 'invitation' in err.lower())
    check('not told they were never invited', 'not a member' not in err.lower())

    print('\n[4] it fails closed, without lying about why')
    ok, err = gate(boom=True)
    check('a network failure refuses the sign-in', ok is False)
    check("but doesn't claim they were removed",
          'not a member' not in err.lower() and "n't confirm" in err.lower())
    ok, err = gate(403, {'message': 'SAML enforcement'})
    check('a SAML/SSO refusal is also closed', ok is False)
    check('and points at authorizing the app for the org', 'single sign-on' in err.lower())
    ok, err = gate(500)
    check('so is an unexpected status', ok is False)
    ok, err = gate(200, {'state': 'weird'})
    check('and an unexpected membership state', ok is False)

    print('\n[5] the org name is stored cleanly')
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(ids['owner'])
        s['_fresh'] = True
        s['admin_website_id'] = ids['site']

    r = c.post('/admin/dashboard/settings/github',
               json={'client_id': 'Iv1.test', 'client_secret': '',
                     'required_org': 'https://github.com/acme-robotics/'})
    check(f'a pasted URL is reduced to the org ({r.get_json().get("required_org")!r})',
          r.get_json().get('required_org') == 'acme-robotics')
    r = c.post('/admin/dashboard/settings/github',
               json={'client_id': 'Iv1.test', 'client_secret': '',
                     'required_org': '@acme-robotics'})
    check('a leading @ is dropped', r.get_json().get('required_org') == 'acme-robotics')
    r = c.post('/admin/dashboard/settings/github',
               json={'client_id': 'Iv1.test', 'client_secret': '',
                     'required_org': 'not a real org!'})
    check(f'and nonsense is refused ({r.status_code})',
          r.status_code == 400 and not r.get_json().get('success'))
    with app.app_context():
        check('leaving the good value in place',
              main.GitHubLoginSettings.query.first().required_org == 'acme-robotics')
    r = c.post('/admin/dashboard/settings/github',
               json={'client_id': 'Iv1.test', 'client_secret': '', 'required_org': ''})
    check('it can be cleared', r.get_json().get('required_org') == '')

    print('\n[6] the org list can be fetched instead of typed')
    # The app has no GitHub identity of its own, so this needs a user token
    # borrowed for one call — hence a round trip rather than a background fetch.
    r = c.get('/admin/auth/github/list-orgs')
    check(f'the button starts an authorize round trip ({r.status_code})',
          r.status_code == 302 and 'github.com/login/oauth/authorize' in r.headers['Location'])
    check('asking for read:org even with no org set yet',
          'read%3Aorg' in r.headers['Location'] or 'read:org' in r.headers['Location'])

    # Simulate the callback landing with a list, the way _github_user_orgs would.
    with c.session_transaction() as sess:
        sess['gh_org_choices'] = ['acme-robotics', 'other-org']
    page = c.get('/admin/dashboard/settings').get_data(as_text=True)
    check('the list becomes a dropdown', 'id="ghRequiredOrgSelect"' in page)
    check('offering each org', '>acme-robotics<' in page and '>other-org<' in page)
    check('and a way to require none', 'No organization required' in page)
    again = c.get('/admin/dashboard/settings').get_data(as_text=True)
    check('the list is consumed once, so it cannot go stale',
          'id="ghRequiredOrgSelect"' not in again)
    check('falling back to typing it', 'id="ghRequiredOrg"' in again)

    print('\n[6b] an empty list without the scope is NOT "no organizations"')
    # /user/orgs answers 200 with only PUBLIC memberships when the token lacks
    # read:org. Most memberships are private, so that reads as an empty list —
    # indistinguishable from having no orgs unless the granted scopes are read
    # off GitHub's own header. Asking for a scope is not being granted it: an
    # existing authorization of the app can return the older, narrower grant.
    orgs, problem = list_orgs(200, [], scopes='')
    check(f'an empty list with no scope is flagged ({problem!r})',
          problem == 'missing_scope')
    check('and the advice is to revoke and re-approve',
          'Revoke it under GitHub' in main.GITHUB_ORGS_PROBLEMS['missing_scope'])
    check('not "you have no organizations"',
          'no organizations' not in main.GITHUB_ORGS_PROBLEMS['missing_scope'])

    orgs, problem = list_orgs(200, [], scopes='read:org')
    check(f'an empty list WITH the scope really is empty ({problem!r})',
          problem is None and orgs == [])

    orgs, problem = list_orgs(200, [{'login': 'acme-robotics'}, {'login': 'zeta'}],
                              scopes='read:org')
    check(f'orgs come back sorted, logins only ({orgs})',
          orgs == ['acme-robotics', 'zeta'] and problem is None)

    orgs, problem = list_orgs(200, [{'login': 'pub-org'}], scopes='')
    check('a partial list is still offered, with the warning',
          orgs == ['pub-org'] and problem == 'missing_scope')

    orgs, problem = list_orgs(boom=True)
    check(f'a network failure is separate again ({problem!r})',
          orgs is None and problem == 'unreachable')

    print('\n[7] the setting is explained where it is set')
    html = c.get('/admin/dashboard/settings').get_data(as_text=True)
    check('the field is on the settings page', 'id="ghRequiredOrg"' in html)
    check('it says GitHub does the 2FA enforcing',
          'Require two-factor authentication' in html)
    check('it admits Uwebia cannot verify that setting',
          "can't verify that setting" in html)
    check('and that the scope widens', 'read:org' in html)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
