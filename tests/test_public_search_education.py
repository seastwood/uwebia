"""Guides, lessons, quizzes and resources are findable from the navbar search.

    venv/bin/python tests/test_public_search_education.py

The public search covered pages, posts, products and newsletter issues. The
whole Education section — guides and their lessons, the public quizzes, the
resources — was missing, so none of it could be found from the search box.

The part that needs care is visibility. Search must never name something the
Education index would hide, or it becomes a way to read the shape of
members-only material without being a member. The rules here are the ones
public_guides_index uses:

    guides     status='published', and not members_only unless you are a member
    lessons    is_published, under a visible guide
    quizzes    is_public,   and not members_only unless you are a member
    resources  is_public,   and not members_only unless you are a member

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-search-education')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-search-test-')
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
    """One site, one search term ('soldering') running through everything."""
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
        site = main.Website(user_id=owner.id, name='Site', is_draft=False, is_live=True,
                            public_users_enabled=True, public_navbar_show_search=True)
        db.session.add(site)
        db.session.commit()
        db.session.add(main.PublicPageContent(website_id=site.id, name='Home', slug='home',
                                              site_active_status=True))

        gc = main.GuideCategory(website_id=site.id, name='Mechanical', slug='mech')
        qc = main.QuizCategory(website_id=site.id, name='Safety', slug='safety')
        rc = main.ResourceCategory(website_id=site.id, name='Forms', slug='forms')
        db.session.add_all([gc, qc, rc])
        db.session.commit()

        guide = main.Guide(website_id=site.id, title='Soldering Basics', slug='soldering',
                           description='Learn to solder safely', status='published',
                           category_id=gc.id)
        db.session.add(guide)
        db.session.commit()
        db.session.add_all([
            main.GuideNode(guide_id=guide.id, website_id=site.id, node_type='lesson',
                           title='Tinning the iron', slug='tinning', is_published=True,
                           content='<p>Always tin the soldering iron before use.</p>'),
            # Not published — must stay out of the results.
            main.GuideNode(guide_id=guide.id, website_id=site.id, node_type='lesson',
                           title='Draft lesson', slug='draft', is_published=False,
                           content='<p>soldering notes not ready yet</p>'),
        ])
        db.session.add_all([
            main.Quiz(website_id=site.id, title='Soldering Safety Quiz', is_public=True,
                      description='Check your soldering knowledge', category_id=qc.id),
            main.Resource(website_id=site.id, title='Soldering checklist', is_public=True,
                          description='Printable soldering checklist',
                          resource_type='link', url='http://example.com', category_id=rc.id),
            # None of these may appear for a non-member.
            main.Guide(website_id=site.id, title='Members soldering manual', slug='mm',
                       status='published', members_only=True),
            main.Guide(website_id=site.id, title='Unpublished soldering guide', slug='ug',
                       status='draft'),
            main.Quiz(website_id=site.id, title='Members soldering exam', is_public=True,
                      members_only=True),
            main.Quiz(website_id=site.id, title='Unlisted soldering quiz', is_public=False),
            main.Resource(website_id=site.id, title='Members soldering sheet', is_public=True,
                          members_only=True, resource_type='link', url='http://example.com'),
            main.Resource(website_id=site.id, title='Unlisted soldering sheet', is_public=False,
                          resource_type='link', url='http://example.com'),
        ])
        db.session.commit()

        member = main.PublicUser(website_id=site.id, username='member',
                                 membership_status='member')
        member.set_password('memberpassword')
        visitor = main.PublicUser(website_id=site.id, username='visitor')
        visitor.set_password('visitorpassword')
        db.session.add_all([member, visitor])
        db.session.commit()
        return site.id, member.id, visitor.id


def search(q='soldering', public_user_id=None, site_id=None):
    c = app.test_client()
    if public_user_id:
        with c.session_transaction() as s:
            s['public_user_id'] = public_user_id
            s['public_user_website_id'] = site_id
    r = c.get(f'/search?q={q}')
    assert r.status_code == 200, r.status_code
    return (r.get_json() or {}).get('results', [])


def by_type(results):
    out = {}
    for r in results:
        out.setdefault(r['type'], []).append(r)
    return out


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    site_id, member_id, visitor_id = setup()

    print('\n[1] the Education content is found at all')
    results = search()
    kinds = by_type(results)
    titles = [r['title'] for r in results]
    for kind, expected in (('guide', 'Soldering Basics'),
                           ('lesson', 'Tinning the iron'),
                           ('quiz', 'Soldering Safety Quiz'),
                           ('resource', 'Soldering checklist')):
        check(f'a {kind} is returned ({expected})',
              kind in kinds and any(r['title'] == expected for r in kinds[kind]))

    print('\n[2] each links somewhere that exists')
    urls = {r['type']: r['url'] for r in results}
    check(f"the guide opens its own page ({urls.get('guide', '')})",
          urls.get('guide', '').startswith('/guides/soldering#'))
    check(f"a lesson opens the LESSON, not the cover ({urls.get('lesson', '')})",
          urls.get('lesson', '').startswith('/guides/soldering/tinning#'))
    # /quiz/<id> and /resource/<id> have no prefixed variant, so they must not
    # be built from the site's URL prefix.
    check(f"the quiz link ({urls.get('quiz', '')})",
          urls.get('quiz', '').startswith('/quiz/'))
    check(f"the resource link ({urls.get('resource', '')})",
          urls.get('resource', '').startswith('/resource/'))
    c = app.test_client()
    for kind, url in urls.items():
        if kind not in ('guide', 'lesson', 'quiz', 'resource'):
            continue
        resp = c.get(url.split('#')[0])
        check(f'{kind}: that URL resolves — got {resp.status_code}',
              resp.status_code not in (404, 500))

    print('\n[3] results carry their category for context')
    ctx = {r['type']: r.get('collection') for r in results}
    check(f"guide shows its category ({ctx.get('guide')})", ctx.get('guide') == 'Mechanical')
    check(f"quiz shows its category ({ctx.get('quiz')})", ctx.get('quiz') == 'Safety')
    check(f"resource shows its category ({ctx.get('resource')})", ctx.get('resource') == 'Forms')
    check(f"a lesson shows its guide ({ctx.get('lesson')})",
          ctx.get('lesson') == 'Soldering Basics')

    print('\n[4] and never name what the index would hide')
    for hidden in ('Members soldering manual', 'Unpublished soldering guide',
                   'Members soldering exam', 'Unlisted soldering quiz',
                   'Members soldering sheet', 'Unlisted soldering sheet',
                   'Draft lesson'):
        check(f'hidden from a signed-out visitor: {hidden}', hidden not in titles)

    visitor_titles = [r['title'] for r in search(public_user_id=visitor_id, site_id=site_id)]
    for hidden in ('Members soldering manual', 'Members soldering exam',
                   'Members soldering sheet'):
        check(f'hidden from a signed-in non-member: {hidden}',
              hidden not in visitor_titles)

    print('\n[5] but a member does find the members-only material')
    member_titles = [r['title'] for r in search(public_user_id=member_id, site_id=site_id)]
    for shown in ('Members soldering manual', 'Members soldering exam',
                  'Members soldering sheet'):
        check(f'a member finds: {shown}', shown in member_titles)
    for still_hidden in ('Unpublished soldering guide', 'Unlisted soldering quiz',
                         'Unlisted soldering sheet', 'Draft lesson'):
        check(f'membership does not unlock unpublished work: {still_hidden}',
              still_hidden not in member_titles)

    print('\n[6] the older surfaces still work')
    with app.app_context():
        coll = main.PostCollection(website_id=site_id, name='Blog', slug='blog')
        db.session.add(coll)
        db.session.commit()
        db.session.add(main.Post(website_id=site_id, collection_id=coll.id,
                                 title='Soldering write-up', slug='wu',
                                 status='published', content='<p>soldering</p>'))
        db.session.commit()
    kinds = by_type(search())
    check('posts are still returned', 'post' in kinds)
    check('and the Education results did not crowd out the limit',
          all(k in by_type(search()) for k in ('guide', 'lesson', 'quiz', 'resource')))

    print('\n[7] very short queries are refused rather than answered badly')
    # One or two letters matched nearly every page — the box filled with
    # everything and told the reader nothing.
    c = app.test_client()
    for q in ('s', 'so'):
        d = c.get(f'/search?q={q}').get_json() or {}
        check(f'"{q}" returns nothing', d.get('results') == [])
        check(f'and says why ({d.get("min_chars")})',
              d.get('min_chars') == main.PUBLIC_SEARCH_MIN_CHARS)
    d = c.get('/search?q=sol').get_json() or {}
    check(f'"sol" is long enough and searches ({len(d.get("results") or [])} hits)',
          'min_chars' not in d and len(d.get('results') or []) > 0)
    check('whitespace does not buy you a shorter query',
          (c.get('/search?q=%20s%20').get_json() or {}).get('min_chars')
          == main.PUBLIC_SEARCH_MIN_CHARS)

    print('\n[8] every type the server sends has a label in the UI')
    # Anything missing here silently renders as "Page".
    tpl = open(os.path.join(_REPO, 'Templates', 'components',
                            'public_navbar.html')).read()
    src = open(os.path.join(_REPO, 'main.py')).read()
    import re
    start = src.index('def _public_search_website')
    end = src.index('def public_search_root')
    emitted = set(re.findall(r"'type':\s*'([a-z_]+)'", src[start:end]))
    labels = set(re.findall(r"^\s*([a-z_]+):\s*'[^']+',", tpl, re.M))
    missing = emitted - labels
    check(f'all {len(emitted)} types are labelled ({sorted(emitted)})'
          + (f' — missing {sorted(missing)}' if missing else ''), not missing)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
