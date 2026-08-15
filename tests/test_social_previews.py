"""Public pages carry Open Graph tags, so shared links preview properly.

    venv/bin/python tests/test_social_previews.py

Discord, Slack and iMessage build a link preview from a page's og: tags. The
site had none, so every link anyone shared — a guide, a quiz, a resource, a
post — arrived as a bare URL with no title and no picture.

The parts that are easy to get wrong:

  * og:image must be an ABSOLUTE url. The consumer fetches it from its own
    servers, so a site-relative '/static/uploads/…' is silently ignored and the
    preview arrives with no picture at all;
  * a page must describe ITSELF, not the site — a guide link should show the
    guide's title and cover, which means each template overrides the defaults;
  * the base template both defines and captures those blocks, so the defaults
    must not leak into the document as stray text.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import atexit
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-social-previews')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-social-test-')
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


def meta(html, prop):
    """The content of <meta property=…> or <meta name=…>, or None."""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')
    tag = soup.find('meta', property=prop) or soup.find('meta', attrs={'name': prop})
    return tag.get('content') if tag else None


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

        site = main.Website(user_id=owner.id, name='Team Site', is_draft=False,
                            is_live=True, description='We build robots.')
        db.session.add(site)
        db.session.commit()
        db.session.add(main.PublicPageContent(website_id=site.id, name='Home',
                                              slug='home', site_active_status=True))

        guide = main.Guide(
            website_id=site.id, title='Swerve drive', slug='swerve',
            status='published', description='<p>How the drivetrain works.</p>',
            cover_image_url='/static/uploads/1/assets/cover.webp',
            show_start_button=True)
        quiz = main.Quiz(website_id=site.id, title='Shop safety', is_public=True,
                         description='Before you touch the mill.',
                         image_url='/static/uploads/1/assets/quiz.webp')
        res = main.Resource(website_id=site.id, title='Handbook',
                            resource_type='page', content='<p>Read this.</p>',
                            description='The team handbook.',
                            image_url='/static/uploads/1/assets/hb.webp',
                            is_public=True)
        db.session.add_all([guide, quiz, res])
        db.session.commit()
        return dict(site=site.id, guide=guide.slug, quiz=quiz.id, res=res.id)


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    ids = setup()
    c = app.test_client()

    print('\n[1] the site itself previews')
    html = c.get('/').get_data(as_text=True)
    check(f'og:site_name is the website ({meta(html, "og:site_name")!r})',
          meta(html, 'og:site_name') == 'Team Site')
    check(f'og:title falls back to the site ({meta(html, "og:title")!r})',
          meta(html, 'og:title') == 'Team Site')
    check(f'og:description uses the site blurb ({meta(html, "og:description")!r})',
          meta(html, 'og:description') == 'We build robots.')
    check(f'og:url is the page itself ({meta(html, "og:url")!r})',
          (meta(html, 'og:url') or '').endswith('/'))
    check('and a plain description tag comes along for search engines',
          meta(html, 'description') == 'We build robots.')

    print('\n[2] a guide link describes the guide, not the site')
    html = c.get(f'/guides/{ids["guide"]}').get_data(as_text=True)
    check(f'og:title is the guide ({meta(html, "og:title")!r})',
          meta(html, 'og:title') == 'Swerve drive')
    check(f'og:type marks it as an article ({meta(html, "og:type")!r})',
          meta(html, 'og:type') == 'article')
    desc = meta(html, 'og:description')
    check(f'og:description is the blurb as plain text ({desc!r})',
          desc == 'How the drivetrain works.')
    check('with the HTML stripped, not escaped into the tag',
          '<p>' not in (desc or ''))
    img = meta(html, 'og:image')
    check(f'og:image is the cover, made ABSOLUTE ({img!r})',
          (img or '').startswith('http') and img.endswith('/static/uploads/1/assets/cover.webp'))
    check(f'a picture upgrades the card to large ({meta(html, "twitter:card")!r})',
          meta(html, 'twitter:card') == 'summary_large_image')

    print('\n[3] quizzes and resources do the same')
    html = c.get(f'/quiz/{ids["quiz"]}').get_data(as_text=True)
    check(f'quiz title ({meta(html, "og:title")!r})', meta(html, 'og:title') == 'Shop safety')
    check('quiz image is absolute',
          (meta(html, 'og:image') or '').startswith('http'))
    html = c.get(f'/resource/{ids["res"]}').get_data(as_text=True)
    check(f'resource title ({meta(html, "og:title")!r})', meta(html, 'og:title') == 'Handbook')
    check(f'resource description ({meta(html, "og:description")!r})',
          meta(html, 'og:description') == 'The team handbook.')

    print('\n[4] the block defaults do not leak into the page')
    # public_base captures og_title/og_description/og_image with
    # {% set %}…{% endset %}; written as bare blocks their default values would
    # print into <head> as loose text. Look for exactly that: a text node in
    # <head> (outside script/style) carrying one of those values.
    from bs4 import BeautifulSoup
    html = c.get(f'/guides/{ids["guide"]}').get_data(as_text=True)
    head = BeautifulSoup(html, 'html.parser').head
    for junk in head.find_all(['script', 'style', 'title']):
        junk.decompose()
    loose = ' '.join(head.get_text().split())
    check(f'no loose text between the head tags ({loose[:60]!r})', loose == '')
    check('and the title tag is still just the title',
          '<title>Swerve drive — Team Site</title>' in html)

    print('\n[5] a page with no picture degrades cleanly')
    with app.app_context():
        g = main.Guide.query.filter_by(slug=ids['guide']).first()
        g.cover_image_url = None
        db.session.commit()
    html = c.get(f'/guides/{ids["guide"]}').get_data(as_text=True)
    check('no og:image tag at all rather than an empty one',
          meta(html, 'og:image') is None)
    check(f'and the card drops to summary ({meta(html, "twitter:card")!r})',
          meta(html, 'twitter:card') == 'summary')
    check('the title still describes the guide',
          meta(html, 'og:title') == 'Swerve drive')

    print('\n[6] absolute_url refuses to guess')
    with app.test_request_context('https://team.example.org/guides/x'):
        check('a relative path picks up the live host',
              main.absolute_url('/static/a.png') == 'https://team.example.org/static/a.png')
        check('an already-absolute URL is passed through',
              main.absolute_url('https://cdn.example.com/a.png') == 'https://cdn.example.com/a.png')
        check('a bare filename is dropped, not glued on',
              main.absolute_url('a.png') == '')
        check('and empty stays empty', main.absolute_url(None) == '')

    print('\n[7] the bind address never becomes a link')
    # This is the reported bug: browsing the address the server LISTENS on put
    # http://0.0.0.0:5772/... into notifications, which opens for nobody.
    check('0.0.0.0 is refused', main._is_unreachable_host('http://0.0.0.0:5772/') is True)
    check('so is a bare ::', main._is_unreachable_host('http://[::]:5772/') is True)
    check('a real domain is fine', main._is_unreachable_host('https://team.example.org') is False)
    check('localhost is left alone — it works for whoever is running it',
          main._is_unreachable_host('http://localhost:5772/') is False)
    with app.test_request_context('http://0.0.0.0:5772/guides/x'):
        check('a request arriving on the bind address yields no base, not a broken one',
              main._site_external_base(None) == '')
        check('so a relative image is dropped rather than made unopenable',
              main.absolute_url('/static/a.png') == '')

    print('\n[8] the configured public address wins over the request host')
    with app.app_context():
        anchor = main.get_main_admin()
        anchor.public_base_url = 'https://team.example.org'
        db.session.commit()
    with app.test_request_context('http://0.0.0.0:5772/guides/x'):
        check(f'the setting overrides a useless host ({main._site_external_base(None)})',
              main._site_external_base(None) == 'https://team.example.org')
        check('and images are built from it',
              main.absolute_url('/static/a.png') == 'https://team.example.org/static/a.png')
    with app.test_request_context('http://some-internal-proxy:8080/guides/x'):
        check('it also overrides a proxy-internal host',
              main._site_external_base(None) == 'https://team.example.org')
    # Background senders have no request at all — this is the scheduler case.
    with app.app_context():
        check('and it works with no request context whatsoever',
              main._site_external_base(None) == 'https://team.example.org')

    print('\n[9] saving the address normalises and validates it')
    c2 = app.test_client()
    with app.app_context():
        owner = main.User.query.filter_by(username='owner').first()
        oid = owner.id
    with c2.session_transaction() as s:
        s['_user_id'] = str(oid)
        s['_fresh'] = True
        s['admin_website_id'] = ids['site']
    r = c2.post('/admin/settings/public-base-url',
                data={'public_base_url': 'team.example.org/some/path/'})
    check(f'a bare host gains https and loses the path ({r.get_json()})',
          r.get_json().get('public_base_url') == 'https://team.example.org')
    r = c2.post('/admin/settings/public-base-url',
                data={'public_base_url': 'http://0.0.0.0:5772'})
    check(f'the bind address is rejected with a reason ({r.get_json().get("error", "")[:40]!r})',
          not r.get_json().get('success'))
    r = c2.post('/admin/settings/public-base-url', data={'public_base_url': ''})
    check('and it can be cleared', r.get_json().get('success')
          and r.get_json().get('public_base_url') == '')


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
