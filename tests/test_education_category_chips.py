"""The Education page can be narrowed to one category, per tab.

    venv/bin/python tests/test_education_category_chips.py

Mirrors the role/division chips on the members directory: one tap to cut a long
list down to what you came for. Everything on this page is already grouped by
category and the tabs already switch client-side, so the filtering is local —
no reload, nothing to fetch.

What the server has to get right is that every chip addresses a section that
exists, and that a page with nothing to choose between does not grow a filter.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-edu-chips')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-edu-test-')
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


def fresh_site():
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
        site = main.Website(user_id=owner.id, name='Site', is_draft=False, is_live=True)
        db.session.add(site)
        db.session.commit()
        db.session.add(main.PublicPageContent(website_id=site.id, name='H', slug='home',
                                              site_active_status=True))
        db.session.commit()
        return site.id


def soup_for_page():
    from bs4 import BeautifulSoup
    c = app.test_client()
    r = c.get('/guides')
    assert r.status_code == 200, r.status_code
    return BeautifulSoup(r.get_data(as_text=True), 'html.parser')


def panel_of(soup, tab):
    return soup.select_one(f'.gi-tab-panel[data-tab="{tab}"]')


def main_test():
    print('\n[1] several categories: a chip each, and every chip has a section')
    site_id = fresh_site()
    with app.app_context():
        gc1 = main.GuideCategory(website_id=site_id, name='Mechanical', slug='mech',
                                 icon='fa-gear', color='#5eeef8')
        gc2 = main.GuideCategory(website_id=site_id, name='Software', slug='soft')
        qc1 = main.QuizCategory(website_id=site_id, name='Safety', slug='safety')
        qc2 = main.QuizCategory(website_id=site_id, name='Theory', slug='theory')
        rc1 = main.ResourceCategory(website_id=site_id, name='Forms', slug='forms')
        rc2 = main.ResourceCategory(website_id=site_id, name='Manuals', slug='manuals')
        db.session.add_all([gc1, gc2, qc1, qc2, rc1, rc2])
        db.session.commit()
        for i, cat in enumerate([gc1, gc2]):
            db.session.add(main.Guide(website_id=site_id, title=f'G{i}', slug=f'g{i}',
                                      status='published', category_id=cat.id))
        for i, cat in enumerate([qc1, qc2]):
            db.session.add(main.Quiz(website_id=site_id, title=f'Q{i}',
                                     category_id=cat.id, is_public=True))
        for i, cat in enumerate([rc1, rc2]):
            db.session.add(main.Resource(website_id=site_id, title=f'R{i}',
                                         resource_type='link', url='http://x',
                                         category_id=cat.id, is_public=True))
        db.session.commit()

    soup = soup_for_page()
    for tab, expected in (('guides', ['Mechanical', 'Software']),
                          ('quizzes', ['Safety', 'Theory']),
                          ('resources', ['Forms', 'Manuals'])):
        panel = panel_of(soup, tab)
        check(f'{tab}: the tab exists', panel is not None)
        if not panel:
            continue
        chips = panel.select('.gi-chip')
        labels = [c.get_text(strip=True) for c in chips]
        check(f'{tab}: All plus one chip per category ({labels})',
              labels == ['All'] + expected)

        chip_cats = {c.get('data-cat') for c in chips if c.get('data-cat') != 'all'}
        sec_cats = {s.get('data-cat') for s in panel.select('.gi-section[data-cat]')}
        check(f'{tab}: every chip points at a section that exists',
              chip_cats and chip_cats <= sec_cats)
        check(f'{tab}: and every section can be reached by a chip',
              sec_cats <= chip_cats)
        check(f'{tab}: "All" starts selected', 'is-active' in (chips[0].get('class') or []))

    check('the category icon travels onto its chip',
          panel_of(soup, 'guides').select_one('.gi-chip[data-cat] i.fa-gear') is not None)
    check("and the category's colour",
          '#5eeef8' in (panel_of(soup, 'guides').select('.gi-chip')[1].get('style') or ''))

    print('\n[2] one category is nothing to choose between')
    site_id = fresh_site()
    with app.app_context():
        only = main.GuideCategory(website_id=site_id, name='Only', slug='only')
        db.session.add(only)
        db.session.commit()
        db.session.add(main.Guide(website_id=site_id, title='G', slug='g',
                                  status='published', category_id=only.id))
        db.session.commit()
    soup = soup_for_page()
    check('no chip bar is rendered for a single category',
          panel_of(soup, 'guides').select_one('.gi-catbar') is None)

    print('\n[3] uncategorized is a category you can pick')
    site_id = fresh_site()
    with app.app_context():
        cat = main.GuideCategory(website_id=site_id, name='Mechanical', slug='mech')
        db.session.add(cat)
        db.session.commit()
        db.session.add(main.Guide(website_id=site_id, title='In a category', slug='a',
                                  status='published', category_id=cat.id))
        db.session.add(main.Guide(website_id=site_id, title='Loose', slug='b',
                                  status='published'))
        db.session.commit()
    soup = soup_for_page()
    panel = panel_of(soup, 'guides')
    labels = [c.get_text(strip=True) for c in panel.select('.gi-chip')]
    check(f'it gets its own chip ({labels})', 'Uncategorized' in labels)
    check('addressed as "none"',
          any(c.get('data-cat') == 'none' for c in panel.select('.gi-chip')))
    check('and its section is tagged to match',
          any(s.get('data-cat') == 'none' for s in panel.select('.gi-section[data-cat]')))

    print('\n[4] the filter is wired to the page')
    check('the chips call the filter', 'giFilterCategory' in str(soup))
    check('which is defined', 'function giFilterCategory' in str(soup))


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
