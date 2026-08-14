"""Every navbar item you can drag actually moves — inline and collapsed.

    venv/bin/python tests/test_navbar_order_applied.py

Reported: putting Notifications at a chosen position did nothing, and the
order was ignored once the bar collapsed into the hamburger.

The order is applied as CSS `order` on flex children, and there were two
separate reasons an item could be dragged and not move:

  * the dropdown was `display:block`, where `order` means nothing — so any
    order was lost the moment the bar collapsed into the hamburger;
  * Notifications, External Drives, AI Agents and Plugins had NO inline icon
    at all. They lived only inside the hamburger, which is pinned to the end
    of the bar. Ordering them within the dropdown is not what "put this second
    in the navbar" means, so fixing only the first reason still looked broken.

They now have inline counterparts, and the dropdown keeps `--responsive`
copies for compact mode. Messages is the one genuine exception: it sits in
`.nav-right` beside the profile menu, so it is marked non-draggable rather
than offered and ignored.

So this pins down: every key the settings page lets you drag is a key the
navbar actually honours; a configured item takes its slot in the visible bar
AND in the collapsed dropdown; and the pieces that must stay put (scroll cues,
Trash) still do.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import re
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-navbar-order')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-navorder-test-')
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

# Notifications first — the reported case — then a couple of others moved so
# the assertions can't pass by coincidence of the default order.
ORDER = ['notifications', 'reviews', 'posts', 'plugins', 'education',
         'storage', 'calendars', 'ai_agents', 'forum', 'newsletters',
         'store', 'palette']


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

        owner = main.User(username='owner', parent_user_id=None,
                          admin_navbar_order=ORDER, admin_navbar_disabled=[])
        owner.set_password('ownerpassword')
        db.session.add(owner)
        db.session.commit()
        site = main.Website(user_id=owner.id, name='Site', is_draft=False, is_live=True)
        db.session.add(site)
        db.session.commit()
        return dict(owner=owner.id, site=site.id)


def main_test():
    app.config['WTF_CSRF_ENABLED'] = False
    ids = setup()
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(ids['owner'])
        s['_fresh'] = True
        s['admin_website_id'] = ids['site']
    html = c.get('/admin/dashboard').get_data(as_text=True)
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')

    def order_of(el):
        m = re.search(r'order:\s*(-?\d+)', el.get('style') or '')
        return int(m.group(1)) if m else None

    print('\n[1] the dropdown can order at all')
    css = open(os.path.join(_REPO, 'static', 'css', 'navbar.css')).read()
    block = css[css.index('.nav-tools-dropdown.open .nav-tools-dropdown-content'):]
    block = block[:block.index('}')]
    check('the open dropdown is a flex column, not a block',
          'display: flex' in block and 'flex-direction: column' in block)

    print('\n[2] the reported case: Notifications is placed where you put it')
    drop = soup.select_one('#navToolsDropdownContent')
    check('the dropdown rendered', drop is not None)
    notif = drop.select_one('a[href*="/admin/notifications"]')
    check('Notifications is in it', notif is not None)
    check(f'and carries the configured order ({order_of(notif)})',
          order_of(notif) == ORDER.index('notifications'))

    print('\n[2b] …and takes that slot in the VISIBLE bar, not just the dropdown')
    # The first fix ordered the dropdown but left Notifications with no inline
    # icon at all, so "move it to second" still moved nothing on screen: the
    # hamburger it lived in is pinned to the end of the bar.
    inline = soup.select_one('#navInlineItems')
    inline_notif = inline.select_one('a[href*="/admin/notifications"]')
    check('Notifications has an inline icon at all', inline_notif is not None)
    check(f'in the configured slot ({order_of(inline_notif) if inline_notif else None})',
          inline_notif is not None and order_of(inline_notif) == ORDER.index('notifications'))
    # Ordering is only meaningful if the bar is one flex run — an item in a
    # different container can't interleave with the rest however it's ordered.
    seq = sorted((order_of(e), e.get('title'))
                 for e in inline.select(':scope > [style*="order:"]')
                 if order_of(e) is not None)
    check(f'and it sorts to the front of the bar ({[t for _, t in seq[:3]]})',
          seq and seq[0][1] == 'Notifications')
    check('every configured key that has an inline icon is a direct child',
          len(seq) >= 10)

    print('\n[3] every draggable key is honoured somewhere')
    settings_src = open(os.path.join(_REPO, 'Templates', 'settings.html')).read()
    defs = settings_src[settings_src.index("{% set _defs = ["):]
    defs = defs[:defs.index('] %}')]
    offered = set(re.findall(r"'key':'([a-z_]+)'", defs))
    fixed = set(re.findall(r"'key':'([a-z_]+)'[^}]*'fixed': True", defs))
    draggable = offered - fixed
    navbar_src = open(os.path.join(_REPO, 'Templates', 'components', 'navbar.html')).read()
    honoured = set(re.findall(r"_ord\('([a-z_]+)'\)", navbar_src))
    missing = draggable - honoured
    check(f'nothing is draggable but ignored ({sorted(missing) if missing else "none"})',
          not missing)
    check(f'Messages is marked fixed instead of pretending ({sorted(fixed)})',
          fixed == {'messages'})
    check('and gets no drag handle',
          'nav-vis-row--fixed' in settings_src
          and ':not(.nav-vis-row--fixed)' in settings_src)

    print('\n[4] the collapsed dropdown follows the same sequence')
    # Compact mode is pure CSS, so the rendered orders are what decide it.
    seen = []
    for el in drop.select('[style*="order:"]'):
        o = order_of(el)
        if o is not None and o < 900:
            seen.append(o)
    check(f'dropdown items carry real orders ({len(seen)} of them)', len(seen) >= 8)
    check('and they are the configured ones, not source order',
          seen != sorted(seen) or len(set(seen)) == len(seen))
    inline_orders = {}
    for el in inline.select('[style*="order:"]'):
        href = el.get('href') or (el.select_one('a[href]') or {}).get('href', '')
        o = order_of(el)
        if o is not None and o < 900:
            inline_orders[href] = o
    check(f'inline items are ordered too ({len(inline_orders)})', len(inline_orders) >= 5)

    print('\n[5] the things that must stay put still do')
    # Trash used to be hard-pinned with order:8000. It is placeable now, so
    # what must hold is that it is ordered like everything else and still
    # anchors the bottom of the menu while it lives there.
    check('Trash is ordered like any other item', "_ord('trash')" in navbar_src)
    check('and keeps its separator only while it anchors the menu',
          "{% if 'trash' in _pin %} nav-tools-item--last{% endif %}" in navbar_src)
    check('the scroll cues sit outside the ordering',
          '.nav-tools-scroll-cue--top    { order: -9999; }' in css
          and '.nav-tools-scroll-cue--bottom { order: 9999; }' in css)

    print('\n[6] Colour Palette is reachable when the bar collapses')
    # It had no dropdown counterpart at all, so collapsing the bar hid it.
    pal = [b for b in drop.select('button') if 'Color Palette' in b.get_text()]
    check('it has a dropdown entry now', len(pal) == 1)
    check(f'ordered with everything else ({order_of(pal[0]) if pal else None})',
          pal and order_of(pal[0]) == ORDER.index('palette'))

    print('\n[7] an unconfigured item still lands after the configured ones')
    with app.app_context():
        owner = db.session.get(main.User, ids['owner'])
        owner.admin_navbar_order = ['notifications']
        db.session.commit()
    drop2 = BeautifulSoup(c.get('/admin/dashboard').get_data(as_text=True),
                          'html.parser').select_one('#navToolsDropdownContent')
    n2 = drop2.select_one('a[href*="/admin/notifications"]')
    check(f'the configured one is first ({order_of(n2)})', order_of(n2) == 0)
    others = [order_of(e) for e in drop2.select('[style*="order:"]')
              if order_of(e) is not None and order_of(e) != 0 and order_of(e) < 8000]
    check(f'the rest trail behind it ({sorted(set(others))[:3]})',
          others and all(o == 900 for o in others))


def placement_test():
    """Bar / hamburger / hidden — the three states an item can be in."""
    ids = setup()
    from bs4 import BeautifulSoup

    def render(pinned, order=None):
        with app.app_context():
            o = db.session.get(main.User, ids['owner'])
            o.admin_navbar_pinned = pinned
            if order is not None:
                o.admin_navbar_order = order
            db.session.commit()
        c = app.test_client()
        with c.session_transaction() as s2:
            s2['_user_id'] = str(ids['owner'])
            s2['_fresh'] = True
            s2['admin_website_id'] = ids['site']
        return BeautifulSoup(c.get('/admin/dashboard').get_data(as_text=True),
                             'html.parser')

    def where(soup, href):
        bar = soup.select_one('#navInlineItems')
        drop = soup.select_one('#navToolsDropdownContent')
        on_bar = bool(bar and bar.select_one(f'a[href*="{href}"]'))
        d = drop.select_one(f'a[href*="{href}"]') if drop else None
        return on_bar, (d.get('class') if d else None)

    print('\n[8] Trash is placeable now, and starts in the menu')
    # NULL means never configured — not the same as "nothing pinned".
    soup = render(None)
    on_bar, cls = where(soup, '/admin/trash')
    check(f'not on the bar by default ({on_bar})', on_bar is False)
    check(f'and sits in the menu permanently, not just when collapsed ({cls})',
          cls is not None and 'nav-tools-item--responsive' not in cls)

    print('\n[9] moving Trash to the bar takes it out of the pinned section')
    soup = render([], order=['trash', 'notifications'])
    on_bar, cls = where(soup, '/admin/trash')
    check(f'it has a bar icon ({on_bar})', on_bar is True)
    check(f'in the configured slot',
          soup.select_one('#navInlineItems a[href*="/admin/trash"]')
              .get('style', '').startswith('order:0'))
    check(f'and its menu copy is collapse-only again ({cls})',
          cls is not None and 'nav-tools-item--responsive' in cls)
    check('the separator above it is dropped once it is not the menu anchor',
          'nav-tools-item--last' not in (cls or []))

    print('\n[10] pinning an item keeps it in the menu whatever the width')
    soup = render(['notifications'])
    on_bar, cls = where(soup, '/admin/notifications')
    check(f'Notifications leaves the bar ({on_bar})', on_bar is False)
    check(f'and is always present in the menu ({cls})',
          cls is not None and 'nav-tools-item--responsive' not in cls)
    # Unpinned items must not be dragged along with it.
    r_bar, r_cls = where(soup, '/admin/reviews')
    check(f'Reviews stays on the bar ({r_bar})', r_bar is True)
    check(f'and its menu copy is still collapse-only ({r_cls})',
          r_cls is not None and 'nav-tools-item--responsive' in r_cls)

    print('\n[11] an empty menu hides the hamburger in expanded mode')
    soup = render([])
    dd = soup.select_one('.nav-tools-dropdown')
    check(f'nothing pinned → --no-pinned ({dd.get("class") if dd else None})',
          dd is not None and 'nav-tools-dropdown--no-pinned' in dd.get('class'))
    soup = render(['plugins'])
    dd = soup.select_one('.nav-tools-dropdown')
    check('something pinned → the hamburger shows',
          dd is not None and 'nav-tools-dropdown--no-pinned' not in dd.get('class'))

    print('\n[12] the setting round-trips through the save route')
    c = app.test_client()
    with c.session_transaction() as s2:
        s2['_user_id'] = str(ids['owner'])
        s2['_fresh'] = True
        s2['admin_website_id'] = ids['site']
    r = c.post('/admin/settings/navbar-visibility',
               json={'disabled': [], 'order': ['notifications', 'trash'],
                     'pinned': ['trash', 'bogus_key']})
    check(f'it saves ({r.status_code})', r.status_code == 200)
    with app.app_context():
        o = db.session.get(main.User, ids['owner'])
        check(f'unknown keys are dropped ({o.admin_navbar_pinned})',
              o.admin_navbar_pinned == ['trash'])
    # [] and None mean different things, so [] must survive as [].
    c.post('/admin/settings/navbar-visibility',
           json={'disabled': [], 'order': [], 'pinned': []})
    with app.app_context():
        o = db.session.get(main.User, ids['owner'])
        check(f'an empty list stays empty, not NULL ({o.admin_navbar_pinned!r})',
              o.admin_navbar_pinned == [])

    print('\n[13] the settings page offers both zones')
    r = c.get('/admin/dashboard/settings')
    check(f'the settings page renders ({r.status_code})', r.status_code == 200)
    html = r.get_data(as_text=True)
    soup = BeautifulSoup(html, 'html.parser')
    check('there is a bar zone', soup.select_one('#navZoneBar') is not None)
    check('there is a menu zone', soup.select_one('#navZoneMenu') is not None)
    rows = soup.select('#navZoneBar > [data-navkey]')
    keys = [r.get('data-navkey') for r in rows]
    check(f'Trash is listed ({"trash" in keys})', 'trash' in keys)
    check('Trash has no visibility tick — it cannot be hidden',
          soup.select_one('[data-navkey="trash"] .nav-vis-check') is None)
    src = open(os.path.join(_REPO, 'Templates', 'settings.html')).read()
    check('both zones share one Sortable group so rows can cross',
          "group: 'navPlacement'" in src)
    check('and the save posts the placement', "pinned })" in src or 'pinned }' in src)


if __name__ == '__main__':
    main_test()
    placement_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
