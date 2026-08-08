"""A dropdown whose title is also a link looks and behaves like one that isn't.

    venv/bin/python tests/test_navbar_group_link_parity.py

Two variants render the group label: <button> when the group has no URL, and
<a class="public-navbar-group-link"> when it does. Several rules named only the
button, so the linked variant lost the active-state treatment (colour, weight,
and the underline drawn by ::after) and sat misaligned inside the More menu.

Behaviour: the label and the chevron used to be one target, so on a linked
group there was no way to open the menu without navigating away — the side
panel and the More menu both worked around it by swallowing the first tap,
which meant the link itself needed two. The chevron is now its own control:
title navigates, arrow opens and closes.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import os
import re
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-navbar-parity')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-parity-test-')
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
_NAVBAR = os.path.join(_REPO, 'Templates', 'components', 'public_navbar.html')


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
        site = main.Website(user_id=owner.id, name='Site', is_draft=False,
                            is_live=True, store_enabled=True, forum_enabled=True)
        db.session.add(site)
        db.session.commit()
        db.session.add(main.PublicPageContent(website_id=site.id, name='Home',
                                              slug='home', site_active_status=True))
        # One of each variant, and the linked one is the active page so the
        # active-state rules are the ones under test.
        # /home, not /: the home page's current_page_url is url_for(
        # 'public_page_by_slug', page_slug='home'), and the active check
        # compares against exactly that.
        site.public_navbar_items = [
            {'type': 'group', 'name': 'Linked', 'url': '/home', 'children': [
                {'type': 'link', 'name': 'Team', 'url': '/team'}]},
            {'type': 'group', 'name': 'Plain', 'url': '', 'children': [
                {'type': 'link', 'name': 'Docs', 'url': '/docs'}]},
        ]
        db.session.commit()


def _render_mode(mode):
    """Render the home page with the navbar in one of its dropdown modes.

    Neither group points at the current page here. The active state legitimately
    changes colour and weight, so leaving one group active would show up as a
    variant difference when it is nothing of the kind.
    """
    with app.app_context():
        site = main.Website.query.first()
        style = dict(site.public_navbar_style or {})
        style['dropdown_mode'] = mode
        site.public_navbar_style = style
        site.public_navbar_items = [
            {'type': 'group', 'name': 'Linked', 'url': '/elsewhere', 'children': [
                {'type': 'link', 'name': 'Team', 'url': '/team'}]},
            {'type': 'group', 'name': 'Plain', 'url': '', 'children': [
                {'type': 'link', 'name': 'Docs', 'url': '/docs'}]},
        ]
        db.session.commit()
    with app.test_client() as c:
        return c.get('/').get_data(as_text=True)


def _css_rules():
    """(selector, specificity, source order, declarations) for the navbar CSS.

    Pseudo-class/element rules are skipped — soupsieve can't match :hover, and
    the base state is what the two variants must agree on.
    """
    raw = open(_NAVBAR).read()
    css = '\n'.join(re.findall(r'<style[^>]*>(.*?)</style>', raw, re.S))
    css = re.sub(r'/\*.*?\*/', '', css, flags=re.S)
    out = []
    for i, m in enumerate(re.finditer(r'([^{}]+)\{([^{}]*)\}', css)):
        group, body = m.group(1).strip(), m.group(2)
        if not group or '@' in group:
            continue
        for sel in group.split(','):
            sel = ' '.join(sel.split())
            if not sel or '::' in sel or ':hover' in sel or ':focus' in sel:
                continue
            decls = {}
            for d in body.split(';'):
                if ':' in d:
                    k, v = d.split(':', 1)
                    decls[k.strip()] = v.strip()
            if not decls:
                continue
            bare = re.sub(r'::?[a-z-]+(\([^)]*\))?', '', sel)
            spec = (bare.count('#'),
                    len(re.findall(r'\.|\[', bare)),
                    len(re.findall(r'(?:^|[\s>+~])([a-z]+)', bare)))
            out.append((sel, spec, i, decls))
    return out


_RULES = None


def _winning_decls(soup, el):
    """The declarations that actually win on this element, by the cascade."""
    global _RULES
    if _RULES is None:
        _RULES = _css_rules()
    best = {}
    for sel, spec, order, decls in _RULES:
        try:
            if el not in soup.select(sel):
                continue
        except Exception:
            continue
        for k, v in decls.items():
            key = ('!important' in v, spec, order)
            if k not in best or key > best[k][0]:
                best[k] = (key, v)
    return {k: v for k, (_, v) in best.items()}


def main_test():
    setup()
    with app.test_client() as c:
        r = c.get('/')
        html = r.get_data(as_text=True)
    check('the page renders', r.status_code == 200)

    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')
    groups = soup.select('.public-navbar-right > .public-navbar-dropdown')
    labels = [g.find(['a', 'button'], recursive=False) for g in groups]
    labels = [l for l in labels if l and l.select_one('.public-navbar-group-chevron')]

    print('\n[1] both variants are on the page')
    kinds = sorted(l.name for l in labels)
    check(f'one <a> group and one <button> group ({kinds})', kinds == ['a', 'button'])

    linked = next((l for l in labels if l.name == 'a'), None)
    plain = next((l for l in labels if l.name == 'button'), None)

    print('\n[2] the linked variant is marked active like the plain one would be')
    check('the linked group is the active one here',
          linked is not None and 'active-navbar-link' in (linked.get('class') or []))
    check('its wrapper carries active-navbar-dropdown',
          linked is not None
          and 'active-navbar-dropdown' in (linked.parent.get('class') or []))

    print('\n[3] every group-label rule covers both variants')
    css = open(_NAVBAR).read()
    gaps = []
    for m in re.finditer(r'([^{}]+)\{([^{}]*)\}', css):
        sel = ' '.join(m.group(1).split())
        if len(sel) > 300:
            continue
        parts = [s.strip() for s in sel.split(',')]
        # Rules that style a group label specifically: a direct-child <button>
        # of a dropdown. Each needs its a.public-navbar-group-link twin.
        if not any(re.search(r'\.public-navbar-dropdown[^,]*>\s*button', p) for p in parts):
            continue
        if not any('public-navbar-group-link' in p for p in parts):
            gaps.append((css[:m.start()].count('\n') + 1, sel[:90]))
    for line, sel in gaps:
        print(f'         button-only rule at line {line}: {sel}')
    check('no rule styles only the button variant', not gaps)

    print('\n[4] the chevron is its own control')
    check('both labels contain a chevron span',
          linked is not None and plain is not None
          and linked.select_one('.public-navbar-group-chevron') is not None
          and plain.select_one('.public-navbar-group-chevron') is not None)
    check('a capture-phase handler claims chevron clicks',
          'initPublicNavbarChevrons' in css
          and "closest(\n                '.public-navbar-group-chevron" in css
          or '.public-navbar-group-chevron, .public-navbar-menu-group-chevron' in css)
    check('is-open beats hover so a tap can hold the menu open',
          '.public-navbar-dropdown.is-open > .public-navbar-dropdown-menu' in css)
    check('is-closed suppresses hover so the arrow can shut it again',
          '.public-navbar-dropdown.is-closed:hover > .public-navbar-dropdown-menu' in css)

    print('\n[5] the two variants compute to the same layout in every mode')
    # Selector-string checks miss this entirely: the linked toggle lost to
    # `.public-navbar-menu a` (0,1,1) beating `.public-navbar-menu-group-toggle`
    # (0,1,0) and fell back to display:block, so justify-content had nothing to
    # do and the chevron sat beside the title instead of at the end of the line.
    # The parity override existed but was scoped to side_panel mode only.
    for mode in ('dropdown', 'side_panel'):
        soup_m = BeautifulSoup(_render_mode(mode), 'html.parser')
        for where, sel_a, sel_b in (
            ('collapsed menu',
             '.public-navbar-menu .public-navbar-menu-group-toggle.public-navbar-menu-group-link',
             '.public-navbar-menu button.public-navbar-menu-group-toggle'),
            ('top bar',
             '.public-navbar-right > .public-navbar-dropdown > a.public-navbar-group-link',
             '.public-navbar-right > .public-navbar-dropdown > button'),
        ):
            a_el, b_el = soup_m.select(sel_a), soup_m.select(sel_b)
            if not a_el or not b_el:
                check(f'{mode}/{where}: both variants present', False)
                continue
            wa, wb = _winning_decls(soup_m, a_el[0]), _winning_decls(soup_m, b_el[0])
            # Colour and opacity legitimately differ when one group is active;
            # everything about the shape of the row must not.
            layout = ['display', 'justify-content', 'align-items', 'padding',
                      'border-radius', 'font-size', 'font-weight', 'letter-spacing',
                      'text-transform', 'width', 'gap']
            diff = [(k, wa.get(k), wb.get(k)) for k in layout if wa.get(k) != wb.get(k)]
            for k, x, y in diff:
                print(f'         {k}: link={x!r} button={y!r}')
            check(f'{mode}/{where}: identical layout ({len(diff)} diffs)', not diff)
            if where == 'collapsed menu':
                check(f'{mode}/{where}: the arrow is pushed to the end of the line',
                      wa.get('display') == 'flex'
                      and wa.get('justify-content') == 'space-between')

    print('\n[6] a linked title navigates on the first click')
    # Both group handlers used to swallow it to expand instead.
    check('the side-panel toggle returns early for links',
          re.search(r'if \(isLink\) return;\s*//\s*let the browser follow href', css)
          is not None)
    check('the first-tap-swallow is gone from the side panel',
          'swallow the first tap' not in css)
    check('and from the More menu',
          'First tap on a link-style group expands' not in css)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
