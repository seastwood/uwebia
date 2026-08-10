"""Every font and size in the toolbar dropdowns is labelled and distinguishable.

    venv/bin/python tests/test_quill_font_size_pickers.py

Quill's snow theme labels these two pickers with a catch-all:

    .ql-picker.ql-font .ql-picker-item::before { content: 'Sans Serif'; }
    .ql-picker.ql-size .ql-picker-item::before { content: 'Normal'; }

and overrides it only for the values IT ships. Point a picker at a custom
whitelist and every entry inherits the catch-all, measured in a browser:

    before: 7x "Sans Serif" (all in Helvetica Neue), 14x "Normal"
    after:  Arial / Georgia / Times New Roman / ... each in its own typeface,
            10 / 12 / 14 / ...

The post editor carried the per-value rules inline; the guide and newsletter
editors never got a copy, so their dropdowns were seven identical rows. The
quiz editor had no font or size picker at all.

The rules now live in one stylesheet all four editors link. The check that
matters most is the last one: every value an editor registers with Quill must
have a rule, or the catch-all silently comes back for it.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSS_PATH = os.path.join(_REPO, 'static', 'css', 'quill_pickers.css')
EDITORS = ['post_editor', 'guide_editor', 'quiz_editor', 'newsletter_campaign_editor']

FAILURES = []
SKIPPED = []


def check(label, cond):
    print(('  PASS  ' if cond else '  FAIL  ') + label)
    if not cond:
        FAILURES.append(label)


def skip(label, why):
    print(f'  SKIP  {label} — {why}')
    SKIPPED.append(label)


def _tpl(name):
    return open(os.path.join(_REPO, 'Templates', f'{name}.html')).read()


def _css():
    return open(CSS_PATH).read()


def _arrays(src):
    """The FONTS and SIZES an editor registers with Quill."""
    def grab(name):
        m = re.search(name + r"\s*=\s*\[([^\]]*)\]", src)
        return [v.strip().strip("'\"") for v in m.group(1).split(',') if v.strip()] if m else []
    return grab('FONTS'), grab('SIZES')


def test_shared_sheet():
    print('\n[1] one stylesheet, linked by every editor that has the pickers')
    check('the shared stylesheet exists', os.path.exists(CSS_PATH))
    for name in EDITORS:
        src = _tpl(name)
        check(f'{name} links it',
              "css/quill_pickers.css" in src)
        # Order matters: these rules have to win over Quill's catch-all, and
        # they have the same specificity, so they must come after it.
        if 'quill_pickers.css' in src and 'quill.snow.css' in src:
            check(f'{name} loads it after quill.snow.css',
                  src.index('quill_pickers.css') > src.index('quill.snow.css'))
    for name in EDITORS:
        src = _tpl(name)
        check(f'{name} no longer carries its own copy',
              'ql-picker.ql-font .ql-picker-item' not in src
              and 'ql-picker.ql-size .ql-picker-item' not in src)


def test_every_value_labelled():
    print('\n[2] every value an editor offers has a rule of its own')
    # The one that actually prevents a repeat: adding a font to FONTS without
    # adding a rule here puts the catch-all back for that entry.
    css = _css()
    for name in EDITORS:
        fonts, sizes = _arrays(_tpl(name))
        if not fonts and not sizes:
            check(f'{name}: offers no font/size picker (nothing to label)',
                  "{ 'font':" not in _tpl(name) and "{ 'size':" not in _tpl(name))
            continue
        missing_f = [f for f in fonts
                     if f'.ql-picker.ql-font .ql-picker-item[data-value="{f}"]::before' not in css]
        missing_s = [s for s in sizes
                     if f'.ql-picker.ql-size .ql-picker-item[data-value="{s}"]::before' not in css]
        check(f'{name}: all {len(fonts)} fonts are labelled'
              + (f' — missing {missing_f}' if missing_f else ''), not missing_f)
        check(f'{name}: all {len(sizes)} sizes are labelled'
              + (f' — missing {missing_s}' if missing_s else ''), not missing_s)

    print('\n[3] and the fonts are shown in their own typeface')
    fonts, _ = _arrays(_tpl('post_editor'))
    for f in fonts:
        rule = re.search(
            re.escape(f'.ql-picker.ql-font .ql-picker-item[data-value="{f}"]::before')
            + r'\s*\{([^}]*)\}', css)
        check(f'{f} carries a font-family',
              bool(rule) and 'font-family' in rule.group(1))
    labels = re.findall(r'\.ql-picker\.ql-font \.ql-picker-item\[data-value="[^"]+"\]::before\s*\{[^}]*'
                        r"content:\s*'([^']*)'", css)
    check(f'and every label is distinct ({len(set(labels))} of {len(labels)})',
          len(set(labels)) == len(labels) and len(labels) >= 7)
    size_labels = re.findall(r'\.ql-picker\.ql-size \.ql-picker-item\[data-value="[^"]+"\]::before\s*\{[^}]*'
                             r"content:\s*'([^']*)'", css)
    check(f'sizes likewise ({len(set(size_labels))} of {len(size_labels)})',
          len(set(size_labels)) == len(size_labels) and len(size_labels) >= 14)


def test_quiz_has_pickers():
    print('\n[4] the quiz editor now has the pickers at all')
    src = _tpl('quiz_editor')
    check("its toolbar offers a font picker", "{ 'font': FONTS }" in src)
    check("and a size picker", "{ 'size': SIZES }" in src)
    check('with the style attributors registered, so choices store as inline '
          'style and need no class on the public side',
          "attributors/style/font" in src and "attributors/style/size" in src)
    fonts, sizes = _arrays(src)
    pf, ps = _arrays(_tpl('post_editor'))
    check(f'the same fonts as posts ({len(fonts)})', fonts == pf and fonts)
    check(f'the same sizes as posts ({len(sizes)})', sizes == ps and sizes)


def _chrome():
    for exe in ('google-chrome', 'chromium', 'chromium-browser'):
        p = shutil.which(exe)
        if p:
            return p
    return None


def test_rendered():
    print('\n[5] and a real browser reads them as distinct')
    chrome = _chrome()
    if not chrome:
        skip('rendered dropdown check', 'no Chrome/Chromium on PATH')
        return
    cache = os.path.join(tempfile.gettempdir(), 'uwebia-quill-assets')
    os.makedirs(cache, exist_ok=True)
    assets = {
        'quill.min.js': 'https://cdn.jsdelivr.net/npm/quill@1.3.6/dist/quill.min.js',
        'quill.snow.css': 'https://cdn.jsdelivr.net/npm/quill@1.3.6/dist/quill.snow.css',
    }
    for fname, url in assets.items():
        dest = os.path.join(cache, fname)
        if not os.path.exists(dest):
            try:
                subprocess.run(['curl', '-sSLf', url, '-o', dest], check=True, timeout=60)
            except Exception:
                skip('rendered dropdown check', f'could not fetch {fname}')
                return

    work = tempfile.mkdtemp(prefix='uwebia-quill-probe-')
    for fname in assets:
        shutil.copy2(os.path.join(cache, fname), work)
    shutil.copy2(CSS_PATH, work)
    fonts, sizes = _arrays(_tpl('post_editor'))

    page = """<!doctype html><html><head><meta charset=utf-8>
<link rel="stylesheet" href="quill.snow.css">
<link rel="stylesheet" href="quill_pickers.css">
</head><body><div id="ed"></div>
<script src="quill.min.js"></script>
<script>
var FONTS = %s, SIZES = %s;
var F = Quill.import('attributors/style/font'); F.whitelist = null; Quill.register(F, true);
var S = Quill.import('attributors/style/size'); S.whitelist = SIZES; Quill.register(S, true);
new Quill('#ed', { theme:'snow', modules:{ toolbar:[[{'font':FONTS},{'size':SIZES}]] } });
window.addEventListener('load', function(){
  function read(sel){ return [].map.call(document.querySelectorAll(sel), function(el){
    var cs = getComputedStyle(el, '::before');
    return { label:(cs.content||'').replace(/^"|"$/g,''),
             font:(cs.fontFamily||'').split(',')[0].replace(/["']/g,'') }; }); }
  var f = read('.ql-picker.ql-font .ql-picker-item'),
      s = read('.ql-picker.ql-size .ql-picker-item');
  var d = document.createElement('div');
  d.textContent = 'RESULT ' + JSON.stringify({
    fontLabels: f.map(function(x){return x.label;}),
    fontFaces:  f.map(function(x){return x.font;}),
    sizeLabels: s.map(function(x){return x.label;}) });
  document.body.appendChild(d);
});
</script></body></html>""" % (repr(fonts).replace("'", '"'), repr(sizes).replace("'", '"'))
    path = os.path.join(work, 'probe.html')
    with open(path, 'w') as fh:
        fh.write(page)

    out = subprocess.run(
        [chrome, '--headless=new', '--disable-gpu', '--no-sandbox',
         f'--user-data-dir={os.path.join(work, "profile")}',
         '--virtual-time-budget=4000', '--window-size=1200,800',
         '--dump-dom', f'file://{path}'],
        capture_output=True, text=True, timeout=120).stdout
    m = re.search(r'RESULT (\{.*?\})</div>', out, re.S) or re.search(r'RESULT (\{.*?\})', out)
    if not m:
        skip('rendered dropdown check', 'browser produced no measurement')
        return
    import json
    r = json.loads(m.group(1))

    check(f'every font row reads differently ({r["fontLabels"]})',
          len(set(r['fontLabels'])) == len(fonts))
    check('none of them still say "Sans Serif"',
          'Sans Serif' not in r['fontLabels'])
    check(f'and each is drawn in its own typeface ({len(set(r["fontFaces"]))} distinct)',
          len(set(r['fontFaces'])) == len(fonts))
    check(f'every size row reads differently ({r["sizeLabels"]})',
          len(set(r['sizeLabels'])) == len(sizes))
    check('none of them still say "Normal"', 'Normal' not in r['sizeLabels'])


if __name__ == '__main__':
    test_shared_sheet()
    test_every_value_labelled()
    test_quiz_has_pickers()
    test_rendered()
    tail = f' ({len(SKIPPED)} skipped)' if SKIPPED else ''
    print('\n' + (f'ALL PASSED{tail}' if not FAILURES
                  else f'{len(FAILURES)} FAILED{tail}: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
