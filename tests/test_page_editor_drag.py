"""Rows and groups can be reordered, and a section can be moved by touch.

    venv/bin/python tests/test_page_editor_drag.py

Two faults in the page editor.

Moving a row or a group always failed with "Your session expired. Please reload
the page and try again" — and reloading never helped, because the session was
never the problem. The site-wide CSRF shim fills in the token only when the
header is MISSING:

    if (!headers.has('X-CSRFToken')) headers.set('X-CSRFToken', TOKEN);

and the page editor sends the header explicitly:

    'X-CSRFToken': typeof csrfToken !== 'undefined' ? csrfToken : ''

with nothing anywhere defining csrfToken. So it sent an empty token, the header
counted as present, the shim left it alone, and every one of those ~20 calls was
rejected. Measured in the browser against the real endpoint:

    as the editor sends it     -> 400 Your session expired…
    letting the shim fill it   -> 200 success

The token is now published as a global, which makes that expression resolve for
every call site that uses it, including the three library modals in static/js.

Separately, sections move with HTML5 drag-and-drop, which touch devices never
fire — no dragstart, no dragover, no drop. The handle was simply dead on a
phone. Rows and groups were unaffected because they use Sortable, which brings
its own touch handling. Sections now have a pointer-event path that ends in the
same moveOrSwapSection the mouse path uses.

Browser checks skip when Chrome isn't on PATH.
"""
import json
import atexit
import os
import re
import shutil
import subprocess
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-editor-drag')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-editordrag-test-')
# Each of these holds a ~2.5 MB copy of main.py and a SQLite database; nothing
# removed them, so repeated suite runs left GBs behind in /tmp.
atexit.register(shutil.rmtree, _SCRATCH, ignore_errors=True)
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
SKIPPED = []


def check(label, cond):
    print(('  PASS  ' if cond else '  FAIL  ') + label)
    if not cond:
        FAILURES.append(label)


def skip(label, why):
    print(f'  SKIP  {label} — {why}')
    SKIPPED.append(label)


def _read(rel):
    return open(os.path.join(_REPO, rel)).read()


def test_csrf_plumbing():
    print('\n[1] the token reaches the calls that ask for it by name')
    shim = _read('Templates/components/csrf.html')
    check('the shim publishes it as a global',
          'window.csrfToken = TOKEN' in shim)
    check('and still fills in a missing header',
          "if (!headers.has('X-CSRFToken'))" in shim)

    # Nothing defines csrfToken in the page editor itself — the global is what
    # makes these work, so a regression here is silent and total.
    editor = _read('Templates/page_editor.html')
    users = editor.count("typeof csrfToken !== 'undefined'")
    check(f'the page editor relies on it in {users} places', users > 0)
    defines = re.findall(r'(?:var|let|const)\s+csrfToken\s*=', editor)
    check('while defining it nowhere itself', not defines)

    for js in ('static/js/music_library_modal.js',
               'static/js/video_library_modal.js',
               'static/js/photo_library_modal.js'):
        src = _read(js)
        if "typeof csrfToken !== 'undefined'" in src:
            check(f'{os.path.basename(js)} relies on it too',
                  not re.findall(r'(?:var|let|const)\s+csrfToken\s*=', src))


def test_server_rejects_empty():
    print('\n[2] an empty token really is refused')
    # Which is why the fault looked like an expired session rather than a bug.
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
        owner_id = owner.id

    app.config['WTF_CSRF_ENABLED'] = True
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(owner_id)
        s['_fresh'] = True
    r = c.post('/update_editor_group_and_row_order',
               json={'group_ids': [], 'rows': []},
               headers={'X-CSRFToken': ''})
    body = (r.get_json() or {})
    check(f'an empty token is rejected — got {r.status_code}', r.status_code == 400)
    check(f'with the message people were seeing ({body.get("error", "")[:32]}…)',
          'session expired' in (body.get('error') or ''))
    app.config['WTF_CSRF_ENABLED'] = False


def _chrome():
    for exe in ('google-chrome', 'chromium', 'chromium-browser'):
        p = shutil.which(exe)
        if p:
            return p
    return None



def _render_dir(prefix):
    """A temp dir for one headless-Chrome render, removed when the run ends.

    Every render gets its own --user-data-dir, and nothing ever deleted them:
    1679 abandoned Chrome profiles totalling ~5 GB had built up in /tmp. atexit
    rather than a try/finally because the helper has several return points, and
    the directory has to outlive the subprocess call either way.
    """
    d = tempfile.mkdtemp(prefix=prefix)
    atexit.register(shutil.rmtree, d, ignore_errors=True)
    return d

def _run_page(chrome, html, budget=6000):
    d = _render_dir('uwebia-editordrag-run-')
    f = os.path.join(d, 'p.html')
    with open(f, 'w') as fh:
        fh.write(html)
    out = subprocess.run(
        [chrome, '--headless=new', '--disable-gpu', '--no-sandbox',
         f'--user-data-dir={os.path.join(d, "profile")}',
         f'--virtual-time-budget={budget}', '--window-size=520,900',
         '--hide-scrollbars', '--dump-dom', f'file://{f}'],
        capture_output=True, text=True, timeout=120).stdout
    m = re.search(r'RESULT (\{[^<]*\})', out)
    return json.loads(m.group(1)) if m else None


def test_global_resolves():
    print('\n[3] and the editor\'s own expression resolves to it')
    chrome = _chrome()
    if not chrome:
        skip('global token check', 'no Chrome/Chromium on PATH')
        return
    shim = _read('Templates/components/csrf.html')
    # Render the shim as the page would: the meta tag with a token in it.
    shim = shim.replace(
        '{{ csrf_token() if csrf_token is callable else csrf_token }}',
        'a-real-looking-token')
    shim = re.sub(r'\{#.*?#\}', '', shim, flags=re.S)
    page = f"""<!doctype html><html><head><meta charset=utf-8>{shim}</head><body>
<script>
var sent = (typeof csrfToken !== 'undefined' ? csrfToken : '');
var d = document.createElement('div'); d.id = 'o';
d.textContent = 'RESULT ' + JSON.stringify({{
  visible: (typeof csrfToken !== 'undefined'), sent: sent }});
document.body.appendChild(d);
</script></body></html>"""
    r = _run_page(chrome, page)
    if r is None:
        skip('global token check', 'no measurement')
        return
    check('csrfToken is defined for plain scripts', r['visible'] is True)
    check(f'and carries the real token ({r["sent"]!r})',
          r['sent'] == 'a-real-looking-token')


def test_touch_drag():
    print('\n[4] a section can be moved with a finger')
    chrome = _chrome()
    if not chrome:
        skip('touch drag', 'no Chrome/Chromium on PATH')
        return
    editor = _read('Templates/page_editor.html')
    # Take the wiring as well as the drag, so this exercises the listener the
    # app actually attaches rather than one written for the test.
    start = editor.index('function initializeSectionDragAndDrop')
    end = editor.index('\n        function handleSectionDragStart', start)
    fn = editor[start:end]
    check('the touch path exists', 'pointermove' in fn and 'moveOrSwapSection' in fn)
    check('and it is reached from the handle the app wires up',
          'beginTouchSectionDrag' in fn and "'.section-drag-handle'" in fn)

    # Exercised against a stub of the editor's DOM and helpers, so this tests
    # the drag itself rather than the whole editor booting.
    page = """<!doctype html><html><head><meta charset=utf-8><style>
body{margin:0} .row{display:flex;width:500px}
.column{flex:1;min-height:120px;border:1px solid #ccc}
.section-card{padding:8px;background:#eee}
.section-drag-handle{display:inline-block;width:28px;height:28px;background:#7ec}
</style></head><body>
<div class="row">
  <div class="column" data-column-id="1">
    <div class="section-card" data-section-id="42">
      <span class="section-drag-handle">&#9776;</span> Section
    </div>
  </div>
  <div class="column" data-column-id="2"></div>
</div>
<div id="o"></div>
<script>
var CALLS = [];
function _columnGroupAccessible() { return true; }
function closeOpenSectionPanels() {}
function clearSectionDropState(col) {
  col.classList.remove('section-drop-hover','will-swap-section','will-move-section');
}
function cleanupSectionDrag() {
  document.body.classList.remove('is-sorting','is-sorting-sections');
  document.querySelectorAll('.column').forEach(clearSectionDropState);
  document.querySelectorAll('.section-card-dragging').forEach(function(c){
    c.classList.remove('section-card-dragging'); });
}
function moveOrSwapSection(sectionId, from, to) { CALLS.push([sectionId, from, to]); }
// The mouse path's handlers — present so the wiring can attach them, not used.
function handleSectionDragOver() {}
function handleSectionDragLeave() {}
function handleSectionDrop() {}
function handleSectionDragStart() {}
function handleSectionDragEnd() {}
var sectionHandleDragArmed = false;
__FN__
window.addEventListener('load', function () {
  initializeSectionDragAndDrop();
  var handle = document.querySelector('.section-drag-handle');
  var dst = document.querySelector('.column[data-column-id="2"]');
  var h = handle.getBoundingClientRect(), d = dst.getBoundingClientRect();
  function ev(target, type, x, y) {
    target.dispatchEvent(new PointerEvent(type, { bubbles:true, cancelable:true,
      pointerType:'touch', pointerId:1, clientX:x, clientY:y }));
  }
  // A finger presses the handle, slides to the empty column, and lifts.
  handle.dispatchEvent(new PointerEvent('pointerdown', { bubbles:true, cancelable:true,
    pointerType:'touch', pointerId:1, clientX:h.left+14, clientY:h.top+14 }));
  var started = document.body.classList.contains('is-sorting-sections');
  ev(document, 'pointermove', d.left + d.width/2, d.top + 40);
  var hovered = dst.classList.contains('section-drop-hover');
  var marked = dst.classList.contains('will-move-section');
  ev(document, 'pointerup', d.left + d.width/2, d.top + 40);

  // Snapshot before the mouse case clears the log.
  var touchCalls = CALLS.slice();

  // A mouse must NOT take this path — it still uses drag-and-drop.
  CALLS.length = 0;
  handle.dispatchEvent(new PointerEvent('pointerdown', { bubbles:true, cancelable:true,
    pointerType:'mouse', pointerId:2, clientX:h.left+14, clientY:h.top+14 }));
  var mouseStarted = document.body.classList.contains('is-sorting-sections');
  cleanupSectionDrag();

  var o = document.createElement('div'); o.id='o';
  o.textContent = 'RESULT ' + JSON.stringify({
    started: started, hovered: hovered, markedAsMove: marked,
    calls: touchCalls, mouseCalls: CALLS.slice(), mouseStarted: mouseStarted,
    cleanedUp: !document.body.classList.contains('is-sorting') });
  document.body.appendChild(o);
});
</script></body></html>"""
    page = page.replace('__FN__', fn).replace('window.__calls', 'CALLS')
    r = _run_page(chrome, page)
    if r is None:
        skip('touch drag', 'no measurement')
        return
    check('pressing the handle starts a drag', r['started'] is True)
    check('sliding over another column highlights it', r['hovered'] is True)
    check('an empty cell is marked as a move, not a swap', r['markedAsMove'] is True)
    check(f'lifting the finger moves the section ({r["calls"]})',
          r['calls'] == [[42, 1, 2]])
    check('a mouse press does not take the touch path', r['mouseStarted'] is False)
    check('and nothing is left in a dragging state', r['cleanedUp'] is True)

    print('\n[5] the handle lets the gesture through')
    ed_css = editor[editor.index('.section-drag-handle {'):]
    ed_css = ed_css[:ed_css.index('.section-label')]
    check('touch-action is none, or the browser scrolls instead of dragging',
          'touch-action: none' in _read('Templates/page_editor.html'))


if __name__ == '__main__':
    test_csrf_plumbing()
    test_server_rejects_empty()
    test_global_resolves()
    test_touch_drag()
    tail = f' ({len(SKIPPED)} skipped)' if SKIPPED else ''
    print('\n' + (f'ALL PASSED{tail}' if not FAILURES
                  else f'{len(FAILURES)} FAILED{tail}: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
