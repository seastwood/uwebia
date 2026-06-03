/* guide_quiz.js — hydrates quiz embeds on public pages.
 *
 * Scans for `.uw-quiz-embed[data-quiz-id]` (emitted by the lesson editor's quiz
 * blot and, later, by the page-builder quiz section), fetches the answer-free
 * quiz payload, renders an interactive form, grades server-side on submit, and
 * shows per-question feedback + score with unlimited retakes.
 *
 * Question types: single_choice, multi_choice, true_false, short_text,
 * fill_blank (partial credit), matching (tap-to-place, mobile friendly),
 * ordering (move up/down), image_choice (image options).
 *
 * Set `window.UW_GUIDE_NODE_ID` before this script runs to attribute attempts
 * to a lesson (used for progress context). Self-contained: injects its own CSS.
 */
(function () {
    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function injectStyles() {
        if (document.getElementById('uwq-styles')) return;
        const css = `
.uw-quiz-embed.uwq-live { display:block; padding:0; border:none; background:none; }
.uwq { border:1px solid rgba(94,238,248,0.25); border-radius:14px; padding:20px 22px; margin:22px 0; background:rgba(94,238,248,0.04); }
.uwq-head { display:flex; align-items:center; gap:10px; margin-bottom:6px; }
.uwq-head i { color:#5eeec8; }
.uwq-head h3 { margin:0; font-size:1.05rem; font-weight:800; }
.uwq-desc { opacity:0.7; font-size:0.92rem; margin:0 0 14px; }
.uwq-q { padding:14px 0; border-top:1px solid rgba(255,255,255,0.08); }
.uwq-q:first-of-type { border-top:none; }
.uwq-prompt { font-weight:600; margin:0 0 10px; display:flex; gap:8px; align-items:baseline; }
.uwq-num { display:inline-flex; align-items:center; justify-content:center; min-width:22px; height:22px; border-radius:50%; background:rgba(94,238,248,0.18); color:#5eeef8; font-size:0.75rem; font-weight:700; flex-shrink:0; }
.uwq-opt { display:flex; align-items:center; gap:9px; padding:8px 10px; border-radius:8px; cursor:pointer; transition:background 0.12s; }
.uwq-opt:hover { background:rgba(255,255,255,0.05); }
.uwq-opt input { accent-color:#5eeef8; width:16px; height:16px; }
.uwq-opt.opt-correct { background:rgba(94,238,200,0.14); }
.uwq-opt.opt-correct span::after { content:" ✓"; color:#5eeec8; font-weight:700; }
.uwq-opt.opt-chosen-wrong { background:rgba(255,90,90,0.14); }
.uwq-opt.opt-chosen-wrong span::after { content:" ✕"; color:#ff7676; font-weight:700; }
.uwq-text { width:100%; max-width:360px; padding:9px 12px; border-radius:8px; border:1px solid rgba(255,255,255,0.18); background:rgba(255,255,255,0.06); color:inherit; font-size:0.95rem; outline:none; }
.uwq-text:focus { border-color:rgba(94,238,248,0.5); }
.uwq-fb { margin-top:8px; font-size:0.84rem; opacity:0.85; }
.uwq-ok { color:#5eeec8; font-weight:700; }
.uwq-no { color:#ff7676; font-weight:700; }
.uwq-actions { display:flex; align-items:center; gap:14px; margin-top:16px; padding-top:14px; border-top:1px solid rgba(255,255,255,0.08); flex-wrap:wrap; }
.uwq-submit { padding:9px 22px; border-radius:9px; border:none; cursor:pointer; font-weight:700; background:linear-gradient(135deg,#5eeef8,#5eeec8); color:#111; }
.uwq-submit:disabled { opacity:0.6; cursor:default; }
.uwq-score { font-size:0.9rem; font-weight:600; opacity:0.85; }
.uwq-status { padding:3px 12px; border-radius:99px; font-size:0.74rem; font-weight:800; letter-spacing:0.06em; text-transform:uppercase; }
.uwq-status.is-pass { background:rgba(94,238,200,0.18); color:#5eeec8; }
.uwq-status.is-fail { background:rgba(255,90,90,0.18); color:#ff8c8c; }
.uwq-hint { font-size:0.78rem; opacity:0.55; flex-basis:100%; margin:4px 0 0; }
.uwq-err { padding:14px; border-radius:10px; background:rgba(255,90,90,0.1); color:#ff9b9b; font-size:0.9rem; }
.uwq-loading { padding:14px; opacity:0.5; font-size:0.9rem; }
/* fill in the blank */
.uwq-blank { display:inline-block; width:120px; padding:3px 8px; margin:0 3px; border:none; border-bottom:2px solid rgba(94,238,248,0.55); background:rgba(255,255,255,0.06); color:inherit; font-size:0.95rem; outline:none; border-radius:4px 4px 0 0; }
.uwq-blank:focus { border-bottom-color:#5eeec8; }
.uwq-blank.bl-correct { border-bottom-color:#5eeec8; background:rgba(94,238,200,0.14); }
.uwq-blank.bl-wrong { border-bottom-color:#ff7676; background:rgba(255,90,90,0.12); }
.uwq-blank-prompt { line-height:2; }
/* image options */
.uwq-img-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(130px,1fr)); gap:10px; }
.uwq-img-opt { position:relative; display:block; border:2px solid rgba(255,255,255,0.14); border-radius:10px; overflow:hidden; cursor:pointer; background:rgba(255,255,255,0.04); }
.uwq-img-opt input { position:absolute; top:8px; left:8px; width:18px; height:18px; accent-color:#5eeef8; z-index:2; }
.uwq-img-opt img { display:block; width:100%; height:120px; object-fit:cover; }
.uwq-img-opt.is-picked { border-color:#5eeec8; }
.uwq-img-cap { font-size:0.78rem; padding:6px 8px; opacity:0.85; }
.uwq-img-opt.opt-correct { border-color:#5eeec8; box-shadow:0 0 0 2px rgba(94,238,200,0.4) inset; }
.uwq-img-opt.opt-chosen-wrong { border-color:#ff7676; box-shadow:0 0 0 2px rgba(255,90,90,0.4) inset; }
.uwq-cell-img { display:block; max-width:100%; max-height:90px; object-fit:contain; border-radius:6px; }
/* matching */
.uwq-match-help { font-size:0.78rem; opacity:0.6; margin:0 0 10px; }
.uwq-match-pool { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:14px; min-height:8px; }
.uwq-chip { display:inline-flex; align-items:center; gap:6px; padding:6px 11px; border-radius:9px; border:1px solid rgba(94,238,248,0.4); background:rgba(94,238,248,0.08); cursor:pointer; font-size:0.9rem; user-select:none; }
.uwq-chip.is-selected { background:rgba(94,238,248,0.28); border-color:#5eeef8; }
.uwq-chip img { max-height:40px; border-radius:4px; }
.uwq-match-targets { display:flex; flex-direction:column; gap:8px; }
.uwq-target { display:flex; align-items:center; gap:10px; padding:8px 10px; border:1px dashed rgba(255,255,255,0.22); border-radius:10px; }
.uwq-target.is-droppable { border-color:rgba(94,238,248,0.7); background:rgba(94,238,248,0.05); cursor:pointer; }
.uwq-target-desc { flex:1; min-width:0; font-size:0.9rem; }
.uwq-target-slot { flex-shrink:0; min-width:90px; min-height:34px; display:flex; align-items:center; justify-content:center; border-radius:8px; background:rgba(255,255,255,0.05); padding:2px; }
.uwq-target.bl-correct { border-style:solid; border-color:#5eeec8; }
.uwq-target.bl-wrong { border-style:solid; border-color:#ff7676; }
/* ordering */
.uwq-order { display:flex; flex-direction:column; gap:7px; }
.uwq-order-row { display:flex; align-items:center; gap:10px; padding:8px 10px; border:1px solid rgba(255,255,255,0.14); border-radius:9px; background:rgba(255,255,255,0.04); }
.uwq-order-pos { min-width:22px; height:22px; border-radius:50%; display:inline-flex; align-items:center; justify-content:center; background:rgba(94,238,248,0.18); color:#5eeef8; font-size:0.74rem; font-weight:700; flex-shrink:0; }
.uwq-order-body { flex:1; min-width:0; font-size:0.9rem; }
.uwq-order-moves { display:flex; flex-direction:column; gap:2px; }
.uwq-move { width:30px; height:22px; border:1px solid rgba(255,255,255,0.18); background:rgba(255,255,255,0.06); color:inherit; border-radius:6px; cursor:pointer; line-height:1; font-size:0.7rem; }
.uwq-move:disabled { opacity:0.3; cursor:default; }
.uwq-order-row.bl-correct { border-color:#5eeec8; }
.uwq-order-row.bl-wrong { border-color:#ff7676; }
`;
        const style = document.createElement('style');
        style.id = 'uwq-styles';
        style.textContent = css;
        document.head.appendChild(style);
    }

    function cellHtml(cell) {
        if (cell && cell.kind === 'image' && cell.image_url) {
            return '<img class="uwq-cell-img" src="' + esc(cell.image_url) + '" alt="' + esc(cell.text || '') + '">'
                + (cell.text ? '<span class="uwq-img-cap">' + esc(cell.text) + '</span>' : '');
        }
        return esc((cell && cell.text) || '');
    }

    async function hydrate(el) {
        const quizId = el.getAttribute('data-quiz-id');
        if (!quizId || el._uwq) return;
        el._uwq = true;
        el.classList.add('uwq-live');
        el.innerHTML = '<div class="uwq-loading">Loading quiz…</div>';
        let data;
        try { data = await (await fetch('/api/quizzes/' + quizId)).json(); }
        catch (e) { el.innerHTML = '<div class="uwq-err">Could not load quiz.</div>'; return; }
        if (!data || !data.success) { el.innerHTML = '<div class="uwq-err">Quiz unavailable.</div>'; return; }
        // Only on first load — a Retake starts from a blank form.
        renderQuiz(el, data.quiz, data.quiz.draft);
    }

    function renderQuiz(el, quiz, draft) {
        el._quiz = quiz;
        el._mstate = {};  // matching: qid -> {leftId: rightId}
        el._ostate = {};  // ordering: qid -> [itemId,...]
        el._sel = {};     // matching: qid -> currently picked leftId
        let html = '<div class="uwq"><div class="uwq-head"><i class="fas fa-clipboard-check"></i><h3>' + esc(quiz.title) + '</h3></div>';
        if (quiz.description) html += '<p class="uwq-desc">' + esc(quiz.description) + '</p>';
        html += '<form class="uwq-form">';
        (quiz.questions || []).forEach((q, qi) => { html += renderQuestion(q, qi); });
        html += '<div class="uwq-actions"><button type="submit" class="uwq-submit">Submit</button><span class="uwq-score"></span></div>';
        html += '</form></div>';
        el.innerHTML = html;

        // Seed interactive widget state (from draft when present) then paint.
        (quiz.questions || []).forEach(q => {
            if (q.question_type === 'ordering') {
                let order = (q.items || []).map(it => it.id);
                if (draft && Array.isArray(draft[q.id]) &&
                    draft[q.id].length === order.length &&
                    draft[q.id].every(id => order.indexOf(id) >= 0)) {
                    order = draft[q.id].slice();
                }
                el._ostate[q.id] = order;
                renderOrdering(el, q);
            } else if (q.question_type === 'matching') {
                const map = {};
                if (draft && draft[q.id] && typeof draft[q.id] === 'object') {
                    Object.keys(draft[q.id]).forEach(k => { map[k] = draft[q.id][k]; });
                }
                el._mstate[q.id] = map;
                renderMatching(el, q);
            }
        });

        const form = el.querySelector('.uwq-form');
        form.addEventListener('submit', ev => { ev.preventDefault(); submit(el, quiz); });
        if (draft) applyDraft(el, quiz, draft);
        form.addEventListener('input', () => scheduleDraftSave(el, quiz));
        form.addEventListener('change', () => {
            (quiz.questions || []).forEach(q => { if (q.question_type === 'image_choice') syncImgPicked(el, q); });
            scheduleDraftSave(el, quiz);
        });
    }

    function renderQuestion(q, qi) {
        const t = q.question_type;
        let h = '<div class="uwq-q" data-qid="' + q.id + '" data-qtype="' + t + '">';
        if (t === 'fill_blank') {
            h += '<p class="uwq-prompt uwq-blank-prompt"><span class="uwq-num">' + (qi + 1) + '</span><span>' + blankPromptHtml(q) + '</span></p>';
        } else {
            h += '<p class="uwq-prompt"><span class="uwq-num">' + (qi + 1) + '</span>' + esc(q.prompt) + '</p>';
        }
        if (t === 'short_text') {
            h += '<input type="text" class="uwq-text" name="q' + q.id + '" autocomplete="off">';
        } else if (t === 'single_choice' || t === 'multi_choice' || t === 'true_false') {
            const inputType = (t === 'multi_choice') ? 'checkbox' : 'radio';
            (q.options || []).forEach(o => {
                h += '<label class="uwq-opt"><input type="' + inputType + '" name="q' + q.id + '" value="' + o.id + '"> <span>' + esc(o.text) + '</span></label>';
            });
        } else if (t === 'image_choice') {
            const inputType = q.multiple ? 'checkbox' : 'radio';
            h += '<div class="uwq-img-grid">';
            (q.options || []).forEach(o => {
                h += '<label class="uwq-img-opt" data-oid="' + o.id + '">'
                    + '<input type="' + inputType + '" name="q' + q.id + '" value="' + o.id + '">'
                    + '<img src="' + esc(o.image_url) + '" alt="' + esc(o.caption || '') + '">'
                    + (o.caption ? '<div class="uwq-img-cap">' + esc(o.caption) + '</div>' : '')
                    + '</label>';
            });
            h += '</div>';
        } else if (t === 'matching') {
            h += '<p class="uwq-match-help">Tap an item, then tap the description it matches. Tap a placed item to send it back.</p>';
            h += '<div class="uwq-match" data-qid="' + q.id + '"></div>';
        } else if (t === 'ordering') {
            h += '<p class="uwq-match-help">Put these in the correct order using the arrows.</p>';
            h += '<div class="uwq-order" data-qid="' + q.id + '"></div>';
        }
        h += '<div class="uwq-fb" style="display:none;"></div></div>';
        return h;
    }

    // fill_blank: render prompt text with <input> in place of each ___ marker.
    function blankPromptHtml(q) {
        const parts = String(q.prompt || '').split(/_{3,}/);
        let h = '';
        parts.forEach((seg, i) => {
            h += esc(seg);
            if (i < parts.length - 1) {
                h += '<input type="text" class="uwq-blank" data-bi="' + i + '" autocomplete="off">';
            }
        });
        return h;
    }

    // ── matching ────────────────────────────────────────────────────────────
    function renderMatching(el, q) {
        const wrap = el.querySelector('.uwq-match[data-qid="' + q.id + '"]');
        if (!wrap) return;
        const map = el._mstate[q.id] || (el._mstate[q.id] = {});
        const placed = {};                       // rightId -> leftId
        Object.keys(map).forEach(lid => { placed[map[lid]] = lid; });
        const leftById = {};
        (q.lefts || []).forEach(l => { leftById[l.id] = l; });
        const sel = el._sel[q.id];

        let h = '<div class="uwq-match-pool">';
        (q.lefts || []).forEach(l => {
            if (map[l.id] != null) return;        // placed → not in pool
            h += '<span class="uwq-chip' + (sel === l.id ? ' is-selected' : '') + '" data-lid="' + l.id + '">' + cellHtml(l) + '</span>';
        });
        h += '</div><div class="uwq-match-targets">';
        (q.rights || []).forEach(r => {
            const lid = placed[r.id];
            h += '<div class="uwq-target' + (sel != null ? ' is-droppable' : '') + '" data-rid="' + r.id + '">'
                + '<div class="uwq-target-desc">' + cellHtml(r) + '</div>'
                + '<div class="uwq-target-slot">'
                + (lid != null ? '<span class="uwq-chip" data-lid="' + lid + '" data-placed="1">' + cellHtml(leftById[lid]) + '</span>' : '')
                + '</div></div>';
        });
        h += '</div>';
        wrap.innerHTML = h;

        wrap.querySelectorAll('.uwq-chip[data-placed="1"]').forEach(chip => {
            chip.addEventListener('click', ev => {
                ev.stopPropagation();
                const lid = parseInt(chip.dataset.lid);
                delete el._mstate[q.id][lid];      // back to pool
                el._sel[q.id] = null;
                renderMatching(el, q); scheduleDraftSave(el, el._quiz);
            });
        });
        wrap.querySelectorAll('.uwq-match-pool .uwq-chip').forEach(chip => {
            chip.addEventListener('click', () => {
                const lid = parseInt(chip.dataset.lid);
                el._sel[q.id] = (el._sel[q.id] === lid) ? null : lid;
                renderMatching(el, q);
            });
        });
        wrap.querySelectorAll('.uwq-target').forEach(tg => {
            tg.addEventListener('click', () => {
                const picked = el._sel[q.id];
                if (picked == null) return;
                const rid = parseInt(tg.dataset.rid);
                // Clear whoever currently sits on this target, and any prior
                // placement of the picked item.
                Object.keys(el._mstate[q.id]).forEach(k => {
                    if (el._mstate[q.id][k] === rid) delete el._mstate[q.id][k];
                });
                el._mstate[q.id][picked] = rid;
                el._sel[q.id] = null;
                renderMatching(el, q); scheduleDraftSave(el, el._quiz);
            });
        });
    }

    // ── ordering ────────────────────────────────────────────────────────────
    function renderOrdering(el, q) {
        const wrap = el.querySelector('.uwq-order[data-qid="' + q.id + '"]');
        if (!wrap) return;
        const order = el._ostate[q.id] || [];
        const byId = {};
        (q.items || []).forEach(it => { byId[it.id] = it; });
        let h = '';
        order.forEach((id, i) => {
            h += '<div class="uwq-order-row" data-id="' + id + '">'
                + '<span class="uwq-order-pos">' + (i + 1) + '</span>'
                + '<div class="uwq-order-body">' + cellHtml(byId[id]) + '</div>'
                + '<div class="uwq-order-moves">'
                + '<button type="button" class="uwq-move" data-dir="-1" ' + (i === 0 ? 'disabled' : '') + '>▲</button>'
                + '<button type="button" class="uwq-move" data-dir="1" ' + (i === order.length - 1 ? 'disabled' : '') + '>▼</button>'
                + '</div></div>';
        });
        wrap.innerHTML = h;
        wrap.querySelectorAll('.uwq-move').forEach(btn => {
            btn.addEventListener('click', () => {
                const row = btn.closest('.uwq-order-row');
                const id = parseInt(row.dataset.id);
                const dir = parseInt(btn.dataset.dir);
                const arr = el._ostate[q.id];
                const idx = arr.indexOf(id);
                const j = idx + dir;
                if (j < 0 || j >= arr.length) return;
                arr[idx] = arr[j]; arr[j] = id;
                renderOrdering(el, q); scheduleDraftSave(el, el._quiz);
            });
        });
    }

    function collect(el, quiz) {
        const answers = {};
        (quiz.questions || []).forEach(q => {
            const name = 'q' + q.id;
            const t = q.question_type;
            if (t === 'short_text') {
                const inp = el.querySelector('input[name="' + name + '"]');
                answers[q.id] = inp ? inp.value : '';
            } else if (t === 'multi_choice' || (t === 'image_choice' && q.multiple)) {
                answers[q.id] = Array.from(el.querySelectorAll('input[name="' + name + '"]:checked')).map(i => parseInt(i.value));
            } else if (t === 'single_choice' || t === 'true_false' || t === 'image_choice') {
                const sel = el.querySelector('input[name="' + name + '"]:checked');
                answers[q.id] = sel ? parseInt(sel.value) : null;
            } else if (t === 'fill_blank') {
                const qEl = el.querySelector('.uwq-q[data-qid="' + q.id + '"]');
                const inputs = Array.from(qEl.querySelectorAll('.uwq-blank'))
                    .sort((a, b) => parseInt(a.dataset.bi) - parseInt(b.dataset.bi));
                answers[q.id] = inputs.map(i => i.value);
            } else if (t === 'matching') {
                answers[q.id] = el._mstate[q.id] || {};
            } else if (t === 'ordering') {
                answers[q.id] = (el._ostate[q.id] || []).slice();
            }
        });
        return answers;
    }

    // Restore previously-saved answers onto a freshly rendered form. Matching
    // and ordering state is seeded in renderQuiz; here we cover the inputs.
    function applyDraft(el, quiz, draft) {
        (quiz.questions || []).forEach(q => {
            if (!(q.id in draft)) return;
            const val = draft[q.id];
            const name = 'q' + q.id;
            const t = q.question_type;
            if (t === 'short_text') {
                const inp = el.querySelector('input[name="' + name + '"]');
                if (inp && val != null) inp.value = val;
            } else if (t === 'multi_choice' || (t === 'image_choice' && q.multiple)) {
                const picked = Array.isArray(val) ? val.map(String) : [];
                el.querySelectorAll('input[name="' + name + '"]').forEach(i => { i.checked = picked.indexOf(String(i.value)) >= 0; });
                if (t === 'image_choice') syncImgPicked(el, q);
            } else if (t === 'single_choice' || t === 'true_false' || t === 'image_choice') {
                el.querySelectorAll('input[name="' + name + '"]').forEach(i => { i.checked = String(i.value) === String(val); });
                if (t === 'image_choice') syncImgPicked(el, q);
            } else if (t === 'fill_blank') {
                const qEl = el.querySelector('.uwq-q[data-qid="' + q.id + '"]');
                const inputs = Array.from(qEl.querySelectorAll('.uwq-blank'))
                    .sort((a, b) => parseInt(a.dataset.bi) - parseInt(b.dataset.bi));
                (Array.isArray(val) ? val : []).forEach((v, i) => { if (inputs[i] && v != null) inputs[i].value = v; });
            }
            // matching / ordering already seeded from draft in renderQuiz.
        });
        // Reflect image-choice selection styling for any seeded radios.
        (quiz.questions || []).forEach(q => { if (q.question_type === 'image_choice') syncImgPicked(el, q); });
    }

    function syncImgPicked(el, q) {
        el.querySelectorAll('.uwq-q[data-qid="' + q.id + '"] .uwq-img-opt').forEach(lab => {
            const inp = lab.querySelector('input');
            lab.classList.toggle('is-picked', !!(inp && inp.checked));
        });
    }

    function scheduleDraftSave(el, quiz) {
        if (!quiz) return;
        clearTimeout(el._uwqDraftTimer);
        el._uwqDraftTimer = setTimeout(() => saveDraft(el, quiz), 700);
    }

    function saveDraft(el, quiz) {
        try {
            fetch('/api/quizzes/' + quiz.id + '/draft', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ answers: collect(el, quiz), guide_node_id: window.UW_GUIDE_NODE_ID || null })
            });
        } catch (e) { /* ignore */ }
    }

    async function submit(el, quiz) {
        clearTimeout(el._uwqDraftTimer);
        const answers = collect(el, quiz);
        const btn = el.querySelector('.uwq-submit');
        btn.disabled = true; btn.textContent = 'Checking…';
        let data;
        try {
            data = await (await fetch('/api/quizzes/' + quiz.id + '/submit', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ answers: answers, guide_node_id: window.UW_GUIDE_NODE_ID || null })
            })).json();
        } catch (e) { btn.disabled = false; btn.textContent = 'Submit'; return; }
        if (!data || !data.success) { btn.disabled = false; btn.textContent = 'Submit'; return; }
        showResults(el, quiz, data);
    }

    function showResults(el, quiz, data) {
        const byId = {};
        (data.results || []).forEach(r => { byId[r.question_id] = r; });
        (quiz.questions || []).forEach(q => {
            const qEl = el.querySelector('.uwq-q[data-qid="' + q.id + '"]');
            const r = byId[q.id];
            if (!qEl || !r) return;
            qEl.classList.remove('is-correct', 'is-wrong');
            qEl.classList.add(r.correct ? 'is-correct' : 'is-wrong');
            const t = q.question_type;

            if (t === 'single_choice' || t === 'multi_choice' || t === 'true_false') {
                paintChoice(qEl, r, '.uwq-opt', 'input');
            } else if (t === 'image_choice') {
                paintChoice(qEl, r, '.uwq-img-opt', 'input');
            } else if (t === 'fill_blank') {
                const inputs = Array.from(qEl.querySelectorAll('.uwq-blank'))
                    .sort((a, b) => parseInt(a.dataset.bi) - parseInt(b.dataset.bi));
                (r.blank_results || []).forEach((ok, i) => {
                    if (!inputs[i]) return;
                    inputs[i].classList.remove('bl-correct', 'bl-wrong');
                    inputs[i].classList.add(ok ? 'bl-correct' : 'bl-wrong');
                });
            } else if (t === 'matching') {
                // Reveal correct mapping only when the server included it.
                if (r.correct_pairs) {
                    qEl.querySelectorAll('.uwq-target').forEach(tg => {
                        const rid = parseInt(tg.dataset.rid);
                        const placed = tg.querySelector('.uwq-target-slot .uwq-chip');
                        const lid = placed ? parseInt(placed.dataset.lid) : null;
                        const ok = lid != null && r.correct_pairs[String(lid)] === rid;
                        tg.classList.add(ok ? 'bl-correct' : 'bl-wrong');
                    });
                }
            } else if (t === 'ordering') {
                if (r.answer_order) {
                    const order = el._ostate[q.id] || [];
                    qEl.querySelectorAll('.uwq-order-row').forEach((row, i) => {
                        row.classList.add(order[i] === r.answer_order[i] ? 'bl-correct' : 'bl-wrong');
                    });
                }
            }

            const fb = qEl.querySelector('.uwq-fb');
            if (fb) {
                fb.style.display = 'block';
                let txt = r.correct ? '<span class="uwq-ok">Correct</span>' : '<span class="uwq-no">Incorrect</span>';
                if (t === 'fill_blank' && Array.isArray(r.blank_results)) {
                    const got = r.blank_results.filter(Boolean).length;
                    txt += ' · ' + got + ' / ' + r.blank_results.length + ' blanks';
                }
                if (t === 'short_text' && !r.correct && r.accepted && r.accepted.length) {
                    txt += ' · Accepted: ' + r.accepted.map(esc).join(', ');
                }
                fb.innerHTML = txt;
            }
        });

        const scoreEl = el.querySelector('.uwq-score');
        let s = 'Score: ' + data.score + ' / ' + data.max_score;
        if (data.best_score != null) s += ' · Best: ' + data.best_score;
        scoreEl.textContent = s;

        const actions = el.querySelector('.uwq-actions');
        let pill = actions.querySelector('.uwq-status');
        if (!pill) {
            pill = document.createElement('span');
            pill.className = 'uwq-status';
            actions.insertBefore(pill, scoreEl);
        }
        const passed = !!data.passed;
        pill.classList.toggle('is-pass', passed);
        pill.classList.toggle('is-fail', !passed);
        pill.textContent = passed ? 'Passed' : 'Failed';
        let hint = actions.querySelector('.uwq-hint');
        if (!passed) {
            if (!hint) { hint = document.createElement('p'); hint.className = 'uwq-hint'; actions.appendChild(hint); }
            const need = Math.round((data.pass_threshold || 0.9) * 100);
            hint.textContent = 'You need at least ' + need + '% to complete this lesson — try again.';
        } else if (hint) { hint.remove(); }

        const btn = el.querySelector('.uwq-submit');
        btn.disabled = false;
        btn.textContent = 'Retake';
        btn.type = 'button';
        btn.onclick = () => renderQuiz(el, quiz);

        if (data.progress) {
            document.dispatchEvent(new CustomEvent('uwq-progress', { detail: data.progress }));
        }
    }

    // Shared text/image choice highlighting (reveal mode vs own-pick-only mode).
    function paintChoice(qEl, r, optSel, inputSel) {
        const correctIds = r.correct_option_ids;
        const reveal = Array.isArray(correctIds);
        qEl.querySelectorAll(optSel).forEach(opt => {
            const inp = opt.querySelector(inputSel);
            if (!inp) return;
            const val = parseInt(inp.value);
            opt.classList.remove('opt-correct', 'opt-chosen-wrong');
            if (reveal) {
                if (correctIds.indexOf(val) >= 0) opt.classList.add('opt-correct');
                if (inp.checked && correctIds.indexOf(val) < 0) opt.classList.add('opt-chosen-wrong');
            } else if (inp.checked) {
                opt.classList.add(r.correct ? 'opt-correct' : 'opt-chosen-wrong');
            }
        });
    }

    function init() {
        injectStyles();
        document.querySelectorAll('.uw-quiz-embed[data-quiz-id]').forEach(hydrate);
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
    window.UWQuiz = { init: init };
})();
